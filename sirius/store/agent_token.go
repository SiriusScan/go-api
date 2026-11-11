package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const (
	// agentTokenPrefix is the Valkey key prefix for per-agent auth tokens.
	agentTokenPrefix = "agent_token:"
)

// AgentTokenMeta holds metadata for a per-agent authentication token.
type AgentTokenMeta struct {
	AgentID      string `json:"agent_id"`
	SubjectID    string `json:"subject_id,omitempty"`
	CredentialID string `json:"credential_id,omitempty"`
	Token        string `json:"token"`
	CreatedAt    string `json:"created_at"`
	LastSeen     string `json:"last_seen"`
}

// GenerateAgentToken creates a cryptographically random token string for an
// agent.  The token is 32 random bytes hex-encoded (64 characters).
func GenerateAgentToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate agent token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// agentTokenKey returns the Valkey key for a given agent ID.
func agentTokenKey(agentID string) string {
	return agentTokenPrefix + agentID
}

// StoreAgentToken explicitly replaces an agent token keyed by agent ID.
// Enrollment must use StoreAgentTokenIfAbsent to avoid replacing existing tokens.
func StoreAgentToken(ctx context.Context, s KVStore, agentID, token string) error {
	meta := AgentTokenMeta{
		AgentID:   agentID,
		Token:     token,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		LastSeen:  time.Now().UTC().Format(time.RFC3339),
	}

	data, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("failed to marshal agent token meta: %w", err)
	}

	return s.SetValue(ctx, agentTokenKey(agentID), string(data))
}

// ValidateAgentToken checks whether the provided token matches the one stored
// for the given agent ID. On success, it updates the LastSeen timestamp.
func ValidateAgentToken(ctx context.Context, s KVStore, agentID, token string) (AgentTokenMeta, error) {
	resp, err := s.GetValue(ctx, agentTokenKey(agentID))
	if err != nil {
		return AgentTokenMeta{}, fmt.Errorf("no token found for agent %s: %w", agentID, err)
	}

	var meta AgentTokenMeta
	if err := json.Unmarshal([]byte(resp.Message.Value), &meta); err != nil {
		return AgentTokenMeta{}, fmt.Errorf("failed to unmarshal agent token: %w", err)
	}

	if meta.Token != token {
		return AgentTokenMeta{}, fmt.Errorf("token mismatch for agent %s", agentID)
	}

	// Update last-seen only if the exact validated record still exists. An
	// unconditional write could restore a revoked or concurrently replaced token.
	meta.LastSeen = time.Now().UTC().Format(time.RFC3339)
	if cas, ok := s.(ValueCompareAndSetter); ok {
		if data, err := json.Marshal(meta); err == nil {
			_, _ = cas.CompareAndSetValue(ctx, agentTokenKey(agentID), resp.Message.Value, string(data))
		}
	}

	return meta, nil
}

// GetAgentToken retrieves the stored token metadata for an agent.
func GetAgentToken(ctx context.Context, s KVStore, agentID string) (AgentTokenMeta, error) {
	resp, err := s.GetValue(ctx, agentTokenKey(agentID))
	if err != nil {
		return AgentTokenMeta{}, fmt.Errorf("no token found for agent %s: %w", agentID, err)
	}

	var meta AgentTokenMeta
	if err := json.Unmarshal([]byte(resp.Message.Value), &meta); err != nil {
		return AgentTokenMeta{}, fmt.Errorf("failed to unmarshal agent token: %w", err)
	}
	return meta, nil
}

// AgentTokenExists distinguishes confirmed absence from a failed store read.
// Any stored value, including malformed metadata, reserves the agent ID.
func AgentTokenExists(ctx context.Context, s KVStore, agentID string) (bool, error) {
	_, err := s.GetValue(ctx, agentTokenKey(agentID))
	if errors.Is(err, ErrKeyNotFound) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to check agent token: %w", err)
	}
	return true, nil
}

// HasAgentToken conservatively treats failed reads as an existing token.
// Deprecated: use AgentTokenExists to handle unavailable storage explicitly.
func HasAgentToken(ctx context.Context, s KVStore, agentID string) bool {
	exists, err := AgentTokenExists(ctx, s, agentID)
	return exists || err != nil
}
