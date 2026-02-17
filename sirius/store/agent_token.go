package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

const (
	// agentTokenPrefix is the Valkey key prefix for per-agent auth tokens.
	agentTokenPrefix = "agent_token:"
)

// AgentTokenMeta holds metadata for a per-agent authentication token.
type AgentTokenMeta struct {
	AgentID   string `json:"agent_id"`
	Token     string `json:"token"`
	CreatedAt string `json:"created_at"`
	LastSeen  string `json:"last_seen"`
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

// StoreAgentToken persists an agent token in Valkey keyed by agent ID.
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

	// Update last-seen (best-effort).
	meta.LastSeen = time.Now().UTC().Format(time.RFC3339)
	if data, err := json.Marshal(meta); err == nil {
		_ = s.SetValue(ctx, agentTokenKey(agentID), string(data))
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

// HasAgentToken returns true if a token already exists for the given agent ID.
func HasAgentToken(ctx context.Context, s KVStore, agentID string) bool {
	_, err := s.GetValue(ctx, agentTokenKey(agentID))
	return err == nil
}
