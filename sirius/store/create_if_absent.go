package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	valkey "github.com/valkey-io/valkey-go"
)

// ValueCreator is an optional atomic KVStore capability. False means the key
// already exists. Errors must never be interpreted as confirmed absence.
type ValueCreator interface {
	SetValueIfAbsent(ctx context.Context, key, value string) (bool, error)
}

// SetValueIfAbsent creates a key atomically without replacing an existing value.
func (s *valkeyStore) SetValueIfAbsent(ctx context.Context, key, value string) (bool, error) {
	err := s.client.Do(ctx, s.client.B().Set().Key(key).Value(value).Nx().Build()).Error()
	if valkey.IsValkeyNil(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("create key %q: %w", key, err)
	}
	return true, nil
}

// StoreAgentTokenIfAbsent enrolls an agent atomically. Existing records are
// never overwritten, even if two callers have both just observed a missing key.
// Stores without atomic creation are rejected rather than using GET then SET.
func StoreAgentTokenIfAbsent(ctx context.Context, s KVStore, agentID, token string) (bool, error) {
	creator, ok := s.(ValueCreator)
	if !ok {
		return false, fmt.Errorf("agent token store does not support atomic creation")
	}
	if agentID == "" || token == "" {
		return false, fmt.Errorf("agent ID and token must not be empty")
	}
	now := time.Now().UTC().Format(time.RFC3339)
	data, err := json.Marshal(AgentTokenMeta{AgentID: agentID, Token: token, CreatedAt: now, LastSeen: now})
	if err != nil {
		return false, fmt.Errorf("failed to marshal agent token meta: %w", err)
	}
	return creator.SetValueIfAbsent(ctx, agentTokenKey(agentID), string(data))
}

var _ ValueCreator = (*valkeyStore)(nil)
