package store

import (
	"context"
	"fmt"
	"time"

	valkey "github.com/valkey-io/valkey-go"
)

const (
	SIRIUS_VALKEY = "sirius-valkey:6379"
)

// KVStore defines the key/value operations our store supports.
type KVStore interface {
	// SetValue sets the given key to the specified value.
	SetValue(ctx context.Context, key, value string) error
	// SetValueWithTTL sets the given key to the specified value with a TTL in seconds.
	SetValueWithTTL(ctx context.Context, key, value string, ttlSeconds int) error
	// GetValue retrieves the value associated with the given key.
	GetValue(ctx context.Context, key string) (ValkeyResponse, error)
	// GetTTL retrieves the remaining TTL in seconds for the given key.
	GetTTL(ctx context.Context, key string) (int, error)
	// SetExpire sets the TTL for an existing key in seconds.
	SetExpire(ctx context.Context, key string, ttlSeconds int) error
	// ListKeys retrieves all keys matching the given pattern.
	ListKeys(ctx context.Context, pattern string) ([]string, error)
	// DeleteValue removes the value associated with the given key.
	DeleteValue(ctx context.Context, key string) error
	// Close shuts down the underlying connection.
	Close() error
}

// valkeyStore is a concrete implementation of KVStore using the valkey-go client.
type valkeyStore struct {
	client valkey.Client
}

// NewValkeyStore creates a new store connected to sirius-valkey:6379.
func NewValkeyStore() (KVStore, error) {
	client, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{SIRIUS_VALKEY}})
	if err != nil {
		return nil, err
	}
	return &valkeyStore{client: client}, nil
}

// SetValue implements KVStore by executing a SET command with NX semantics.
func (s *valkeyStore) SetValue(ctx context.Context, key, value string) error {
	cmd := s.client.B().Set().Key(key).Value(value).Build()
	return s.client.Do(ctx, cmd).Error()
}

// SetValueWithTTL implements KVStore by executing a SET command with TTL.
func (s *valkeyStore) SetValueWithTTL(ctx context.Context, key, value string, ttlSeconds int) error {
	cmd := s.client.B().Set().Key(key).Value(value).Ex(time.Duration(ttlSeconds) * time.Second).Build()
	return s.client.Do(ctx, cmd).Error()
}

// GetTTL implements KVStore by executing a TTL command.
func (s *valkeyStore) GetTTL(ctx context.Context, key string) (int, error) {
	cmd := s.client.B().Ttl().Key(key).Build()
	resp := s.client.Do(ctx, cmd)

	if err := resp.Error(); err != nil {
		return -1, fmt.Errorf("valkey TTL for key '%s' failed: %w", key, err)
	}

	ttl, err := resp.ToInt64()
	if err != nil {
		return -1, fmt.Errorf("failed to convert TTL reply to int64 for key '%s': %w", key, err)
	}

	return int(ttl), nil
}

// SetExpire implements KVStore by executing an EXPIRE command.
func (s *valkeyStore) SetExpire(ctx context.Context, key string, ttlSeconds int) error {
	cmd := s.client.B().Expire().Key(key).Seconds(int64(ttlSeconds)).Build()
	return s.client.Do(ctx, cmd).Error()
}

// GetValue implements KVStore by executing a GET command.
func (s *valkeyStore) GetValue(ctx context.Context, key string) (ValkeyResponse, error) {
	cmd := s.client.B().Get().Key(key).Build()
	resp := s.client.Do(ctx, cmd)
	var val ValkeyResponse

	if err := resp.Error(); err != nil {
		if valkey.IsValkeyNil(err) {
			return val, fmt.Errorf("key '%s' not found", key)
		}
		return val, fmt.Errorf("valkey GET for key '%s' failed: %w", key, err)
	}

	// Key exists, get its string value. resp itself can be used for result conversion if no error.
	stringValue, err := resp.ToString()
	if err != nil {
		return val, fmt.Errorf("failed to convert valkey reply to string for key '%s': %w", key, err)
	}

	// Return the raw string value directly
	val = ValkeyResponse{
		Message: ValkeyValue{Value: stringValue},
	}
	return val, nil
}

// ListKeys implements KVStore by executing a KEYS command with pattern matching.
func (s *valkeyStore) ListKeys(ctx context.Context, pattern string) ([]string, error) {
	cmd := s.client.B().Keys().Pattern(pattern).Build()
	resp := s.client.Do(ctx, cmd) // resp is valkey.Completed

	if err := resp.Error(); err != nil {
		return nil, fmt.Errorf("valkey KEYS with pattern '%s' failed: %w", pattern, err)
	}

	// resp.ToArray() likely returns []valkey.ValkeyMessage or similar.
	// We need to convert each element to a string.
	keyMessages, err := resp.ToArray()
	if err != nil {
		return nil, fmt.Errorf("failed to convert valkey KEYS reply to array for pattern '%s': %w", pattern, err)
	}

	stringKeys := make([]string, len(keyMessages))
	for i, keyMsg := range keyMessages {
		s, err := keyMsg.ToString() // Assuming ValkeyMessage has ToString()
		if err != nil {
			// This could happen if a key in the list is not a string, which is unusual for KEYS
			return nil, fmt.Errorf("failed to convert key message at index %d to string in KEYS result for pattern '%s': %w", i, pattern, err)
		}
		stringKeys[i] = s
	}
	return stringKeys, nil
}

// DeleteValue implements KVStore by executing a DEL command.
func (s *valkeyStore) DeleteValue(ctx context.Context, key string) error {
	cmd := s.client.B().Del().Key(key).Build()
	if err := s.client.Do(ctx, cmd).Error(); err != nil {
		return fmt.Errorf("failed to delete key: %w", err)
	}
	return nil
}

// Close shuts down the underlying client connection.
func (s *valkeyStore) Close() error {
	s.client.Close()
	return nil
}

type ValkeyResponse struct {
	Message ValkeyValue `json:"Message"`
	Type    string      `json:"Type"`
}

type ValkeyValue struct {
	Value string `json:"Value"`
}

type VulnerabilitySummary struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

type ScanResult struct {
	ID              string                 `json:"id"`
	Status          string                 `json:"status"`
	Targets         []string               `json:"targets"`
	Hosts           []string               `json:"hosts"`
	HostsCompleted  int                    `json:"hosts_completed"`
	Vulnerabilities []VulnerabilitySummary `json:"vulnerabilities"`
	StartTime       string                 `json:"start_time"`
	EndTime         string                 `json:"end_time,omitempty"`
}
