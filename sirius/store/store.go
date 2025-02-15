package store

import (
	"context"
	"encoding/json"
	"log"

	"github.com/valkey-io/valkey-go"
)

const (
	SIRIUS_VALKEY = "sirius-valkey:6379"
)

// KVStore defines the key/value operations our store supports.
type KVStore interface {
	// SetValue sets the given key to the specified value.
	SetValue(ctx context.Context, key, value string) error
	// GetValue retrieves the value associated with the given key.
	GetValue(ctx context.Context, key string) (ValkeyResponse, error)
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

// GetValue implements KVStore by executing a GET command.
func (s *valkeyStore) GetValue(ctx context.Context, key string) (ValkeyResponse, error) {
	cmd := s.client.B().Get().Key(key).Build()
	resp := s.client.Do(ctx, cmd)
	var val ValkeyResponse
	if err := resp.Error(); err != nil {
		return val, err
	}
	err := json.Unmarshal([]byte(resp.String()), &val)
	if err != nil {
		log.Fatalf("Error unmarshalling ValkeyResponse: %v", err)
	}
	log.Println(val)
	return val, nil
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
	HostsCompleted  int                    `json:"hostsCompleted"`
	Vulnerabilities []VulnerabilitySummary `json:"vulnerabilities"`
}
