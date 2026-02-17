package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	// APIKeyPrefix is prepended to all generated API keys for easy identification.
	APIKeyPrefix = "sk_"
	// apiKeyStorePrefix is the Valkey key prefix for API key metadata.
	apiKeyStorePrefix = "apikey:"
	// apiKeyBootstrapFlag marks that a root key has already been generated.
	apiKeyBootstrapFlag = "apikey:bootstrap_complete"
	// apiKeyRootRef stores the hashed key reference for the root key.
	apiKeyRootRef = "apikey:root"
)

// APIKeyMeta holds metadata about an API key. The raw key is never persisted.
type APIKeyMeta struct {
	ID         string `json:"id"`          // SHA-256 hash of the raw key (also used as Valkey key suffix)
	Label      string `json:"label"`       // Human-readable label
	Prefix     string `json:"prefix"`      // First 8 characters of the raw key for display
	CreatedBy  string `json:"created_by"`  // User or system that created the key
	CreatedAt  string `json:"created_at"`  // RFC-3339 timestamp
	LastUsedAt string `json:"last_used_at"` // RFC-3339 timestamp, empty if never used
}

// GenerateAPIKey creates a cryptographically random API key with the sk_ prefix.
// The returned string is the only time the raw key is available.
func GenerateAPIKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return APIKeyPrefix + hex.EncodeToString(b), nil
}

// hashKey returns the hex-encoded SHA-256 hash of a raw API key.
func hashKey(rawKey string) string {
	h := sha256.Sum256([]byte(rawKey))
	return hex.EncodeToString(h[:])
}

// valkeyKey returns the full Valkey key for a given key hash.
func valkeyKey(keyHash string) string {
	return apiKeyStorePrefix + keyHash
}

// StoreAPIKey persists API key metadata in Valkey. The raw key is hashed and
// used as the lookup key; the raw key itself is never stored.
func StoreAPIKey(ctx context.Context, s KVStore, rawKey, label, createdBy string) (APIKeyMeta, error) {
	keyHash := hashKey(rawKey)
	meta := APIKeyMeta{
		ID:        keyHash,
		Label:     label,
		Prefix:    safePrefix(rawKey),
		CreatedBy: createdBy,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}

	data, err := json.Marshal(meta)
	if err != nil {
		return APIKeyMeta{}, fmt.Errorf("failed to marshal API key metadata: %w", err)
	}

	if err := s.SetValue(ctx, valkeyKey(keyHash), string(data)); err != nil {
		return APIKeyMeta{}, fmt.Errorf("failed to store API key: %w", err)
	}

	return meta, nil
}

// EnsureAPIKey ensures metadata exists for a raw API key hash. If metadata is
// already present it is returned unchanged; otherwise it is created.
func EnsureAPIKey(ctx context.Context, s KVStore, rawKey, label, createdBy string) (APIKeyMeta, error) {
	keyHash := hashKey(rawKey)
	resp, err := s.GetValue(ctx, valkeyKey(keyHash))
	if err == nil {
		var existing APIKeyMeta
		if unmarshalErr := json.Unmarshal([]byte(resp.Message.Value), &existing); unmarshalErr == nil {
			return existing, nil
		}
	}
	return StoreAPIKey(ctx, s, rawKey, label, createdBy)
}

// ValidateAPIKey checks whether the given raw key exists in Valkey. If valid it
// returns the associated metadata and updates the LastUsedAt timestamp.
func ValidateAPIKey(ctx context.Context, s KVStore, rawKey string) (APIKeyMeta, error) {
	keyHash := hashKey(rawKey)
	resp, err := s.GetValue(ctx, valkeyKey(keyHash))
	if err != nil {
		return APIKeyMeta{}, fmt.Errorf("invalid API key: %w", err)
	}

	var meta APIKeyMeta
	if err := json.Unmarshal([]byte(resp.Message.Value), &meta); err != nil {
		return APIKeyMeta{}, fmt.Errorf("failed to unmarshal API key metadata: %w", err)
	}

	// Update last-used timestamp (best-effort, don't fail the request).
	meta.LastUsedAt = time.Now().UTC().Format(time.RFC3339)
	if data, err := json.Marshal(meta); err == nil {
		_ = s.SetValue(ctx, valkeyKey(keyHash), string(data))
	}

	return meta, nil
}

// ListAPIKeys returns metadata for every API key stored in Valkey.
func ListAPIKeys(ctx context.Context, s KVStore) ([]APIKeyMeta, error) {
	keys, err := s.ListKeys(ctx, apiKeyStorePrefix+"*")
	if err != nil {
		return nil, fmt.Errorf("failed to list API keys: %w", err)
	}

	var result []APIKeyMeta
	for _, k := range keys {
		// Skip non-metadata keys (bootstrap flag, root ref, etc.)
		if k == apiKeyBootstrapFlag || k == apiKeyRootRef {
			continue
		}
		resp, err := s.GetValue(ctx, k)
		if err != nil {
			continue // key may have been deleted between list and get
		}
		var meta APIKeyMeta
		if err := json.Unmarshal([]byte(resp.Message.Value), &meta); err != nil {
			continue
		}
		result = append(result, meta)
	}
	return result, nil
}

// RevokeAPIKey deletes an API key by its hash ID.
func RevokeAPIKey(ctx context.Context, s KVStore, keyID string) error {
	if err := s.DeleteValue(ctx, valkeyKey(keyID)); err != nil {
		return fmt.Errorf("failed to revoke API key: %w", err)
	}
	return nil
}

// IsBootstrapped returns true if a root key has already been generated.
func IsBootstrapped(ctx context.Context, s KVStore) bool {
	_, err := s.GetValue(ctx, apiKeyBootstrapFlag)
	return err == nil
}

// MarkBootstrapped sets the bootstrap flag so that a root key is not
// regenerated on subsequent startups.
func MarkBootstrapped(ctx context.Context, s KVStore) error {
	return s.SetValue(ctx, apiKeyBootstrapFlag, "true")
}

// StoreRootKeyRef stores the hash of the root key so the UI backend can
// read it from Valkey and use it for authenticated requests.
func StoreRootKeyRef(ctx context.Context, s KVStore, rawKey string) error {
	return s.SetValue(ctx, apiKeyRootRef, rawKey)
}

// GetRootKeyRef retrieves the raw root key stored during bootstrap.
func GetRootKeyRef(ctx context.Context, s KVStore) (string, error) {
	resp, err := s.GetValue(ctx, apiKeyRootRef)
	if err != nil {
		return "", fmt.Errorf("root key reference not found: %w", err)
	}
	return resp.Message.Value, nil
}

// safePrefix returns the first 8 characters of a key for safe display.
func safePrefix(rawKey string) string {
	if len(rawKey) <= 8 {
		return rawKey
	}
	// Include the sk_ prefix and a few chars after for recognisability.
	if strings.HasPrefix(rawKey, APIKeyPrefix) {
		end := len(APIKeyPrefix) + 8
		if end > len(rawKey) {
			end = len(rawKey)
		}
		return rawKey[:end] + "..."
	}
	return rawKey[:8] + "..."
}
