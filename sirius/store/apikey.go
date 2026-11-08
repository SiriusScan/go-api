package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
//
// Scopes is optional. A nil or empty slice means the key has no scope
// restriction and keeps the historical full-access semantics of keys created
// before scopes existed. A non-empty slice is an allow-list enforced by the
// API; unknown scope names are rejected at creation time and fail closed if
// they are ever persisted.
type APIKeyMeta struct {
	ID         string   `json:"id"`               // SHA-256 hash of the raw key (also used as Valkey key suffix)
	Label      string   `json:"label"`            // Human-readable label
	Prefix     string   `json:"prefix"`           // First 8 characters of the raw key for display
	CreatedBy  string   `json:"created_by"`       // User or system that created the key
	CreatedAt  string   `json:"created_at"`       // RFC-3339 timestamp
	LastUsedAt string   `json:"last_used_at"`     // RFC-3339 timestamp, empty if never used
	Scopes     []string `json:"scopes,omitempty"` // Optional allow-list; empty preserves legacy full access
}

// ScopeMCPRead is the only scope currently granted to dedicated MCP readers.
// It authorizes an exact GET allow-list enforced by sirius-api; it never
// grants key management, writes, or generic store/queue/log/admin access.
const ScopeMCPRead = "mcp:read"

// knownAPIKeyScopes is the closed set of scopes a key may carry. Adding a
// scope here is not enough to authorize anything; the API must also enforce it.
var knownAPIKeyScopes = map[string]struct{}{
	ScopeMCPRead: {},
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

// StoreAPIKey persists an unrestricted (legacy full-access) API key. The raw
// key is hashed and used as the lookup key; the raw key itself is never stored.
// Existing callers keep pre-scope semantics. Scoped keys must use
// StoreAPIKeyWithScopes.
func StoreAPIKey(ctx context.Context, s KVStore, rawKey, label, createdBy string) (APIKeyMeta, error) {
	return storeAPIKey(ctx, s, rawKey, label, createdBy, nil)
}

// StoreAPIKeyWithScopes persists API key metadata restricted to scopes.
// scopes must be non-empty and every entry must be a known scope; unknown or
// blank values fail closed and nothing is written. A nil or empty slice is
// rejected — use StoreAPIKey for legacy unrestricted keys so an accidental
// empty scope list cannot be confused with a scoped key.
func StoreAPIKeyWithScopes(ctx context.Context, s KVStore, rawKey, label, createdBy string, scopes []string) (APIKeyMeta, error) {
	normalized, err := NormalizeAPIKeyScopes(scopes)
	if err != nil {
		return APIKeyMeta{}, err
	}
	if len(normalized) == 0 {
		return APIKeyMeta{}, fmt.Errorf("scopes are required")
	}
	return storeAPIKey(ctx, s, rawKey, label, createdBy, normalized)
}

// NormalizeAPIKeyScopes validates and canonicalizes a requested scope list.
// An empty list is valid and means "no scopes" (legacy full access) for
// callers that accept optional scopes, such as key creation. Any blank or
// unknown scope fails closed. Duplicates collapse to one entry; order follows
// first occurrence.
func NormalizeAPIKeyScopes(scopes []string) ([]string, error) {
	if len(scopes) == 0 {
		return nil, nil
	}
	seen := make(map[string]struct{}, len(scopes))
	out := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			return nil, fmt.Errorf("invalid API key scope %q", scope)
		}
		if _, ok := knownAPIKeyScopes[scope]; !ok {
			return nil, fmt.Errorf("unknown API key scope %q", scope)
		}
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		out = append(out, scope)
	}
	return out, nil
}

// AllowsUnrestricted reports whether meta has no scope restriction.
// Nil and empty scopes preserve pre-scope full-access semantics.
func (m APIKeyMeta) AllowsUnrestricted() bool {
	return len(m.Scopes) == 0
}

// HasScope reports whether meta grants scope. Unrestricted keys do not
// implicitly match a named scope; callers that want legacy full access must
// check AllowsUnrestricted first.
//
// A key that carries any unknown or blank scope fails closed entirely: it
// matches no scope, even one that is otherwise present. That stops a persisted
// scope list from being treated as a partial grant after it has been widened
// outside StoreAPIKeyWithScopes.
func (m APIKeyMeta) HasScope(scope string) bool {
	if _, ok := knownAPIKeyScopes[scope]; !ok {
		return false
	}
	matched := false
	for _, got := range m.Scopes {
		if _, known := knownAPIKeyScopes[got]; !known {
			return false
		}
		if got == scope {
			matched = true
		}
	}
	return matched
}

func storeAPIKey(ctx context.Context, s KVStore, rawKey, label, createdBy string, scopes []string) (APIKeyMeta, error) {
	keyHash := hashKey(rawKey)
	var storedScopes []string
	if len(scopes) > 0 {
		storedScopes = append([]string(nil), scopes...)
	}
	meta := APIKeyMeta{
		ID:        keyHash,
		Label:     label,
		Prefix:    safePrefix(rawKey),
		CreatedBy: createdBy,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Scopes:    storedScopes,
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

// EnsureAPIKey returns existing metadata unchanged, or atomically creates an
// unrestricted legacy key after confirmed absence. Creation requires ValueCreator.
// Failed reads and malformed records fail closed. A concurrent creation wins;
// its metadata is reread rather than overwritten. Errors may have an uncertain
// outcome and must not be treated as confirmed absence.
func EnsureAPIKey(ctx context.Context, s KVStore, rawKey, label, createdBy string) (APIKeyMeta, error) {
	keyHash := hashKey(rawKey)
	key := valkeyKey(keyHash)
	decode := func(value string) (APIKeyMeta, error) {
		var existing *APIKeyMeta
		if err := json.Unmarshal([]byte(value), &existing); err != nil {
			return APIKeyMeta{}, fmt.Errorf("failed to unmarshal existing API key: %w", err)
		}
		if existing == nil {
			return APIKeyMeta{}, fmt.Errorf("existing API key metadata is null")
		}
		return *existing, nil
	}
	resp, err := s.GetValue(ctx, key)
	if err == nil {
		return decode(resp.Message.Value)
	}
	if !errors.Is(err, ErrKeyNotFound) {
		return APIKeyMeta{}, fmt.Errorf("failed to read existing API key: %w", err)
	}
	creator, ok := s.(ValueCreator)
	if !ok {
		return APIKeyMeta{}, fmt.Errorf("API key store does not support atomic creation")
	}
	meta := APIKeyMeta{
		ID: keyHash, Label: label, Prefix: safePrefix(rawKey), CreatedBy: createdBy,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	data, err := json.Marshal(meta)
	if err != nil {
		return APIKeyMeta{}, fmt.Errorf("failed to marshal API key: %w", err)
	}
	created, err := creator.SetValueIfAbsent(ctx, key, string(data))
	if err != nil {
		return APIKeyMeta{}, fmt.Errorf("failed to create API key: %w", err)
	}
	if created {
		return meta, nil
	}
	// Do not retry creation if the winner disappears or cannot be read.
	resp, err = s.GetValue(ctx, key)
	if err != nil {
		return APIKeyMeta{}, fmt.Errorf("failed to read concurrently created API key: %w", err)
	}
	return decode(resp.Message.Value)
}

// ValidateAPIKey checks whether the given raw key exists in Valkey. If valid it
// returns the associated metadata with a current LastUsedAt timestamp. Persisting
// that timestamp is best-effort and requires atomic compare-and-set support.
// Scope enforcement is the caller's responsibility; this function only loads
// the persisted metadata, including any scopes.
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

	// Touch only the exact record that was validated. An unconditional write
	// could restore a revoked key or overwrite concurrently changed scopes.
	// A failed comparison or an unsupported store simply skips this best-effort
	// update; never fall back to SET or retry with the stale metadata.
	meta.LastUsedAt = time.Now().UTC().Format(time.RFC3339)
	if cas, ok := s.(ValueCompareAndSetter); ok {
		if data, err := json.Marshal(meta); err == nil {
			_, _ = cas.CompareAndSetValue(ctx, valkeyKey(keyHash), resp.Message.Value, string(data))
		}
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
