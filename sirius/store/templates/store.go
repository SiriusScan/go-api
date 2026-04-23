package templates

import (
	"context"
	"fmt"

	"github.com/SiriusScan/go-api/sirius/store"
)

// kvReader / kvWriter narrow the surface area we depend on so unit
// tests can fake just what's needed without standing up valkey.
type kvReader interface {
	GetValue(ctx context.Context, key string) (store.ValkeyResponse, error)
}

type kvWriter interface {
	SetValue(ctx context.Context, key, value string) error
	DeleteValue(ctx context.Context, key string) error
}

// ReadTemplate fetches and decodes a template envelope. Tries the
// custom namespace first, then standard, so callers don't have to know
// which side wrote it. Returns (nil, nil) when neither key exists.
func ReadTemplate(ctx context.Context, kv kvReader, id string) (*TemplateRecord, error) {
	for _, key := range []string{AgentTemplateKey(id, true), AgentTemplateKey(id, false)} {
		resp, err := kv.GetValue(ctx, key)
		if err != nil {
			continue // not found / nil bubble up as errors from the store
		}
		if resp.Message.Value == "" {
			continue
		}
		rec, decErr := DecodeTemplate([]byte(resp.Message.Value))
		if decErr != nil {
			return nil, fmt.Errorf("read template %q at %q: %w", id, key, decErr)
		}
		return rec, nil
	}
	return nil, nil
}

// ReadTemplateMeta fetches and decodes the meta snapshot for id.
// Returns (nil, nil) when the key is absent.
func ReadTemplateMeta(ctx context.Context, kv kvReader, id string) (*TemplateRecord, error) {
	resp, err := kv.GetValue(ctx, AgentTemplateMetaKey(id))
	if err != nil || resp.Message.Value == "" {
		return nil, nil
	}
	rec, decErr := DecodeTemplate([]byte(resp.Message.Value))
	if decErr != nil {
		return nil, fmt.Errorf("read template meta %q: %w", id, decErr)
	}
	return rec, nil
}

// WriteTemplate persists the envelope and its meta snapshot atomically
// from the caller's perspective: if the meta write fails the envelope
// is rolled back so an enumerator never sees a custom record without a
// matching meta entry.
func WriteTemplate(ctx context.Context, kv interface {
	kvReader
	kvWriter
}, r *TemplateRecord) error {
	if r == nil || r.ID == "" {
		return fmt.Errorf("write template: id is required")
	}
	envelopeJSON, err := EncodeTemplate(r)
	if err != nil {
		return err
	}
	metaJSON, err := EncodeMeta(r)
	if err != nil {
		return err
	}

	templateKey := AgentTemplateKey(r.ID, r.IsCustom)
	metaKey := AgentTemplateMetaKey(r.ID)

	if err := kv.SetValue(ctx, templateKey, string(envelopeJSON)); err != nil {
		return fmt.Errorf("write template envelope %q: %w", r.ID, err)
	}
	if err := kv.SetValue(ctx, metaKey, string(metaJSON)); err != nil {
		// Best-effort rollback. Swallow the delete error so the original
		// failure is what the caller sees.
		_ = kv.DeleteValue(ctx, templateKey)
		return fmt.Errorf("write template meta %q: %w", r.ID, err)
	}
	return nil
}

// ReadNseScript fetches and decodes a script envelope. Canonicalizes
// the id before lookup so callers can safely pass raw input.
func ReadNseScript(ctx context.Context, kv kvReader, id string) (*NseScriptRecord, error) {
	resp, err := kv.GetValue(ctx, NseScriptKey(id))
	if err != nil || resp.Message.Value == "" {
		return nil, nil
	}
	return DecodeNseScript([]byte(resp.Message.Value))
}

// WriteNseScript persists a script envelope. Canonicalizes the key so
// producers don't accidentally write `.nse`-suffixed entries.
func WriteNseScript(ctx context.Context, kv kvWriter, id string, r *NseScriptRecord) error {
	if r == nil {
		return fmt.Errorf("write nse script: nil record")
	}
	data, err := EncodeNseScript(r)
	if err != nil {
		return err
	}
	return kv.SetValue(ctx, NseScriptKey(id), string(data))
}

// WriteNseManifest persists the manifest with canonicalized map keys.
// The original Scripts map is left untouched on the caller's side.
func WriteNseManifest(ctx context.Context, kv kvWriter, m *NseManifest) error {
	if m == nil {
		return fmt.Errorf("write nse manifest: nil manifest")
	}
	if m.Scripts != nil {
		canon := make(map[string]NseManifestEntry, len(m.Scripts))
		for k, v := range m.Scripts {
			canon[CanonicalScriptID(k)] = v
		}
		m = &NseManifest{
			Name:        m.Name,
			Version:     m.Version,
			Description: m.Description,
			Scripts:     canon,
		}
	}
	data, err := EncodeNseManifest(m)
	if err != nil {
		return err
	}
	return kv.SetValue(ctx, KeyNseManifest, string(data))
}

// ReadNseManifest fetches and decodes the manifest.
func ReadNseManifest(ctx context.Context, kv kvReader) (*NseManifest, error) {
	resp, err := kv.GetValue(ctx, KeyNseManifest)
	if err != nil || resp.Message.Value == "" {
		return nil, nil
	}
	return DecodeNseManifest([]byte(resp.Message.Value))
}
