package templates

import (
	"encoding/json"
	"fmt"
)

// NseScriptRecord is the envelope persisted at nse:script:<canonical-id>.
// Field names and JSON tags match the legacy app-scanner ScriptContent
// type so this package can be a drop-in for that producer.
type NseScriptRecord struct {
	Content   string          `json:"content"`
	Metadata  NseScriptMeta   `json:"metadata"`
	UpdatedAt int64           `json:"updatedAt"`
}

// NseScriptMeta carries lightweight script metadata (author, tags,
// description). Mirrors app-scanner/internal/nse.Metadata.
type NseScriptMeta struct {
	Author      string   `json:"author"`
	Tags        []string `json:"tags"`
	Description string   `json:"description"`
}

// NseManifestEntry mirrors app-scanner/internal/nse.Script. Manifest
// keys are canonicalized (no .nse suffix); Path preserves whatever
// the on-disk repository expects.
type NseManifestEntry struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Protocol string `json:"protocol"`
}

// NseManifest mirrors app-scanner/internal/nse.Manifest. The Scripts
// map is keyed by canonical id.
type NseManifest struct {
	Name        string                       `json:"name"`
	Version     string                       `json:"version"`
	Description string                       `json:"description"`
	Scripts     map[string]NseManifestEntry  `json:"scripts"`
}

// EncodeNseScript marshals a script envelope to JSON.
func EncodeNseScript(r *NseScriptRecord) ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("encode nse script: nil record")
	}
	out, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("encode nse script: %w", err)
	}
	return out, nil
}

// DecodeNseScript parses a JSON envelope back into an NseScriptRecord.
func DecodeNseScript(data []byte) (*NseScriptRecord, error) {
	var r NseScriptRecord
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("decode nse script: %w", err)
	}
	return &r, nil
}

// EncodeNseManifest marshals the manifest to JSON.
func EncodeNseManifest(m *NseManifest) ([]byte, error) {
	if m == nil {
		return nil, fmt.Errorf("encode nse manifest: nil manifest")
	}
	out, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("encode nse manifest: %w", err)
	}
	return out, nil
}

// DecodeNseManifest parses a JSON envelope back into an NseManifest.
func DecodeNseManifest(data []byte) (*NseManifest, error) {
	var m NseManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("decode nse manifest: %w", err)
	}
	return &m, nil
}
