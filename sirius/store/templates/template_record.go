package templates

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// TemplateRecord is the agent vulnerability template envelope persisted
// at template:standard:<id> and template:custom:<id>. Field names and
// JSON tags MUST match app-agent/internal/template/valkey.TemplateInfo
// because the agent reads those keys directly.
//
// `Content` is the raw template bytes (typically YAML). On the JSON
// wire the field encodes as base64 by Go convention for []byte; agents
// expect that encoding.
type TemplateRecord struct {
	ID               string            `json:"id"`
	Version          string            `json:"version"`
	Checksum         string            `json:"checksum"`
	Size             int64             `json:"size"`
	Severity         string            `json:"severity"`
	Platforms        []string          `json:"platforms"`
	DetectionType    string            `json:"detection_type"`
	Author           string            `json:"author"`
	Created          time.Time         `json:"created"`
	Updated          time.Time         `json:"updated"`
	VulnerabilityIDs []string          `json:"vulnerability_ids"`
	IsCustom         bool              `json:"is_custom"`
	Content          []byte            `json:"content,omitempty"`
	Metadata         map[string]string `json:"metadata,omitempty"`
}

// Meta returns a copy of the record with Content stripped, suitable for
// writing to template:meta:<id>. The meta record carries enough info
// for fast enumeration without pulling the whole template body.
func (r TemplateRecord) Meta() TemplateRecord {
	m := r
	m.Content = nil
	return m
}

// EncodeTemplate marshals the envelope to JSON. Wraps json.Marshal so
// callers don't have to redeclare the error context.
func EncodeTemplate(r *TemplateRecord) ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("encode template: nil record")
	}
	out, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("encode template %q: %w", r.ID, err)
	}
	return out, nil
}

// DecodeTemplate parses a JSON envelope back into a TemplateRecord.
func DecodeTemplate(data []byte) (*TemplateRecord, error) {
	var r TemplateRecord
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("decode template: %w", err)
	}
	return &r, nil
}

// EncodeMeta is a convenience for `EncodeTemplate(r.Meta())`. Use this
// when persisting the meta snapshot to keep call sites symmetric with
// the template-content path.
func EncodeMeta(r *TemplateRecord) ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("encode meta: nil record")
	}
	m := r.Meta()
	return EncodeTemplate(&m)
}

// SHA256Hex returns the hex-encoded SHA-256 of the supplied bytes.
// Callers building a TemplateRecord should populate Checksum from this
// helper so the field stays consistent across components.
func SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
