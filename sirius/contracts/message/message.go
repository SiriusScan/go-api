// Package message defines versioned, policy-neutral queue contracts.
package message

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/SiriusScan/go-api/sirius/scope"
)

const (
	SpecVersion              = "1.0"
	ScanJobSchemaVersion     = "1.0"
	ScanControlSchemaVersion = "1.0"
	ScanRequested            = "sirius.scan.requested"
	ScanCancelRequested      = "sirius.scan.cancel.requested"
)

// Envelope carries a stable message identity, optional attribution, and a
// separately versioned payload. Scope authorization belongs to the publisher.
type Envelope struct {
	SpecVersion    string               `json:"spec_version"`
	ID             string               `json:"id"`
	Type           string               `json:"type"`
	Source         string               `json:"source"`
	SchemaVersion  string               `json:"schema_version"`
	CorrelationID  string               `json:"correlation_id,omitempty"`
	CausationID    string               `json:"causation_id,omitempty"`
	IdempotencyKey string               `json:"idempotency_key,omitempty"`
	CreatedAt      time.Time            `json:"created_at"`
	ResourceScope  *scope.ResourceScope `json:"resource_scope,omitempty"`
	Payload        json.RawMessage      `json:"payload"`
}

type ScanTarget struct {
	Value   string `json:"value"`
	Type    string `json:"type"`
	Timeout int    `json:"timeout,omitempty"`
}

type ScanOptions struct {
	TemplateID         string   `json:"template_id"`
	PortRange          string   `json:"port_range"`
	Aggressive         bool     `json:"aggressive"`
	ExcludePorts       []string `json:"exclude_ports"`
	ScanTypes          []string `json:"scan_types"`
	MaxRetries         int      `json:"max_retries"`
	Parallel           bool     `json:"parallel"`
	FingerprintProbes  []string `json:"fingerprint_probes,omitempty"`
	FingerprintTimeout string   `json:"fingerprint_timeout,omitempty"`
	DisableICMP        bool     `json:"disable_icmp,omitempty"`
}

type ScanJob struct {
	ScanID      string       `json:"scan_id"`
	Targets     []ScanTarget `json:"targets"`
	Options     ScanOptions  `json:"options"`
	Priority    int          `json:"priority,omitempty"`
	CallbackURL string       `json:"callback_url,omitempty"`
	StateMode   string       `json:"state_mode,omitempty"`
}

type ScanControl struct {
	ScanID    string `json:"scan_id"`
	Action    string `json:"action"`
	StateMode string `json:"state_mode,omitempty"`
}

// ValidateScanJob rejects unsupported contract versions before interpreting a
// payload. Additional JSON fields remain valid within v1.
func (e Envelope) ValidateScanJob() (ScanJob, error) {
	var job ScanJob
	if e.SpecVersion != SpecVersion || e.SchemaVersion != ScanJobSchemaVersion || e.Type != ScanRequested {
		return job, fmt.Errorf("unsupported scan envelope type or version")
	}
	if e.ID == "" || e.Source == "" || e.CreatedAt.IsZero() || e.CreatedAt.Location() != time.UTC || len(e.Payload) == 0 || string(e.Payload) == "null" {
		return job, fmt.Errorf("missing required scan envelope fields or UTC timestamp")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(e.Payload, &fields); err != nil || len(fields["options"]) == 0 || string(fields["options"]) == "null" {
		return job, fmt.Errorf("scan options object is required")
	}
	if err := json.Unmarshal(e.Payload, &job); err != nil {
		return job, fmt.Errorf("decode scan job: %w", err)
	}
	if job.ScanID == "" || len(job.Targets) == 0 {
		return job, fmt.Errorf("scan ID and targets are required")
	}
	for _, target := range job.Targets {
		if target.Value == "" || target.Type == "" {
			return job, fmt.Errorf("scan target value and type are required")
		}
	}
	return job, nil
}

// ValidateScanControl validates an exact-ID cancellation request.
func (e Envelope) ValidateScanControl() (ScanControl, error) {
	var control ScanControl
	if e.SpecVersion != SpecVersion || e.SchemaVersion != ScanControlSchemaVersion || e.Type != ScanCancelRequested {
		return control, fmt.Errorf("unsupported scan control envelope type or version")
	}
	if e.ID == "" || e.Source == "" || e.CreatedAt.IsZero() || e.CreatedAt.Location() != time.UTC || len(e.Payload) == 0 || string(e.Payload) == "null" {
		return control, fmt.Errorf("missing required scan control envelope fields or UTC timestamp")
	}
	if err := json.Unmarshal(e.Payload, &control); err != nil {
		return control, fmt.Errorf("decode scan control: %w", err)
	}
	if control.ScanID == "" || (control.Action != "cancel" && control.Action != "force_cancel") {
		return control, fmt.Errorf("scan ID and supported action are required")
	}
	return control, nil
}
