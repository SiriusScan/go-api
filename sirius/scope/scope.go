// Package scope defines policy-neutral resource attribution.
package scope

import "github.com/SiriusScan/go-api/sirius/identity"

// Version identifies the resource scope wire contract.
const Version = "1.0"

// ResourceScope attributes a resource to an opaque subject. Callers must
// authorize the scope at their trust boundary before passing it to storage.
type ResourceScope struct {
	OwnerSubjectID identity.SubjectID `json:"owner_subject_id,omitempty"`
}

// Global returns the legacy Community scope.
func Global() ResourceScope { return ResourceScope{} }

// ForSubject returns a scope for an opaque subject.
func ForSubject(id identity.SubjectID) ResourceScope { return ResourceScope{OwnerSubjectID: id} }

// IsGlobal reports whether this is the legacy global scope.
func (s ResourceScope) IsGlobal() bool { return s.OwnerSubjectID.IsGlobal() }
