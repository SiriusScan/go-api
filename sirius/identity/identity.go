// Package identity defines opaque resource attribution identifiers.
package identity

// SubjectID identifies a subject without prescribing authentication or policy.
// The empty subject represents the legacy global scope.
type SubjectID string

// IsGlobal reports whether the subject is the legacy global subject.
func (s SubjectID) IsGlobal() bool { return s == "" }
