package templates

import "testing"

func TestCanonicalScriptID(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"*", "*"},
		{"bar", "bar"},
		{"bar.nse", "bar"},
		{"foo/bar.nse", "bar"},
		{"scripts/foo/bar.nse", "bar"},
		{"scripts/foo/bar", "bar"},
		// idempotent
		{CanonicalScriptID("scripts/foo/bar.nse"), "bar"},
	}
	for _, tc := range cases {
		if got := CanonicalScriptID(tc.in); got != tc.want {
			t.Errorf("CanonicalScriptID(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNseScriptKey_AlwaysCanonical(t *testing.T) {
	if got := NseScriptKey("scripts/foo/bar.nse"); got != "nse:script:bar" {
		t.Errorf("NseScriptKey did not canonicalize: %q", got)
	}
	if got := NseScriptKey("bar"); got != "nse:script:bar" {
		t.Errorf("NseScriptKey changed already-canonical id: %q", got)
	}
}

func TestAgentTemplateKey_NamespaceSelection(t *testing.T) {
	if got := AgentTemplateKey("foo", true); got != "template:custom:foo" {
		t.Errorf("custom key wrong: %q", got)
	}
	if got := AgentTemplateKey("foo", false); got != "template:standard:foo" {
		t.Errorf("standard key wrong: %q", got)
	}
	if got := AgentTemplateMetaKey("foo"); got != "template:meta:foo" {
		t.Errorf("meta key wrong: %q", got)
	}
}
