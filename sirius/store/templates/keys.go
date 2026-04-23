// Package templates is the single source of truth for the Valkey
// contracts that bind the scanner stack together. Every component that
// reads or writes agent vulnerability templates or NSE scripts should
// import the helpers here instead of hand-rolling key strings or
// JSON envelopes.
//
// Producers/consumers as of go-api v0.0.18:
//   - sirius-api      (handlers/agent_template_handler.go) - writes custom templates
//   - app-agent       (internal/template/valkey)            - writes built-in + reads everything
//   - app-scanner     (internal/nse)                        - writes NSE script content + manifest
//   - sirius-ui       (utils/nseScriptIds.ts)               - mirrors CanonicalScriptID
//
// PR 7 of the scanner-templates-fix sprint migrates each of those
// callers off their local copies and onto these helpers.
package templates

// Agent vulnerability template keys.
//
// Layout (mirrors app-agent/internal/template/valkey/storage.go):
//
//	template:standard:<id>   - built-in templates synced from a Git repo, JSON envelope (TemplateInfo)
//	template:custom:<id>     - operator-uploaded templates,            JSON envelope (TemplateInfo)
//	template:meta:<id>       - per-template metadata snapshot used for fast enumeration; same shape as the envelope but with `content` omitted
//	template:manifest        - global manifest snapshot (TemplateManifest)
//	template:repo-manifest   - per-repository manifest map
//	template:version:<id>    - version-pinning index (reserved)
const (
	KeyAgentTemplateStandardPrefix = "template:standard:"
	KeyAgentTemplateCustomPrefix   = "template:custom:"
	KeyAgentTemplateMetaPrefix     = "template:meta:"
	KeyAgentTemplateManifest       = "template:manifest"
	KeyAgentTemplateRepoManifest   = "template:repo-manifest"
	KeyAgentTemplateVersionPrefix  = "template:version:"
)

// NSE script keys.
//
// Layout (mirrors app-scanner/internal/nse/types.go):
//
//	nse:script:<id>          - script content + metadata (ScriptContent envelope)
//	nse:meta:<id>             - lightweight script metadata (reserved; not all writers populate today)
//	nse:manifest             - global manifest of all scripts (Manifest)
//	nse:repo-manifest        - repository list driving the sync (RepositoryList)
//
// IDs in this namespace are always canonical: no `.nse` suffix, no
// directory prefix. Use CanonicalScriptID to normalize anything that
// crosses a process boundary.
const (
	KeyNseScriptPrefix       = "nse:script:"
	KeyNseScriptMetaPrefix   = "nse:meta:"
	KeyNseManifest           = "nse:manifest"
	KeyNseRepoManifest       = "nse:repo-manifest"
)

// AgentTemplateKey returns the Valkey key for a template's content
// envelope. `isCustom` selects the namespace; pass true for
// operator-uploaded templates and false for repo-synced ones.
func AgentTemplateKey(id string, isCustom bool) string {
	if isCustom {
		return KeyAgentTemplateCustomPrefix + id
	}
	return KeyAgentTemplateStandardPrefix + id
}

// AgentTemplateMetaKey returns the Valkey key for a template's
// metadata snapshot. Always under the same `template:meta:` namespace
// regardless of whether the source is custom or standard.
func AgentTemplateMetaKey(id string) string {
	return KeyAgentTemplateMetaPrefix + id
}

// NseScriptKey returns the Valkey key for a script's content envelope.
// The id is canonicalized so callers can safely pass anything coming
// off the wire (manifest paths, UI input, etc.).
func NseScriptKey(id string) string {
	return KeyNseScriptPrefix + CanonicalScriptID(id)
}
