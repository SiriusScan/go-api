package templates

import "strings"

// CanonicalScriptID normalizes an NSE script identifier so producers and
// consumers agree on the Valkey key.
//
// Rules (mirrors sirius-ui/src/utils/nseScriptIds.ts and the helper
// originally introduced in PR 1 of the scanner-templates-fix sprint
// at app-scanner/internal/nse/sync.go):
//
//   - Strip any directory prefix ("scripts/foo/bar.nse" -> "bar.nse").
//   - Strip a trailing ".nse" extension ("bar.nse" -> "bar").
//   - Pass "" and the wildcard "*" through unchanged so callers can
//     use them as sentinels in patterns / KEYS commands.
//
// CanonicalScriptID is idempotent: CanonicalScriptID(CanonicalScriptID(x)) == CanonicalScriptID(x).
func CanonicalScriptID(id string) string {
	if id == "" || id == "*" {
		return id
	}
	if i := strings.LastIndex(id, "/"); i >= 0 {
		id = id[i+1:]
	}
	return strings.TrimSuffix(id, ".nse")
}
