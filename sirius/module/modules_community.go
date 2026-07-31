package module

import "fmt"

// Community module IDs document the historical sirius-api RouteSetter wiring
// order from main.go. Consuming API binaries should keep these IDs stable when
// adapting existing setters.
const (
	IDHost                    = "community.host"
	IDApp                     = "community.app"
	IDVulnerability           = "community.vulnerability"
	IDTemplate                = "community.template"
	IDScript                  = "community.script"
	IDAgentTemplateRepository = "community.agent_template_repository"
	IDAgentTemplate           = "community.agent_template"
	IDEvent                   = "community.event"
	IDSnapshot                = "community.snapshot"
	IDStatistics              = "community.statistics"
	IDScan                    = "community.scan"
	IDAPIKey                  = "community.apikey"
)

// CommunityModuleVersion is the default version stamped on Community adapters.
const CommunityModuleVersion = "1.0.0"

// communityModuleIDs is the canonical ordered Community module inventory.
var communityModuleIDs = []string{
	IDHost,
	IDApp,
	IDVulnerability,
	IDTemplate,
	IDScript,
	IDAgentTemplateRepository,
	IDAgentTemplate,
	IDEvent,
	IDSnapshot,
	IDStatistics,
	IDScan,
	IDAPIKey,
}

// CommunityModuleIDs returns a defensive copy of the canonical Community module
// ID list in registration order.
func CommunityModuleIDs() []string {
	out := make([]string, len(communityModuleIDs))
	copy(out, communityModuleIDs)
	return out
}

// CommunityCore holds the Community API modules supplied by the consuming API
// binary. Handlers remain in sirius-api (or a private Pro overlay); this helper
// only validates order and registers Modules atomically.
//
// Compile-time composition belongs in the consuming API (Community wiring or a
// private Pro overlay). go-api provides the contract and this ordering helper;
// it is not a file that Pro "replaces" inside the SDK checkout.
type CommunityCore struct {
	Host                    Module
	App                     Module
	Vulnerability           Module
	Template                Module
	Script                  Module
	AgentTemplateRepository Module
	AgentTemplate           Module
	Event                   Module
	Snapshot                Module
	Statistics              Module
	Scan                    Module
	APIKey                  Module
}

// RegisterCommunity prevalidates the complete ordered Community module set and
// registers it atomically via Registry.RegisterAll. On any invalid, missing,
// typed-nil, ID-mismatched, or duplicate input the registry is left unchanged.
//
// Callers may Register additional modules afterward (for tests or Pro modules
// composed by the API binary) until Mount succeeds.
func RegisterCommunity(reg *Registry, core CommunityCore) error {
	if reg == nil {
		return fmt.Errorf("module: nil registry")
	}
	ordered := []struct {
		id string
		m  Module
	}{
		{IDHost, core.Host},
		{IDApp, core.App},
		{IDVulnerability, core.Vulnerability},
		{IDTemplate, core.Template},
		{IDScript, core.Script},
		{IDAgentTemplateRepository, core.AgentTemplateRepository},
		{IDAgentTemplate, core.AgentTemplate},
		{IDEvent, core.Event},
		{IDSnapshot, core.Snapshot},
		{IDStatistics, core.Statistics},
		{IDScan, core.Scan},
		{IDAPIKey, core.APIKey},
	}

	modules := make([]Module, 0, len(ordered))
	for _, item := range ordered {
		if isNilInterface(item.m) {
			return fmt.Errorf("module: community core missing %q", item.id)
		}
		if item.m.ID() != item.id {
			return fmt.Errorf("module: community core %q has ID %q", item.id, item.m.ID())
		}
		modules = append(modules, item.m)
	}
	return reg.RegisterAll(modules...)
}
