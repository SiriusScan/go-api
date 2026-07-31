package module

import "fmt"

// Community module IDs mirror the historical sirius-api RouteSetter wiring order
// from main.go. Keep these stable; route inventory golden tests depend on them.
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

// CommunityModuleIDs is the ordered Community module inventory. A future Pro
// registration file may append proprietary IDs after this list.
var CommunityModuleIDs = []string{
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

// CommunityCore holds the Community API modules supplied by the API binary.
// Handlers remain in sirius-api; this seam only orders and registers Modules.
//
// Pro API builds replace this file (or an overlay twin) to register Community
// modules plus proprietary modules without runtime plugin loading.
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

// RegisterCommunity registers Community modules in historical main.go order.
// Missing (nil) modules are rejected so the Community route table cannot shrink
// silently. Callers may Register additional modules afterward without editing
// this file (for tests or optional overlays).
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
	for _, item := range ordered {
		if item.m == nil {
			return fmt.Errorf("module: community core missing %q", item.id)
		}
		if item.m.ID() != item.id {
			return fmt.Errorf("module: community core %q has ID %q", item.id, item.m.ID())
		}
		if err := reg.Register(item.m); err != nil {
			return err
		}
	}
	return nil
}
