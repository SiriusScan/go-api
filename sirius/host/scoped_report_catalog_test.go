package host

import (
	"testing"

	"github.com/SiriusScan/go-api/sirius"
	"github.com/SiriusScan/go-api/sirius/postgres/models"
	"github.com/SiriusScan/go-api/sirius/scope"
)

func TestScopedReportsDoNotPublishPrivateFindingToSharedCatalog(t *testing.T) {
	repo := reportFixture(t)
	source := models.ScanSource{Name: "test"}
	global := Report{Host: sirius.Host{IP: "192.0.2.1", HID: "global", Vulnerabilities: []sirius.Vulnerability{{VID: "CVE-SHARED", Title: "public", Description: "public description", RiskScore: 3}}}, Source: source}
	if err := repo.addReport(global); err != nil {
		t.Fatal(err)
	}
	private := Report{Host: sirius.Host{IP: "192.0.2.1", HID: "private", Vulnerabilities: []sirius.Vulnerability{{VID: "CVE-SHARED", Title: "private title", Description: "private description", RiskScore: 9, Confidence: 0.9}, {VID: "CVE-PRIVATE", Title: "private only", Description: "private only description", RiskScore: 10}}}, Source: source,
		Catalog: []sirius.Vulnerability{{VID: "CVE-SHARED", Title: "private enrichment", Description: "private enrichment details", RiskScore: 10}}}
	alice := scope.ForSubject("alice")
	if err := repo.addReportScoped(alice, private); err != nil {
		t.Fatal(err)
	}
	var privateHost models.Host
	if err := repo.db.Where("owner_subject_id = ?", "alice").First(&privateHost).Error; err != nil {
		t.Fatal(err)
	}
	if err := repo.UpsertHostVulnerability(privateHost.ID, sirius.Vulnerability{VID: "CVE-SHARED", Title: "direct private", Description: "direct private details", RiskScore: 8}, models.ScanSource{Name: "direct"}); err != nil {
		t.Fatal(err)
	}
	var catalog []models.Vulnerability
	if err := repo.db.Order("v_id").Find(&catalog).Error; err != nil {
		t.Fatal(err)
	}
	if len(catalog) != 2 || catalog[0].VID != "CVE-PRIVATE" || catalog[0].Title != "" || catalog[0].Description != "" || catalog[0].RiskScore != 0 || catalog[1].Title != "public" || catalog[1].Description != "public description" || catalog[1].RiskScore != 3 {
		t.Fatalf("private catalog contamination: %+v", catalog)
	}
	var summary []VulnerabilitySummary
	if err := vulnerabilitySummariesQuery(repo.db).Scan(&summary).Error; err != nil {
		t.Fatal(err)
	}
	if len(summary) != 1 || summary[0].Title != "public" || summary[0].Description != "public description" {
		t.Fatalf("global summary leaked: %+v", summary)
	}
	host, err := repo.GetHostWithRelationsScoped(alice, "192.0.2.1")
	if err != nil || len(host.Vulnerabilities) != 2 {
		t.Fatalf("scoped observations: %+v %v", host, err)
	}
	found := false
	for _, v := range host.Vulnerabilities {
		if v.Finding != nil && v.Finding.VID == "CVE-SHARED" && v.Finding.Description == "private description" {
			found = true
		}
	}
	if !found {
		t.Fatal("scoped observation lost private details")
	}
}
