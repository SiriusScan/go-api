package nvd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// =============== Types ===============

// Top-level response
type NVDResponse struct {
	ResultsPerPage  int          `json:"resultsPerPage"`
	StartIndex      int          `json:"startIndex"`
	TotalResults    int          `json:"totalResults"`
	Format          string       `json:"format"`
	Version         string       `json:"version"`
	Timestamp       string       `json:"timestamp"`
	Vulnerabilities []DefCVEItem `json:"vulnerabilities"`
}

// An item in the "vulnerabilities" array
type DefCVEItem struct {
	CVE CveItem `json:"cve"`
}

// CVE object per NVD schema
type CveItem struct {
	ID                    string          `json:"id"`
	SourceIdentifier      string          `json:"sourceIdentifier"`
	VulnStatus            string          `json:"vulnStatus"`
	Published             string          `json:"published"`
	LastModified          string          `json:"lastModified"`
	EvaluatorComment      *string         `json:"evaluatorComment,omitempty"`
	EvaluatorSolution     *string         `json:"evaluatorSolution,omitempty"`
	EvaluatorImpact       *string         `json:"evaluatorImpact,omitempty"`
	CisaExploitAdd        *string         `json:"cisaExploitAdd,omitempty"`
	CisaActionDue         *string         `json:"cisaActionDue,omitempty"`
	CisaRequiredAction    *string         `json:"cisaRequiredAction,omitempty"`
	CisaVulnerabilityName *string         `json:"cisaVulnerabilityName,omitempty"`
	CveTags               []CveTag        `json:"cveTags,omitempty"`
	Descriptions          []LangString    `json:"descriptions"`
	References            []Reference     `json:"references"`
	Metrics               Metrics         `json:"metrics,omitempty"`
	Weaknesses            []Weakness      `json:"weaknesses,omitempty"`
	Configurations        []Config        `json:"configurations,omitempty"`
	VendorComments        []VendorComment `json:"vendorComments,omitempty"`
}

// Each object in "cveTags"
type CveTag struct {
	SourceIdentifier string   `json:"sourceIdentifier"`
	Tags             []string `json:"tags"`
}

// "descriptions" array items
type LangString struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// "references" array items
type Reference struct {
	URL    string   `json:"url"`
	Source string   `json:"source,omitempty"`
	Tags   []string `json:"tags,omitempty"`
}

// Container for multiple CVSS versions
type Metrics struct {
	CvssMetricV40 []CvssV40 `json:"cvssMetricV40,omitempty"`
	CvssMetricV31 []CvssV31 `json:"cvssMetricV31,omitempty"`
	CvssMetricV30 []CvssV30 `json:"cvssMetricV30,omitempty"`
	CvssMetricV2  []CvssV2  `json:"cvssMetricV2,omitempty"`
}

// CVSS v4.0
type CvssV40 struct {
	Source   string      `json:"source"`
	Type     string      `json:"type"`
	CvssData CvssDataV40 `json:"cvssData"`
}

// CVSS v3.1
type CvssV31 struct {
	Source              string      `json:"source"`
	Type                string      `json:"type"`
	CvssData            CvssDataV31 `json:"cvssData"`
	ExploitabilityScore float64     `json:"exploitabilityScore,omitempty"`
	ImpactScore         float64     `json:"impactScore,omitempty"`
}

// CVSS v3.0
type CvssV30 struct {
	Source              string      `json:"source"`
	Type                string      `json:"type"`
	CvssData            CvssDataV30 `json:"cvssData"`
	ExploitabilityScore float64     `json:"exploitabilityScore,omitempty"`
	ImpactScore         float64     `json:"impactScore,omitempty"`
}

// CVSS v2.0
type CvssV2 struct {
	Source                  string     `json:"source"`
	Type                    string     `json:"type"`
	CvssData                CvssDataV2 `json:"cvssData"`
	BaseSeverity            *string    `json:"baseSeverity,omitempty"`
	ExploitabilityScore     *float64   `json:"exploitabilityScore,omitempty"`
	ImpactScore             *float64   `json:"impactScore,omitempty"`
	AcInsufInfo             *bool      `json:"acInsufInfo,omitempty"`
	ObtainAllPrivilege      *bool      `json:"obtainAllPrivilege,omitempty"`
	ObtainUserPrivilege     *bool      `json:"obtainUserPrivilege,omitempty"`
	ObtainOtherPrivilege    *bool      `json:"obtainOtherPrivilege,omitempty"`
	UserInteractionRequired *bool      `json:"userInteractionRequired,omitempty"`
}

// CVSS v4.0 data
type CvssDataV40 struct {
	// For full parity, define fields from https://csrc.nist.gov/schema/nvd/api/2.0/external/cvss-v4.0.json
	// This example structure only shows typical fields from sample data; expand as needed.
	Version      string `json:"version"`
	VectorString string `json:"vectorString"`
}

// CVSS v3.1 data
type CvssDataV31 struct {
	Version               string  `json:"version"`
	VectorString          string  `json:"vectorString"`
	BaseScore             float64 `json:"baseScore"`
	BaseSeverity          string  `json:"baseSeverity"`
	AttackVector          string  `json:"attackVector"`
	AttackComplexity      string  `json:"attackComplexity"`
	PrivilegesRequired    string  `json:"privilegesRequired"`
	UserInteraction       string  `json:"userInteraction"`
	Scope                 string  `json:"scope"`
	ConfidentialityImpact string  `json:"confidentialityImpact"`
	IntegrityImpact       string  `json:"integrityImpact"`
	AvailabilityImpact    string  `json:"availabilityImpact"`
}

// CVSS v3.0 data
type CvssDataV30 struct {
	Version               string  `json:"version"`
	VectorString          string  `json:"vectorString"`
	BaseScore             float64 `json:"baseScore"`
	BaseSeverity          string  `json:"baseSeverity"`
	AttackVector          string  `json:"attackVector"`
	AttackComplexity      string  `json:"attackComplexity"`
	PrivilegesRequired    string  `json:"privilegesRequired"`
	UserInteraction       string  `json:"userInteraction"`
	Scope                 string  `json:"scope"`
	ConfidentialityImpact string  `json:"confidentialityImpact"`
	IntegrityImpact       string  `json:"integrityImpact"`
	AvailabilityImpact    string  `json:"availabilityImpact"`
}

// CVSS v2.0 data
type CvssDataV2 struct {
	Version               string  `json:"version"`
	VectorString          string  `json:"vectorString"`
	BaseScore             float64 `json:"baseScore"`
	AccessVector          string  `json:"accessVector"`
	AccessComplexity      string  `json:"accessComplexity"`
	Authentication        string  `json:"authentication"`
	ConfidentialityImpact string  `json:"confidentialityImpact"`
	IntegrityImpact       string  `json:"integrityImpact"`
	AvailabilityImpact    string  `json:"availabilityImpact"`
}

// "weaknesses" array items
type Weakness struct {
	Source      string       `json:"source"`
	Type        string       `json:"type"`
	Description []LangString `json:"description"`
}

// "configurations" array items
type Config struct {
	Operator string `json:"operator"`
	Negate   bool   `json:"negate,omitempty"`
	Nodes    []Node `json:"nodes"`
}

// Each node in "configurations"
type Node struct {
	Operator string     `json:"operator"`
	Negate   bool       `json:"negate,omitempty"`
	CpeMatch []CpeMatch `json:"cpeMatch,omitempty"`
}

// An item in "cpeMatch"
type CpeMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	MatchCriteriaID       string `json:"matchCriteriaId"`
	VersionStartExcluding string `json:"versionStartExcluding,omitempty"`
	VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
	VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
	VersionEndIncluding   string `json:"versionEndIncluding,omitempty"`
}

// "vendorComments" array items
type VendorComment struct {
	Organization string `json:"organization"`
	Comment      string `json:"comment"`
	LastModified string `json:"lastModified"`
}

func GetCVE(vid string) (CveItem, error) {
	var baseCve CveItem
	// api request to NVD: https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-1010218
	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s", vid)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return baseCve, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")

	// Execute the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return baseCve, fmt.Errorf("request error: %w", err)
	}
	defer resp.Body.Close()

	// Ensure we got a 200 OK
	if resp.StatusCode != http.StatusOK {
		return baseCve, fmt.Errorf("received status code %d from NVD API", resp.StatusCode)
	}

	// Read the response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return baseCve, fmt.Errorf("failed to read response body: %w", err)
	}
	// Unmarshal JSON into our NVDResponse struct
	var nvdResp NVDResponse
	if err := json.Unmarshal(bodyBytes, &nvdResp); err != nil {
		return baseCve, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	if len(nvdResp.Vulnerabilities) == 0 {
		return CveItem{}, nil
	}
	return nvdResp.Vulnerabilities[0].CVE, nil
}
