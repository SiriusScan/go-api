package sirius

import (
	"fmt"
	"time"
)

// Star represents a celestial object.
type Star struct {
	Name string
	Type string
	Mass float64
}

// NewStar creates a new Star.
func NewStar(name, starType string, mass float64) Star {
	return Star{name, starType, mass}
}

// Info prints information about the Star.
func (s Star) Info() {
	fmt.Printf("Star Name: %s\nType: %s\nMass: %f\n", s.Name, s.Type, s.Mass)
	fmt.Println("Done")
	fmt.Println("Done")
	fmt.Println("Done")
}

type Entry struct {
	EntryId             string
	CVE                 string
	CVEDataFormat       string
	CVEDataType         string
	CVEDataVersion      string
	CVEDataNumberOfCVEs string
	CVEDataTimestamp    string
	CVEItems            []CVEItem
	CVEDataMeta         CVEDataMeta
	Description         Description
	CPE                 Node
	CVSSV3              CVSSV3
	References          []string
	Tags                []string
}

// ========================= Vulnerability =========================
type Vulnerability struct {
	VID         string  `json:"vid"`
	Description string  `json:"description"`
	Title       string  `json:"title"`
	RiskScore   float64 `json:"riskScore,omitempty"`
}

type RiskScore struct {
	CVSSV3 BaseMetricV3 `json:"CVSSV3,omitempty"`
	CVSSV2 BaseMetricV2 `json:"CVSSV2,omitempty"`
}

type BaseMetricV3 struct {
	CVSSV3              CVSSV3  `json:"cvssV3"`
	ExploitabilityScore float64 `json:"exploitabilityScore"`
	ImpactScore         float64 `json:"impactScore"`
}

type CVSSV3 struct {
	Version                       string  `json:"version"`
	VectorString                  string  `json:"vectorString"`
	AttackVector                  string  `json:"attackVector"`
	AttackComplexity              string  `json:"attackComplexity"`
	PrivilegesRequired            string  `json:"privilegesRequired"`
	UserInteraction               string  `json:"userInteraction"`
	Scope                         string  `json:"scope"`
	ConfidentialityImpact         string  `json:"confidentialityImpact"`
	IntegrityImpact               string  `json:"integrityImpact"`
	AvailabilityImpact            string  `json:"availabilityImpact"`
	BaseScore                     float64 `json:"baseScore"`
	BaseSeverity                  string  `json:"baseSeverity"`
	ExploitCodeMaturity           string  `json:"exploitCodeMaturity"`
	RemediationLevel              string  `json:"remediationLevel"`
	ReportConfidence              string  `json:"reportConfidence"`
	TemporalScore                 float64 `json:"temporalScore"`
	TemporalSeverity              string  `json:"temporalSeverity"`
	ConfidentialityRequirement    string  `json:"confidentialityRequirement"`
	IntegrityRequirement          string  `json:"integrityRequirement"`
	AvailabilityRequirement       string  `json:"availabilityRequirement"`
	ModifiedAttackVector          string  `json:"modifiedAttackVector"`
	ModifiedAttackComplexity      string  `json:"modifiedAttackComplexity"`
	ModifiedPrivilegesRequired    string  `json:"modifiedPrivilegesRequired"`
	ModifiedUserInteraction       string  `json:"modifiedUserInteraction"`
	ModifiedScope                 string  `json:"modifiedScope"`
	ModifiedConfidentialityImpact string  `json:"modifiedConfidentialityImpact"`
	ModifiedIntegrityImpact       string  `json:"modifiedIntegrityImpact"`
	ModifiedAvailabilityImpact    string  `json:"modifiedAvailabilityImpact"`
	EnvironmentalScore            float64 `json:"environmentalScore"`
	EnvironmentalSeverity         string  `json:"environmentalSeverity"`
}

type BaseMetricV2 struct {
	CVSSV2                  CVSSV2  `json:"cvssV2"`
	Severity                string  `json:"severity"`
	ExploitabilityScore     float64 `json:"exploitabilityScore"`
	ImpactScore             float64 `json:"impactScore"`
	AcInsufInfo             bool    `json:"acInsufInfo"`
	ObtainAllPrivilege      bool    `json:"obtainAllPrivilege"`
	ObtainUserPrivilege     bool    `json:"obtainUserPrivilege"`
	ObtainOtherPrivilege    bool    `json:"obtainOtherPrivilege"`
	UserInteractionRequired bool    `json:"userInteractionRequired"`
}

type CVSSV2 struct {
	Version                    string  `json:"version"`
	VectorString               string  `json:"vectorString"`
	AccessVector               string  `json:"accessVector"`
	AccessComplexity           string  `json:"accessComplexity"`
	Authentication             string  `json:"authentication"`
	ConfidentialityImpact      string  `json:"confidentialityImpact"`
	IntegrityImpact            string  `json:"integrityImpact"`
	AvailabilityImpact         string  `json:"availabilityImpact"`
	BaseScore                  float64 `json:"baseScore"`
	Exploitability             string  `json:"exploitability"`
	RemediationLevel           string  `json:"remediationLevel"`
	ReportConfidence           string  `json:"reportConfidence"`
	TemporalScore              float64 `json:"temporalScore"`
	CollateralDamagePotential  string  `json:"collateralDamagePotential"`
	TargetDistribution         string  `json:"targetDistribution"`
	ConfidentialityRequirement string  `json:"confidentialityRequirement"`
	IntegrityRequirement       string  `json:"integrityRequirement"`
	AvailabilityRequirement    string  `json:"availabilityRequirement"`
	EnvironmentalScore         float64 `json:"environmentalScore"`
}

// ========================= HOST =========================

type Host struct {
	HID             string          `gorm:"primaryKey" json:"hid"`
	OS              string          `json:"os"`
	OSVersion       string          `json:"osversion"`
	IP              string          `json:"ip"`
	Hostname        string          `json:"hostname"`
	Ports           []Port          `json:"ports"`
	Services        []Service      `json:"services,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
	CPE             []string        `json:"cpe"`
	Users           []string        `json:"users"`
	Notes           []string        `json:"notes"`
	Agent           *SiriusAgent    `json:"agent,omitempty"`
}
type Port struct {
	ID       int    `json:"id"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
}

// ========================= LEGACY =========================

type SiriusAgent struct {
	AgentId string
	HostKey string
	IP      string
	OS      string
	Tasks   []Task
}
type TaskResponse struct {
	AgentId string
	IP      string
	Task    Task
}
type Task struct {
	ID      string
	Type    string
	Command string
	Result  string
	Status  string
	Date    time.Time
}
type Service struct {
	Port    int    `json:"port"`
	Product string `json:"product"`
	Version string `json:"version"`
	CPE     string `json:"cpe"`
}
type TerminalHistory struct {
	Id      string
	IP      string
	Command string
	Result  string
	Status  string
	Date    time.Time
}
type Finding struct {
	CVE    CVE
	SVDBID string
}
type FindingRequest struct {
	CVE    []string
	SVDBID string
}
type CVEFinding struct {
	CVEDataType         string  `json:"cvedatatype"`
	CVEDataFormat       string  `json:"cvedataformat"`
	CVEDataVersion      string  `json:"cvedataversion"`
	CVEDataNumberOfCVEs *string `json:"cvedatanumberofcves,omitempty"`
	CVEDataTimestamp    string  `json:"cvedatatimestamp"`
	CVEDataMeta         CVEDataMeta
	Description         Description `json:"description"`
}

type (
	CVEResponse struct {
		ResultsPerPage int       `json:"resultsPerPage"`
		StartIndex     int       `json:"startIndex"`
		TotalResults   int       `json:"totalResults"`
		Result         CVEResult `json:"result"`
	}

	CVEResult struct {
		CVEDataType         string     `json:"CVE_data_type"`
		CVEDataFormat       string     `json:"CVE_data_format"`
		CVEDataVersion      string     `json:"CVE_data_version"`
		CVEDataNumberOfCVEs *string    `json:"CVE_data_numberOfCVEs,omitempty"`
		CVEDataTimestamp    string     `json:"CVE_data_timestamp"`
		CVEItems            *[]CVEItem `json:"CVE_Items,omitempty"`
	}

	// CVEITEM defines a vulnerability in the NVD data feed as defined
	// in the NIST API schema.
	CVEItem struct {
		CVE              CVE            `json:"cve"`
		Configurations   Configurations `json:"configurations,omitempty"`
		Impact           *Impact        `json:"impact,omitempty"`
		PublishedDate    *string        `json:"publishedDate,omitempty"`
		LastModifiedDate *string        `json:"lastModifiedDate,omitempty"`
	}

	// CVE as defined in the NIST API schema.
	CVE struct {
		DataType    string        `json:"data_type"`
		DataFormat  string        `json:"data_format"`
		DataVersion string        `json:"data_version"`
		CVEDataMeta CVEDataMeta   `json:"cve_data_meta"`
		Affects     *Affects      `json:"affects,omitempty"`
		ProblemType ProblemType   `json:"problemtype"`
		References  CVEReferences `json:"references"`
		Description Description   `json:"description"`
	}

	CVEDataMeta struct {
		ID       string  `json:"ID"`
		ASSIGNER string  `json:"ASSIGNER"`
		STATE    *string `json:"STATE,omitempty"`
	}

	Affects struct {
		Vendor Vendor `json:"vendor"`
	}

	Vendor struct {
		// VendorData has a minimum of 0 items according to the
		// NIST API schema.
		VendorData []VendorData `json:""`
	}

	VendorData struct {
		VendorName string        `json:"vendor_name"`
		Product    VendorProduct `json:"product"`
	}

	VendorProduct struct {
		// ProductData has a minimum of 1 item according to the
		// NIST API schema.
		ProductData []Product `json:"product_data"`
	}

	ProblemType struct {
		// ProblemTypeData has a minimum of 0 items according to the
		// NIST API schema.
		ProblemTypeData []ProblemTypeData `json:"problemtype_data"`
	}

	ProblemTypeData struct {
		// Description has a minimum of 0 items according to the
		// NIST API schema.
		Description []LangString `json:"description"`
	}

	CVEReferences struct {
		// ReferenceData has a minimum of 0 and a maximum of 500
		// items according to the NIST API schema.
		ReferenceData []CVEReference `json:"reference_data"`
	}

	Description struct {
		// DescriptionData has a minimum of 0 items according to
		// the NIST API schema.
		Value string `json:"value"`
		// DescriptionData []LangString `json:"description_data"`
	}

	Product struct {
		ProductName string  `json:"product_name"`
		Version     Version `json:"version"`
	}

	Version struct {
		// VersionData has a minimum of 1 item according to the
		// NIST API schema.
		VersionData []VersionData `json:"version_data"`
	}

	VersionData struct {
		VersionValue    string  `json:"version_value"`
		VersionAffected *string `json:"version_affected,omitempty"`
	}

	CVEReference struct {
		// URL has a maximum length of 500 characters according to the
		// NIST API schema.
		URL       string    `json:"url"`
		Name      *string   `json:"name,omitempty"`
		Refsource *string   `json:"refsource,omitempty"`
		Tags      *[]string `json:"tags,omitempty"`
	}

	LangString struct {
		Lang string `json:"lang"`
		// Value has a maximum length of 3999 characters according to the
		// NIST API schema.
		Value string `json:"value"`
	}

	// Configurations defines the set of product configurations for a
	// NVD applicability statement as defined in the NIST API schema.
	Configurations struct {
		CVEDataVersion string `json:"CVE_data_version"`
		Nodes          []Node `json:"nodes,omitempty"`
	}

	// Node is a node or sub-node in an NVD applicability statement
	// as defined in the NIST API schema.
	Node struct {
		Operator string     `json:"operator,omitempty"`
		Negate   bool       `json:"negate,omitempty"`
		Children []Node     `json:"children,omitempty"`
		CPEMatch []CPEMatch `json:"cpe_match,omitempty"`
	}

	// CPEMatch is the CPE Match string or range as defined in the
	// NIST API schema.
	CPEMatch struct {
		Vulnerable            bool         `json:"vulnerable"`
		CPE22URI              string       `json:"cpe22Uri,omitempty"`
		CPE23URI              string       `json:"cpe23Uri"`
		VersionStartExcluding string       `json:"versionStartExcluding,omitempty"`
		VersionStartIncluding string       `json:"versionStartIncluding,omitempty"`
		VersionEndExcluding   string       `json:"versionEndExcluding,omitempty"`
		VersionEndIncluding   string       `json:"versionEndIncluding,omitempty"`
		CPEName               []CVECPEName `json:"cpe_name,omitempty"`
	}

	// CPEName is the CPE name as defined in the NIST API schema.
	CVECPEName struct {
		CPE22URI         string `json:"cpe22Uri,omitempty"`
		CPE23URI         string `json:"cpe23Uri"`
		LastModifiedDate string `json:"lastModifiedDate,omitempty"`
	}

	// Impact scores for a vulnerability as found on NVD as defined
	// in the NIST API schema.
	Impact struct {
		BaseMetricV3 BaseMetricV3 `json:"baseMetricV3,omitempty"`
		BaseMetricV2 BaseMetricV2 `json:"baseMetricV2,omitempty"`
	}

	CPEResponse struct {
		ResultsPerPage int       `json:"resultsPerPage"`
		StartIndex     int       `json:"startIndex"`
		TotalResults   int       `json:"totalResults"`
		Result         CPEResult `json:"result"`
	}

	CPEResult struct {
		DataType    string `json:"dataType"`
		FeedVersion string `json:"feedVersion"`
		// Number of CPE in this feed
		CPECount int `json:"cpeCount"`
		// Timestamp indicates when feed was generated
		FeedTimestamp *string   `json:"feedTimestamp,omitempty"`
		CPEs          []CPEName `json:"cpes"`
	}

	// CPE name
	CPEName struct {
		CPE23URI         string         `json:"cpe23Uri"`
		LastModifiedDate string         `json:"lastModifiedDate"`
		Deprecated       bool           `json:"deprecated,omitempty"`
		DeprecatedBy     []string       `json:"deprecatedBy,omitempty"`
		Titles           []Title        `json:"titles,omitempty"`
		Refs             []CPEReference `json:"refs,omitempty"`
		Vulnerabilities  []string       `json:"vulnerabilities,omitempty"`
	}

	// Human readable title for CPE
	Title struct {
		Title string `json:"title"`
		Lang  string `json:"lang"`
	}

	// Internet resource for CPE
	CPEReference struct {
		Ref  string           `json:"ref"`
		Type CPEReferenceType `json:"type,omitempty"`
	}

	CPEReferenceType string
)

var (
	ADVISORY   CPEReferenceType = "Advisory"
	CHANGE_LOG CPEReferenceType = "Change Log"
	PRODUCT    CPEReferenceType = "Product"
	PROJECT    CPEReferenceType = "Project"
	VENDOR     CPEReferenceType = "Vendor"
	VERSION    CPEReferenceType = "Version"
)
