package host

import "gorm.io/gorm"

// selectedFindingRiskSQL follows inventory's complete observation: a present
// snapshot has its own risk (an omitted riskScore encodes zero), while legacy
// relationships without a snapshot use the shared vulnerability catalog.
const selectedFindingRiskSQL = "COALESCE(CASE WHEN findings.finding IS NOT NULL THEN COALESCE((findings.finding->>'riskScore')::double precision, 0) ELSE vulnerabilities.risk_score END, 0)"

// currentVulnerabilityFindings returns one row per active (host, vulnerability),
// regardless of how many scanners reported it. A finding remains current while
// any source is active; resolved/false-positive sources and deleted records do
// not contribute. Deduplicate identities before aggregating, never risk scores:
// distinct vulnerabilities can legitimately have identical scores.
func currentVulnerabilityFindings(db *gorm.DB) *gorm.DB {
	findings := db.Session(&gorm.Session{NewDB: true}).
		Table("host_vulnerabilities").
		Select("DISTINCT ON (host_id, vulnerability_id) host_id, vulnerability_id, finding").
		Where("status = ?", "active").
		// Match preferVulnerabilityObservation exactly, including Go's bytewise
		// source tie-break instead of the database's locale-dependent collation.
		Order("host_id, vulnerability_id, COALESCE(confidence, 0) DESC, last_seen DESC NULLS LAST, source COLLATE \"C\" ASC")

	return db.Table("hosts").
		Joins("JOIN (?) AS findings ON findings.host_id = hosts.id", findings).
		Joins("JOIN vulnerabilities ON vulnerabilities.id = findings.vulnerability_id").
		Where("hosts.deleted_at IS NULL AND vulnerabilities.deleted_at IS NULL")
}

func hostRiskStatisticsQuery(db *gorm.DB, ip string) *gorm.DB {
	return currentVulnerabilityFindings(db).
		Select(`COUNT(*) AS vulnerability_count,
			COALESCE(SUM(`+selectedFindingRiskSQL+`), 0) AS total_risk_score,
			COALESCE(AVG(`+selectedFindingRiskSQL+`), 0) AS average_risk_score`).
		Where("hosts.ip = ?", ip)
}

func hostSeverityCountsQuery(db *gorm.DB, ip string) *gorm.DB {
	return currentVulnerabilityFindings(db).
		Select(`COALESCE(SUM(CASE WHEN `+selectedFindingRiskSQL+` >= 9 THEN 1 ELSE 0 END), 0) AS critical,
			COALESCE(SUM(CASE WHEN `+selectedFindingRiskSQL+` >= 7 AND `+selectedFindingRiskSQL+` < 9 THEN 1 ELSE 0 END), 0) AS high,
			COALESCE(SUM(CASE WHEN `+selectedFindingRiskSQL+` >= 4 AND `+selectedFindingRiskSQL+` < 7 THEN 1 ELSE 0 END), 0) AS medium,
			COALESCE(SUM(CASE WHEN `+selectedFindingRiskSQL+` > 0 AND `+selectedFindingRiskSQL+` < 4 THEN 1 ELSE 0 END), 0) AS low,
			COALESCE(SUM(CASE WHEN `+selectedFindingRiskSQL+` = 0 THEN 1 ELSE 0 END), 0) AS informational`).
		Where("hosts.ip = ?", ip)
}

// Vulnerability summaries remain a catalog view: title/description/riskScore
// are shared catalog metadata, while hostCount counts current affected hosts.
// Per-host risk, severity and rankings above/below use selected observations.
func vulnerabilitySummariesQuery(db *gorm.DB) *gorm.DB {
	return currentVulnerabilityFindings(db).
		Select(`vulnerabilities.v_id, vulnerabilities.title, vulnerabilities.description,
			vulnerabilities.risk_score, COUNT(DISTINCT hosts.id) AS host_count`).
		Group("vulnerabilities.id, vulnerabilities.v_id, vulnerabilities.title, vulnerabilities.description, vulnerabilities.risk_score")
}

func mostVulnerableHostsQuery(db *gorm.DB, limit int) *gorm.DB {
	return currentVulnerabilityFindings(db).
		Select(`COALESCE(hosts.h_id, hosts.ip) AS host_id,
			hosts.ip AS host_ip, hosts.hostname,
			COUNT(*) AS total_vulnerabilities,
			COALESCE(SUM(` + selectedFindingRiskSQL + `), 0) AS weighted_risk_score,
			hosts.updated_at AS last_updated`).
		Group("hosts.id, hosts.h_id, hosts.ip, hosts.hostname, hosts.updated_at").
		Order("weighted_risk_score DESC, total_vulnerabilities DESC, hosts.id ASC").
		Limit(limit)
}
