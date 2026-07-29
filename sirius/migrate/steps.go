package migrate

import (
	"fmt"

	"gorm.io/gorm"
)

func execAll(db *gorm.DB, statements []string) error {
	for _, sql := range statements {
		if err := db.Exec(sql).Error; err != nil {
			return fmt.Errorf("%w\nSQL: %s", err, sql)
		}
	}
	return nil
}

func columnExists(db *gorm.DB, table, column string) (bool, error) {
	var exists bool
	err := db.Raw(`
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_schema = 'public' AND table_name = ? AND column_name = ?
		)
	`, table, column).Scan(&exists).Error
	return exists, err
}

func apply002(db *gorm.DB) error {
	statements := []string{
		`ALTER TABLE host_vulnerabilities ADD COLUMN IF NOT EXISTS source VARCHAR(255) DEFAULT 'unknown'`,
		`ALTER TABLE host_vulnerabilities ADD COLUMN IF NOT EXISTS source_version VARCHAR(255) DEFAULT ''`,
		`ALTER TABLE host_vulnerabilities ADD COLUMN IF NOT EXISTS first_seen TIMESTAMP DEFAULT NOW()`,
		`ALTER TABLE host_vulnerabilities ADD COLUMN IF NOT EXISTS last_seen TIMESTAMP DEFAULT NOW()`,
		`ALTER TABLE host_vulnerabilities ADD COLUMN IF NOT EXISTS status VARCHAR(255) DEFAULT 'active'`,
		`ALTER TABLE host_vulnerabilities ADD COLUMN IF NOT EXISTS confidence DECIMAL(3,2) DEFAULT 1.0`,
		`ALTER TABLE host_vulnerabilities ADD COLUMN IF NOT EXISTS port INTEGER`,
		`ALTER TABLE host_vulnerabilities ADD COLUMN IF NOT EXISTS service_info TEXT`,
		`ALTER TABLE host_vulnerabilities ADD COLUMN IF NOT EXISTS notes TEXT`,
		`ALTER TABLE host_ports ADD COLUMN IF NOT EXISTS source VARCHAR(255) DEFAULT 'unknown'`,
		`ALTER TABLE host_ports ADD COLUMN IF NOT EXISTS source_version VARCHAR(255) DEFAULT ''`,
		`ALTER TABLE host_ports ADD COLUMN IF NOT EXISTS first_seen TIMESTAMP DEFAULT NOW()`,
		`ALTER TABLE host_ports ADD COLUMN IF NOT EXISTS last_seen TIMESTAMP DEFAULT NOW()`,
		`ALTER TABLE host_ports ADD COLUMN IF NOT EXISTS status VARCHAR(255) DEFAULT 'active'`,
		`ALTER TABLE host_ports ADD COLUMN IF NOT EXISTS notes TEXT`,
		`CREATE TABLE IF NOT EXISTS scan_history_entries (
			id BIGSERIAL PRIMARY KEY,
			scan_id VARCHAR(255) NOT NULL,
			host_ip VARCHAR(255),
			source VARCHAR(255),
			source_version VARCHAR(255),
			started_at TIMESTAMP,
			completed_at TIMESTAMP,
			status VARCHAR(255),
			hosts_discovered INTEGER DEFAULT 0,
			vulnerabilities_found INTEGER DEFAULT 0,
			metadata JSONB DEFAULT '{}'::jsonb,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		)`,
	}
	return execAll(db, statements)
}

func apply003(db *gorm.DB) error {
	// Never DROP populated junction tables. Ensure enhanced shape via CREATE IF NOT EXISTS
	// and additive columns (002). Fresh installs get tables from baseline AutoMigrate;
	// this step only fills gaps when tables are missing entirely.
	statements := []string{
		`CREATE TABLE IF NOT EXISTS host_vulnerabilities (
			host_id BIGINT NOT NULL,
			vulnerability_id BIGINT NOT NULL,
			source VARCHAR(255) NOT NULL DEFAULT 'unknown',
			source_version VARCHAR(255) DEFAULT '',
			first_seen TIMESTAMP DEFAULT NOW(),
			last_seen TIMESTAMP DEFAULT NOW(),
			status VARCHAR(255) DEFAULT 'active',
			confidence DECIMAL(3,2) DEFAULT 1.0,
			port INTEGER,
			service_info TEXT,
			notes TEXT,
			PRIMARY KEY (host_id, vulnerability_id, source)
		)`,
		`CREATE TABLE IF NOT EXISTS host_ports (
			host_id BIGINT NOT NULL,
			port_id BIGINT NOT NULL,
			source VARCHAR(255) NOT NULL DEFAULT 'unknown',
			source_version VARCHAR(255) DEFAULT '',
			first_seen TIMESTAMP DEFAULT NOW(),
			last_seen TIMESTAMP DEFAULT NOW(),
			status VARCHAR(255) DEFAULT 'active',
			notes TEXT,
			PRIMARY KEY (host_id, port_id, source)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_host_vulnerabilities_source ON host_vulnerabilities(source)`,
		`CREATE INDEX IF NOT EXISTS idx_host_vulnerabilities_status ON host_vulnerabilities(status)`,
		`CREATE INDEX IF NOT EXISTS idx_host_ports_source ON host_ports(source)`,
		`CREATE INDEX IF NOT EXISTS idx_host_ports_status ON host_ports(status)`,
	}
	return execAll(db, statements)
}

func apply004(db *gorm.DB) error {
	statements := []string{
		`ALTER TABLE hosts ADD COLUMN IF NOT EXISTS software_inventory JSONB DEFAULT '{}'::jsonb`,
		`ALTER TABLE hosts ADD COLUMN IF NOT EXISTS system_fingerprint JSONB DEFAULT '{}'::jsonb`,
		`ALTER TABLE hosts ADD COLUMN IF NOT EXISTS agent_version VARCHAR(255) DEFAULT ''`,
		`ALTER TABLE hosts ADD COLUMN IF NOT EXISTS last_agent_checkin TIMESTAMP`,
		`CREATE INDEX IF NOT EXISTS idx_hosts_software_inventory ON hosts USING GIN (software_inventory)`,
		`CREATE INDEX IF NOT EXISTS idx_hosts_system_fingerprint ON hosts USING GIN (system_fingerprint)`,
	}
	return execAll(db, statements)
}

func apply005(db *gorm.DB) error {
	// Port.ID → number migration is destructive when needed; skip if already migrated
	// or if ports table has the modern shape (number column present).
	hasNumber, err := columnExists(db, "ports", "number")
	if err != nil {
		return err
	}
	if !hasNumber {
		var tableExists bool
		if err := db.Raw(`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='ports')`).Scan(&tableExists).Error; err != nil {
			return err
		}
		if tableExists {
			// Legacy shape: rename id→number and add serial id. Only when number is absent.
			// Prefer additive path used by current GORM models on fresh installs (baseline
			// already creates number). For legacy DBs without number, run the rename path.
			stmts := []string{
				`ALTER TABLE ports DROP CONSTRAINT IF EXISTS ports_pkey CASCADE`,
				`ALTER TABLE ports RENAME COLUMN id TO number`,
				`ALTER TABLE ports ADD COLUMN IF NOT EXISTS id SERIAL`,
			}
			if err := execAll(db, stmts); err != nil {
				return fmt.Errorf("ports id/number migration: %w", err)
			}
			// Ensure primary key on id
			_ = db.Exec(`ALTER TABLE ports ADD PRIMARY KEY (id)`).Error
			_ = db.Exec(`ALTER TABLE ports ADD CONSTRAINT unique_port_number_protocol UNIQUE (number, protocol)`).Error
		}
	}

	statements := []string{
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_vulnerabilities_vid ON vulnerabilities(vid)`,
		`CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip)`,
		`CREATE INDEX IF NOT EXISTS idx_ports_number ON ports(number)`,
		`CREATE INDEX IF NOT EXISTS idx_host_vulnerabilities_host_id ON host_vulnerabilities(host_id)`,
		`CREATE INDEX IF NOT EXISTS idx_host_vulnerabilities_vuln_id ON host_vulnerabilities(vulnerability_id)`,
	}
	return execAll(db, statements)
}

func apply006(db *gorm.DB) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS events (
			id BIGSERIAL PRIMARY KEY,
			event_id VARCHAR(255) UNIQUE NOT NULL,
			timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			service VARCHAR(100) NOT NULL,
			subcomponent VARCHAR(100),
			event_type VARCHAR(50) NOT NULL,
			severity VARCHAR(20) NOT NULL,
			title VARCHAR(255) NOT NULL,
			description TEXT,
			metadata JSONB,
			entity_type VARCHAR(50),
			entity_id VARCHAR(255),
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_events_service ON events(service)`,
		`CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type)`,
		`CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)`,
		`CREATE INDEX IF NOT EXISTS idx_events_entity ON events(entity_type, entity_id)`,
	}
	return execAll(db, statements)
}

func apply007(db *gorm.DB) error {
	statements := []string{
		`CREATE INDEX IF NOT EXISTS idx_host_vulnerabilities_host_id ON host_vulnerabilities(host_id)`,
		`CREATE INDEX IF NOT EXISTS idx_host_vulnerabilities_vuln_id ON host_vulnerabilities(vulnerability_id)`,
		`CREATE INDEX IF NOT EXISTS idx_vulnerabilities_risk_score ON vulnerabilities(risk_score DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_host_vuln_stats ON host_vulnerabilities(host_id, vulnerability_id, status) WHERE status = 'active'`,
	}
	return execAll(db, statements)
}
