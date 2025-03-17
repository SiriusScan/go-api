# Running Migrations in Docker Containers

This guide provides detailed instructions for executing database migrations in a Docker container environment, specifically for the relationship fixes in our database models.

## Preparation

Before running the migration, it's recommended to:

1. **Backup your database**:

   ```bash
   # From the host
   docker-compose exec db pg_dump -U postgres -d sirius > sirius_backup_$(date +%Y%m%d).sql
   ```

2. **Check container status**:
   ```bash
   # Make sure all containers are running
   docker-compose ps
   ```

## Running the Migration

### 1. Access the API Container

```bash
# Get a shell in the API container
docker-compose exec api bash
```

### 2. Navigate to the Migrations Directory

```bash
# Inside the container
cd /app/migrations
```

### 3. Execute the Migration

```bash
# Run the migration script
go run 001_fix_relationships.go
```

The script will:

- Back up existing relationships
- Update the schema
- Restore relationships to the new structure
- Remove obsolete columns

### 4. Verify the Migration

After running the migration, verify that it was successful:

```bash
# Inside the container, connect to the database
docker-compose exec db psql -U postgres -d sirius

# Check that the junction table exists
\dt host_ports
\dt host_vulnerabilities

# Verify port relationships
SELECT COUNT(*) FROM host_ports;

# Verify that the host_id columns are gone
\d ports
\d vulnerabilities
```

## Troubleshooting

If you encounter issues during the migration:

### Connection Errors

```bash
# Check if the database is accessible from the API container
docker-compose exec api ping db

# Verify database connection settings in the API container
docker-compose exec api env | grep DB_
```

### Schema Conflicts

```bash
# If you encounter schema conflicts, check current schema
docker-compose exec db psql -U postgres -d sirius -c "\d ports"
docker-compose exec db psql -U postgres -d sirius -c "\d vulnerabilities"
```

### Data Loss Concerns

The migration script is designed to preserve data by backing up relationships before making schema changes. If you're concerned about potential data loss:

1. Run the migration on a staging environment first
2. Use the backup created in the preparation step if you need to roll back

## Manual Recovery (If Needed)

If you need to recover manually:

```bash
# Restore from backup
docker-compose exec -T db psql -U postgres -d sirius < sirius_backup_YYYYMMDD.sql
```

## Running the Test Suite

To verify that the model relationships work correctly after migration:

```bash
# Inside the API container
cd /app/tests
go test -v ./models
```

This will run the test suite that validates the many-to-many relationships between hosts, ports, and vulnerabilities.

## Container Resource Considerations

The migration process may require additional memory or CPU resources. If you encounter resource limitations:

```bash
# Monitor container resource usage during migration
docker stats api db
```

If needed, allocate more resources to the containers before running the migration.
