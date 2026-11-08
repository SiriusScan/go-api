#!/usr/bin/env bash
# New disposable database only. Does not use or migrate an installed database.
set -euo pipefail
cd "$(dirname "$0")/.."
fixture=""
cleanup() { if [[ -n "$fixture" ]]; then docker rm -f "$fixture" >/dev/null; fi; }
trap cleanup EXIT
fixture=$(docker run -d --pull=never --memory=384m --cpus=1 --pids-limit=128 \
  --publish 127.0.0.1::5432 --tmpfs /var/lib/postgresql/data:rw,size=192m \
  -e POSTGRES_PASSWORD=integration-fixture -e POSTGRES_DB=sdk_test postgres:16)
port=$(docker port "$fixture" 5432/tcp | sed 's/.*://')
ready=false
for _ in {1..40}; do
  if docker exec "$fixture" pg_isready -U postgres -d sdk_test >/dev/null 2>&1; then ready=true; break; fi
  sleep 1
done
if [[ "$ready" != true ]]; then echo 'Disposable PostgreSQL did not become ready.' >&2; exit 1; fi
export GOWORK=off GOMAXPROCS="${GOMAXPROCS:-2}"
export DB_HOST=127.0.0.1 DB_PORT=1 SIRIUS_SCHEMA_AUTO_MIGRATE=false SIRIUS_SCHEMA_FORCE_RESET=false
DSN="host=127.0.0.1 port=$port user=postgres password=integration-fixture dbname=sdk_test sslmode=disable"
export SIRIUS_AGGREGATION_TEST_DSN="$DSN" SIRIUS_FINDING_TEST_DSN="$DSN"
export SIRIUS_PORT_TEST_DSN="$DSN" SIRIUS_REPORT_TEST_DSN="$DSN"
go test -timeout=180s -race -short -count=3 -p=1 ./sirius/host ./sirius/migrate
