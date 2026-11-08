#!/usr/bin/env bash
# Run only against a newly created fixture; never accepts an application address.
set -euo pipefail
cd "$(dirname "$0")/.."
fixture=""
cleanup() { if [[ -n "$fixture" ]]; then docker rm -f "$fixture" >/dev/null; fi; }
trap cleanup EXIT
fixture=$(docker run -d --pull=never --memory=128m --cpus=0.5 --pids-limit=128 \
  --publish 127.0.0.1::6379 --tmpfs /data:rw,size=64m \
  valkey/valkey:8-alpine valkey-server --save '' --appendonly no)
port=$(docker port "$fixture" 6379/tcp | sed 's/.*://')
ready=false
for _ in {1..30}; do
  if docker exec "$fixture" valkey-cli ping 2>/dev/null | grep -q '^PONG'; then ready=true; break; fi
  sleep 1
done
if [[ "$ready" != true ]]; then echo 'Disposable Valkey did not become ready.' >&2; exit 1; fi
export GOWORK=off GOMAXPROCS="${GOMAXPROCS:-2}"
export DB_HOST=127.0.0.1 DB_PORT=1
export SIRIUS_TEST_VALKEY_ADDR="127.0.0.1:$port"
export SIRIUS_TEST_ATOMIC_ISOLATED_ADDR="127.0.0.1:$port"
go test -timeout=120s -race -short -count=20 -p=1 ./sirius/store
remaining=$(docker exec "$fixture" valkey-cli dbsize)
if [[ "$remaining" != 0 ]]; then echo "Fixture leaked $remaining keys" >&2; exit 1; fi
