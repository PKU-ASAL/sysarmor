#!/usr/bin/env bash
set -euo pipefail

name="sysarmor-opensearch-lifecycle-$$"
port="${SYSARMOR_OPENSEARCH_TEST_PORT:-39200}"
base="http://127.0.0.1:${port}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"

cleanup() {
  docker rm -f "${name}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker run -d --name "${name}" -p "${port}:9200" \
  -e discovery.type=single-node -e DISABLE_SECURITY_PLUGIN=true \
  -e OPENSEARCH_JAVA_OPTS='-Xms512m -Xmx512m' sysarmor-opensearch:latest >/dev/null

deadline=$((SECONDS + 120))
until curl -fsS "${base}/_cluster/health" >/dev/null 2>&1; do
  if (( SECONDS >= deadline )); then
    echo "opensearch test instance did not become ready" >&2
    exit 1
  fi
  sleep 2
done

curl -fsS -X PUT -H 'Content-Type: application/json' \
  --data-binary "@${root}/deployments/opensearch/mappings/signals-v1.json" \
  "${base}/sysarmor-signals-v1" >/dev/null
curl -fsS -X POST -H 'Content-Type: application/json' -d '{"actions":[
  {"add":{"index":"sysarmor-signals-v1","alias":"sysarmor-signals-read"}},
  {"add":{"index":"sysarmor-signals-v1","alias":"sysarmor-signals-write","is_write_index":true}}
]}' "${base}/_aliases" >/dev/null
curl -fsS -X PUT -H 'Content-Type: application/json' \
  -d '{"id":"legacy-rule","tenant_id":"default","terminal":false}' \
  "${base}/sysarmor-signals-write/_doc/legacy-rule" >/dev/null
curl -fsS -X PUT -H 'Content-Type: application/json' \
  -d '{"id":"legacy-health","tenant_id":"default","terminal":true,"labels":{"signal_class":"agent-health"}}' \
  "${base}/sysarmor-signals-write/_doc/legacy-health?refresh=true" >/dev/null

SYSARMOR_OPENSEARCH_URL="${base}" \
SYSARMOR_OPENSEARCH_MAPPING_DIR="${root}/deployments/opensearch/mappings" \
  bash "${root}/deployments/opensearch/init.sh"

aliases="$(curl -fsS "${base}/_alias/sysarmor-signals-read,sysarmor-signals-write")"
[[ "${aliases}" == *'sysarmor-signals-v2'* ]]
[[ "${aliases}" != *'sysarmor-signals-v1'* ]]
curl -fsS "${base}/sysarmor-signals-read/_doc/legacy-rule" | \
  grep -q '"stage":"SIGNAL_STAGE_CANDIDATE"'
curl -fsS "${base}/sysarmor-signals-read/_doc/legacy-rule" | \
  grep -q '"detectorKind":"DETECTOR_KIND_RULE"'
curl -fsS "${base}/sysarmor-signals-read/_doc/legacy-rule" | \
  grep -q '"where":"SIGNAL_WHERE_ENDPOINT"'
curl -fsS "${base}/sysarmor-signals-read/_doc/legacy-health" | \
  grep -q '"stage":"SIGNAL_STAGE_CONCLUSION"'
curl -fsS "${base}/sysarmor-signals-read/_doc/legacy-health" | \
  grep -q '"detectorKind":"DETECTOR_KIND_SYSTEM"'
curl -fsS "${base}/sysarmor-signals-read/_doc/legacy-health" | \
  grep -q '"where":"SIGNAL_WHERE_ENDPOINT"'
if curl -fsS "${base}/sysarmor-signals-read/_doc/legacy-rule" | grep -q '"terminal"'; then
  echo "migrated signal still contains terminal" >&2
  exit 1
fi
curl -fsS "${base}/sysarmor-signals-v1/_count" | grep -q '"count":2'
SYSARMOR_OPENSEARCH_URL="${base}" \
SYSARMOR_OPENSEARCH_MAPPING_DIR="${root}/deployments/opensearch/mappings" \
  bash "${root}/deployments/opensearch/init.sh"

curl -fsS -X PUT -H 'Content-Type: application/json' \
  -d '{"id":"lifecycle-v1","tenant_id":"default","@timestamp":"2026-07-12T00:00:00Z"}' \
  "${base}/sysarmor-events-write/_doc/lifecycle-v1?refresh=true" >/dev/null
curl -fsS "${base}/sysarmor-events-read/_doc/lifecycle-v1" | grep -q 'lifecycle-v1'

curl -fsS -X PUT -H 'Content-Type: application/json' \
  --data-binary "@${root}/deployments/opensearch/mappings/events-v1.json" \
  "${base}/sysarmor-events-v2" >/dev/null
curl -fsS -X POST -H 'Content-Type: application/json' \
  -d '{"source":{"index":"sysarmor-events-v1"},"dest":{"index":"sysarmor-events-v2"}}' \
  "${base}/_reindex?wait_for_completion=true&refresh=true" >/dev/null
curl -fsS -X POST -H 'Content-Type: application/json' -d '{"actions":[
  {"remove":{"index":"sysarmor-events-v1","alias":"sysarmor-events-read"}},
  {"remove":{"index":"sysarmor-events-v1","alias":"sysarmor-events-write"}},
  {"add":{"index":"sysarmor-events-v2","alias":"sysarmor-events-read"}},
  {"add":{"index":"sysarmor-events-v2","alias":"sysarmor-events-write","is_write_index":true}}
]}' "${base}/_aliases" >/dev/null
curl -fsS "${base}/sysarmor-events-read/_doc/lifecycle-v1" | grep -q 'lifecycle-v1'

curl -fsS -X PUT -H 'Content-Type: application/json' \
  -d '{"id":"lifecycle-v2","tenant_id":"default","@timestamp":"2026-07-12T00:01:00Z"}' \
  "${base}/sysarmor-events-write/_doc/lifecycle-v2?refresh=true" >/dev/null
curl -fsS "${base}/sysarmor-events-v2/_doc/lifecycle-v2" | grep -q 'lifecycle-v2'

curl -fsS -X POST -H 'Content-Type: application/json' -d '{"actions":[
  {"remove":{"index":"sysarmor-events-v2","alias":"sysarmor-events-read"}},
  {"remove":{"index":"sysarmor-events-v2","alias":"sysarmor-events-write"}},
  {"add":{"index":"sysarmor-events-v1","alias":"sysarmor-events-read"}},
  {"add":{"index":"sysarmor-events-v1","alias":"sysarmor-events-write","is_write_index":true}}
]}' "${base}/_aliases" >/dev/null
curl -fsS "${base}/sysarmor-events-read/_doc/lifecycle-v1" | grep -q 'lifecycle-v1'
if curl -fsS "${base}/sysarmor-events-read/_doc/lifecycle-v2" >/dev/null 2>&1; then
  echo "rollback still exposes v2-only document" >&2
  exit 1
fi

echo "opensearch alias lifecycle passed"
