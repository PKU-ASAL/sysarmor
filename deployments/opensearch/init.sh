#!/usr/bin/env bash
set -euo pipefail

base_url="${SYSARMOR_OPENSEARCH_URL:-http://opensearch:9200}"
mapping_dir="${SYSARMOR_OPENSEARCH_MAPPING_DIR:-/opt/sysarmor/opensearch/mappings}"
timeout="${SYSARMOR_OPENSEARCH_INIT_TIMEOUT_SECONDS:-120}"
curl_args=(
  -fsS
  --connect-timeout 5
  --max-time 20
  --retry 5
  --retry-delay 2
  --retry-all-errors
)
if [[ -n "${SYSARMOR_OPENSEARCH_USERNAME:-}" ]]; then
  curl_args+=(-u "${SYSARMOR_OPENSEARCH_USERNAME}:${SYSARMOR_OPENSEARCH_PASSWORD:-}")
fi

deadline=$((SECONDS + timeout))
until curl "${curl_args[@]}" "${base_url}/_cluster/health" >/dev/null 2>&1; do
  if (( SECONDS >= deadline )); then
    echo "opensearch initialization timed out" >&2
    exit 1
  fi
  sleep 2
done

exists() {
  curl "${curl_args[@]}" -o /dev/null -w '%{http_code}' "${base_url}/$1" 2>/dev/null | grep -Eq '^(200|201)$'
}

add_alias() {
  local physical="$1" alias="$2" action
  action="{\"actions\":[{\"add\":{\"index\":\"${physical}\",\"alias\":\"${alias}\""
  if [[ "${alias}" == *-write ]]; then
    action+=',"is_write_index":true'
  fi
  action+='}}]}'
  curl "${curl_args[@]}" -X POST -H 'Content-Type: application/json' \
    --data-binary "${action}" "${base_url}/_aliases" >/dev/null
}

alias_points_to() {
  local alias="$1" physical="$2" response
  response="$(curl "${curl_args[@]}" "${base_url}/_alias/${alias}")"
  [[ "${response}" == *"\"${physical}\""* ]]
}

for kind in events incidents evidence; do
  physical="sysarmor-${kind}-v1"
  read_alias="sysarmor-${kind}-read"
  write_alias="sysarmor-${kind}-write"

  if ! exists "${physical}"; then
    curl "${curl_args[@]}" -X PUT -H 'Content-Type: application/json' \
      --data-binary "@${mapping_dir}/${kind}-v1.json" "${base_url}/${physical}" >/dev/null
  fi

  for alias in "${read_alias}" "${write_alias}"; do
    if exists "_alias/${alias}"; then
      response="$(curl "${curl_args[@]}" "${base_url}/_alias/${alias}")"
      if [[ "${response}" != *"\"${physical}\""* ]]; then
        echo "alias ${alias} does not point to ${physical}" >&2
        exit 1
      fi
      continue
    fi
    add_alias "${physical}" "${alias}"
  done
done

signals_v1="sysarmor-signals-v1"
signals_v2="sysarmor-signals-v2"
signals_read="sysarmor-signals-read"
signals_write="sysarmor-signals-write"

read_on_v2=false
write_on_v2=false
if exists "_alias/${signals_read}" && alias_points_to "${signals_read}" "${signals_v2}"; then
  read_on_v2=true
fi
if exists "_alias/${signals_write}" && alias_points_to "${signals_write}" "${signals_v2}"; then
  write_on_v2=true
fi
if [[ "${read_on_v2}" == true || "${write_on_v2}" == true ]]; then
  if [[ "${read_on_v2}" != true || "${write_on_v2}" != true ]]; then
    echo "signal aliases are split across schema versions" >&2
    exit 1
  fi
elif exists "_alias/${signals_read}" && ! alias_points_to "${signals_read}" "${signals_v1}"; then
  echo "alias ${signals_read} does not point to ${signals_v1}" >&2
  exit 1
elif exists "_alias/${signals_write}" && ! alias_points_to "${signals_write}" "${signals_v1}"; then
  echo "alias ${signals_write} does not point to ${signals_v1}" >&2
  exit 1
fi

if [[ "${read_on_v2}" != true ]]; then
  if ! exists "${signals_v2}"; then
    curl "${curl_args[@]}" -X PUT -H 'Content-Type: application/json' \
      --data-binary "@${mapping_dir}/signals-v2.json" "${base_url}/${signals_v2}" >/dev/null
  fi

  if exists "${signals_v1}"; then
    migration='{"source":{"index":"sysarmor-signals-v1"},"dest":{"index":"sysarmor-signals-v2"},"script":{"lang":"painless","source":"ctx._source.stage = ctx._source.containsKey(\u0027terminal\u0027) && ctx._source.terminal == true ? \u0027SIGNAL_STAGE_CONCLUSION\u0027 : \u0027SIGNAL_STAGE_CANDIDATE\u0027; ctx._source.remove(\u0027terminal\u0027); ctx._source.detectorKind = ctx._source.containsKey(\u0027labels\u0027) && ctx._source.labels instanceof Map && ctx._source.labels.signal_class == \u0027agent-health\u0027 ? \u0027DETECTOR_KIND_SYSTEM\u0027 : \u0027DETECTOR_KIND_RULE\u0027; ctx._source.where = \u0027SIGNAL_WHERE_ENDPOINT\u0027"}}'
    response="$(curl "${curl_args[@]}" -X POST -H 'Content-Type: application/json' \
      --data-binary "${migration}" "${base_url}/_reindex?wait_for_completion=true&refresh=true")"
    if [[ "${response}" != *'"timed_out":false'* || "${response}" != *'"failures":[]'* ]]; then
      echo "signal migration failed: ${response}" >&2
      exit 1
    fi
    source_count="$(curl "${curl_args[@]}" "${base_url}/${signals_v1}/_count" | sed -n 's/.*"count":\([0-9][0-9]*\).*/\1/p')"
    destination_count="$(curl "${curl_args[@]}" "${base_url}/${signals_v2}/_count" | sed -n 's/.*"count":\([0-9][0-9]*\).*/\1/p')"
    if [[ -z "${source_count}" || "${source_count}" != "${destination_count}" ]]; then
      echo "signal migration count mismatch: source=${source_count:-unknown} destination=${destination_count:-unknown}" >&2
      exit 1
    fi
  fi

  actions='{"actions":['
  separator=''
  for alias in "${signals_read}" "${signals_write}"; do
    if exists "_alias/${alias}"; then
      actions+="${separator}{\"remove\":{\"index\":\"${signals_v1}\",\"alias\":\"${alias}\"}}"
      separator=','
    fi
  done
  actions+="${separator}{\"add\":{\"index\":\"${signals_v2}\",\"alias\":\"${signals_read}\"}}"
  actions+=",{\"add\":{\"index\":\"${signals_v2}\",\"alias\":\"${signals_write}\",\"is_write_index\":true}}]}"
  curl "${curl_args[@]}" -X POST -H 'Content-Type: application/json' \
    --data-binary "${actions}" "${base_url}/_aliases" >/dev/null
fi

echo "opensearch indices and aliases are ready"
