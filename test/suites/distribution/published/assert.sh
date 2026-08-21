#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$HERE/config.sh"
# shellcheck source=/dev/null
source "$HERE/scenarios.sh"

fail() {
  echo "[release-assert][ERROR] $*" >&2
  return 1
}

query_events() {
  docker exec "$1" sysarmorctl --json event watch --snapshot --include-recent \
    --behavior process.exec --limit 1000
}

query_signals_with_events() {
  docker exec "$1" sysarmorctl --json signal watch --snapshot --include-recent \
    --include-events --rule-id "$2" --limit 1000
}

capture_signals() {
  local container="$1" output="$2" count expected=0 hits=0 scenario
  docker exec "$container" sysarmorctl --json signal watch --snapshot --include-recent \
    --include-events --limit 1001 >"$output"
  count="$(wc -l <"$output")"
  (( count < 1001 )) || fail "Signal 快照达到 1001 条，结果可能被截断"
  while IFS= read -r scenario; do
    expected=$((expected + 1))
    [[ ! -s "$(dirname "$output")/$scenario.jsonl" ]] || hits=$((hits + 1))
  done < <(release_scenarios)
  summarize_signals "$output" "$(dirname "$output")/signal-summary.json" "$expected" "$hits"
}

summarize_signals() {
  local input="$1" output="$2" expected="$3" hits="$4"
  jq -s --argjson expected "$expected" --argjson hits "$hits" '
    (map(select(.signalFrame.signal.id != null)) | unique_by(.signalFrame.signal.id)) as $signals |
    ($signals | map(select(any(.eventFrames[]?; (.event | tostring | contains("sysarmor-")))))) as $tp |
    {
      signal_total: ($signals | length), true_positives: ($tp | length),
      false_positives: (($signals | length) - ($tp | length)),
      precision: (if ($signals | length) == 0 then 1 else ($tp | length) / ($signals | length) end),
      expected_scenarios: $expected, detected_scenarios: $hits,
      recall: (if $expected == 0 then 1 else $hits / $expected end),
      by_rule: ($signals | group_by(.signalFrame.signal.ruleId) |
        map({rule_id: .[0].signalFrame.signal.ruleId, count: length}))
    }
  ' "$input" >"$output"
}

assert_ready() {
  local container="$1" output="$2" deadline=$((SECONDS + HEALTH_TIMEOUT))
  until docker exec "$container" sysarmorctl --json agent health >"$output" 2>"$output.err" &&
    jq -e '
      .status == "ok" and
      .scope.type == "namespace" and .scope.selector == "self" and
      .capability.backend == "tetragon" and
      .sensor.running == true and .sensor.policyLoaded == true
    ' "$output" >/dev/null; do
    if (( SECONDS >= deadline )); then
      docker logs "$container" >&2 2>/dev/null || true
      fail "Agent 未在 ${HEALTH_TIMEOUT} 秒内就绪: $container"
      return
    fi
    sleep 1
  done
}

signal_matches_scenario() {
  local input="$1" marker="$2" rule="$3" severity="$4" stage="$5" behaviors="$6" ports="$7"
  jq -s -e --arg marker "$marker" --arg rule "$rule" --arg severity "$severity" \
    --arg stage "$stage" --arg behaviors "$behaviors" --arg ports "$ports" '
      ($behaviors | split(" ") | map(select(length > 0))) as $requiredBehaviors |
      ($ports | split(" ") | map(select(length > 0))) as $requiredPorts |
      any(.[];
        . as $record |
        .signalFrame.signal.ruleId == $rule and
        .signalFrame.signal.severity == $severity and
        .signalFrame.signal.stage == $stage and
        ((.missingEventRefs // []) | length) == 0 and
        all($requiredBehaviors[];
          . as $behavior | any($record.eventFrames[]?; .event.behavior == $behavior)
        ) and
        all($requiredPorts[];
          . as $port | any($record.eventFrames[]?;
            ((.event.object.socketAddr // "") | endswith(":" + $port))
          )
        ) and
        any(.eventFrames[]?;
          (
            ((.event.subjectProc.argv // []) | join(" ")) + " " +
            (.event.object.filePath // "") + " " +
            (.event.object.socketAddr // "")
          ) | contains($marker)
        )
      )
    ' "$input" >/dev/null
}

assert_detected() {
  local container="$1" scenario="$2" marker="$3" output="$4"
  local rule severity stage behaviors ports deadline=$((SECONDS + DETECTION_TIMEOUT))
  rule="$(scenario_rule "$scenario")" || fail "未知场景: $scenario"
  severity="$(scenario_severity "$scenario")"
  stage="$(scenario_stage "$scenario")"
  behaviors="$(scenario_behaviors "$scenario")"
  ports="$(scenario_ports "$scenario")"
  until query_signals_with_events "$container" "$rule" >"$output" 2>"$output.err" &&
    signal_matches_scenario "$output" "$marker" "$rule" "$severity" "$stage" "$behaviors" "$ports"; do
    if (( SECONDS >= deadline )); then
      cat "$output" >&2 2>/dev/null || true
      fail "未观察到场景 $scenario 的完整 Event/Signal 证据: $marker"
      return
    fi
    sleep 1
  done
}

assert_absent() {
  local container="$1" marker="$2" output="$3" deadline=$((SECONDS + ISOLATION_TIMEOUT))
  while :; do
    query_events "$container" >"$output" 2>"$output.err"
    if ! jq -s -e --arg marker "$marker" '
      all(.[]; ((.event.subjectProc.argv // []) | join(" ") | contains($marker)) | not)
    ' "$output" >/dev/null; then
      fail "namespace/self 采集到了外部 marker: $marker"
      return
    fi
    (( SECONDS >= deadline )) && return 0
    sleep 0.25
  done
}

case "${1:-}" in
  ready) [[ $# -eq 3 ]] || fail "usage: assert.sh ready CONTAINER OUTPUT"; assert_ready "$2" "$3" ;;
  detected) [[ $# -eq 5 ]] || fail "usage: assert.sh detected CONTAINER SCENARIO MARKER OUTPUT"; assert_detected "$2" "$3" "$4" "$5" ;;
  absent) [[ $# -eq 4 ]] || fail "usage: assert.sh absent CONTAINER MARKER OUTPUT"; assert_absent "$2" "$3" "$4" ;;
  capture-signals) [[ $# -eq 3 ]] || fail "usage: assert.sh capture-signals CONTAINER OUTPUT"; capture_signals "$2" "$3" ;;
  summarize-signals) [[ $# -eq 5 ]] || fail "usage: assert.sh summarize-signals INPUT OUTPUT EXPECTED HITS"; summarize_signals "$2" "$3" "$4" "$5" ;;
  *) fail "usage: assert.sh ready|detected|absent|capture-signals|summarize-signals ..." ;;
esac
