#!/usr/bin/env bash
set -euo pipefail

CMD="${1:-}"
if [[ -z "$CMD" ]]; then
  echo "usage: recorder-vm.sh <start|mark|stop|report>" >&2
  exit 2
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
VM_ENV="${SYSARMOR_VM_ENV:-${ENV:-vm-endpoint}}"
ENVDIR="$(cd "$ROOT/environments/$VM_ENV" && pwd)"
RESULTS="$ROOT/.results"
RUN_ID="${RUN_ID:-${SYSARMOR_RECORDER_RUN_ID:-manual}}"
OUT_DIR="$RESULTS/recordings/$RUN_ID"
AGENT_SOCK="${SYSARMOR_AGENT_SOCK:-/run/sysarmor/agent/control.sock}"
AGENT_ID="${SYSARMOR_RECORDER_AGENT_ID:-${SYSARMOR_BENCH_AGENT_ID:-}}"
TENANT_ID="${SYSARMOR_RECORDER_TENANT_ID:-${SYSARMOR_BENCH_TENANT_ID:-}}"
DURATION="${DURATION:-${SYSARMOR_RECORDER_DURATION:-3600}}"
SEMANTIC_INTERVAL="${SYSARMOR_RECORDER_SEMANTIC_INTERVAL:-10}"
LABELS="${SYSARMOR_RECORDER_LABELS:-}"
PHASE="${PHASE:-}"
DETAIL="${DETAIL:-}"

mkdir -p "$OUT_DIR"

json_escape() {
  python3 -c 'import json,sys; print(json.dumps(sys.argv[1])[1:-1])' "$1"
}

mark_local() {
  local phase="$1"
  local detail="${2:-}"
  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '{"ts":"%s","phase":"%s","detail":"%s"}\n' \
    "$ts" "$(json_escape "$phase")" "$(json_escape "$detail")" >> "$OUT_DIR/markers.ndjson"
}

write_scope_labels() {
  python3 - "$LABELS" "$OUT_DIR/scope-labels.json" <<'PY'
import json
import sys

raw, path = sys.argv[1], sys.argv[2]
labels = {}
for item in raw.split(","):
    if "=" not in item:
        continue
    key, value = item.split("=", 1)
    key = key.strip()
    if key:
        labels[key] = value.strip()
with open(path, "w") as f:
    json.dump(labels, f, indent=2, sort_keys=True)
    f.write("\n")
PY
}

start_remote_sampler() {
  cd "$ENVDIR"
  vagrant ssh node-a -c "sudo mkdir -p /run/sysarmor/recorder && sudo tee /run/sysarmor/recorder/recorder-vm.sh >/dev/null <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
DUR=\"\${1:-3600}\"
AGENT_SOCK=\"\${2:-/run/sysarmor/agent/control.sock}\"
AGENT_ID=\"\${3:-}\"
TENANT_ID=\"\${4:-}\"
LABELS=\"\${5:-}\"
SEMANTIC_INTERVAL=\"\${6:-10}\"
STATE_DIR=/run/sysarmor/recorder
RAW_DIR=\"\$STATE_DIR/raw\"
mkdir -p \"\$STATE_DIR\" \"\$RAW_DIR\"
OUT=\"\$STATE_DIR/timeline.csv\"
DONE=\"\$STATE_DIR/done\"
STOP=\"\$STATE_DIR/stop\"
HEALTH_JSON=\"\$STATE_DIR/health.json\"
EVENTS_NDJSON=\"\$STATE_DIR/events.ndjson\"
SIGNALS_NDJSON=\"\$STATE_DIR/signals.ndjson\"
WATCH_PIDS=\"\$STATE_DIR/watch-pids\"
EVENT_WATCH_ERR=\"\$STATE_DIR/event-watch.err\"
SIGNAL_WATCH_ERR=\"\$STATE_DIR/signal-watch.err\"
rm -f \"\$OUT\" \"\$DONE\" \"\$STOP\" \"\$EVENTS_NDJSON\" \"\$SIGNALS_NDJSON\"
rm -f \"\$WATCH_PIDS\" \"\$EVENT_WATCH_ERR\" \"\$SIGNAL_WATCH_ERR\"
rm -rf \"\$RAW_DIR\"
mkdir -p \"\$RAW_DIR\"
WATCH_LIMIT=\"\${SYSARMOR_RECORDER_WATCH_LIMIT:-20000}\"
WATCH_TIMEOUT=\"\$((DUR + 120))s\"
echo 'ts,elapsed_s,agent_cpu_pct,agent_rss_mb,sensor_cpu_pct,sensor_rss_mb,edr_cpu_pct,edr_rss_mb,events_seen,events_captured,events_seen_since_cursor,signals_captured,signals_seen_since_cursor,dropped_events,parse_errors,agent_active,sensor_running,policy_id,policy_version,event_cursor,signal_cursor' > \"\$OUT\"
CLK_TCK=\"\$(getconf CLK_TCK 2>/dev/null || echo 100)\"
num_json() {
  local key=\"\$1\"
  local file=\"\$2\"
  python3 - \"\$key\" \"\$file\" <<'PY' 2>/dev/null || true
import json, sys
key, path = sys.argv[1], sys.argv[2]
try:
    data = json.load(open(path))
except Exception:
    print(0)
    raise SystemExit
cur = data
for part in key.split('.'):
    cur = cur.get(part, {}) if isinstance(cur, dict) else {}
try:
    print(int(cur))
except Exception:
    print(0)
PY
}
str_json() {
  local key=\"\$1\"
  local file=\"\$2\"
  python3 - \"\$key\" \"\$file\" <<'PY' 2>/dev/null || true
import json, sys
key, path = sys.argv[1], sys.argv[2]
try:
    data = json.load(open(path))
except Exception:
    print('')
    raise SystemExit
cur = data
for part in key.split('.'):
    cur = cur.get(part, '') if isinstance(cur, dict) else ''
print(cur if isinstance(cur, str) else '')
PY
}
last_sequence() {
  local file=\"\$1\"
  tail -n 32 \"\$file\" 2>/dev/null | python3 -c '
import json, sys
max_seq = 0
for line in sys.stdin:
    if not line.strip():
        continue
    try:
        data = json.loads(line)
    except Exception:
        continue
    seq = data.get('sequence') or data.get('seq') or 0
    try:
        max_seq = max(max_seq, int(seq))
    except Exception:
        pass
print(max_seq)
' 2>/dev/null || echo 0
}
advance_cursors() {
  next_event_cursor=\"\$(last_sequence \"\$EVENTS_NDJSON\")\"
  next_signal_cursor=\"\$(last_sequence \"\$SIGNALS_NDJSON\")\"
  if [ \"\${next_event_cursor:-0}\" -gt \"\$EVENT_CURSOR\" ]; then EVENT_CURSOR=\"\$next_event_cursor\"; fi
  if [ \"\${next_signal_cursor:-0}\" -gt \"\$SIGNAL_CURSOR\" ]; then SIGNAL_CURSOR=\"\$next_signal_cursor\"; fi
}
line_count() {
  local file=\"\$1\"
  awk 'NF {n++} END {print n+0}' \"\$file\" 2>/dev/null || echo 0
}
identity=\"\$(sysarmorctl --socket \"\$AGENT_SOCK\" --json agent health)\"
AGENT_ID=\"\$(jq -r '.agentId // .agent_id // empty' <<<\"\$identity\")\"
TENANT_ID=\"\$(jq -r '.tenantId // .tenant_id // empty' <<<\"\$identity\")\"
if [ -z \"\$AGENT_ID\" ] || [ -z \"\$TENANT_ID\" ]; then
  echo \"recorder: Agent health did not expose runtime identity: \$identity\" >&2
  exit 1
fi
sysarmorctl --socket \"\$AGENT_SOCK\" --json agent health --agent-id \"\$AGENT_ID\" --tenant-id \"\$TENANT_ID\" >\"\$HEALTH_JSON\"
EVENT_CURSOR=\"\$(num_json streams.eventNewestSequence \"\$HEALTH_JSON\")\"
SIGNAL_CURSOR=\"\$(num_json streams.signalNewestSequence \"\$HEALTH_JSON\")\"
start_watchers() {
  : > \"\$WATCH_PIDS\"
  sysarmorctl --socket \"\$AGENT_SOCK\" --json event watch --after-seq \"\$EVENT_CURSOR\" --limit \"\$WATCH_LIMIT\" --agent-id \"\$AGENT_ID\" --tenant-id \"\$TENANT_ID\" --timeout \"\$WATCH_TIMEOUT\" >>\"\$EVENTS_NDJSON\" 2>\"\$EVENT_WATCH_ERR\" &
  EVENT_WATCH_PID=\"\$!\"
  echo \"\$EVENT_WATCH_PID\" >>\"\$WATCH_PIDS\"
  sysarmorctl --socket \"\$AGENT_SOCK\" --json signal watch --after-seq \"\$SIGNAL_CURSOR\" --limit \"\$WATCH_LIMIT\" --agent-id \"\$AGENT_ID\" --tenant-id \"\$TENANT_ID\" --timeout \"\$WATCH_TIMEOUT\" >>\"\$SIGNALS_NDJSON\" 2>\"\$SIGNAL_WATCH_ERR\" &
  SIGNAL_WATCH_PID=\"\$!\"
  echo \"\$SIGNAL_WATCH_PID\" >>\"\$WATCH_PIDS\"
}
ensure_watchers() {
  if kill -0 \"\$EVENT_WATCH_PID\" 2>/dev/null && kill -0 \"\$SIGNAL_WATCH_PID\" 2>/dev/null; then
    return
  fi
  kill \"\$EVENT_WATCH_PID\" \"\$SIGNAL_WATCH_PID\" 2>/dev/null || true
  wait \"\$EVENT_WATCH_PID\" 2>/dev/null || true
  wait \"\$SIGNAL_WATCH_PID\" 2>/dev/null || true
  advance_cursors
  sysarmorctl --socket \"\$AGENT_SOCK\" --json agent health --agent-id \"\$AGENT_ID\" --tenant-id \"\$TENANT_ID\" >\"\$HEALTH_JSON\" 2>/dev/null || return 0
  runtime_event_cursor=\"\$(num_json streams.eventNewestSequence \"\$HEALTH_JSON\")\"
  runtime_signal_cursor=\"\$(num_json streams.signalNewestSequence \"\$HEALTH_JSON\")\"
  if [ \"\$runtime_event_cursor\" -lt \"\$EVENT_CURSOR\" ]; then EVENT_CURSOR=0; fi
  if [ \"\$runtime_signal_cursor\" -lt \"\$SIGNAL_CURSOR\" ]; then SIGNAL_CURSOR=0; fi
  start_watchers
}
stop_watchers() {
  [ -f \"\$WATCH_PIDS\" ] || return 0
  while read -r pid; do
    [ -n \"\$pid\" ] || continue
    kill \"\$pid\" 2>/dev/null || true
  done <\"\$WATCH_PIDS\"
  while read -r pid; do
    [ -n \"\$pid\" ] || continue
    wait \"\$pid\" 2>/dev/null || true
  done <\"\$WATCH_PIDS\"
}
start_watchers
pid_list() {
  local names=\"\$1\"
  for name in \$names; do
    pidof \"\$name\" 2>/dev/null || true
  done | tr ' ' '\\n' | awk 'NF && !seen[\$1]++'
}
proc_cpu_jiffies() {
  local pids=\"\$1\"
  local total=0
  local pid stat rest utime stime
  for pid in \$pids; do
    [ -r \"/proc/\$pid/stat\" ] || continue
    stat=\"\$(cat \"/proc/\$pid/stat\" 2>/dev/null || true)\"
    rest=\"\${stat##*) }\"
    utime=\"\$(echo \"\$rest\" | awk '{print \$12}')\"
    stime=\"\$(echo \"\$rest\" | awk '{print \$13}')\"
    total=\$((total + \${utime:-0} + \${stime:-0}))
  done
  echo \"\$total\"
}
proc_rss_mb() {
  local pids=\"\$1\"
  local total=0
  local pid rss
  for pid in \$pids; do
    [ -r \"/proc/\$pid/status\" ] || continue
    rss=\"\$(awk '/VmRSS:/ {print \$2}' \"/proc/\$pid/status\" 2>/dev/null || echo 0)\"
    total=\$((total + \${rss:-0}))
  done
  awk -v kb=\"\$total\" 'BEGIN { printf \"%.2f\", kb / 1024 }'
}
cpu_pct() {
  local prev=\"\$1\"
  local curr=\"\$2\"
  local interval=\"\$3\"
  if [ \"\$prev\" -le 0 ] || [ \"\$curr\" -lt \"\$prev\" ] || [ \"\$interval\" -le 0 ]; then
    echo \"0.00\"
    return
  fi
  awk -v delta=\$((curr - prev)) -v hz=\"\$CLK_TCK\" -v sec=\"\$interval\" 'BEGIN { printf \"%.2f\", (delta / hz) / sec * 100 }'
}
elapsed=0
prev_agent_jiffies=0
prev_sensor_jiffies=0
prev_sample_epoch=0
events=0
events_captured=0
signals_captured=0
dropped=0
parse_errors=0
policy_id=\"\"
policy_version=\"\"
while [ \"\$elapsed\" -le \"\$DUR\" ]; do
  [ -f \"\$STOP\" ] && break
  ensure_watchers
  ts=\"\$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
  sample_epoch=\"\$(date +%s)\"
  agent_pids=\"\$(pid_list 'sysarmor-agent')\"
  sensor_pids=\"\$(pid_list 'tetragon sysarmor-sensor')\"
  agent_jiffies=\"\$(proc_cpu_jiffies \"\$agent_pids\")\"
  sensor_jiffies=\"\$(proc_cpu_jiffies \"\$sensor_pids\")\"
  interval=\$((sample_epoch - prev_sample_epoch))
  agent_cpu=\"\$(cpu_pct \"\$prev_agent_jiffies\" \"\$agent_jiffies\" \"\$interval\")\"
  sensor_cpu=\"\$(cpu_pct \"\$prev_sensor_jiffies\" \"\$sensor_jiffies\" \"\$interval\")\"
  edr_cpu=\"\$(awk -v a=\"\$agent_cpu\" -v s=\"\$sensor_cpu\" 'BEGIN { printf \"%.2f\", a + s }')\"
  agent_rss=\"\$(proc_rss_mb \"\$agent_pids\")\"
  sensor_rss=\"\$(proc_rss_mb \"\$sensor_pids\")\"
  edr_rss=\"\$(awk -v a=\"\$agent_rss\" -v s=\"\$sensor_rss\" 'BEGIN { printf \"%.2f\", a + s }')\"
  prev_agent_jiffies=\"\$agent_jiffies\"
  prev_sensor_jiffies=\"\$sensor_jiffies\"
  prev_sample_epoch=\"\$sample_epoch\"
  agent_active=\"\$(systemctl is-active sysarmor-agent 2>/dev/null || true)\"
  if pidof tetragon >/dev/null 2>&1 || pidof sysarmor-sensor >/dev/null 2>&1; then sensor_running=1; else sensor_running=0; fi
  if [ \"\$elapsed\" -eq 0 ] || [ \$((elapsed % SEMANTIC_INTERVAL)) -eq 0 ]; then
    sample_tag=\"\$(printf '%06d' \"\$elapsed\")\"
    sysarmorctl --socket \"\$AGENT_SOCK\" --json agent health --agent-id \"\$AGENT_ID\" --tenant-id \"\$TENANT_ID\" >\"\$HEALTH_JSON\" 2>/dev/null || true
    cp \"\$HEALTH_JSON\" \"\$RAW_DIR/\$sample_tag.health.json\" 2>/dev/null || true
    events=\"\$(num_json sensor.eventsSeen \"\$HEALTH_JSON\")\"
    dropped=\"\$(num_json sensor.eventsDropped \"\$HEALTH_JSON\")\"
    parse_errors=\"\$(num_json sensor.parseErrors \"\$HEALTH_JSON\")\"
    policy_id=\"\$(str_json policyId \"\$HEALTH_JSON\")\"
    policy_version=\"\$(str_json policyVersion \"\$HEALTH_JSON\")\"
    events_captured=\"\$(line_count \"\$EVENTS_NDJSON\")\"
    signals_captured=\"\$(line_count \"\$SIGNALS_NDJSON\")\"
  fi
  advance_cursors
  echo \"\$ts,\$elapsed,\$agent_cpu,\$agent_rss,\$sensor_cpu,\$sensor_rss,\$edr_cpu,\$edr_rss,\$events,\$events_captured,\$events_captured,\$signals_captured,\$signals_captured,\$dropped,\$parse_errors,\$agent_active,\$sensor_running,\$policy_id,\$policy_version,\$EVENT_CURSOR,\$SIGNAL_CURSOR\" >> \"\$OUT\"
  [ \"\$elapsed\" -ge \"\$DUR\" ] && break
  sleep 1
  elapsed=\$((elapsed + 1))
done
stop_watchers
touch \"\$DONE\"
EOS
sudo chmod +x /run/sysarmor/recorder/recorder-vm.sh
sudo sh -c 'nohup bash /run/sysarmor/recorder/recorder-vm.sh "\$1" "\$2" "\$3" "\$4" "\$5" "\$6" >/run/sysarmor/recorder/recorder.log 2>&1 &' sh '$DURATION' '$AGENT_SOCK' '$AGENT_ID' '$TENANT_ID' '$LABELS' '$SEMANTIC_INTERVAL'
" >/dev/null
}

stop_remote_sampler() {
  cd "$ENVDIR"
  vagrant ssh node-a -c "sudo mkdir -p /run/sysarmor/recorder && sudo touch /run/sysarmor/recorder/stop" >/dev/null || true
  vagrant ssh node-a -c "deadline=\$((SECONDS + 90)); until sudo test -f /run/sysarmor/recorder/done; do if (( SECONDS >= deadline )); then sudo cat /run/sysarmor/recorder/recorder.log 2>/dev/null || true; exit 1; fi; sleep 1; done; sudo cat /run/sysarmor/recorder/timeline.csv" \
    > "$OUT_DIR/timeline.csv" 2>"$OUT_DIR/timeline.err"
  vagrant ssh node-a -c "sudo cat /run/sysarmor/recorder/recorder.log 2>/dev/null || true" \
    > "$OUT_DIR/recorder.log" 2>/dev/null || true
  vagrant ssh node-a -c "sudo cat /run/sysarmor/recorder/events.ndjson 2>/dev/null || true" \
    > "$OUT_DIR/events.ndjson" 2>/dev/null || true
  vagrant ssh node-a -c "sudo cat /run/sysarmor/recorder/signals.ndjson 2>/dev/null || true" \
    > "$OUT_DIR/signals.ndjson" 2>/dev/null || true
  vagrant ssh node-a -c "sudo cat /run/sysarmor/recorder/event-watch.err 2>/dev/null || true" \
    > "$OUT_DIR/event-watch.err" 2>/dev/null || true
  vagrant ssh node-a -c "sudo cat /run/sysarmor/recorder/signal-watch.err 2>/dev/null || true" \
    > "$OUT_DIR/signal-watch.err" 2>/dev/null || true
  mkdir -p "$OUT_DIR/raw"
  vagrant ssh node-a -c "cd /run/sysarmor/recorder && sudo tar -cf - raw 2>/dev/null || true" \
    > "$OUT_DIR/raw.tar" 2>/dev/null || true
  if [[ -s "$OUT_DIR/raw.tar" ]]; then
    tar -xf "$OUT_DIR/raw.tar" -C "$OUT_DIR" 2>/dev/null || true
  fi
}

case "$CMD" in
  start)
    : > "$OUT_DIR/markers.ndjson"
    mark_local "recorder_start" ""
    write_scope_labels
    start_remote_sampler
    echo "[recorder-vm] started RUN_ID=$RUN_ID OUT_DIR=$OUT_DIR"
    ;;
  mark)
    if [[ -z "$PHASE" ]]; then
      echo "[recorder-vm][ERROR] PHASE is required for mark" >&2
      exit 2
    fi
    mark_local "$PHASE" "$DETAIL"
    echo "[recorder-vm] mark RUN_ID=$RUN_ID PHASE=$PHASE"
    ;;
  stop)
    mark_local "recorder_stop" ""
    stop_remote_sampler
    echo "[recorder-vm] stopped RUN_ID=$RUN_ID OUT_DIR=$OUT_DIR"
    ;;
  report)
    python3 "$ROOT/shared/reports/lifecycle_report.py" "$OUT_DIR"
    echo "[recorder-vm] report written to $OUT_DIR/summary.json"
    ;;
  *)
    echo "usage: recorder-vm.sh <start|mark|stop|report>" >&2
    exit 2
    ;;
esac
