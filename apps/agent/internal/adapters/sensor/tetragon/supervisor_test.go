package tetragon

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestProcessSupervisorDrainsStdoutBeforeExit(t *testing.T) {
	sh := requireShell(t)
	supervisor := &ProcessSupervisor{}
	stdout, err := supervisor.StartWithStdout(context.Background(), ProcessSpec{
		Name: "tail-output",
		Path: sh,
		Args: []string{"-c", "i=0; while [ $i -lt 20000 ]; do printf 'event-%s\\n' \"$i\"; i=$((i+1)); done; printf 'final-dropped-events\\n'"},
	})
	if err != nil {
		t.Fatalf("StartWithStdout() error = %v", err)
	}
	data, err := io.ReadAll(stdout)
	if err != nil {
		t.Fatalf("ReadAll(stdout) error = %v", err)
	}
	if got := bytes.Count(data, []byte{'\n'}); got != 20001 {
		t.Fatalf("stdout lines = %d, want 20001", got)
	}
	if !bytes.HasSuffix(data, []byte("final-dropped-events\n")) {
		t.Fatalf("stdout missing final dropped-events record")
	}
}

func TestProcessSupervisorDrainsStdoutForSlowConsumer(t *testing.T) {
	sh := requireShell(t)
	supervisor := &ProcessSupervisor{}
	stdout, err := supervisor.StartWithStdout(context.Background(), ProcessSpec{
		Name: "slow-tail-output",
		Path: sh,
		Args: []string{"-c", "i=0; while [ $i -lt 100 ]; do printf 'event-%s\\n' \"$i\"; i=$((i+1)); done; printf 'final-dropped-events\\n'"},
	})
	if err != nil {
		t.Fatalf("StartWithStdout() error = %v", err)
	}
	time.Sleep(250 * time.Millisecond)
	data, err := io.ReadAll(stdout)
	if err != nil {
		t.Fatalf("ReadAll(stdout) error = %v", err)
	}
	if got := bytes.Count(data, []byte{'\n'}); got != 101 {
		t.Fatalf("stdout lines = %d, want 101", got)
	}
	if !bytes.HasSuffix(data, []byte("final-dropped-events\n")) {
		t.Fatal("stdout missing final dropped-events record")
	}
}

func TestProcessSupervisorCancellationClosesStdout(t *testing.T) {
	sh := requireShell(t)
	ctx, cancel := context.WithCancel(context.Background())
	supervisor := &ProcessSupervisor{}
	stdout, err := supervisor.StartWithStdout(ctx, ProcessSpec{
		Name: "cancel-output",
		Path: sh,
		Args: []string{"-c", "printf 'ready\\n'; sleep 30"},
	})
	if err != nil {
		t.Fatalf("StartWithStdout() error = %v", err)
	}
	ready := make([]byte, len("ready\n"))
	if _, err := io.ReadFull(stdout, ready); err != nil {
		t.Fatalf("ReadFull(stdout) error = %v", err)
	}
	cancel()
	done := make(chan error, 1)
	go func() {
		_, err := io.ReadAll(stdout)
		done <- err
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stdout remained open after cancellation")
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), time.Second)
	defer stopCancel()
	if err := supervisor.Stop(stopCtx); err != nil {
		t.Fatalf("Stop() after cancellation error = %v", err)
	}
}

func TestProcessSupervisorStartsAndStopsProcess(t *testing.T) {
	sh := requireShell(t)
	supervisor := &ProcessSupervisor{}
	if err := supervisor.Start(context.Background(), ProcessSpec{Name: "sleep", Path: sh, Args: []string{"-c", "sleep 5"}}); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if status := supervisor.Status(); !status.Running || status.RestartCount != 1 {
		t.Fatalf("status after start = %+v", status)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := supervisor.Stop(ctx); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if status := supervisor.Status(); status.Running || status.LastExit != "stopped" {
		t.Fatalf("status after stop = %+v", status)
	}
}

func TestProcessSupervisorRecordsFailedExit(t *testing.T) {
	sh := requireShell(t)
	supervisor := &ProcessSupervisor{}
	if err := supervisor.Start(context.Background(), ProcessSpec{Name: "fail", Path: sh, Args: []string{"-c", "exit 7"}}); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		status := supervisor.Status()
		if !status.Running {
			if status.LastError == "" || !strings.Contains(status.LastExit, "exit status 7") {
				t.Fatalf("status after failed exit = %+v", status)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for process exit")
}

func TestProcessSupervisorRejectsDuplicateStart(t *testing.T) {
	sh := requireShell(t)
	supervisor := &ProcessSupervisor{}
	if err := supervisor.Start(context.Background(), ProcessSpec{Name: "sleep", Path: sh, Args: []string{"-c", "sleep 5"}}); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer supervisor.Stop(context.Background())
	if err := supervisor.Start(context.Background(), ProcessSpec{Name: "sleep", Path: sh, Args: []string{"-c", "sleep 5"}}); err == nil {
		t.Fatal("second Start() error = nil")
	}
}

func TestProcessSupervisorRestartsFailedProcessUntilLimit(t *testing.T) {
	sh := requireShell(t)
	dir := t.TempDir()
	countPath := filepath.Join(dir, "count")
	supervisor := &ProcessSupervisor{}
	err := supervisor.StartRestarting(context.Background(), ProcessSpec{
		Name: "fail",
		Path: sh,
		Args: []string{"-c", "n=0; if [ -f \"$COUNT\" ]; then n=$(cat \"$COUNT\"); fi; n=$((n+1)); printf '%s' \"$n\" > \"$COUNT\"; exit 7"},
		Env:  []string{"COUNT=" + countPath},
	}, RestartPolicy{MaxRestarts: 3, Delay: 10 * time.Millisecond})
	if err != nil {
		t.Fatalf("StartRestarting() error = %v", err)
	}
	waitForStatus(t, supervisor, func(status ProcessStatus) bool {
		return !status.Running && status.RestartCount == 3 && strings.Contains(status.LastExit, "exit status 7")
	})
	data, err := os.ReadFile(countPath)
	if err != nil {
		t.Fatalf("ReadFile(count) error = %v", err)
	}
	if string(data) != "3" {
		t.Fatalf("restart count file = %q, want 3", string(data))
	}
}

func TestProcessSupervisorStopsRestartLoopAndProcess(t *testing.T) {
	sh := requireShell(t)
	supervisor := &ProcessSupervisor{}
	if err := supervisor.StartRestarting(context.Background(), ProcessSpec{Name: "sleep", Path: sh, Args: []string{"-c", "sleep 5"}}, RestartPolicy{MaxRestarts: 10, Delay: time.Millisecond}); err != nil {
		t.Fatalf("StartRestarting() error = %v", err)
	}
	waitForStatus(t, supervisor, func(status ProcessStatus) bool {
		return status.Running && status.RestartCount == 1
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := supervisor.Stop(ctx); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if status := supervisor.Status(); status.Running || status.LastExit != "stopped" {
		t.Fatalf("status after stop = %+v", status)
	}
}

func TestProcessSupervisorStopsRestartLoopProcessGroup(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("process group cleanup is Linux-specific")
	}
	sh := requireShell(t)
	childPIDPath := filepath.Join(t.TempDir(), "child.pid")
	supervisor := &ProcessSupervisor{}
	err := supervisor.StartRestarting(t.Context(), ProcessSpec{
		Name: "process-tree",
		Path: sh,
		Args: []string{"-c", "sleep 30 & child=$!; printf '%s' \"$child\" > \"$CHILD_PID\"; wait"},
		Env:  []string{"CHILD_PID=" + childPIDPath},
	}, RestartPolicy{MaxRestarts: 2, Delay: time.Millisecond})
	if err != nil {
		t.Fatalf("StartRestarting() error = %v", err)
	}
	childPID := waitForProcessPID(t, childPIDPath)
	stopCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := supervisor.Stop(stopCtx); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	waitForProcessExit(t, childPID)
}

func waitForProcessPID(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			pid, err := strconv.Atoi(string(data))
			if err == nil {
				return pid
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for child process PID")
	return 0
}

func waitForProcessExit(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("child process %d remained after supervisor stop", pid)
}

func TestProcessSupervisorRejectsDuplicateRestartLoop(t *testing.T) {
	sh := requireShell(t)
	supervisor := &ProcessSupervisor{}
	if err := supervisor.StartRestarting(context.Background(), ProcessSpec{Name: "sleep", Path: sh, Args: []string{"-c", "sleep 5"}}, RestartPolicy{MaxRestarts: 10, Delay: time.Millisecond}); err != nil {
		t.Fatalf("StartRestarting() error = %v", err)
	}
	defer supervisor.Stop(context.Background())
	if err := supervisor.StartRestarting(context.Background(), ProcessSpec{Name: "sleep", Path: sh, Args: []string{"-c", "sleep 5"}}, RestartPolicy{MaxRestarts: 10, Delay: time.Millisecond}); err == nil {
		t.Fatal("second StartRestarting() error = nil")
	}
	if err := supervisor.Start(context.Background(), ProcessSpec{Name: "sleep", Path: sh, Args: []string{"-c", "sleep 5"}}); err == nil {
		t.Fatal("Start() during restart loop error = nil")
	}
}

func waitForStatus(t *testing.T, supervisor *ProcessSupervisor, done func(ProcessStatus) bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	var last ProcessStatus
	for time.Now().Before(deadline) {
		last = supervisor.Status()
		if done(last) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for status, last = %+v", last)
}

func requireShell(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell process supervisor tests require /bin/sh")
	}
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh is unavailable")
	}
	return "/bin/sh"
}
