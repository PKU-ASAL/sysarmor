package tetragon

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type ProcessSpec struct {
	Name    string
	Path    string
	Args    []string
	Dir     string
	Env     []string
	LogPath string
}

type ProcessStatus struct {
	Running      bool
	RestartCount uint64
	LastExit     string
	LastError    string
}

type RestartPolicy struct {
	MaxRestarts int
	Delay       time.Duration
}

type ProcessSupervisor struct {
	mu           sync.Mutex
	cmd          *exec.Cmd
	cancel       context.CancelFunc
	done         chan struct{}
	loopCancel   context.CancelFunc
	loopDone     chan struct{}
	running      bool
	restartCount uint64
	lastExit     string
	lastError    string
}

func (s *ProcessSupervisor) Start(ctx context.Context, spec ProcessSpec) error {
	_, err := s.start(ctx, spec, false)
	return err
}

func (s *ProcessSupervisor) StartWithStdout(ctx context.Context, spec ProcessSpec) (io.ReadCloser, error) {
	return s.start(ctx, spec, true)
}

func (s *ProcessSupervisor) start(ctx context.Context, spec ProcessSpec, captureStdout bool) (io.ReadCloser, error) {
	if strings.TrimSpace(spec.Path) == "" {
		return nil, fmt.Errorf("process path is required")
	}
	s.mu.Lock()
	if s.running || s.loopCancel != nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("%s process is already running", firstNonEmpty(spec.Name, spec.Path))
	}
	procCtx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(procCtx, spec.Path, spec.Args...)
	configureProcessGroup(cmd)
	cmd.Dir = spec.Dir
	cmd.Env = append(os.Environ(), spec.Env...)
	logFile, err := openProcessLog(spec.LogPath)
	if err != nil {
		logFile = nil
	}
	if logFile != nil {
		cmd.Stderr = logFile
	}
	var stdout *io.PipeReader
	var stdoutWriter *io.PipeWriter
	if captureStdout {
		stdout, stdoutWriter = io.Pipe()
		cmd.Stdout = stdoutWriter
	} else if logFile != nil {
		cmd.Stdout = logFile
	}
	done := make(chan struct{})
	s.cmd = cmd
	s.cancel = cancel
	s.done = done
	s.running = true
	s.restartCount++
	s.lastExit = ""
	s.lastError = ""
	s.mu.Unlock()

	if err := cmd.Start(); err != nil {
		if stdoutWriter != nil {
			_ = stdoutWriter.CloseWithError(err)
			_ = stdout.Close()
		}
		if logFile != nil {
			_ = logFile.Close()
		}
		s.mu.Lock()
		s.cmd = nil
		s.cancel = nil
		s.done = nil
		s.running = false
		s.lastError = err.Error()
		s.mu.Unlock()
		cancel()
		close(done)
		return nil, err
	}

	go s.wait(procCtx, cmd, done, logFile, stdoutWriter)
	return stdout, nil
}

func (s *ProcessSupervisor) StartRestarting(ctx context.Context, spec ProcessSpec, policy RestartPolicy) error {
	if strings.TrimSpace(spec.Path) == "" {
		return fmt.Errorf("process path is required")
	}
	if policy.MaxRestarts <= 0 {
		policy.MaxRestarts = 1
	}
	if policy.Delay <= 0 {
		policy.Delay = time.Second
	}
	s.mu.Lock()
	if s.running || s.loopCancel != nil {
		s.mu.Unlock()
		return fmt.Errorf("%s process is already running", firstNonEmpty(spec.Name, spec.Path))
	}
	loopCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	s.loopCancel = cancel
	s.loopDone = done
	s.mu.Unlock()
	go s.restartLoop(loopCtx, spec, policy, done)
	return nil
}

func (s *ProcessSupervisor) Stop(ctx context.Context) error {
	s.mu.Lock()
	loopCancel := s.loopCancel
	loopDone := s.loopDone
	cancel := s.cancel
	done := s.done
	s.mu.Unlock()
	if loopCancel != nil && loopDone != nil {
		loopCancel()
		select {
		case <-loopDone:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if cancel == nil || done == nil {
		return nil
	}
	cancel()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *ProcessSupervisor) restartLoop(ctx context.Context, spec ProcessSpec, policy RestartPolicy, loopDone chan struct{}) {
	defer close(loopDone)
	defer func() {
		s.mu.Lock()
		s.loopCancel = nil
		s.loopDone = nil
		s.mu.Unlock()
	}()
	for attempt := 0; attempt < policy.MaxRestarts; attempt++ {
		err := s.runProcess(ctx, spec)
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			return
		}
		if attempt == policy.MaxRestarts-1 {
			return
		}
		timer := time.NewTimer(policy.Delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (s *ProcessSupervisor) runProcess(ctx context.Context, spec ProcessSpec) error {
	procCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(procCtx, spec.Path, spec.Args...)
	configureProcessGroup(cmd)
	cmd.Dir = spec.Dir
	cmd.Env = append(os.Environ(), spec.Env...)
	logFile, err := openProcessLog(spec.LogPath)
	if err != nil {
		logFile = nil
	}
	if logFile != nil {
		cmd.Stdout = logFile
		cmd.Stderr = logFile
		defer logFile.Close()
	}
	done := make(chan struct{})
	s.mu.Lock()
	s.cmd = cmd
	s.cancel = cancel
	s.done = done
	s.running = true
	s.restartCount++
	s.lastExit = ""
	s.lastError = ""
	s.mu.Unlock()
	if err := cmd.Start(); err != nil {
		s.mu.Lock()
		s.cmd = nil
		s.cancel = nil
		s.done = nil
		s.running = false
		s.lastError = err.Error()
		s.mu.Unlock()
		close(done)
		return err
	}
	err = cmd.Wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	close(done)
	s.running = false
	s.cmd = nil
	s.cancel = nil
	s.done = nil
	if procCtx.Err() != nil {
		s.lastExit = "stopped"
		return nil
	}
	if err != nil {
		s.lastExit = err.Error()
		s.lastError = err.Error()
		return err
	}
	s.lastExit = "exited"
	return nil
}

func openProcessLog(path string) (*os.File, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	return os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
}

func (s *ProcessSupervisor) Status() ProcessStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return ProcessStatus{
		Running:      s.running,
		RestartCount: s.restartCount,
		LastExit:     s.lastExit,
		LastError:    s.lastError,
	}
}

func (s *ProcessSupervisor) wait(ctx context.Context, cmd *exec.Cmd, done chan struct{}, logFile *os.File, stdout *io.PipeWriter) {
	if logFile != nil {
		defer logFile.Close()
	}
	err := cmd.Wait()
	if stdout != nil {
		_ = stdout.Close()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	defer close(done)
	s.running = false
	s.cmd = nil
	s.cancel = nil
	s.done = nil
	if ctx.Err() != nil {
		s.lastExit = "stopped"
		return
	}
	if err != nil {
		s.lastExit = err.Error()
		s.lastError = err.Error()
		return
	}
	s.lastExit = "exited"
}
