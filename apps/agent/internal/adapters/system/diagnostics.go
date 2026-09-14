package system

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"runtime/pprof"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/ports"
)

type ProfileCapturer struct{}

func NewProfileCapturer() ProfileCapturer {
	return ProfileCapturer{}
}

func (ProfileCapturer) Capture(ctx context.Context, request ports.ProfileRequest) ([]byte, error) {
	if request.Type == "cpu" {
		return captureCPUProfile(ctx, time.Duration(request.Seconds)*time.Second)
	}
	if request.Type == "runtime" {
		return captureRuntimeProfile(request)
	}
	runtime.GC()
	profile := pprof.Lookup(request.Type)
	if profile == nil {
		return nil, fmt.Errorf("profile %q unavailable", request.Type)
	}
	var buf bytes.Buffer
	if err := profile.WriteTo(&buf, 0); err != nil {
		return nil, fmt.Errorf("write %s profile: %w", request.Type, err)
	}
	return buf.Bytes(), nil
}

func captureCPUProfile(ctx context.Context, duration time.Duration) ([]byte, error) {
	var buf bytes.Buffer
	if err := pprof.StartCPUProfile(&buf); err != nil {
		return nil, fmt.Errorf("start cpu profile: %w", err)
	}
	timer := time.NewTimer(duration)
	select {
	case <-ctx.Done():
		timer.Stop()
		pprof.StopCPUProfile()
		return nil, ctx.Err()
	case <-timer.C:
		pprof.StopCPUProfile()
		return buf.Bytes(), nil
	}
}

func captureRuntimeProfile(request ports.ProfileRequest) ([]byte, error) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(runtimeStats(request)); err != nil {
		return nil, fmt.Errorf("encode runtime stats: %w", err)
	}
	return buf.Bytes(), nil
}

func runtimeStats(request ports.ProfileRequest) map[string]any {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	return map[string]any{
		"observed_at": request.StartedAt.Format(time.RFC3339Nano), "label": request.Label,
		"go_version": runtime.Version(), "goos": runtime.GOOS, "goarch": runtime.GOARCH,
		"gomaxprocs": runtime.GOMAXPROCS(0), "goroutines": runtime.NumGoroutine(), "cgo_calls": runtime.NumCgoCall(),
		"heap_alloc_bytes": mem.HeapAlloc, "heap_sys_bytes": mem.HeapSys, "heap_idle_bytes": mem.HeapIdle,
		"heap_inuse_bytes": mem.HeapInuse, "heap_released_bytes": mem.HeapReleased, "heap_objects": mem.HeapObjects,
		"stack_inuse_bytes": mem.StackInuse, "stack_sys_bytes": mem.StackSys, "alloc_bytes_total": mem.TotalAlloc,
		"mallocs_total": mem.Mallocs, "frees_total": mem.Frees, "gc_count": mem.NumGC,
		"gc_pause_ns_total": mem.PauseTotalNs, "last_gc_unix_ns": mem.LastGC,
		"next_gc_bytes": mem.NextGC, "gc_cpu_fraction": mem.GCCPUFraction,
	}
}
