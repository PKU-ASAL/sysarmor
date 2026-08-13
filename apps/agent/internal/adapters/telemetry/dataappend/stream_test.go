package dataappend

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/telemetry/ringbuffer"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	sensorv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/sensor/v1"
	"github.com/sysarmor/sysarmor-next-project/packages/contracts/schema"
)

type recordingUploader struct {
	batches []*dataplanev1.DataBatch
}

func (u *recordingUploader) SendBatch(batch *dataplanev1.DataBatch) (*dataplanev1.DataAck, error) {
	u.batches = append(u.batches, batch)
	return &dataplanev1.DataAck{Accepted: true, BatchId: batch.GetHeader().GetBatchId()}, nil
}

func TestStreamJSONLBatchesAndAssignsRawRefs(t *testing.T) {
	input := strings.Join([]string{
		`{"mono_ns":"1","behavior":"process.exec","proc":{"pid":1,"binary":"/usr/bin/java-web","start_time_ns":"11"}}`,
		`{"mono_ns":"2","behavior":"process.exec","proc":{"pid":2,"ppid":1,"binary":"/bin/bash","argv":["/bin/bash"],"start_time_ns":"22"}}`,
		`{"mono_ns":"3","behavior":"file.write","proc":{"pid":2,"ppid":1,"binary":"/bin/bash","start_time_ns":"22"},"object":{"path":"/dev/shm/x.sh"}}`,
	}, "\n") + "\n"
	rec := &recordingUploader{}
	ring := ringbuffer.New(8)

	stats, err := StreamJSONL(context.Background(), strings.NewReader(input), rec, StreamOptions{
		AgentID:       "agent-a",
		HostID:        "host-a",
		PolicyID:      "policy-a",
		PolicyVersion: 3,
		Labels:        map[string]string{"scenario": "scenario-a"},
		Version:       "test",
		BatchSize:     2,
		FlushInterval: time.Hour,
		RawRing:       ring,
		SensorParser:  testSensorParser,
	})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Events != 3 || stats.Batches != 2 {
		t.Fatalf("stats = %#v, want 3 events and 2 batches", stats)
	}
	if len(rec.batches) != 2 {
		t.Fatalf("appended batches = %d, want 2", len(rec.batches))
	}
	if rec.batches[0].GetHeader().GetAgentId() != "agent-a" {
		t.Fatalf("agent metadata missing: %#v", rec.batches[0].GetHeader())
	}
	if rec.batches[0].GetHeader().GetTenantId() != "default" {
		t.Fatalf("tenant metadata missing: %#v", rec.batches[0].GetHeader())
	}
	if rec.batches[0].GetHeader().GetBatchId() == "" || rec.batches[0].GetHeader().GetPolicyId() != "policy-a" || rec.batches[0].GetHeader().GetPolicyVersion() != 3 {
		t.Fatalf("batch identity missing: %#v", rec.batches[0].GetHeader())
	}
	labels := rec.batches[0].GetEvents()[0].GetEvent().GetLabels()
	if labels["policy_id"] != "policy-a" || labels["policy_version"] != "3" {
		t.Fatalf("event policy labels = %+v", labels)
	}
	if rec.batches[0].GetSchemaVersion() != schema.DataPlaneCurrent {
		t.Fatalf("schema version = %q", rec.batches[0].GetSchemaVersion())
	}
	firstRef := rec.batches[0].GetEvents()[0].GetEvent().GetRawRef()
	if firstRef == "" {
		t.Fatal("first event raw ref is empty")
	}
	if _, ok := ring.Get(firstRef); !ok {
		t.Fatalf("raw ref %q not found in ring", firstRef)
	}
}

func TestStreamJSONLStoresTetragonRawLineBehindRef(t *testing.T) {
	input := `{"process_exec":{"process":{"pid":100,"uid":0,"binary":"/usr/bin/curl","arguments":"-o /dev/shm/x.sh","start_time":"2026-06-14T10:00:00Z"},"parent":{"pid":99,"binary":"/bin/bash","start_time":"2026-06-14T09:59:59Z"}},"node_name":"node-a","time":"2026-06-14T10:00:00Z"}` + "\n"
	rec := &recordingUploader{}
	ring := ringbuffer.New(8)

	stats, err := StreamJSONL(context.Background(), strings.NewReader(input), rec, StreamOptions{
		AgentID:       "agent-a",
		HostID:        "host-a",
		PolicyID:      "policy-a",
		PolicyVersion: 3,
		Labels:        map[string]string{"scenario": "scenario-a"},
		Version:       "test",
		BatchSize:     10,
		FlushInterval: time.Hour,
		RawRing:       ring,
		SensorParser:  testSensorParser,
	})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Events != 2 {
		t.Fatalf("events = %d, want exec + inferred write", stats.Events)
	}
	ref := rec.batches[0].GetEvents()[0].GetEvent().GetRawRef()
	if ref == "" || strings.HasPrefix(ref, "{") {
		t.Fatalf("raw ref = %q, want compact ring ref", ref)
	}
	entry, ok := ring.Get(ref)
	if !ok {
		t.Fatalf("raw ref %q missing from ring", ref)
	}
	if !strings.Contains(string(entry.Data), `"process_exec"`) {
		t.Fatalf("raw entry = %s", string(entry.Data))
	}
}

func testSensorParser(data []byte) ([]*sensorv1.SensorEvent, bool) {
	if !strings.Contains(string(data), `"process_exec"`) {
		return nil, false
	}
	return []*sensorv1.SensorEvent{
		{Behavior: "process.exec", Proc: &sensorv1.RawProcess{Pid: 100, Binary: "/usr/bin/curl", StartTimeNs: 1}},
		{Behavior: "file.write", Proc: &sensorv1.RawProcess{Pid: 100, Binary: "/usr/bin/curl", StartTimeNs: 1}, Object: &sensorv1.RawObject{Path: "/dev/shm/x.sh"}},
	}, true
}
