package dataappend

import (
	"strings"
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/telemetry/ringbuffer"
)

func TestReadProtoJSONLStoresSensorRawRefs(t *testing.T) {
	raw := `{"mono_ns":"1","behavior":"process.exec","proc":{"pid":7,"binary":"/bin/bash","start_time_ns":"77"},"raw_ref":"sensor-raw-1"}`
	ring := ringbuffer.New(8)

	batch, err := ReadProtoJSONLWithRing(strings.NewReader(raw+"\n"), "agent-a", "host-a", "policy-a", 3, map[string]string{"scenario": "scenario-a"}, ring, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.GetEvents()) != 1 {
		t.Fatalf("events = %d, want 1", len(batch.GetEvents()))
	}
	if batch.GetHeader().GetBatchId() == "" || batch.GetEvents()[0].GetEvent().GetLabels()["policy_id"] != "policy-a" {
		t.Fatalf("replay policy identity missing: header=%+v labels=%+v", batch.GetHeader(), batch.GetEvents()[0].GetEvent().GetLabels())
	}
	if got := batch.GetEvents()[0].GetEvent().GetRawRef(); got != "sensor-raw-1" {
		t.Fatalf("raw ref = %q, want sensor-raw-1", got)
	}
	entry, ok := ring.Get("sensor-raw-1")
	if !ok {
		t.Fatal("sensor raw line was not stored")
	}
	if !strings.Contains(string(entry.Data), `"process.exec"`) {
		t.Fatalf("stored raw = %s", string(entry.Data))
	}
}

func TestReadProtoJSONLAllocatesMissingSensorRawRef(t *testing.T) {
	raw := `{"mono_ns":"1","behavior":"process.exec","proc":{"pid":7,"binary":"/bin/bash","start_time_ns":"77"}}`
	ring := ringbuffer.New(8)

	batch, err := ReadProtoJSONLWithRing(strings.NewReader(raw+"\n"), "agent-a", "host-a", "policy-a", 3, map[string]string{"scenario": "scenario-a"}, ring, nil)
	if err != nil {
		t.Fatal(err)
	}
	ref := batch.GetEvents()[0].GetEvent().GetRawRef()
	if ref == "" {
		t.Fatal("raw ref should be allocated")
	}
	if _, ok := ring.Get(ref); !ok {
		t.Fatalf("allocated raw ref %q missing from ring", ref)
	}
}
