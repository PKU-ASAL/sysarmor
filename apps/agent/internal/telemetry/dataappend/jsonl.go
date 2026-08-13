package dataappend

import (
	"bufio"
	"fmt"
	"io"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/detection"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/event/normalize"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/telemetry/ringbuffer"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
	sensorv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/sensor/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
	"google.golang.org/protobuf/encoding/protojson"
)

func ReadProtoJSONL(r io.Reader, agentID, hostID, policyID string, policyVersion uint64, labels map[string]string) (*dataplanev1.DataBatch, error) {
	return ReadProtoJSONLWithRing(r, agentID, hostID, policyID, policyVersion, labels, ringbuffer.New(4096))
}

func ReadProtoJSONLWithRing(r io.Reader, agentID, hostID, policyID string, policyVersion uint64, labels map[string]string, rawRing *ringbuffer.Buffer) (*dataplanev1.DataBatch, error) {
	if err := validateReplayPolicy(policyID, policyVersion); err != nil {
		return nil, err
	}
	if rawRing == nil {
		rawRing = ringbuffer.New(4096)
	}
	labels = replayLabels(labels, policyID, policyVersion)
	batch := newBatch(StreamOptions{AgentID: agentID, HostID: hostID, TenantID: "default", PolicyID: policyID, PolicyVersion: policyVersion, Labels: labels})
	norm := normalize.New(agentID, hostID, nil)
	detector, _ := detection.New(policymodel.DefaultDetectionPolicy())
	scanner := bufio.NewScanner(r)
	line := 0
	for scanner.Scan() {
		line++
		data := scanner.Bytes()
		if len(data) == 0 {
			continue
		}
		rawData := append([]byte(nil), data...)
		events, signals, err := decodeLine(rawData, norm, detector, labels, rawRing)
		if err != nil {
			return nil, fmt.Errorf("line %d is neither Signal, CanonicalEvent, SensorEvent nor Tetragon event", line)
		}
		appendFrames(batch, events, signals)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return batch, nil
}

func decodeSignal(data []byte) (*signalv1.Signal, bool) {
	msg := &signalv1.Signal{}
	if err := protojson.Unmarshal(data, msg); err != nil {
		return nil, false
	}
	return msg, msg.GetName() != "" || len(msg.GetEntities()) > 0
}

func decodeEvent(data []byte) (*eventv1.CanonicalEvent, bool) {
	msg := &eventv1.CanonicalEvent{}
	if err := protojson.Unmarshal(data, msg); err != nil {
		return nil, false
	}
	return msg, msg.GetId() != "" || msg.GetBehavior() != ""
}

func decodeSensorEvent(data []byte) (*sensorv1.SensorEvent, bool) {
	msg := &sensorv1.SensorEvent{}
	if err := protojson.Unmarshal(data, msg); err != nil {
		return nil, false
	}
	return msg, msg.GetProc() != nil && msg.GetBehavior() != ""
}
