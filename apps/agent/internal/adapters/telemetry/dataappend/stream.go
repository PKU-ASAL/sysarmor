package dataappend

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"github.com/sysarmor/sysarmor-next-project/packages/contracts/schema"

	contractmapper "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/contracts"
	detection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/detection"
	eventadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sensor/tetragon"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/telemetry/ringbuffer"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
	sensorv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/sensor/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
)

type BatchSender interface {
	SendBatch(batch *dataplanev1.DataBatch) (*dataplanev1.DataAck, error)
}

type SensorLineParser func([]byte) ([]*sensorv1.SensorEvent, bool)

type StreamOptions struct {
	AgentID       string
	HostID        string
	TenantID      string
	PolicyID      string
	PolicyVersion uint64
	Labels        map[string]string
	Version       string
	BatchSize     int
	FlushInterval time.Duration
	RawRing       *ringbuffer.Buffer
	SensorParser  SensorLineParser
}

type StreamStats struct {
	Events  int
	Signals int
	Batches int
}

var batchSequence atomic.Uint64

func StreamJSONL(ctx context.Context, r io.Reader, up BatchSender, opts StreamOptions) (StreamStats, error) {
	if up == nil {
		return StreamStats{}, fmt.Errorf("batch appender is nil")
	}
	if err := validateReplayPolicy(opts.PolicyID, opts.PolicyVersion); err != nil {
		return StreamStats{}, err
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 128
	}
	if opts.FlushInterval <= 0 {
		opts.FlushInterval = time.Second
	}
	if opts.RawRing == nil {
		opts.RawRing = ringbuffer.New(4096)
	}
	opts.Labels = replayLabels(opts.Labels, opts.PolicyID, opts.PolicyVersion)

	norm := eventadapter.NewEventNormalizer(opts.AgentID, opts.HostID, eventadapter.EventNormalizerOptions{})
	detector, _ := detection.New(policymodel.DefaultDetectionPolicy())
	lines := scanLines(r)
	ticker := time.NewTicker(opts.FlushInterval)
	defer ticker.Stop()

	batch := newBatch(opts)
	var stats StreamStats
	line := 0
	flush := func() error {
		if len(batch.GetEvents()) == 0 && len(batch.GetSignals()) == 0 {
			return nil
		}
		if _, err := up.SendBatch(batch); err != nil {
			return err
		}
		stats.Batches++
		batch = newBatch(opts)
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			if err := flush(); err != nil {
				return stats, err
			}
			return stats, ctx.Err()
		case <-ticker.C:
			if err := flush(); err != nil {
				return stats, err
			}
		case scanned, ok := <-lines:
			if !ok {
				if err := flush(); err != nil {
					return stats, err
				}
				return stats, nil
			}
			if scanned.err != nil {
				return stats, scanned.err
			}
			line++
			if len(scanned.data) == 0 {
				continue
			}
			events, signals, err := decodeLine(scanned.data, norm, detector, opts.Labels, opts.RawRing, opts.SensorParser)
			if err != nil {
				return stats, fmt.Errorf("line %d: %w", line, err)
			}
			appendFrames(batch, events, signals)
			stats.Events += len(events)
			stats.Signals += len(signals)
			if len(batch.GetEvents())+len(batch.GetSignals()) < opts.BatchSize {
				continue
			}
			if err := flush(); err != nil {
				return stats, err
			}
		}
	}
}

type scannedLine struct {
	data []byte
	err  error
}

func scanLines(r io.Reader) <-chan scannedLine {
	out := make(chan scannedLine)
	go func() {
		defer close(out)
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			out <- scannedLine{data: append([]byte(nil), scanner.Bytes()...)}
		}
		if err := scanner.Err(); err != nil {
			out <- scannedLine{err: err}
		}
	}()
	return out
}

func newBatch(opts StreamOptions) *dataplanev1.DataBatch {
	tenantID := opts.TenantID
	if tenantID == "" {
		tenantID = "default"
	}
	now := time.Now().UTC()
	return &dataplanev1.DataBatch{SchemaVersion: schema.DataPlaneCurrent, Header: &dataplanev1.BatchHeader{
		BatchId:           fmt.Sprintf("batch-jsonl-%d-%d", now.UnixNano(), batchSequence.Add(1)),
		AgentId:           opts.AgentID,
		HostId:            opts.HostID,
		TenantId:          tenantID,
		PolicyId:          opts.PolicyID,
		PolicyVersion:     opts.PolicyVersion,
		PolicyMode:        "observe",
		CreatedAtUnixNano: now.UnixNano(),
		Labels:            replayLabels(opts.Labels, opts.PolicyID, opts.PolicyVersion),
	}}
}

func replayLabels(labels map[string]string, policyID string, policyVersion uint64) map[string]string {
	return mergeLabels(labels, map[string]string{
		"policy_id":      policyID,
		"policy_version": fmt.Sprint(policyVersion),
	})
}

func validateReplayPolicy(policyID string, policyVersion uint64) error {
	if policyID == "" || policyVersion == 0 {
		return fmt.Errorf("replay policy_id and policy_version are required")
	}
	return nil
}

func appendFrames(batch *dataplanev1.DataBatch, events []*eventv1.CanonicalEvent, signals []*signalv1.Signal) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, ev := range events {
		batch.Events = append(batch.Events, &dataplanev1.EventFrame{
			Sequence:   ev.GetSeq(),
			ObservedAt: now,
			Event:      ev,
		})
	}
	for _, sig := range signals {
		batch.Signals = append(batch.Signals, &dataplanev1.SignalFrame{
			ObservedAt: now,
			Signal:     sig,
		})
	}
	if batch.Header != nil {
		batch.Header.EventCount = uint32(len(batch.GetEvents()))
		batch.Header.SignalCount = uint32(len(batch.GetSignals()))
		if len(batch.GetEvents()) > 0 {
			batch.Header.EventSeqStart = batch.GetEvents()[0].GetSequence()
			batch.Header.EventSeqEnd = batch.GetEvents()[len(batch.GetEvents())-1].GetSequence()
		}
		if len(batch.GetSignals()) > 0 {
			batch.Header.SignalSeqStart = batch.GetSignals()[0].GetSequence()
			batch.Header.SignalSeqEnd = batch.GetSignals()[len(batch.GetSignals())-1].GetSequence()
		}
	}
}

func decodeLine(data []byte, norm *eventadapter.EventNormalizer, detector *detection.Engine, labels map[string]string, rawRing *ringbuffer.Buffer, parser SensorLineParser) ([]*eventv1.CanonicalEvent, []*signalv1.Signal, error) {
	if sig, ok := decodeSignal(data); ok {
		sig.Labels = mergeLabels(sig.GetLabels(), labels)
		return nil, []*signalv1.Signal{sig}, nil
	}
	if ev, ok := decodeEvent(data); ok {
		ev.Labels = mergeLabels(ev.GetLabels(), labels)
		domainSignals := detector.Process(contractmapper.DomainEvent(ev))
		signals := make([]*signalv1.Signal, 0, len(domainSignals))
		for _, sig := range domainSignals {
			sig.Labels = mergeLabels(sig.Labels, labels)
			signals = append(signals, contractmapper.Signal(*sig))
		}
		return []*eventv1.CanonicalEvent{ev}, signals, nil
	}
	if sev, ok := decodeSensorEvent(data); ok {
		sev.RawRef = rawRing.Remember(sev.GetRawRef(), data)
		domainEvent := norm.NormalizeDomain(sev)
		domainEvent.Labels = mergeLabels(domainEvent.Labels, labels)
		ev := contractmapper.CanonicalEvent(domainEvent)
		domainSignals := detector.Process(domainEvent)
		signals := make([]*signalv1.Signal, 0, len(domainSignals))
		for _, sig := range domainSignals {
			sig.Labels = mergeLabels(sig.Labels, labels)
			signals = append(signals, contractmapper.Signal(*sig))
		}
		return []*eventv1.CanonicalEvent{ev}, signals, nil
	}
	if parser != nil {
		if sevs, ok := parser(data); ok {
			return decodeSensorEvents(data, sevs, norm, detector, labels, rawRing)
		}
	}
	return nil, nil, fmt.Errorf("not Signal, CanonicalEvent, SensorEvent nor Tetragon event")
}

func decodeSensorEvents(data []byte, sevs []*sensorv1.SensorEvent, norm *eventadapter.EventNormalizer, detector *detection.Engine, labels map[string]string, rawRing *ringbuffer.Buffer) ([]*eventv1.CanonicalEvent, []*signalv1.Signal, error) {
	rawRef := rawRing.Put(data)
	events := make([]*eventv1.CanonicalEvent, 0, len(sevs))
	var signals []*signalv1.Signal
	for _, sev := range sevs {
		if sev.GetRawRef() == "" {
			sev.RawRef = rawRef
		} else {
			rawRing.Remember(sev.GetRawRef(), data)
		}
		domainEvent := norm.NormalizeDomain(sev)
		domainEvent.Labels = mergeLabels(domainEvent.Labels, labels)
		ev := contractmapper.CanonicalEvent(domainEvent)
		events = append(events, ev)
		domainDetected := detector.Process(domainEvent)
		var detected []*signalv1.Signal
		for _, sig := range domainDetected {
			sig.Labels = mergeLabels(sig.Labels, labels)
			detected = append(detected, contractmapper.Signal(*sig))
		}
		signals = append(signals, detected...)
	}
	return events, signals, nil
}

func cloneLabels(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		if key == "" {
			continue
		}
		out[key] = value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func mergeLabels(base, extra map[string]string) map[string]string {
	out := cloneLabels(base)
	if out == nil {
		out = map[string]string{}
	}
	for key, value := range extra {
		if key == "" {
			continue
		}
		out[key] = value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
