package runtime

import (
	"context"
	"time"

	contractadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/contracts"
	domainhealth "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/health"
	agenthealth "github.com/sysarmor/sysarmor-next-project/packages/contracts/health"
	controlplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/controlplane/v1"
)

func (s *localStatusService) Health(ctx context.Context, req *controlplanev1.HealthRequest) (*controlplanev1.HealthResponse, error) {
	snapshot := s.runner.collectHealthSnapshot(ctx, s.runtime, s.bus, s.batcher, s.sender, s.startedAt)
	return healthResponseSnapshot(snapshot), nil
}

func (s *localStatusService) Capability(ctx context.Context, req *controlplanev1.CapabilityRequest) (*controlplanev1.CapabilityResponse, error) {
	identity := s.runner.currentIdentity()
	return &controlplanev1.CapabilityResponse{
		AgentId:  identity.AgentID,
		HostId:   identity.HostID,
		TenantId: identity.TenantID,
		Scope:    scopeMessage(s.runner.runtimeScope()),
		Sensor:   capabilityMessage(s.runner.runtimeCapability()),
		SupportedPolicySections: []string{
			"collection",
			"detection",
			"response",
			"resource",
			"telemetry",
		},
		SupportedResponseActions: []string{
			"collect_evidence",
		},
		CollectionBehaviors: collectionBehaviorMessages(s.runner.runtimeCapability().Collection),
	}, nil
}

func healthResponseSnapshot(snapshot domainhealth.Snapshot) *controlplanev1.HealthResponse {
	response := healthResponse(contractadapter.AgentHealth(snapshot))
	if snapshot.Storage.Available {
		response.LocalStore = &controlplanev1.LocalStoreHealth{
			Mode: snapshot.Storage.Mode, DeviceId: snapshot.Storage.DeviceID,
			StorageBytes: int64(snapshot.Storage.StorageBytes), StorageMaxBytes: int64(snapshot.Storage.StorageMaxBytes),
			OldestEventSequence: snapshot.Storage.OldestEventSequence, LatestEventSequence: snapshot.Storage.LatestEventSequence,
			SignalCount: snapshot.Storage.SignalCount, SealedSegmentCount: snapshot.Storage.SealedSegmentCount,
			OpenSegmentBytes: int64(snapshot.Storage.OpenSegmentBytes), UploadSegmentId: snapshot.Storage.UploadSegmentID,
			UploadRecordOffset: snapshot.Storage.UploadRecordOffset, DroppedBatchesStorage: snapshot.Storage.DroppedBatches,
			DroppedEventsStorage: snapshot.Storage.DroppedEvents,
		}
	}
	response.ManagementLifecycle = &controlplanev1.ManagementLifecycleStatus{
		Mode: snapshot.Lifecycle.Mode, TransitionPhase: snapshot.Lifecycle.TransitionPhase,
		RevocationConfirmed:     snapshot.Lifecycle.RevocationConfirmed,
		ManagerCompletionStatus: snapshot.Lifecycle.ManagerCompletionStatus,
		LastTransitionError:     snapshot.Lifecycle.LastError, UpdatedAt: timestampString(snapshot.Lifecycle.UpdatedAt),
	}
	return response
}

func healthResponse(health agenthealth.AgentHealth) *controlplanev1.HealthResponse {
	return &controlplanev1.HealthResponse{
		AgentId:       health.AgentID,
		HostId:        health.HostID,
		TenantId:      health.TenantID,
		Scope:         scopeMessage(health.Scope),
		Status:        health.Status,
		PolicyId:      health.PolicyID,
		PolicyVersion: health.PolicyVersion,
		PolicyMode:    health.PolicyMode,
		PendingPolicy: pendingPolicyMessage(health.PendingPolicy),
		UptimeSeconds: health.UptimeSeconds,
		Capability:    capabilityMessage(health.Capability),
		Sensor: &controlplanev1.SensorHealth{
			Backend:        health.Sensor.Backend,
			Installed:      health.Sensor.Installed,
			Running:        health.Sensor.Running,
			Version:        health.Sensor.Version,
			PolicyLoaded:   health.Sensor.PolicyLoaded,
			EventsSeen:     health.Sensor.EventsSeen,
			EventsDropped:  health.Sensor.EventsDropped,
			ParseErrors:    health.Sensor.ParseErrors,
			RestartCount:   health.Sensor.RestartCount,
			LastEventAt:    timestampString(health.Sensor.LastEventAt),
			LastExitReason: health.Sensor.LastExitReason,
			LastError:      health.Sensor.LastError,
		},
		TelemetryBus: &controlplanev1.TelemetryBusHealth{
			EventCapacity:     health.TelemetryBus.EventCapacity,
			EventBuffered:     health.TelemetryBus.EventBuffered,
			EventDropped:      health.TelemetryBus.EventDropped,
			EventSubscribers:  health.TelemetryBus.EventSubscribers,
			SignalCapacity:    health.TelemetryBus.SignalCapacity,
			SignalBuffered:    health.TelemetryBus.SignalBuffered,
			SignalDropped:     health.TelemetryBus.SignalDropped,
			SignalSubscribers: health.TelemetryBus.SignalSubscribers,
		},
		TelemetryBatcher: &controlplanev1.TelemetryBatcherHealth{
			PendingEvents:     health.TelemetryBatcher.PendingEvents,
			PendingSignals:    health.TelemetryBatcher.PendingSignals,
			QueuedBatches:     health.TelemetryBatcher.QueuedBatches,
			QueueCapacity:     health.TelemetryBatcher.QueueCapacity,
			DroppedBatches:    health.TelemetryBatcher.DroppedBatches,
			DroppedEvents:     health.TelemetryBatcher.DroppedEvents,
			DroppedSignals:    health.TelemetryBatcher.DroppedSignals,
			FlushedBatches:    health.TelemetryBatcher.FlushedBatches,
			FlushedEvents:     health.TelemetryBatcher.FlushedEvents,
			FlushedSignals:    health.TelemetryBatcher.FlushedSignals,
			PendingBytes:      health.TelemetryBatcher.PendingBytes,
			MaxBytes:          health.TelemetryBatcher.MaxBytes,
			FlushedByCount:    health.TelemetryBatcher.FlushedByCount,
			FlushedByBytes:    health.TelemetryBatcher.FlushedByBytes,
			FlushedByInterval: health.TelemetryBatcher.FlushedByInterval,
			FlushedByShutdown: health.TelemetryBatcher.FlushedByShutdown,
			LastFlushReason:   health.TelemetryBatcher.LastFlushReason,
			Closed:            health.TelemetryBatcher.Closed,
			LastError:         health.TelemetryBatcher.LastError,
		},
		TelemetrySender: &controlplanev1.TelemetrySenderHealth{
			SentBatches:     health.TelemetrySender.SentBatches,
			SentEvents:      health.TelemetrySender.SentEvents,
			SentSignals:     health.TelemetrySender.SentSignals,
			RejectedBatches: health.TelemetrySender.RejectedBatches,
			RetriedBatches:  health.TelemetrySender.RetriedBatches,
			Drained:         health.TelemetrySender.Drained,
			LastError:       health.TelemetrySender.LastError,
		},
		Detection: &controlplanev1.DetectionRuntimeHealth{
			PolicyId:               health.Detection.PolicyID,
			PolicyVersion:          health.Detection.PolicyVersion,
			ContentRefs:            detectionContentRefMessages(health.Detection.ContentRefs),
			LastApplyStatus:        health.Detection.LastApplyStatus,
			LastApplyError:         health.Detection.LastApplyError,
			UpdatedAt:              timestampString(health.Detection.UpdatedAt),
			DefaultManifestVersion: health.Detection.DefaultManifestVersion,
		},
		Cep: &controlplanev1.CEPHealth{
			ActiveGroups:     health.CEP.ActiveGroups,
			EvictedGroups:    health.CEP.EvictedGroups,
			ExpiredGroups:    health.CEP.ExpiredGroups,
			DroppedEventRefs: health.CEP.DroppedEventRefs,
			EvalErrors:       health.CEP.EvalErrors,
			EmittedSignals:   health.CEP.EmittedSignals,
			Degraded:         health.CEP.Degraded,
		},
		Streams: &controlplanev1.LocalStreamHealth{
			EventCapacity:        health.Streams.EventCapacity,
			EventBuffered:        health.Streams.EventBuffered,
			EventNextSequence:    health.Streams.EventNextSequence,
			EventOldestSequence:  health.Streams.EventOldestSequence,
			EventNewestSequence:  health.Streams.EventNewestSequence,
			EventEvicted:         health.Streams.EventEvicted,
			EventSubscribers:     health.Streams.EventSubscribers,
			SignalCapacity:       health.Streams.SignalCapacity,
			SignalBuffered:       health.Streams.SignalBuffered,
			SignalNextSequence:   health.Streams.SignalNextSequence,
			SignalOldestSequence: health.Streams.SignalOldestSequence,
			SignalNewestSequence: health.Streams.SignalNewestSequence,
			SignalEvicted:        health.Streams.SignalEvicted,
			SignalSubscribers:    health.Streams.SignalSubscribers,
		},
		ObservedAt: timestampString(health.ObservedAt),
	}
}

func detectionContentRefMessages(in []agenthealth.ContentRef) []*controlplanev1.DetectionContentRef {
	out := make([]*controlplanev1.DetectionContentRef, 0, len(in))
	for _, item := range in {
		out = append(out, &controlplanev1.DetectionContentRef{
			Ref:     item.Ref,
			Kind:    item.Kind,
			Version: item.Version,
			Digest:  item.Digest,
		})
	}
	return out
}

func scopeMessage(scope agenthealth.RuntimeScope) *controlplanev1.Scope {
	return &controlplanev1.Scope{Type: scope.Type, Selector: scope.Selector}
}

func capabilityMessage(cap agenthealth.SensorCapability) *controlplanev1.SensorCapability {
	return &controlplanev1.SensorCapability{
		Backend:         cap.Backend,
		Version:         cap.Version,
		SupportsExec:    cap.SupportsExec,
		SupportsConnect: cap.SupportsConnect,
		SupportsFile:    cap.SupportsFile,
		SupportsEnforce: cap.SupportsEnforce,
		SupportsHealth:  cap.SupportsHealth,
		KernelRelease:   cap.KernelRelease,
		BtfAvailable:    cap.BTFAvailable,
		BpffsAvailable:  cap.BPFFSAvailable,
	}
}

func collectionBehaviorMessages(in []agenthealth.CollectionBehaviorCapability) []*controlplanev1.CollectionBehaviorCapability {
	out := make([]*controlplanev1.CollectionBehaviorCapability, 0, len(in))
	for _, item := range in {
		out = append(out, &controlplanev1.CollectionBehaviorCapability{
			Behavior:             item.Behavior,
			Fields:               append([]string(nil), item.Fields...),
			PushdownSelectors:    append([]string(nil), item.PushdownSelectors...),
			AgentSideSelectors:   append([]string(nil), item.AgentSideSelectors...),
			UnsupportedSelectors: append([]string(nil), item.UnsupportedSelectors...),
			SensorMapping:        item.SensorMapping,
		})
	}
	return out
}

func timestampString(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}
