package runtime

import (
	"context"
	"time"

	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sensor/runtime"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sqlite"
	telemetryadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/telemetry"
	domainhealth "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/health"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/management"
	domainprocess "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/process"
)

type runtimeHealthSource struct {
	health    runtimeHealth
	runtime   sensorruntime.Runtime
	bus       *telemetryadapter.Bus
	batcher   *telemetryadapter.Batcher
	sender    *telemetryadapter.RuntimeSender
	startedAt time.Time
}

func newRuntimeHealthSource(health runtimeHealth, rt sensorruntime.Runtime, bus *telemetryadapter.Bus, batcher *telemetryadapter.Batcher, sender *telemetryadapter.RuntimeSender, startedAt time.Time) *runtimeHealthSource {
	return &runtimeHealthSource{health: health, runtime: rt, bus: bus, batcher: batcher, sender: sender, startedAt: startedAt}
}

func (s *runtimeHealthSource) Runtime(ctx context.Context) (domainhealth.Runtime, error) {
	identity := s.health.management.currentIdentity()
	policy := s.health.policy.activePolicy()
	value := domainhealth.Runtime{StartedAt: s.startedAt}
	value.AgentID, value.HostID, value.TenantID = identity.AgentID, identity.HostID, identity.TenantID
	value.PolicyID, value.PolicyVersion, value.PolicyMode = policy.PolicyID, policy.Version, s.health.policyMode()
	scope, err := s.health.config.Sensor.EffectiveScope()
	if err != nil {
		value.ScopeType = "host"
	} else {
		value.ScopeType, value.ScopeSelector = scope.Type, scope.Selector
	}
	value.Capability = s.health.sensor.domainCapability()
	pending, err := s.health.policy.pendingPolicyStatus(ctx)
	if err != nil {
		return value, err
	}
	value.PendingPolicy = domainhealth.PendingPolicy{
		Status: pending.Status, Source: pending.Source, PolicyID: pending.PolicyID, Version: pending.Version, Digest: pending.Digest,
	}
	return value, nil
}

func (s *runtimeHealthSource) Sensor(ctx context.Context) (domainhealth.Sensor, error) {
	value, err := s.runtime.Health(ctx)
	if supervisor := s.health.sensor.currentSupervisor(); supervisor != nil {
		status := supervisor.Status()
		value, _ = resolveSensorHealth(value, err, &status, s.health.config.Sensor.Backend)
		err = nil
	}
	return domainhealth.Sensor{
		Backend: value.Backend, Installed: value.Installed, Running: value.Running, Version: value.Version,
		PolicyLoaded: value.PolicyLoaded, EventsSeen: value.EventsSeen, EventsDropped: value.EventsDropped,
		ParseErrors: value.ParseErrors, RestartCount: value.RestartCount, LastEventAt: value.LastEventAt,
		LastExitReason: value.LastExitReason, LastError: value.LastError,
		MaxParseErrors: s.health.config.Sensor.MaxParseErrors, MaxDroppedEvents: s.health.config.Sensor.MaxDroppedEvents,
	}, err
}

func (s *runtimeHealthSource) Telemetry(context.Context) (domainhealth.Telemetry, error) {
	bus, batcher, sender := s.bus.Stats(), s.batcher.Stats(), s.sender.Stats()
	return domainhealth.Telemetry{
		Bus: domainhealth.Bus{
			EventCapacity: bus.EventCapacity, EventBuffered: bus.EventBuffered, EventSubscribers: bus.EventSubscribers,
			SignalCapacity: bus.SignalCapacity, SignalBuffered: bus.SignalBuffered, SignalSubscribers: bus.SignalSubscribers,
		},
		Batcher: domainhealth.Batcher{
			PendingEvents: batcher.PendingEvents, PendingSignals: batcher.PendingSignals, QueuedBatches: batcher.QueuedBatches,
			QueueCapacity: batcher.QueueCapacity, DroppedBatches: batcher.DroppedBatches, DroppedEvents: batcher.DroppedEvents,
			DroppedSignals: batcher.DroppedSignals, FlushedBatches: batcher.FlushedBatches, FlushedEvents: batcher.FlushedEvents,
			FlushedSignals: batcher.FlushedSignals, PendingBytes: batcher.PendingBytes, MaxBytes: batcher.MaxBytes,
			FlushedByCount: batcher.FlushedByCount, FlushedByBytes: batcher.FlushedByBytes,
			FlushedByInterval: batcher.FlushedByInterval, FlushedByShutdown: batcher.FlushedByShutdown,
			LastFlushReason: batcher.LastFlushReason, Closed: batcher.Closed, LastError: batcher.LastError,
		},
		Sender: domainhealth.Sender{
			SentBatches: sender.SentBatches, SentEvents: sender.SentEvents, SentSignals: sender.SentSignals,
			RejectedBatches: sender.RejectedBatches, RetriedBatches: sender.RetriedBatches, Drained: sender.Drained, LastError: sender.LastError,
		},
		Streams: domainhealth.Streams{
			EventCapacity: bus.EventCapacity, EventBuffered: bus.EventBuffered, EventNextSequence: bus.EventNextSequence,
			EventOldestSequence: bus.EventOldestSequence, EventNewestSequence: bus.EventNewestSequence,
			EventEvicted: bus.EventEvicted, EventSubscribers: bus.EventSubscribers,
			SignalCapacity: bus.SignalCapacity, SignalBuffered: bus.SignalBuffered, SignalNextSequence: bus.SignalNextSequence,
			SignalOldestSequence: bus.SignalOldestSequence, SignalNewestSequence: bus.SignalNewestSequence,
			SignalEvicted: bus.SignalEvicted, SignalSubscribers: bus.SignalSubscribers,
		},
	}, nil
}

func (s *runtimeHealthSource) Detection(ctx context.Context) (domainhealth.Detection, error) {
	status := s.health.detectionHealth()
	refs := make([]domainhealth.ContentRef, 0, len(status.ContentRefs))
	for _, ref := range status.ContentRefs {
		refs = append(refs, domainhealth.ContentRef{Ref: ref.Ref, Kind: ref.Kind, Version: ref.Version, Digest: ref.Digest})
	}
	metrics := s.health.policy.currentDetection().Metrics()
	profileMetrics := domainprocess.Metrics{}
	candidates := s.health.management.telemetry.candidateLifecycle.Snapshot()
	if s.health.profiles != nil {
		profileMetrics = s.health.profiles.Metrics()
	}
	degraded := metrics.EvictedCEPGroups > 0 || metrics.DroppedEventRefs > 0 || metrics.CEPEvalErrors > 0
	return domainhealth.Detection{
		PolicyID: status.PolicyID, PolicyVersion: status.PolicyVersion, ContentRefs: refs,
		DefaultManifestVersion: status.DefaultManifestVersion, MatcherStrategy: status.FeatureFlags.MatcherStrategy,
		LastApplyStatus: status.LastApplyStatus, LastApplyError: status.LastApplyError, UpdatedAt: status.UpdatedAt,
		Learning: domainhealth.Learning{
			Status: status.Learning.Status, LastError: status.Learning.LastError,
			Candidates: domainhealth.CandidateLifecycleHealth{
				Created: candidates.Created, Spooled: candidates.Spooled, GatewayAccepted: candidates.GatewayAccepted,
				GatewayDuplicateAck: candidates.GatewayDuplicateAck,
				ContractRejected:    candidates.ContractRejected, GatewayRejected: candidates.GatewayRejected,
				DeliveryAttempted: candidates.DeliveryAttempted, GatewayRetryable: candidates.GatewayRetryable,
				DeliveryErrors: candidates.DeliveryErrors, LastDeliveryError: candidates.LastDeliveryError,
			},
			Profiles: domainhealth.ProcessProfileHealth{
				Active: profileMetrics.Active, Exited: profileMetrics.Exited, Retained: profileMetrics.Retained,
				Compactions: profileMetrics.Compactions, Expired: profileMetrics.Expired, CapacityEvictions: profileMetrics.CapacityEvictions,
				FileEvictions: profileMetrics.FileEvictions, NetworkEvictions: profileMetrics.NetworkEvictions, EventRefEvictions: profileMetrics.EventRefEvictions,
				IdentityRetained: profileMetrics.IdentityRetained, IdentityEvictions: profileMetrics.IdentityEvictions, ActiveEvictions: profileMetrics.ActiveEvictions, IdentityGaps: profileMetrics.IdentityGaps,
				ProfileObservations: profileMetrics.ProfileObservations, FeatureUpdates: profileMetrics.FeatureUpdates, LearningScoreCalls: profileMetrics.LearningScoreCalls,
				LifecycleOnlyObservations: profileMetrics.LifecycleOnlyObservations, SuppressedCheckpoints: profileMetrics.SuppressedCheckpoints,
			},
		},
		CEP: domainhealth.CEP{ActiveGroups: metrics.ActiveCEPGroups, EvictedGroups: metrics.EvictedCEPGroups,
			ExpiredGroups: metrics.ExpiredCEPGroups, DroppedEventRefs: metrics.DroppedEventRefs,
			EvalErrors: metrics.CEPEvalErrors, EmittedSignals: metrics.EmittedSignals, Degraded: degraded},
	}, nil
}

func (s *runtimeHealthSource) Storage(ctx context.Context) (domainhealth.Storage, error) {
	if s.health.management.localStore == nil {
		return domainhealth.Storage{}, nil
	}
	stats, err := s.health.management.localStore.Stats(ctx)
	if err != nil {
		return domainhealth.Storage{}, err
	}
	identity, err := s.health.management.localStore.DeviceIdentity(ctx)
	if err != nil {
		return domainhealth.Storage{}, err
	}
	enrollment, err := s.health.management.localStore.Enrollment(ctx)
	if err != nil {
		return domainhealth.Storage{}, err
	}
	checkpoint, err := s.health.management.localStore.Checkpoint(ctx, enrollment.EnrollmentID)
	if err != nil {
		return domainhealth.Storage{}, err
	}
	return domainhealth.Storage{
		Available: true, Mode: string(enrollment.State), DeviceID: identity.DeviceID,
		StorageBytes: uint64(stats.StorageBytes), StorageMaxBytes: uint64(stats.StorageMaxBytes),
		OldestEventSequence: stats.OldestEventSequence, LatestEventSequence: stats.LatestEventSequence,
		SignalCount: stats.SignalCount, SealedSegmentCount: stats.SealedSegmentCount, OpenSegmentBytes: uint64(stats.OpenSegmentBytes),
		UploadSegmentID: checkpoint.SegmentID, UploadRecordOffset: checkpoint.RecordOffset,
		DroppedBatches: stats.DroppedBatchesStorage, DroppedEvents: stats.DroppedEventsStorage,
	}, nil
}

func (s *runtimeHealthSource) Lifecycle(ctx context.Context) (domainhealth.Lifecycle, error) {
	if s.health.management.localStore == nil {
		return domainhealth.Lifecycle{Mode: "standalone"}, nil
	}
	enrollment, err := s.health.management.localStore.Enrollment(ctx)
	if err != nil {
		return domainhealth.Lifecycle{}, err
	}
	mode, err := management.Resolve(enrollment.State)
	if err != nil {
		return domainhealth.Lifecycle{}, err
	}
	value := domainhealth.Lifecycle{
		Mode: string(mode.State), TransitionPhase: enrollment.TransitionPhase,
		RevocationConfirmed: enrollment.RevocationConfirmed, LastError: enrollment.LastTransitionError,
		UpdatedAt: enrollment.UpdatedAt,
	}
	completion, ok, err := s.health.management.localStore.UnenrollmentCompletion(ctx)
	if err != nil {
		return domainhealth.Lifecycle{}, err
	}
	if ok {
		switch completion.Status {
		case sqlite.CompletionPrepared:
			value.ManagerCompletionStatus = "revocation_pending"
		case sqlite.CompletionReady:
			value.ManagerCompletionStatus = "endpoint_completion_pending"
		}
		value.UpdatedAt = completion.UpdatedAt
		if completion.LastError != "" {
			value.LastError = completion.LastError
		}
	}
	value.TransitionPending = value.TransitionPhase != "" || value.ManagerCompletionStatus != ""
	return value, nil
}

func (r *sensorRuntime) domainCapability() domainhealth.Capability {
	collection := make([]domainhealth.CollectionCapability, 0, len(r.capability.Collection))
	for _, item := range r.capability.Collection {
		collection = append(collection, domainhealth.CollectionCapability{
			Behavior: item.Behavior, SensorMapping: item.SensorMapping, Fields: append([]string(nil), item.Fields...),
			PushdownSelectors: append([]string(nil), item.PushdownSelectors...), AgentSideSelectors: append([]string(nil), item.AgentSideSelectors...),
			UnsupportedSelectors: append([]string(nil), item.UnsupportedSelectors...),
		})
	}
	return domainhealth.Capability{
		Backend: r.capability.Backend, Version: r.capability.Version, SupportsExec: r.capability.SupportsExec,
		SupportsConnect: r.capability.SupportsConnect, SupportsFile: r.capability.SupportsFile,
		SupportsEnforce: r.capability.SupportsEnforce, SupportsHealth: r.capability.SupportsHealth,
		KernelRelease: r.capability.KernelRelease, BTFAvailable: r.capability.BTFAvailable,
		BPFFSAvailable: r.capability.BPFFSAvailable, Collection: collection,
	}
}
