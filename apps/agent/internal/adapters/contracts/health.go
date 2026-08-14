package contracts

import (
	domainhealth "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/health"
	agenthealth "github.com/sysarmor/sysarmor-next-project/packages/contracts/health"
)

func AgentHealth(value domainhealth.Snapshot) agenthealth.AgentHealth {
	return agenthealth.AgentHealth{
		AgentID: value.AgentID, HostID: value.HostID, TenantID: value.TenantID,
		Scope:  agenthealth.RuntimeScope{Type: value.ScopeType, Selector: value.ScopeSelector},
		Status: string(value.Status), PolicyID: value.PolicyID, PolicyVersion: value.PolicyVersion,
		PolicyMode: value.PolicyMode, PendingPolicy: pendingPolicy(value.PendingPolicy),
		UptimeSeconds: value.UptimeSeconds, Capability: SensorCapability(value.Capability),
		Sensor: sensorHealth(value.Sensor), TelemetryBus: busHealth(value.Telemetry.Bus),
		TelemetryBatcher: batcherHealth(value.Telemetry.Batcher), TelemetrySender: senderHealth(value.Telemetry.Sender),
		Detection: detectionHealth(value.Detection), CEP: cepHealth(value.Detection.CEP),
		Streams: streamHealth(value.Telemetry.Streams), ObservedAt: value.ObservedAt,
	}
}

func pendingPolicy(value domainhealth.PendingPolicy) agenthealth.PendingPolicyStatus {
	return agenthealth.PendingPolicyStatus{
		Status: value.Status, Source: value.Source, PolicyID: value.PolicyID, Version: value.Version, Digest: value.Digest,
	}
}

func SensorCapability(value domainhealth.Capability) agenthealth.SensorCapability {
	collection := make([]agenthealth.CollectionBehaviorCapability, 0, len(value.Collection))
	for _, item := range value.Collection {
		collection = append(collection, agenthealth.CollectionBehaviorCapability{
			Behavior: item.Behavior, SensorMapping: item.SensorMapping, Fields: cloneStrings(item.Fields),
			PushdownSelectors: cloneStrings(item.PushdownSelectors), AgentSideSelectors: cloneStrings(item.AgentSideSelectors),
			UnsupportedSelectors: cloneStrings(item.UnsupportedSelectors),
		})
	}
	return agenthealth.SensorCapability{
		Backend: value.Backend, Version: value.Version, SupportsExec: value.SupportsExec,
		SupportsConnect: value.SupportsConnect, SupportsFile: value.SupportsFile,
		SupportsEnforce: value.SupportsEnforce, SupportsHealth: value.SupportsHealth,
		KernelRelease: value.KernelRelease, BTFAvailable: value.BTFAvailable,
		BPFFSAvailable: value.BPFFSAvailable, Collection: collection,
	}
}

func sensorHealth(value domainhealth.Sensor) agenthealth.SensorHealth {
	return agenthealth.SensorHealth{
		Backend: value.Backend, Installed: value.Installed, Running: value.Running, Version: value.Version,
		PolicyLoaded: value.PolicyLoaded, EventsSeen: value.EventsSeen, EventsDropped: value.EventsDropped,
		ParseErrors: value.ParseErrors, RestartCount: value.RestartCount, LastEventAt: value.LastEventAt,
		LastExitReason: value.LastExitReason, LastError: value.LastError,
	}
}

func busHealth(value domainhealth.Bus) agenthealth.TelemetryBusHealth {
	return agenthealth.TelemetryBusHealth{
		EventCapacity: value.EventCapacity, EventBuffered: value.EventBuffered, EventDropped: value.EventDropped,
		EventSubscribers: value.EventSubscribers, SignalCapacity: value.SignalCapacity,
		SignalBuffered: value.SignalBuffered, SignalDropped: value.SignalDropped, SignalSubscribers: value.SignalSubscribers,
	}
}

func batcherHealth(value domainhealth.Batcher) agenthealth.TelemetryBatcherHealth {
	return agenthealth.TelemetryBatcherHealth{
		PendingEvents: value.PendingEvents, PendingSignals: value.PendingSignals, QueuedBatches: value.QueuedBatches,
		QueueCapacity: value.QueueCapacity, DroppedBatches: value.DroppedBatches, DroppedEvents: value.DroppedEvents,
		DroppedSignals: value.DroppedSignals, FlushedBatches: value.FlushedBatches, FlushedEvents: value.FlushedEvents,
		FlushedSignals: value.FlushedSignals, PendingBytes: value.PendingBytes, MaxBytes: value.MaxBytes,
		FlushedByCount: value.FlushedByCount, FlushedByBytes: value.FlushedByBytes,
		FlushedByInterval: value.FlushedByInterval, FlushedByShutdown: value.FlushedByShutdown,
		LastFlushReason: value.LastFlushReason, Closed: value.Closed, LastError: value.LastError,
	}
}

func senderHealth(value domainhealth.Sender) agenthealth.TelemetrySenderHealth {
	return agenthealth.TelemetrySenderHealth{
		SentBatches: value.SentBatches, SentEvents: value.SentEvents, SentSignals: value.SentSignals,
		RejectedBatches: value.RejectedBatches, RetriedBatches: value.RetriedBatches,
		Drained: value.Drained, LastError: value.LastError,
	}
}

func detectionHealth(value domainhealth.Detection) agenthealth.DetectionHealth {
	refs := make([]agenthealth.ContentRef, 0, len(value.ContentRefs))
	for _, ref := range value.ContentRefs {
		refs = append(refs, agenthealth.ContentRef{Ref: ref.Ref, Kind: ref.Kind, Version: ref.Version, Digest: ref.Digest})
	}
	return agenthealth.DetectionHealth{
		PolicyID: value.PolicyID, PolicyVersion: value.PolicyVersion, ContentRefs: refs,
		DefaultManifestVersion: value.DefaultManifestVersion,
		FeatureFlags:           agenthealth.RuntimeFeatureFlags{MatcherStrategy: value.MatcherStrategy},
		LastApplyStatus:        value.LastApplyStatus, LastApplyError: value.LastApplyError, UpdatedAt: value.UpdatedAt,
	}
}

func cepHealth(value domainhealth.CEP) agenthealth.CEPHealth {
	return agenthealth.CEPHealth{
		ActiveGroups: value.ActiveGroups, EvictedGroups: value.EvictedGroups, ExpiredGroups: value.ExpiredGroups,
		DroppedEventRefs: value.DroppedEventRefs, EvalErrors: value.EvalErrors,
		EmittedSignals: value.EmittedSignals, Degraded: value.Degraded,
	}
}

func streamHealth(value domainhealth.Streams) agenthealth.LocalStreamHealth {
	return agenthealth.LocalStreamHealth{
		EventCapacity: value.EventCapacity, EventBuffered: value.EventBuffered, EventNextSequence: value.EventNextSequence,
		EventOldestSequence: value.EventOldestSequence, EventNewestSequence: value.EventNewestSequence,
		EventEvicted: value.EventEvicted, EventSubscribers: value.EventSubscribers,
		SignalCapacity: value.SignalCapacity, SignalBuffered: value.SignalBuffered, SignalNextSequence: value.SignalNextSequence,
		SignalOldestSequence: value.SignalOldestSequence, SignalNewestSequence: value.SignalNewestSequence,
		SignalEvicted: value.SignalEvicted, SignalSubscribers: value.SignalSubscribers,
	}
}
