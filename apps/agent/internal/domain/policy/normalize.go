package policy

import "time"

func (value Policy) EndpointPolicy() EndpointPolicy {
	normalized := Normalize(value)
	collection := defaultCollectionPolicy()
	if normalized.Collection != nil {
		collection = *normalized.Collection
	}
	telemetry := defaultTelemetryPolicy()
	if normalized.Telemetry != nil {
		telemetry = *normalized.Telemetry
	}
	return EndpointPolicy{
		PolicyID: normalized.PolicyID, Version: normalized.Version,
		Collection: collection, Detection: *normalized.Detection,
		Telemetry: telemetry, Response: normalized.Response,
	}
}

func Normalize(value Policy) Policy {
	if value.TenantID == "" {
		value.TenantID = "default"
	}
	if value.Version == 0 {
		value.Version = 1
	}
	if value.Mode == "" {
		value.Mode = "observe"
	}
	if value.Detection == nil {
		value.Detection = DefaultDetectionPolicy()
	}
	detection := NormalizeDetectionPolicy(*value.Detection)
	value.Detection = &detection
	if value.Converge == nil {
		value.Converge = defaultConvergeParams()
	}
	if len(value.Response.AllowedActions) == 0 && len(value.Response.AllowedModes) == 0 {
		value.Response = defaultResponsePolicy()
	}
	now := time.Now().UTC()
	if value.CreatedAt.IsZero() {
		value.CreatedAt = now
	}
	value.UpdatedAt = now
	return value
}

func NormalizeDetectionPolicy(value DetectionPolicy) DetectionPolicy {
	if value.PolicyID == "" {
		value.PolicyID = "default-endpoint-detection"
	}
	if value.Version == 0 {
		value.Version = 1
	}
	if value.Mode == "" {
		value.Mode = "observe"
	}
	for index := range value.RuleSets {
		if value.RuleSets[index].Version == "" {
			value.RuleSets[index].Version = "latest"
		}
	}
	return value
}

func defaultCollectionPolicy() CollectionPolicy {
	return CollectionPolicy{
		Behaviors: []string{
			"process.exec", "file.read", "file.write", "file.chmod", "network.connect",
		},
		ObserveOnly: true,
	}
}

func defaultTelemetryPolicy() TelemetryPolicy {
	return TelemetryPolicy{
		MaxBatchItems: 256, MaxBatchBytes: 256 << 10, FlushInterval: "1s",
	}
}
