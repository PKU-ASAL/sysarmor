package policy

import (
	"encoding/json"
	"fmt"

	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/policy"
)

func DecodeDetectionDocument(document []byte) (domainpolicy.DetectionPolicy, error) {
	payload, err := nestedPolicySection(document, "detection")
	if err != nil {
		return domainpolicy.DetectionPolicy{}, fmt.Errorf("invalid detection policy json: %w", err)
	}
	var wire detectionWire
	if err := json.Unmarshal(payload, &wire); err != nil {
		return domainpolicy.DetectionPolicy{}, fmt.Errorf("invalid detection policy json: %w", err)
	}
	return *domainDetection(&wire), nil
}

func DecodeTelemetryDocument(document []byte) (domainpolicy.TelemetryPolicy, error) {
	payload, err := nestedPolicySection(document, "telemetry")
	if err != nil {
		return domainpolicy.TelemetryPolicy{}, fmt.Errorf("invalid telemetry policy json: %w", err)
	}
	var wire telemetryWire
	if err := json.Unmarshal(payload, &wire); err != nil {
		return domainpolicy.TelemetryPolicy{}, fmt.Errorf("invalid telemetry policy json: %w", err)
	}
	return *domainTelemetry(&wire), nil
}

func EncodeTelemetryDocument(value domainpolicy.TelemetryPolicy) ([]byte, error) {
	document, err := json.Marshal(wireTelemetry(value))
	if err != nil {
		return nil, fmt.Errorf("encode telemetry policy: %w", err)
	}
	return document, nil
}

func EncodeTelemetryEnvelope(value domainpolicy.TelemetryPolicy) ([]byte, error) {
	document, err := json.Marshal(struct {
		Telemetry *telemetryWire `json:"telemetry"`
	}{Telemetry: wireTelemetry(value)})
	if err != nil {
		return nil, fmt.Errorf("encode telemetry policy envelope: %w", err)
	}
	return document, nil
}

func nestedPolicySection(document []byte, section string) ([]byte, error) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(document, &envelope); err != nil {
		return nil, err
	}
	if nested, ok := envelope[section]; ok {
		return nested, nil
	}
	return document, nil
}
