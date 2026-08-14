package policy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	contractmapper "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/contracts"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sqlite"
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/policy"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
	responsemodel "github.com/sysarmor/sysarmor-next-project/packages/response"
)

const endpointPolicyKind = "endpoint"

type EndpointPolicy = policymodel.EndpointPolicy

func ParseEndpointPolicy(document []byte) (EndpointPolicy, error) {
	var envelope struct {
		PolicyID   string                       `json:"policy_id"`
		Version    uint64                       `json:"version"`
		Collection json.RawMessage              `json:"collection"`
		Detection  *policymodel.DetectionPolicy `json:"detection"`
		Telemetry  *policymodel.TelemetryPolicy `json:"telemetry"`
		Response   *responsemodel.Policy        `json:"response"`
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return EndpointPolicy{}, fmt.Errorf("decode endpoint policy: %w", err)
	}
	collection, err := ParseCollectionPolicyJSON(envelope.Collection, true)
	if err != nil {
		return EndpointPolicy{}, err
	}
	candidate := domainpolicy.ActivationCandidate{
		Identity:   domainpolicy.Identity{ID: envelope.PolicyID, Version: envelope.Version},
		Collection: contractmapper.DomainCollectionPolicy(collection),
		Sections: domainpolicy.EndpointSections{
			Collection: len(envelope.Collection) > 0, Detection: envelope.Detection != nil,
			Telemetry: envelope.Telemetry != nil, Response: envelope.Response != nil,
		},
	}
	if err := candidate.Validate(); err != nil {
		return EndpointPolicy{}, err
	}
	response := *envelope.Response
	if len(response.AllowedActions) == 0 && len(response.AllowedModes) == 0 {
		response = responsemodel.DefaultPolicy()
	}
	return EndpointPolicy{PolicyID: envelope.PolicyID, Version: envelope.Version, Collection: collection,
		Detection: policymodel.NormalizeDetectionPolicy(*envelope.Detection), Telemetry: *envelope.Telemetry, Response: response}, nil
}

func LoadEffectiveEndpointPolicy(ctx context.Context, store *sqlite.Store, path string) (EndpointPolicy, error) {
	if store == nil {
		return EndpointPolicy{}, fmt.Errorf("local store is required")
	}
	if record, _, ok, err := store.ActivePolicy(ctx, endpointPolicyKind); err != nil {
		return EndpointPolicy{}, err
	} else if ok {
		return ParseEndpointPolicy(record.Document)
	}
	if record, ok, err := store.Policy(ctx, endpointPolicyKind); err != nil {
		return EndpointPolicy{}, err
	} else if ok {
		return ParseEndpointPolicy(record.Document)
	}
	document, err := os.ReadFile(path)
	if err != nil {
		return EndpointPolicy{}, fmt.Errorf("read bootstrap policy: %w", err)
	}
	policy, err := ParseEndpointPolicy(document)
	if err != nil {
		return EndpointPolicy{}, err
	}
	if err := SaveEffectiveEndpointPolicy(ctx, store, policy); err != nil {
		return EndpointPolicy{}, fmt.Errorf("persist bootstrap policy: %w", err)
	}
	return policy, nil
}

func SaveEffectiveEndpointPolicy(ctx context.Context, store *sqlite.Store, policy EndpointPolicy) error {
	record, err := endpointPolicyRecord(policy)
	if err != nil {
		return err
	}
	return store.PutAndActivateStandalonePolicy(ctx, record)
}

func EnsureStandaloneEndpointPolicy(ctx context.Context, store *sqlite.Store, path string) (bool, error) {
	if store == nil {
		return false, fmt.Errorf("local store is required")
	}
	if _, ok, err := store.PolicySlot(ctx, endpointPolicyKind, sqlite.PolicySourceStandalone); err != nil || ok {
		return false, err
	}
	document, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("read bootstrap policy: %w", err)
	}
	policy, err := ParseEndpointPolicy(document)
	if err != nil {
		return false, err
	}
	record, err := endpointPolicyRecord(policy)
	if err != nil {
		return false, err
	}
	if err := store.InitializeStandalonePolicy(ctx, record); err != nil {
		return false, fmt.Errorf("initialize standalone policy: %w", err)
	}
	return true, nil
}

func ActivateManagedEndpointPolicy(ctx context.Context, store *sqlite.Store, policy EndpointPolicy) error {
	record, err := endpointPolicyRecord(policy)
	if err != nil {
		return err
	}
	return store.ActivateManagedPolicy(ctx, record)
}

func SaveDesiredManagedEndpointPolicy(ctx context.Context, store *sqlite.Store, policy EndpointPolicy) error {
	record, err := endpointPolicyRecord(policy)
	if err != nil {
		return err
	}
	return store.PutDesiredManagedPolicy(ctx, record)
}

func LoadEndpointPolicy(ctx context.Context, store *sqlite.Store, source sqlite.PolicySource) (EndpointPolicy, bool, error) {
	record, ok, err := store.PolicySlot(ctx, endpointPolicyKind, source)
	if err != nil || !ok {
		return EndpointPolicy{}, ok, err
	}
	policy, err := ParseEndpointPolicy(record.Document)
	return policy, err == nil, err
}

func LoadActiveEndpointPolicy(ctx context.Context, store *sqlite.Store) (EndpointPolicy, sqlite.PolicySource, error) {
	record, source, ok, err := store.ActivePolicy(ctx, endpointPolicyKind)
	if err != nil {
		return EndpointPolicy{}, "", err
	}
	if !ok {
		return EndpointPolicy{}, "", fmt.Errorf("active endpoint policy is not initialized")
	}
	policy, err := ParseEndpointPolicy(record.Document)
	return policy, source, err
}

func endpointPolicyRecord(policy EndpointPolicy) (sqlite.PolicyRecord, error) {
	canonical, err := json.Marshal(policy)
	if err != nil {
		return sqlite.PolicyRecord{}, err
	}
	if _, err := ParseEndpointPolicy(canonical); err != nil {
		return sqlite.PolicyRecord{}, err
	}
	digest := sha256.Sum256(canonical)
	return sqlite.PolicyRecord{Kind: endpointPolicyKind, Version: policy.Version, Document: canonical, Digest: hex.EncodeToString(digest[:])}, nil
}
