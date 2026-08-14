package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sqlite"
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/policy"
)

const endpointPolicyKind = "endpoint"

func ParseEndpointPolicy(document []byte) (domainpolicy.EndpointPolicy, error) {
	return DecodeEndpointPolicy(document)
}

func LoadEffectiveEndpointPolicy(ctx context.Context, store *sqlite.Store, path string) (domainpolicy.EndpointPolicy, error) {
	if store == nil {
		return domainpolicy.EndpointPolicy{}, fmt.Errorf("local store is required")
	}
	if record, _, ok, err := store.ActivePolicy(ctx, endpointPolicyKind); err != nil {
		return domainpolicy.EndpointPolicy{}, err
	} else if ok {
		return ParseEndpointPolicy(record.Document)
	}
	if record, ok, err := store.Policy(ctx, endpointPolicyKind); err != nil {
		return domainpolicy.EndpointPolicy{}, err
	} else if ok {
		return ParseEndpointPolicy(record.Document)
	}
	document, err := os.ReadFile(path)
	if err != nil {
		return domainpolicy.EndpointPolicy{}, fmt.Errorf("read bootstrap policy: %w", err)
	}
	policy, err := ParseEndpointPolicy(document)
	if err != nil {
		return domainpolicy.EndpointPolicy{}, err
	}
	if err := SaveEffectiveEndpointPolicy(ctx, store, policy); err != nil {
		return domainpolicy.EndpointPolicy{}, fmt.Errorf("persist bootstrap policy: %w", err)
	}
	return policy, nil
}

func SaveEffectiveEndpointPolicy(ctx context.Context, store *sqlite.Store, policy domainpolicy.EndpointPolicy) error {
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

func ActivateManagedEndpointPolicy(ctx context.Context, store *sqlite.Store, policy domainpolicy.EndpointPolicy) error {
	record, err := endpointPolicyRecord(policy)
	if err != nil {
		return err
	}
	return store.ActivateManagedPolicy(ctx, record)
}

func SaveDesiredManagedEndpointPolicy(ctx context.Context, store *sqlite.Store, policy domainpolicy.EndpointPolicy) error {
	record, err := endpointPolicyRecord(policy)
	if err != nil {
		return err
	}
	return store.PutDesiredManagedPolicy(ctx, record)
}

func LoadEndpointPolicy(ctx context.Context, store *sqlite.Store, source sqlite.PolicySource) (domainpolicy.EndpointPolicy, bool, error) {
	record, ok, err := store.PolicySlot(ctx, endpointPolicyKind, source)
	if err != nil || !ok {
		return domainpolicy.EndpointPolicy{}, ok, err
	}
	policy, err := ParseEndpointPolicy(record.Document)
	return policy, err == nil, err
}

func LoadActiveEndpointPolicy(ctx context.Context, store *sqlite.Store) (domainpolicy.EndpointPolicy, sqlite.PolicySource, error) {
	record, source, ok, err := store.ActivePolicy(ctx, endpointPolicyKind)
	if err != nil {
		return domainpolicy.EndpointPolicy{}, "", err
	}
	if !ok {
		return domainpolicy.EndpointPolicy{}, "", fmt.Errorf("active endpoint policy is not initialized")
	}
	policy, err := ParseEndpointPolicy(record.Document)
	return policy, source, err
}

func endpointPolicyRecord(policy domainpolicy.EndpointPolicy) (sqlite.PolicyRecord, error) {
	canonical, err := EncodeEndpointPolicy(policy)
	if err != nil {
		return sqlite.PolicyRecord{}, err
	}
	if _, err := ParseEndpointPolicy(canonical); err != nil {
		return sqlite.PolicyRecord{}, err
	}
	digest := sha256.Sum256(canonical)
	return sqlite.PolicyRecord{Kind: endpointPolicyKind, Version: policy.Version, Document: canonical, Digest: hex.EncodeToString(digest[:])}, nil
}
