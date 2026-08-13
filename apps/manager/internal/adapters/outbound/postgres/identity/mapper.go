package identity

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

func decodeAgent(tenantID tenant.ID, id, host, version string, document []byte) (domainidentity.Agent, error) {
	var fields struct {
		AuthType            string `json:"auth_type"`
		CertificateIdentity string `json:"cert_identity"`
	}
	if err := json.Unmarshal(document, &fields); err != nil {
		return domainidentity.Agent{}, fmt.Errorf("decode agent: %w", err)
	}
	return domainidentity.Agent{TenantID: tenantID, ID: domainidentity.AgentID(id), HostID: host, Version: version, AuthType: fields.AuthType, CertificateIdentity: fields.CertificateIdentity}, nil
}

func decodeHealth(tenantID tenant.ID, agentID domainidentity.AgentID, host, scopeType, scopeSelector string, observed time.Time, document []byte) (domainidentity.Health, error) {
	var fields struct {
		Status        string    `json:"status"`
		PolicyID      string    `json:"policyId"`
		PolicyVersion string    `json:"policyVersion"`
		ObservedAt    time.Time `json:"observedAt"`
		PendingPolicy struct {
			Status   string `json:"status"`
			Source   string `json:"source"`
			PolicyID string `json:"policyId"`
			Version  string `json:"version"`
			Digest   string `json:"digest"`
		} `json:"pendingPolicy"`
	}
	if err := json.Unmarshal(document, &fields); err != nil {
		return domainidentity.Health{}, fmt.Errorf("decode agent health: %w", err)
	}
	canonical := map[string]json.RawMessage{}
	if err := json.Unmarshal(document, &canonical); err != nil {
		return domainidentity.Health{}, fmt.Errorf("decode health document: %w", err)
	}
	canonical["tenantId"], _ = json.Marshal(tenantID.String())
	canonical["agentId"], _ = json.Marshal(string(agentID))
	delete(canonical, "tenant_id")
	delete(canonical, "agent_id")
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return domainidentity.Health{}, fmt.Errorf("encode health document: %w", err)
	}
	policyVersion, err := parseWireVersion("policyVersion", fields.PolicyVersion)
	if err != nil {
		return domainidentity.Health{}, err
	}
	pendingVersion, err := parseWireVersion("pendingPolicy.version", fields.PendingPolicy.Version)
	if err != nil {
		return domainidentity.Health{}, err
	}
	return domainidentity.Health{TenantID: tenantID, AgentID: agentID, HostID: host, Status: fields.Status,
		Scope: domainidentity.Scope{Type: scopeType, Selector: scopeSelector}, ObservedAt: observed, ReportedAt: fields.ObservedAt, Document: encoded,
		AppliedPolicy: domainidentity.PolicyRef{ID: fields.PolicyID, Version: policyVersion},
		PendingPolicy: domainidentity.PendingPolicy{Status: fields.PendingPolicy.Status, Source: fields.PendingPolicy.Source,
			ID: fields.PendingPolicy.PolicyID, Version: pendingVersion, Digest: fields.PendingPolicy.Digest}}, nil
}

func parseWireVersion(field, value string) (uint64, error) {
	if value == "" {
		return 0, nil
	}
	version, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %w", field, err)
	}
	return version, nil
}
