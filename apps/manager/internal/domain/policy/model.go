package policy

import (
	"strconv"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

type ID string
type Version uint64

const DefaultPolicyID ID = "default-edr-policy"

const defaultEndpointPolicySections = `"collection":{"behaviors":["process.exec","file.read","file.write","file.chmod","network.connect"],"observe_only":true},"detection":{"policy_id":"default-endpoint-detection","version":1,"mode":"observe","rulesets":[{"ref":"ruleset:cep-endpoint","version":"v1","enabled":true}]},"telemetry":{"max_batch_items":256,"max_batch_bytes":262144,"flush_interval":"1s"}`

const defaultResponsePolicy = `{"allowed_actions":["collect","noop"],"allowed_modes":["observe"]}`

const defaultManagerPolicy = `"cloud_rules":["dropped_payload_executed_and_connects","web_shell_chain"],"detectors":["rule-correlation-v1","provenance-shortest-path-v1","nodlink"],"converge":{"mode":"rarity_structural","cross_lineage":true,"top_k":8,"max_path_hops":6}`

type Policy struct {
	TenantID         tenant.ID
	ID               ID
	Version          Version
	Published        bool
	CreatedAt        time.Time
	UpdatedAt        time.Time
	Document         []byte
	DownlinkDocument []byte
}

type Target struct {
	AgentID       string
	ScopeType     string
	ScopeSelector string
}

type Assignment struct {
	ID            string
	TenantID      tenant.ID
	Target        Target
	PolicyID      ID
	PolicyVersion Version
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type Filter struct {
	PolicyID ID
}

type AssignmentFilter struct {
	AgentID string
}

type Rule struct {
	TenantID tenant.ID
	Where    string
	Document []byte
}

type RuleFilter struct{ Where string }

func ManagerDefault(tenantID tenant.ID) Policy {
	identity := `"policy_id":"default-edr-policy","version":1`
	document := `{"tenant_id":` + strconv.Quote(tenantID.String()) + `,` + identity + `,` +
		`"protection_mode":"rule-only",` + defaultEndpointPolicySections + `,` + defaultManagerPolicy +
		`,"response_policy":` + defaultResponsePolicy + `,"published":true}`
	downlink := `{` + identity + `,` + defaultEndpointPolicySections + `,"response":` + defaultResponsePolicy + `}`
	return Policy{
		TenantID: tenantID, ID: DefaultPolicyID, Version: 1, Published: true,
		Document: []byte(document), DownlinkDocument: []byte(downlink),
	}
}
