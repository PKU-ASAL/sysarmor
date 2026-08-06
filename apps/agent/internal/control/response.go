package control

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	controlmodel "github.com/sysarmor/sysarmor-next-project/packages/contracts/controlmodel"
	incidentv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/incident/v1"
	responsemodel "github.com/sysarmor/sysarmor-next-project/packages/response"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
	"google.golang.org/protobuf/encoding/protojson"
)

type ResponseController interface {
	ExecuteResponse(context.Context, responsemodel.Command) responsemodel.Ack
	CollectEvidence(context.Context, controlmodel.EvidencePullbackRequest) controlmodel.EvidencePullbackResult
}

type ResponseIdentity struct {
	TenantID string
	AgentID  string
}

type ResponseRuntime interface {
	ResponseIdentity() ResponseIdentity
	EnforceResponse(context.Context, contract.EnforcementCmd) (contract.EnforcementAck, error)
}

type responseController struct {
	runtime ResponseRuntime
}

func NewResponseController(runtime ResponseRuntime) ResponseController {
	return &responseController{runtime: runtime}
}

func (c *responseController) ExecuteResponse(ctx context.Context, command responsemodel.Command) responsemodel.Ack {
	command = responsemodel.NormalizeCommand(command)
	identity := c.runtime.ResponseIdentity()
	if command.Mode != "enforce" {
		return responsemodel.Ack{
			ResponseID: command.ResponseID, TenantID: identity.TenantID, AgentID: identity.AgentID,
			Accepted: true, ObserveOnly: true,
			Message:    fmt.Sprintf("observe-only response accepted; would execute action=%s target=%s", command.Action, command.Target),
			ObservedAt: time.Now().UTC(),
		}
	}
	enforcement := responsemodel.ToEnforcement(command)
	ack, err := c.runtime.EnforceResponse(ctx, enforcement)
	if err != nil {
		ack = contract.UnsupportedAck(enforcement, err.Error())
	}
	out := responsemodel.FromEnforcementAck(command, ack)
	out.TenantID = identity.TenantID
	out.AgentID = identity.AgentID
	return out
}

func (c *responseController) CollectEvidence(_ context.Context, request controlmodel.EvidencePullbackRequest) controlmodel.EvidencePullbackResult {
	identity := c.runtime.ResponseIdentity()
	result := controlmodel.EvidencePullbackResult{
		RequestID: request.RequestID, TenantID: identity.TenantID, AgentID: identity.AgentID,
		OK: true, Message: "collected target evidence", ObservedAt: time.Now().UTC(),
	}
	if request.Target == "" {
		result.Message = "collected no target evidence"
		return result
	}
	evidence := &incidentv1.EvidenceSubgraph{Nodes: []*incidentv1.GraphNode{{
		Id: request.Target, Kind: evidenceKindFromTarget(request.Target), Label: request.Target,
	}}}
	data, err := protojson.Marshal(evidence)
	if err != nil {
		result.OK = false
		result.Message = fmt.Sprintf("encode evidence: %v", err)
		return result
	}
	result.Evidence = json.RawMessage(data)
	return result
}

func evidenceKindFromTarget(target string) string {
	if index := strings.Index(target, ":"); index > 0 {
		return target[:index]
	}
	return "entity"
}
