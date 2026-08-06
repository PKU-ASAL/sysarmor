package control

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	controlmodel "github.com/sysarmor/sysarmor-next-project/packages/contracts/controlmodel"
	incidentv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/incident/v1"
	responsemodel "github.com/sysarmor/sysarmor-next-project/packages/response"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
	"google.golang.org/protobuf/encoding/protojson"
)

type recordingResponseRuntime struct {
	identity ResponseIdentity
	ack      contract.EnforcementAck
	err      error
	command  contract.EnforcementCmd
}

func (r *recordingResponseRuntime) ResponseIdentity() ResponseIdentity {
	return r.identity
}

func (r *recordingResponseRuntime) EnforceResponse(_ context.Context, command contract.EnforcementCmd) (contract.EnforcementAck, error) {
	r.command = command
	return r.ack, r.err
}

func TestResponseControllerObserveModeBindsEndpointIdentity(t *testing.T) {
	runtime := &recordingResponseRuntime{identity: ResponseIdentity{TenantID: "tenant-a", AgentID: "agent-a"}}
	ack := NewResponseController(runtime).ExecuteResponse(t.Context(), responsemodel.Command{
		ResponseID: "response-a", Action: "kill", Target: "process:42",
	})
	if !ack.Accepted || !ack.ObserveOnly || ack.Executed || ack.TenantID != "tenant-a" || ack.AgentID != "agent-a" {
		t.Fatalf("ack=%+v", ack)
	}
	if runtime.command.ID != "" {
		t.Fatalf("observe response reached enforcement runtime: %+v", runtime.command)
	}
}

func TestResponseControllerEnforcementFailureIsUnsupported(t *testing.T) {
	runtime := &recordingResponseRuntime{
		identity: ResponseIdentity{TenantID: "tenant-a", AgentID: "agent-a"},
		err:      errors.New("sensor unavailable"),
	}
	ack := NewResponseController(runtime).ExecuteResponse(t.Context(), responsemodel.Command{
		ResponseID: "response-a", Mode: "enforce", Action: "kill", Target: "process:42",
	})
	if ack.Accepted || !ack.Unsupported || ack.Executed || ack.TenantID != "tenant-a" || ack.AgentID != "agent-a" {
		t.Fatalf("ack=%+v", ack)
	}
	if runtime.command.ID != "response-a" || runtime.command.Action != "kill" || runtime.command.Target != "process:42" {
		t.Fatalf("enforcement command=%+v", runtime.command)
	}
}

func TestResponseControllerCollectEvidenceBuildsSubgraph(t *testing.T) {
	runtime := &recordingResponseRuntime{identity: ResponseIdentity{TenantID: "tenant-a", AgentID: "agent-a"}}
	result := NewResponseController(runtime).CollectEvidence(t.Context(), controlmodel.EvidencePullbackRequest{
		RequestID: "request-a", Target: "process:42",
	})
	if !result.OK || result.TenantID != "tenant-a" || result.AgentID != "agent-a" || !json.Valid(result.Evidence) {
		t.Fatalf("result=%+v", result)
	}
	var evidence incidentv1.EvidenceSubgraph
	if err := protojson.Unmarshal(result.Evidence, &evidence); err != nil {
		t.Fatal(err)
	}
	if len(evidence.GetNodes()) != 1 || evidence.GetNodes()[0].GetKind() != "process" {
		t.Fatalf("evidence=%+v", evidence.GetNodes())
	}
}
