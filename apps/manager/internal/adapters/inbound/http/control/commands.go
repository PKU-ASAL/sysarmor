package control

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	controlapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/control"
	domaincontrol "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/control"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
)

func (handler *Handler) listCommands(writer http.ResponseWriter, request *http.Request, requestContext managerapp.RequestContext) {
	query := request.URL.Query()
	values, err := handler.options.Query.Commands(request.Context(), requestContext, controlapp.CommandQuery{
		AgentID: query.Get("agent_id"), Type: domaincontrol.CommandType(query.Get("type")),
	})
	if err != nil {
		writeFailure(writer, err)
		return
	}
	documents := make([]commandDocument, 0, len(values))
	for _, value := range values {
		documents = append(documents, mapCommand(value))
	}
	writeJSON(writer, documents)
}

func (handler *Handler) writeCommand(writer http.ResponseWriter, request *http.Request, requestContext managerapp.RequestContext) {
	var body commandRequest
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
		writeFailure(writer, failure.New(failure.InvalidArgument, fmt.Sprintf("decode control command: %v", err)))
		return
	}
	if strings.TrimSpace(body.Action) != "" {
		handler.act(writer, request, requestContext, body)
		return
	}
	command, err := handler.createCommand(request, requestContext, body)
	if err != nil {
		writeFailure(writer, err)
		return
	}
	result, err := handler.options.Management.CreateCommand(request.Context(), requestContext, command)
	if err != nil {
		writeFailure(writer, err)
		return
	}
	writeJSON(writer, mapCommand(result))
}

func (handler *Handler) createCommand(request *http.Request, requestContext managerapp.RequestContext, body commandRequest) (controlapp.CreateCommand, error) {
	command := controlapp.CreateCommand{CommandID: body.CommandID, TenantID: body.TenantID, AgentID: body.AgentID,
		Type: domaincontrol.CommandType(strings.TrimSpace(body.Type)), PolicyID: body.PolicyID,
		PolicyVersion: body.PolicyVersion, ContentRef: body.ContentRef, ContentKind: body.ContentKind,
		ContentVersion: body.ContentVersion, Payload: append([]byte(nil), body.Payload...), Reason: body.Reason}
	if command.Type == domaincontrol.CommandTypeContentUpdate {
		if len(command.Payload) == 0 {
			return controlapp.CreateCommand{}, failure.New(failure.InvalidArgument, "payload_json is required for content_update")
		}
		fillContentMetadata(&command)
	}
	if command.Type == domaincontrol.CommandTypePolicyUpdate && len(command.Payload) != 0 {
		fillPolicyMetadata(&command)
	}
	if command.Type != domaincontrol.CommandTypePolicyUpdate || len(command.Payload) != 0 {
		return command, nil
	}
	if strings.TrimSpace(command.PolicyID) == "" || handler.options.Policies == nil {
		return controlapp.CreateCommand{}, failure.New(failure.InvalidArgument, "policy_id or payload_json is required for policy_update")
	}
	payload, policyID, version, err := handler.options.Policies.Resolve(request.Context(), requestContext, command.PolicyID, command.PolicyVersion)
	command.Payload, command.PolicyID, command.PolicyVersion = payload, policyID, version
	return command, err
}

func fillPolicyMetadata(command *controlapp.CreateCommand) {
	var document struct {
		PolicyID string `json:"policy_id"`
		Version  uint64 `json:"version"`
	}
	_ = json.Unmarshal(command.Payload, &document)
	if command.PolicyID == "" {
		command.PolicyID = document.PolicyID
	}
	if command.PolicyVersion == 0 {
		command.PolicyVersion = document.Version
	}
}

func (handler *Handler) act(writer http.ResponseWriter, request *http.Request, requestContext managerapp.RequestContext, body commandRequest) {
	if strings.TrimSpace(body.CommandID) == "" {
		writeFailure(writer, failure.New(failure.InvalidArgument, "command_id is required"))
		return
	}
	result, err := handler.options.Management.Act(request.Context(), requestContext, controlapp.ActionCommand{
		TenantID: body.TenantID, CommandID: body.CommandID, AgentID: body.AgentID,
		Action: controlapp.Action(strings.TrimSpace(body.Action)), Reason: body.Reason,
	})
	if err != nil {
		writeFailure(writer, err)
		return
	}
	writeJSON(writer, mapCommand(result))
}

func fillContentMetadata(command *controlapp.CreateCommand) {
	var document struct {
		Kind     string `json:"kind"`
		Metadata struct {
			ID      string `json:"id"`
			Version string `json:"version"`
		} `json:"metadata"`
	}
	_ = json.Unmarshal(command.Payload, &document)
	if command.ContentRef == "" {
		command.ContentRef = document.Metadata.ID
	}
	if command.ContentKind == "" {
		command.ContentKind = document.Kind
	}
	if command.ContentVersion == "" {
		command.ContentVersion = document.Metadata.Version
	}
}
