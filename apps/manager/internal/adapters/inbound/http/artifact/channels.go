package artifact

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	artifactapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/artifact"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
)

func (handler *Handler) Channels(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodPost {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	requestContext, ok := handler.resolve(writer, request)
	if !ok {
		return
	}
	if request.Method == http.MethodGet {
		handler.listChannels(writer, request, requestContext)
		return
	}
	handler.createChannel(writer, request, requestContext)
}

func (handler *Handler) listChannels(writer http.ResponseWriter, request *http.Request, requestContext managerapp.RequestContext) {
	values, err := handler.options.Service.ListChannels(request.Context(), requestContext)
	if err != nil {
		writeFailure(writer, err)
		return
	}
	writeJSON(writer, map[string]any{"channels": mapChannels(values)})
}

func (handler *Handler) createChannel(writer http.ResponseWriter, request *http.Request, requestContext managerapp.RequestContext) {
	var body channelRequest
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
		writeFailure(writer, failure.New(failure.InvalidArgument, fmt.Sprintf("decode channel: %v", err)))
		return
	}
	body.Name, body.ArtifactID = strings.TrimSpace(body.Name), strings.TrimSpace(body.ArtifactID)
	if body.Name == "" || body.ArtifactID == "" {
		writeFailure(writer, failure.New(failure.InvalidArgument, "channel and artifact_id are required"))
		return
	}
	channel, err := handler.options.Service.SetChannel(request.Context(), requestContext,
		artifactapp.SetChannelCommand{Name: body.Name, ArtifactID: body.ArtifactID})
	if err != nil {
		writeFailure(writer, err)
		return
	}
	artifact, err := handler.options.Service.GetArtifact(request.Context(), requestContext, channel.ArtifactID)
	if err != nil {
		writeFailure(writer, err)
		return
	}
	writeJSON(writer, map[string]any{"channel": mapChannel(channel), "artifact": mapArtifact(artifact)})
}
