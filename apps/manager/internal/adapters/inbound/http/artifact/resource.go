package artifact

import (
	"net/http"
	"strings"

	artifactapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/artifact"
	domainartifact "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/artifact"
)

func (handler *Handler) Artifact(writer http.ResponseWriter, request *http.Request) {
	parts := artifactPathParts(request.URL.Path)
	if len(parts) == 0 || len(parts) > 2 {
		http.NotFound(writer, request)
		return
	}
	if len(parts) == 1 {
		handler.getArtifact(writer, request, parts[0])
		return
	}
	if parts[1] == "download" {
		handler.download(writer, request, parts[0])
		return
	}
	if parts[1] != "activate" && parts[1] != "revoke" {
		http.NotFound(writer, request)
		return
	}
	handler.changeStatus(writer, request, parts[0], parts[1])
}

func (handler *Handler) getArtifact(writer http.ResponseWriter, request *http.Request, id string) {
	if request.Method != http.MethodGet {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	requestContext, ok := handler.resolve(writer, request)
	if !ok {
		return
	}
	value, err := handler.options.Service.GetArtifact(request.Context(), requestContext, id)
	if err != nil {
		writeFailure(writer, err)
		return
	}
	writeJSON(writer, mapArtifact(value))
}

func (handler *Handler) changeStatus(writer http.ResponseWriter, request *http.Request, id, action string) {
	if request.Method != http.MethodPost {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	requestContext, ok := handler.resolve(writer, request)
	if !ok {
		return
	}
	status := domainartifact.StatusRevoked
	if action == "activate" {
		status = domainartifact.StatusActive
	}
	value, err := handler.options.Service.ChangeStatus(request.Context(), requestContext,
		artifactapp.ChangeStatusCommand{ArtifactID: id, Status: status})
	if err != nil {
		writeFailure(writer, err)
		return
	}
	writeJSON(writer, mapArtifact(value))
}

func artifactPathParts(path string) []string {
	rest := strings.TrimPrefix(path, "/api/v1/artifacts/")
	if rest == path {
		return nil
	}
	rest = strings.Trim(rest, "/")
	if rest == "" {
		return nil
	}
	return strings.Split(rest, "/")
}
