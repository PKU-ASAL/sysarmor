package artifact

import (
	"net/http"
	"strings"

	artifactapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/artifact"
	domainartifact "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/artifact"
)

func (handler *Handler) Artifacts(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodPost {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	requestContext, ok := handler.resolve(writer, request)
	if !ok {
		return
	}
	if request.Method == http.MethodPost {
		handler.upload(writer, request, requestContext)
		return
	}
	query := artifactapp.ArtifactQuery{Kind: strings.TrimSpace(request.URL.Query().Get("kind")),
		Status: domainartifact.Status(strings.TrimSpace(request.URL.Query().Get("status")))}
	values, err := handler.options.Service.ListArtifacts(request.Context(), requestContext, query)
	if err != nil {
		writeFailure(writer, err)
		return
	}
	writeJSON(writer, map[string]any{"artifacts": mapArtifacts(values)})
}
