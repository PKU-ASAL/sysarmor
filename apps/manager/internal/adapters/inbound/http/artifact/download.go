package artifact

import (
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"

	domainartifact "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/artifact"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
)

const artifactDownloadURLMetadataKey = "download_url"

func (handler *Handler) download(writer http.ResponseWriter, request *http.Request, id string) {
	if request.Method != http.MethodGet {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	requestContext, ok := handler.resolve(writer, request)
	if !ok {
		return
	}
	artifact, err := handler.options.Service.GetArtifact(request.Context(), requestContext, id)
	if err != nil {
		writeFailure(writer, err)
		return
	}
	if artifact.Status == domainartifact.StatusRevoked {
		http.NotFound(writer, request)
		return
	}
	if artifact.StoragePath == "" {
		handler.redirectExternal(writer, request, artifact)
		return
	}
	if handler.options.Content == nil {
		writeFailure(writer, failure.New(failure.Internal, "artifact content reader is not configured"))
		return
	}
	content, err := handler.options.Content.Open(request.Context(), artifact.StoragePath)
	if err != nil {
		writeFailure(writer, err)
		return
	}
	defer content.Content.Close()
	writer.Header().Set("X-SysArmor-Artifact-ID", artifact.ID)
	writer.Header().Set("X-SysArmor-Artifact-SHA256", artifact.SHA256)
	http.ServeContent(writer, request, content.Name, content.ModTime, content.Content)
}

func (handler *Handler) redirectExternal(writer http.ResponseWriter, request *http.Request, artifact domainartifact.Artifact) {
	downloadURL := ""
	if artifact.Metadata != nil {
		downloadURL = strings.TrimSpace(artifact.Metadata[artifactDownloadURLMetadataKey])
	}
	if downloadURL == "" {
		http.Error(writer, "artifact has no storage path", http.StatusNotFound)
		return
	}
	http.Redirect(writer, request, rewritePackageDownloadURL(downloadURL), http.StatusFound)
}

func rewritePackageDownloadURL(downloadURL string) string {
	base := strings.TrimSpace(os.Getenv("SYSARMOR_AGENT_PACKAGE_DOWNLOAD_BASE_URL"))
	if base == "" {
		return downloadURL
	}
	parsed, err := url.Parse(downloadURL)
	if err != nil || parsed.Path == "" {
		return downloadURL
	}
	return strings.TrimRight(base, "/") + "/" + path.Base(parsed.Path)
}
