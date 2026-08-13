package enrollment

import (
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

	enrollmentapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/enrollment"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
)

func (handler *Handler) Artifact(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := enrollmentAuthorizationToken(request)
	if token == "" {
		http.NotFound(writer, request)
		return
	}
	result, err := handler.artifact.Authorize(request.Context(), enrollmentapp.AuthorizeArtifactCommand{
		TokenHash: hashToken(token),
	})
	if err != nil {
		writeArtifactError(writer, request, err)
		return
	}
	artifact := result.Artifact
	writer.Header().Set("X-SysArmor-Artifact-ID", artifact.ID)
	writer.Header().Set("X-SysArmor-Artifact-SHA256", artifact.SHA256)
	if artifact.StoragePath != "" {
		if !pathWithinArtifactDir(handler.artifactDir, artifact.StoragePath) {
			http.Error(writer, "artifact storage path is invalid", http.StatusInternalServerError)
			return
		}
		http.ServeFile(writer, request, artifact.StoragePath)
		return
	}
	if target, ok := externalArtifactURL(artifact.DownloadURL); ok {
		http.Redirect(writer, request, target, http.StatusFound)
		return
	}
	http.NotFound(writer, request)
}

func enrollmentAuthorizationToken(request *http.Request) string {
	const prefix = "Enrollment "
	value := strings.TrimSpace(request.Header.Get("Authorization"))
	if !strings.HasPrefix(value, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(value, prefix))
}

func pathWithinArtifactDir(root, path string) bool {
	root, path = strings.TrimSpace(root), strings.TrimSpace(path)
	if root == "" || path == "" {
		return false
	}
	rootAbs, rootErr := filepath.Abs(root)
	pathAbs, pathErr := filepath.Abs(path)
	if rootErr != nil || pathErr != nil {
		return false
	}
	relative, err := filepath.Rel(rootAbs, pathAbs)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func externalArtifactURL(raw string) (string, bool) {
	target, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !target.IsAbs() || target.Host == "" || target.Scheme != "http" && target.Scheme != "https" {
		return "", false
	}
	return target.String(), true
}

func writeArtifactError(writer http.ResponseWriter, request *http.Request, err error) {
	switch failure.KindOf(err) {
	case failure.NotFound, failure.Conflict:
		http.NotFound(writer, request)
	case failure.FailedPrecondition:
		http.Error(writer, "enrollment expired", http.StatusGone)
	default:
		http.Error(writer, "authorize enrollment artifact", http.StatusInternalServerError)
	}
}
