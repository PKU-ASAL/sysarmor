package managerapi

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

func artifactDownloadURL(request *http.Request, artifactID string) string {
	return absoluteURL(request, "/api/v1/artifacts/"+url.PathEscape(artifactID)+"/download")
}

func absoluteURL(request *http.Request, path string) string {
	if publicURL := strings.TrimSpace(os.Getenv("SYSARMOR_PUBLIC_URL")); publicURL != "" {
		if parsed, err := url.Parse(publicURL); err == nil && parsed.IsAbs() && parsed.Host != "" {
			return strings.TrimRight(publicURL, "/") + "/" + strings.TrimLeft(path, "/")
		}
	}
	scheme := "http"
	if request.TLS != nil {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s%s", scheme, request.Host, path)
}
