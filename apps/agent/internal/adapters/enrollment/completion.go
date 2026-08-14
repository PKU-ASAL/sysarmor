package enrollment

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sqlite"
)

const maxUnenrollmentCompletionResponse = 16 << 10

func ReportCompletion(ctx context.Context, completion sqlite.UnenrollmentCompletion, allowInsecure bool, timeout time.Duration) error {
	endpoint, err := CompletionEndpoint(completion.ManagerURL, allowInsecure)
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]string{
		"schema_version": "sysarmor.unenrollment-completion/v1", "tenant_id": completion.TenantID,
		"agent_id": completion.AgentID, "enrollment_id": completion.EnrollmentID,
		"certificate_serial": completion.CertificateSerial, "revocation_receipt": completion.RevocationReceipt,
		"completion_token": completion.Token,
	})
	if err != nil {
		return fmt.Errorf("encode unenrollment completion: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create unenrollment completion request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("send unenrollment completion: %w", err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxUnenrollmentCompletionResponse+1))
	if err != nil || len(raw) > maxUnenrollmentCompletionResponse {
		return fmt.Errorf("read unenrollment completion response")
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("manager rejected unenrollment completion: HTTP %d", response.StatusCode)
	}
	var result struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(raw, &result); err != nil || result.Status != "endpoint_completed" {
		return fmt.Errorf("manager unenrollment completion response is invalid")
	}
	return nil
}

func CompletionEndpoint(base string, allowInsecure bool) (string, error) {
	base, err := normalizeManagerURL(base)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	if u.Scheme == "http" && !allowInsecure && !loopbackHost(u.Hostname()) {
		return "", fmt.Errorf("unenrollment completion requires HTTPS for non-loopback manager")
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/api/v1/unenrollment-completions"
	return u.String(), nil
}

func loopbackHost(host string) bool {
	if strings.EqualFold(strings.TrimSpace(host), "localhost") {
		return true
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	return ip != nil && ip.IsLoopback()
}
