package enrollment

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sqlite"
)

func TestCompletionEndpointTransportPolicy(t *testing.T) {
	tests := []struct {
		name, base, want string
		allowInsecure    bool
		wantErr          bool
	}{
		{name: "https", base: "https://manager.example/control/", want: "https://manager.example/control/api/v1/unenrollment-completions"},
		{name: "localhost http", base: "http://localhost:8080", want: "http://localhost:8080/api/v1/unenrollment-completions"},
		{name: "IPv4 loopback http", base: "http://127.0.0.1:8080", want: "http://127.0.0.1:8080/api/v1/unenrollment-completions"},
		{name: "IPv6 loopback http", base: "http://[::1]:8080", want: "http://[::1]:8080/api/v1/unenrollment-completions"},
		{name: "remote http rejected", base: "http://manager.example", wantErr: true},
		{name: "remote http explicitly allowed", base: "http://manager.example", allowInsecure: true, want: "http://manager.example/api/v1/unenrollment-completions"},
		{name: "userinfo rejected", base: "https://user:password@manager.example", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := CompletionEndpoint(test.base, test.allowInsecure)
			if (err != nil) != test.wantErr || got != test.want {
				t.Fatalf("endpoint=%q err=%v, want=%q wantErr=%t", got, err, test.want, test.wantErr)
			}
		})
	}
}

func TestCompletionClientDoesNotFollowRedirect(t *testing.T) {
	var redirected atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Add(1) }))
	defer target.Close()
	manager := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, target.URL, http.StatusTemporaryRedirect)
	}))
	defer manager.Close()

	err := ReportCompletion(t.Context(), testCompletion(manager.URL), false, time.Second)
	if err == nil || !strings.Contains(err.Error(), "HTTP 307") || redirected.Load() != 0 {
		t.Fatalf("report error=%v redirected=%d", err, redirected.Load())
	}
}

func TestCompletionClientBoundsAndRedactsErrors(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{name: "HTTP rejection", status: http.StatusUnauthorized, body: "manager-sensitive-response"},
		{name: "oversized response", status: http.StatusOK, body: strings.Repeat("x", maxUnenrollmentCompletionResponse+1)},
		{name: "invalid JSON", status: http.StatusOK, body: "manager-sensitive-response"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manager := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer manager.Close()
			completion := testCompletion(manager.URL)
			err := ReportCompletion(t.Context(), completion, false, time.Second)
			if err == nil {
				t.Fatal("report error = nil")
			}
			for _, secret := range []string{completion.Token, test.body} {
				if secret != "" && strings.Contains(err.Error(), secret) {
					t.Fatalf("error leaks sensitive value: %v", err)
				}
			}
		})
	}
}

func testCompletion(managerURL string) sqlite.UnenrollmentCompletion {
	return sqlite.UnenrollmentCompletion{
		TenantID: "tenant-a", AgentID: "agent-a", EnrollmentID: "enroll-a",
		CertificateSerial: "42", ManagerURL: managerURL, RevocationReceipt: "receipt-a",
		Token: "completion-secret-token", Status: sqlite.CompletionReady,
	}
}
