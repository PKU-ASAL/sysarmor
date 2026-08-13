package daemon

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	agentpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/policy"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/localstore"
)

func TestCompletionReporterRetriesReadyOutboxAfterRestart(t *testing.T) {
	store := coordinatorManagedStore(t)
	if _, err := store.PrepareUnenrollment(t.Context(), "completion-token", strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if err := store.ConfirmEnrollmentRevocation(t.Context(), "receipt-a", time.Unix(100, 0).UTC()); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteUnenrollment(t.Context(), "endpoint"); err != nil {
		t.Fatal(err)
	}
	var attempts atomic.Int32
	failing := newUnenrollmentCompletionReporter(store, func(context.Context, localstore.UnenrollmentCompletion) error {
		attempts.Add(1)
		return errors.New("manager unavailable")
	}, time.Millisecond, 10*time.Millisecond)
	if sent, err := failing.ReportOnce(t.Context()); err == nil || sent {
		t.Fatalf("first report sent=%t err=%v", sent, err)
	}
	completion, ok, err := store.UnenrollmentCompletion(t.Context())
	if err != nil || !ok || completion.AttemptCount != 1 || completion.LastError == "" {
		t.Fatalf("completion=%+v ok=%t err=%v", completion, ok, err)
	}

	restarted := newUnenrollmentCompletionReporter(store, func(context.Context, localstore.UnenrollmentCompletion) error {
		attempts.Add(1)
		return nil
	}, time.Millisecond, 10*time.Millisecond)
	if sent, err := restarted.ReportOnce(t.Context()); err != nil || !sent {
		t.Fatalf("restart report sent=%t err=%v", sent, err)
	}
	if _, ok, err := store.UnenrollmentCompletion(t.Context()); err != nil || ok || attempts.Load() != 2 {
		t.Fatalf("completion remains=%t attempts=%d err=%v", ok, attempts.Load(), err)
	}
}

func TestCompletionReporterRecoversReadyOutboxAfterStoreReopen(t *testing.T) {
	root := t.TempDir()
	store, err := localstore.Open(t.Context(), localstore.Options{RootDir: root})
	if err != nil {
		t.Fatal(err)
	}
	if err := agentpolicy.SaveEffectiveEndpointPolicy(t.Context(), store, parseEndpointPolicy(t, standaloneEndpointPolicyJSON)); err != nil {
		t.Fatal(err)
	}
	setManagedEnrollmentForTest(t, store)
	if _, err := store.PrepareUnenrollment(t.Context(), "completion-token", strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if err := store.ConfirmEnrollmentRevocation(t.Context(), "receipt-a", time.Unix(100, 0).UTC()); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteUnenrollment(t.Context(), "endpoint"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := localstore.Open(t.Context(), localstore.Options{RootDir: root})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reporter := newUnenrollmentCompletionReporter(reopened, func(context.Context, localstore.UnenrollmentCompletion) error {
		return nil
	}, time.Millisecond, 10*time.Millisecond)
	if sent, err := reporter.ReportOnce(t.Context()); err != nil || !sent {
		t.Fatalf("reopened report sent=%t err=%v", sent, err)
	}
	if _, ok, err := reopened.UnenrollmentCompletion(t.Context()); err != nil || ok {
		t.Fatalf("completion remains after reopened report: ok=%t err=%v", ok, err)
	}
}

func TestUnenrollmentCompletionEndpointTransportPolicy(t *testing.T) {
	tests := []struct {
		name          string
		base          string
		allowInsecure bool
		want          string
		wantErr       bool
	}{
		{name: "https", base: "https://manager.example/control/", want: "https://manager.example/control/api/v1/unenrollment-completions"},
		{name: "localhost http", base: "http://localhost:8080", want: "http://localhost:8080/api/v1/unenrollment-completions"},
		{name: "IPv4 loopback http", base: "http://127.0.0.1:8080", want: "http://127.0.0.1:8080/api/v1/unenrollment-completions"},
		{name: "IPv6 loopback http", base: "http://[::1]:8080", want: "http://[::1]:8080/api/v1/unenrollment-completions"},
		{name: "remote http rejected", base: "http://manager.example", wantErr: true},
		{name: "remote http explicitly allowed", base: "http://manager.example", allowInsecure: true, want: "http://manager.example/api/v1/unenrollment-completions"},
		{name: "userinfo rejected", base: "https://user:password@manager.example", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := unenrollmentCompletionEndpoint(tt.base, tt.allowInsecure)
			if (err != nil) != tt.wantErr || got != tt.want {
				t.Fatalf("endpoint=%q err=%v, want=%q wantErr=%t", got, err, tt.want, tt.wantErr)
			}
		})
	}
}

func TestUnenrollmentCompletionClientDoesNotFollowRedirect(t *testing.T) {
	var redirected atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected.Add(1)
	}))
	defer target.Close()
	manager := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, target.URL, http.StatusTemporaryRedirect)
	}))
	defer manager.Close()

	err := reportUnenrollmentCompletionOnline(t.Context(), testUnenrollmentCompletion(manager.URL), false, time.Second)
	if err == nil || !strings.Contains(err.Error(), "HTTP 307") {
		t.Fatalf("report error=%v, want HTTP 307 rejection", err)
	}
	if redirected.Load() != 0 {
		t.Fatalf("redirect target calls=%d, want 0", redirected.Load())
	}
}

func TestUnenrollmentCompletionClientBoundsAndRedactsErrors(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{name: "HTTP rejection", status: http.StatusUnauthorized, body: "manager-sensitive-response"},
		{name: "oversized response", status: http.StatusOK, body: strings.Repeat("x", maxUnenrollmentCompletionResponse+1)},
		{name: "invalid JSON", status: http.StatusOK, body: "manager-sensitive-response"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer manager.Close()
			completion := testUnenrollmentCompletion(manager.URL)
			err := reportUnenrollmentCompletionOnline(t.Context(), completion, false, time.Second)
			if err == nil {
				t.Fatal("report error = nil")
			}
			for _, secret := range []string{completion.Token, tt.body} {
				if secret != "" && strings.Contains(err.Error(), secret) {
					t.Fatalf("error leaks sensitive value: %v", err)
				}
			}
		})
	}
}

func testUnenrollmentCompletion(managerURL string) localstore.UnenrollmentCompletion {
	return localstore.UnenrollmentCompletion{
		TenantID: "tenant-a", AgentID: "agent-a", EnrollmentID: "enroll-a",
		CertificateSerial: "42", ManagerURL: managerURL, RevocationReceipt: "receipt-a",
		Token: "completion-secret-token", Status: localstore.CompletionReady,
	}
}

func TestHealthReportsCompletionOutboxLifecycle(t *testing.T) {
	store := coordinatorManagedStore(t)
	if _, err := store.PrepareUnenrollment(t.Context(), "completion-token", strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	runner := newEndpointPolicyRunner(t, store, &healthOnlySensor{})
	assertManagerCompletionStatus(t, runner, "revocation_pending", "")

	if err := store.ConfirmEnrollmentRevocation(t.Context(), "receipt-a", time.Unix(100, 0).UTC()); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteUnenrollment(t.Context(), "endpoint"); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordCompletionAttempt(t.Context(), "manager unavailable"); err != nil {
		t.Fatal(err)
	}
	assertManagerCompletionStatus(t, runner, "endpoint_completion_pending", "manager unavailable")
}

func assertManagerCompletionStatus(t *testing.T, runner *AgentRuntime, wantStatus, wantError string) {
	t.Helper()
	status, err := runner.managementLifecycleStatus(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if status.GetManagerCompletionStatus() != wantStatus || status.GetLastTransitionError() != wantError || status.GetUpdatedAt() == "" {
		t.Fatalf("management lifecycle=%s", fmt.Sprint(status))
	}
	if !managementLifecycleDegraded(status) {
		t.Fatal("management lifecycle is not degraded")
	}
}
