package enrollment

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	domainenrollment "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/enrollment"
)

func TestInstallScriptRendererPreservesContainerArtifactContract(t *testing.T) {
	renderer := NewInstallScriptRenderer([]byte("PUBLIC KEY"), "https://manager.example/base")
	request := httptest.NewRequest(http.MethodGet, "http://manager.internal/api/v1/agent-install.sh", nil)
	script, err := renderer.Render(request, domainenrollment.Enrollment{
		ID: "enroll-a", Profile: "linux-container", ArtifactID: "artifact-a", ArtifactSHA256: "sha256-a",
		Labels: map[string]string{"scenario": "namespace-self-container"},
	}, "rotated-token")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`SYSARMOR_INSTALL_PROFILE="${SYSARMOR_INSTALL_PROFILE:-linux-container}"`,
		`label.scenario: "namespace-self-container"`,
		`Authorization: Enrollment $(cat "$ENROLLMENT_TOKEN_FILE")`,
		`SYSARMOR_AGENT_BUNDLE_SHA256="${SYSARMOR_AGENT_BUNDLE_SHA256:-sha256-a}"`,
		`--manager-url 'https://manager.example/base' --token-file "$ENROLLMENT_TOKEN_FILE" --timeout 60s`,
		`"/opt/sysarmor/agent/bin/sysarmor-agent" run --config "/etc/sysarmor/agent/agent.yaml"`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("script missing %q:\n%s", want, script)
		}
	}
	if strings.Contains(script, "/api/v1/enrollment-artifact?token=") || strings.Contains(script, "python3") {
		t.Fatalf("script contains unsupported container behavior:\n%s", script)
	}
}
