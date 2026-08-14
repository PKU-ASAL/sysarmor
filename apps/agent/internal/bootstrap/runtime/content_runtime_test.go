package runtime

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/config"
	agentcontent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/content"
	detection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/detection"
	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/control"
)

func TestContentRuntimeUsesProjectedManagementIdentity(t *testing.T) {
	runner := &Runtime{Config: config.Config{Agent: config.AgentConfig{TenantID: "local", ID: "device-a"}}}
	runner.setRuntimeIdentity(runtimeIdentity{TenantID: "tenant-a", AgentID: "agent-a"})
	runtime := newContentApplicationAdapter(runner)

	if identity := runtime.ContentIdentity(); identity.TenantID != "tenant-a" || identity.AgentID != "agent-a" {
		t.Fatalf("result identity=%+v", identity)
	}
	if err := runtime.ValidateContentContext(agentcontrol.RequestContext{TenantID: "tenant-a", AgentID: "agent-a"}); err != nil {
		t.Fatalf("validate managed identity: %v", err)
	}
	if err := runtime.ValidateContentContext(agentcontrol.RequestContext{TenantID: "local", AgentID: "device-a"}); err == nil {
		t.Fatal("standalone identity accepted while managed identity is active")
	}
}

func TestContentControllerPersistenceFailureKeepsPreviousDetection(t *testing.T) {
	contentDir := filepath.Join(t.TempDir(), "content")
	store, err := agentcontent.NewStoreWithOptions(agentcontent.Options{Dir: contentDir})
	if err != nil {
		t.Fatal(err)
	}
	runner := &Runtime{
		Config:  config.Config{Agent: config.AgentConfig{TenantID: "tenant-a", ID: "agent-a"}},
		content: store,
	}
	previousDetection := &detection.Engine{}
	runner.setDetection(previousDetection)
	if err := os.RemoveAll(contentDir); err != nil {
		t.Fatal(err)
	}

	result := agentcontrol.NewContentController(newContentApplicationAdapter(runner)).ApplyContent(t.Context(), agentcontrol.ContentCommand{
		Context: agentcontrol.RequestContext{TenantID: "tenant-a", AgentID: "agent-a"},
		Document: `{
			"api_version":"sysarmor.content/v1",
			"kind":"iocpack",
			"metadata":{"id":"ioc:test-feed","version":"v1"},
			"spec":{"value_type":"ip","values":["192.0.2.1"]}
		}`,
		AllowUnsigned: true,
		Source:        agentcontrol.PolicySourceManaged,
	})

	if result.Status != "rejected" {
		t.Fatalf("result=%+v", result)
	}
	if runner.currentDetection() != previousDetection {
		t.Fatal("detection changed after content persistence failure")
	}
	if _, ok := runner.contentStore().Get("ioc:test-feed"); ok {
		t.Fatal("content remained active after persistence failure")
	}
}
