package bootstrap

import (
	"testing"

	statushttp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/inbound/http/status"
)

func TestNewManagerStatusHTTPBuildsHandler(t *testing.T) {
	handler := NewManagerStatusHTTP(ManagerStatus{Backend: "postgres", PostgresSchemaVersion: 6})
	if handler == nil {
		t.Fatal("handler is nil")
	}
	var _ *statushttp.Handler = handler
}
