package bootstrap

import (
	"database/sql"
	"net/http"
	"testing"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	_ "modernc.org/sqlite"
)

func TestNewManagerIdentityHTTPRequiresDependencies(t *testing.T) {
	resolve := func(*http.Request) (managerapp.RequestContext, error) { return managerapp.RequestContext{}, nil }
	if _, err := NewManagerIdentityHTTP(nil, resolve); err == nil {
		t.Fatal("NewManagerIdentityHTTP() accepted nil database")
	}
	db, err := sql.Open("sqlite", "file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := NewManagerIdentityHTTP(db, nil); err == nil {
		t.Fatal("NewManagerIdentityHTTP() accepted nil resolver")
	}
}
