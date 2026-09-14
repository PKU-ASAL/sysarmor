package bootstrap

import "testing"

func TestNewManagerPolicyHTTPRejectsNilDatabase(t *testing.T) {
	if _, err := NewManagerPolicyHTTP(nil, nil); err == nil {
		t.Fatal("NewManagerPolicyHTTP() accepted nil database")
	}
}
