package bootstrap

import "testing"

func TestNewManagerEnrollmentHTTPRejectsIncompleteConfig(t *testing.T) {
	if _, err := NewManagerEnrollmentHTTP(EnrollmentHTTPConfig{}); err == nil {
		t.Fatal("empty enrollment HTTP config accepted")
	}
}
