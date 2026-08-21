package main

import "testing"

func TestRunRequiresSigningInputs(t *testing.T) {
	if err := run(nil); err == nil {
		t.Fatal("run() error = nil")
	}
}
