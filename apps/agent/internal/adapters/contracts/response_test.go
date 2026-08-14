package contracts

import (
	"testing"
	"time"
)

func TestResponseCommandDocumentRoundTripPreservesPublishedFields(t *testing.T) {
	input := []byte(`{"response_id":"r1","tenant_id":"t1","agent_id":"a1","policy_id":"p1","policy_version":3,"action":"collect","mode":"observe","status":"pending","approved_by":"lead","approved_at":"2026-08-14T01:02:03Z","approvals":[{"actor":"alice","role":"operator","approved":true,"reason":"reviewed","observed_at":"2026-08-14T01:00:00Z"}]}`)
	command, err := DecodeResponseCommand(input)
	if err != nil {
		t.Fatal(err)
	}
	if command.ID != "r1" || command.PolicyVersion != 3 || command.ApprovedBy != "lead" {
		t.Fatalf("command = %+v", command)
	}
	if len(command.Approvals) != 1 || command.Approvals[0].Reason != "reviewed" {
		t.Fatalf("approvals = %+v", command.Approvals)
	}
	if command.ApprovedAt != time.Date(2026, 8, 14, 1, 2, 3, 0, time.UTC) {
		t.Fatalf("approved at = %s", command.ApprovedAt)
	}
	output, err := EncodeResponseCommand(command)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeResponseCommand(output)
	if err != nil || decoded.Approvals[0].ObservedAt != command.Approvals[0].ObservedAt {
		t.Fatalf("round trip command = %+v, err = %v", decoded, err)
	}
}
