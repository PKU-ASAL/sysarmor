package policy

import "testing"

func TestIdentityRequiresIDAndPositiveVersion(t *testing.T) {
	for _, identity := range []Identity{{Version: 1}, {ID: "endpoint"}} {
		if err := identity.Validate(); err == nil {
			t.Fatalf("identity %+v accepted", identity)
		}
	}
	if err := (Identity{ID: " endpoint ", Version: 1}).Validate(); err != nil {
		t.Fatalf("valid identity rejected: %v", err)
	}
}

func TestValidateVersionTransitionPreservesPolicySlotSemantics(t *testing.T) {
	current := Identity{ID: "endpoint", Version: 4}
	if err := ValidateVersionTransition(VersionTransition{Current: current, Candidate: Identity{ID: "other", Version: 4}}); err != nil {
		t.Fatalf("different policy identity rejected: %v", err)
	}
	if err := ValidateVersionTransition(VersionTransition{Current: current, Candidate: Identity{ID: "endpoint", Version: 3}}); err == nil {
		t.Fatal("version rollback accepted")
	}
	if err := ValidateVersionTransition(VersionTransition{Current: current, Candidate: current, SameDigest: true, SameDocument: true}); err != nil {
		t.Fatalf("idempotent replay rejected: %v", err)
	}
	if err := ValidateVersionTransition(VersionTransition{Current: current, Candidate: current}); err == nil {
		t.Fatal("same-version conflict accepted")
	}
}

func TestValidateSourceAcceptsKnownAuthority(t *testing.T) {
	if err := ValidateSource(Source("other")); err == nil {
		t.Fatal("unknown source accepted")
	}
	if err := ValidateSource(SourceManaged); err != nil {
		t.Fatalf("managed source rejected: %v", err)
	}
}

func TestActivationCandidateRequiresEveryEndpointSection(t *testing.T) {
	candidate := ActivationCandidate{
		Identity:   Identity{ID: "endpoint", Version: 1},
		Collection: CollectionPolicy{Behaviors: []string{"process.exec"}},
		Sections:   EndpointSections{Collection: true, Detection: true, Telemetry: true},
	}
	if err := candidate.Validate(); err == nil {
		t.Fatal("candidate without response section accepted")
	}
	candidate.Sections.Response = true
	if err := candidate.Validate(); err != nil {
		t.Fatalf("complete candidate rejected: %v", err)
	}
}
