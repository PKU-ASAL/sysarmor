package management

import "testing"

func TestResolveProjectsManagementContext(t *testing.T) {
	tests := []struct {
		state State
		want  Context
	}{
		{StateStandalone, Context{State: StateStandalone, Authority: AuthorityLocal, IdentitySource: IdentityStandalone, Transport: TransportStandalone}},
		{StateEnrolling, Context{State: StateEnrolling, Authority: AuthorityManager, IdentitySource: IdentityEnrollment, Transport: TransportManaged}},
		{StateManaged, Context{State: StateManaged, Authority: AuthorityManager, IdentitySource: IdentityEnrollment, Transport: TransportManaged}},
		{StateUnenrolling, Context{State: StateUnenrolling, Authority: AuthorityManager, IdentitySource: IdentityEnrollment, Transport: TransportManaged}},
	}
	for _, test := range tests {
		t.Run(string(test.state), func(t *testing.T) {
			got, err := Resolve(test.state)
			if err != nil || got != test.want {
				t.Fatalf("Resolve(%q) = %+v, %v; want %+v", test.state, got, err, test.want)
			}
		})
	}
}

func TestResolveRejectsUnknownState(t *testing.T) {
	if _, err := Resolve(State("corrupt")); err == nil {
		t.Fatal("Resolve accepted an unknown state")
	}
}

func TestContextAuthorizesOnlyItsPolicyAuthority(t *testing.T) {
	tests := []struct {
		name   string
		state  State
		origin PolicyWriteOrigin
		wantOK bool
	}{
		{"standalone local", StateStandalone, PolicyWriteLocal, true},
		{"standalone manager", StateStandalone, PolicyWriteManager, false},
		{"enrolling local", StateEnrolling, PolicyWriteLocal, false},
		{"enrolling manager", StateEnrolling, PolicyWriteManager, true},
		{"managed local", StateManaged, PolicyWriteLocal, false},
		{"managed manager", StateManaged, PolicyWriteManager, true},
		{"unenrolling local", StateUnenrolling, PolicyWriteLocal, false},
		{"unenrolling manager", StateUnenrolling, PolicyWriteManager, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mode, err := Resolve(test.state)
			if err != nil {
				t.Fatal(err)
			}
			err = mode.Authorize(test.origin)
			if (err == nil) != test.wantOK {
				t.Fatalf("Authorize(%q) error = %v, wantOK=%t", test.origin, err, test.wantOK)
			}
		})
	}
}

func TestValidateTransitionAllowsOnlyLifecycleEdges(t *testing.T) {
	allowed := map[[2]State]bool{
		{StateStandalone, StateEnrolling}:   true,
		{StateEnrolling, StateManaged}:      true,
		{StateManaged, StateUnenrolling}:    true,
		{StateUnenrolling, StateStandalone}: true,
	}
	states := []State{StateStandalone, StateEnrolling, StateManaged, StateUnenrolling}
	for _, from := range states {
		for _, to := range states {
			err := ValidateTransition(from, to)
			if (err == nil) != allowed[[2]State{from, to}] {
				t.Fatalf("ValidateTransition(%q, %q) error = %v", from, to, err)
			}
		}
	}
}

func TestValidateTransitionRejectsUnknownState(t *testing.T) {
	if err := ValidateTransition(State("corrupt"), StateStandalone); err == nil {
		t.Fatal("ValidateTransition accepted an unknown source state")
	}
	if err := ValidateTransition(StateStandalone, State("corrupt")); err == nil {
		t.Fatal("ValidateTransition accepted an unknown target state")
	}
}
