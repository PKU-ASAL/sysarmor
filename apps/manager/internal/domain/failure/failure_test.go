package failure

import "testing"

func TestKindsAreStable(t *testing.T) {
	want := []Kind{
		InvalidArgument,
		Unauthenticated,
		PermissionDenied,
		NotFound,
		Conflict,
		FailedPrecondition,
		ResourceExhausted,
		RetryableDependency,
		Internal,
	}
	seen := make(map[Kind]struct{}, len(want))
	for _, kind := range want {
		if kind == "" {
			t.Fatal("failure kind must not be empty")
		}
		if _, duplicate := seen[kind]; duplicate {
			t.Fatalf("duplicate failure kind %q", kind)
		}
		seen[kind] = struct{}{}
	}
}

func TestNewPreservesKindAndMessage(t *testing.T) {
	err := New(Conflict, "policy version already exists")
	if KindOf(err) != Conflict {
		t.Fatalf("KindOf() = %q, want %q", KindOf(err), Conflict)
	}
	if err.Error() != "policy version already exists" {
		t.Fatalf("Error() = %q", err.Error())
	}
}
