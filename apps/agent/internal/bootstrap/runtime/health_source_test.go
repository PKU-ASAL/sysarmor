package runtime

import "testing"

func TestRuntimeHealthSourceMarksMissingStorageUnavailable(t *testing.T) {
	value, err := (&runtimeHealthSource{health: runtimeHealth{management: &managementRuntime{}}}).Storage(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if value.Available {
		t.Fatalf("storage=%+v", value)
	}
}
