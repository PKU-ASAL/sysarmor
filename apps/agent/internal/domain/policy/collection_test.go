package policy

import (
	"fmt"
	"reflect"
	"testing"
)

func TestNormalizeCollectionRemovesEmptyAndDuplicateValues(t *testing.T) {
	policy := NormalizeCollection(CollectionPolicy{
		Identity:       Identity{ID: " collection ", Version: 2},
		Behaviors:      []string{" PROCESS.EXEC ", "process.exec", ""},
		BinaryPrefixes: []string{" /bin/ ", "/bin/", ""},
	})
	if policy.Identity.ID != "collection" || len(policy.Behaviors) != 1 || policy.Behaviors[0] != "process.exec" {
		t.Fatalf("normalized policy = %+v", policy)
	}
	if len(policy.BinaryPrefixes) != 1 || policy.BinaryPrefixes[0] != "/bin/" {
		t.Fatalf("binary prefixes = %+v", policy.BinaryPrefixes)
	}
}

func TestNormalizeCollectionDoesNotMutateInput(t *testing.T) {
	enabled := true
	input := CollectionPolicy{BehaviorSpecs: []BehaviorPolicy{{
		ID: " FILE.WRITE ", Enabled: &enabled,
		Selectors: BehaviorSelectors{File: FileSelector{Prefixes: []string{" /tmp/ ", "/tmp/"}}},
	}}}
	want := CollectionPolicy{BehaviorSpecs: []BehaviorPolicy{{
		ID: " FILE.WRITE ", Enabled: &enabled,
		Selectors: BehaviorSelectors{File: FileSelector{Prefixes: []string{" /tmp/ ", "/tmp/"}}},
	}}}
	_ = NormalizeCollection(input)
	if !reflect.DeepEqual(input, want) {
		t.Fatalf("input mutated: got %+v want %+v", input, want)
	}
}

func TestExpandCollectionRejectsMissingReference(t *testing.T) {
	_, _, err := ExpandCollection(CollectionPolicy{BehaviorSpecs: []BehaviorPolicy{{
		ID: "file.write", Selectors: BehaviorSelectors{File: FileSelector{PrefixRefs: []string{"ctx:missing"}}},
	}}}, ContentSnapshot{})
	if err == nil {
		t.Fatal("missing content reference accepted")
	}
}

func TestCollectionIntentRejectsUnknownBehavior(t *testing.T) {
	if _, err := CompileCollectionIntent(CollectionPolicy{Behaviors: []string{"unknown.behavior"}}); err == nil {
		t.Fatal("unknown behavior accepted")
	}
}

func TestNormalizeCollectionDropsEmptyBehaviorSpecs(t *testing.T) {
	policy := NormalizeCollection(CollectionPolicy{BehaviorSpecs: []BehaviorPolicy{{ID: " "}, {ID: "file.write"}}})
	if len(policy.BehaviorSpecs) != 1 || policy.BehaviorSpecs[0].ID != "file.write" {
		t.Fatalf("behavior specs = %+v", policy.BehaviorSpecs)
	}
}

func TestExpandCollectionRejectsDirectSelectorOverBudget(t *testing.T) {
	prefixes := make([]string, maxFilePrefixes+1)
	for index := range prefixes {
		prefixes[index] = fmt.Sprintf("/tmp/%d", index)
	}
	_, _, err := ExpandCollection(CollectionPolicy{BehaviorSpecs: []BehaviorPolicy{{
		ID: "file.write", Selectors: BehaviorSelectors{File: FileSelector{Prefixes: prefixes}},
	}}}, ContentSnapshot{})
	if err == nil {
		t.Fatal("direct selector over budget accepted")
	}
}

func TestFlatProcessExitDoesNotClaimBinarySelector(t *testing.T) {
	intent, err := CompileCollectionIntent(CollectionPolicy{Behaviors: []string{"process.exit"}, BinaryPrefixes: []string{"/bin/"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(intent.BehaviorFilters) != 1 || len(intent.BehaviorFilters[0].BinaryPrefixes) != 0 {
		t.Fatalf("process.exit filter = %+v", intent.BehaviorFilters)
	}
}
