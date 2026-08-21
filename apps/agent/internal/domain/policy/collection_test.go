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

func TestCompileCollectionIntentDoesNotInjectCausalBaseline(t *testing.T) {
	intent, err := CompileCollectionIntent(CollectionPolicy{Behaviors: []string{"file.read"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(intent.Behaviors) != 1 || intent.Behaviors[0] != "file.read" {
		t.Fatalf("compiled behaviors = %v", intent.Behaviors)
	}
	if len(intent.MandatoryBehaviors) != 0 || len(intent.FileWriteExcludes) != 0 {
		t.Fatalf("implicit causal requirements remain in %+v", intent)
	}
}

func TestCompileCollectionIntentPreservesRequestedSelectors(t *testing.T) {
	intent, err := CompileCollectionIntent(CollectionPolicy{
		BehaviorSpecs: []BehaviorPolicy{{ID: "network.connect", Selectors: BehaviorSelectors{
			Process: ProcessSelector{BinaryPrefixes: []string{"/tmp/"}},
			Socket:  SocketSelector{Ports: []string{"443"}},
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, filter := range intent.BehaviorFilters {
		if filter.Behavior == "network.connect" && (len(filter.BinaryPrefixes) != 1 || len(filter.SocketPorts) != 1) {
			t.Fatalf("requested selectors were discarded: %+v", filter)
		}
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
	for _, filter := range intent.BehaviorFilters {
		if filter.Behavior == "process.exit" && len(filter.BinaryPrefixes) != 0 {
			t.Fatalf("process.exit filter = %+v", filter)
		}
	}
}
