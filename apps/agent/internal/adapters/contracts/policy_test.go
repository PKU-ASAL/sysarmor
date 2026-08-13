package contracts

import (
	"reflect"
	"testing"

	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/policy"
	sharedpolicy "github.com/sysarmor/sysarmor-next-project/packages/policy"
)

func TestCollectionPolicyRoundTripPreservesBoundaryFields(t *testing.T) {
	enabled := false
	shared := sharedpolicy.CollectionPolicy{
		PolicyID: "collection-a", Version: 7, Behaviors: []string{"process.exec"},
		BehaviorSpecs: []sharedpolicy.CollectionBehaviorPolicy{{
			ID: "file.write", Enabled: &enabled,
			Selectors: sharedpolicy.CollectionBehaviorSelectors{
				Process: sharedpolicy.ProcessSelector{BinaryPrefixes: []string{"/usr/bin/"}},
				File:    sharedpolicy.FileSelector{Prefixes: []string{"/tmp/"}, PrefixRefs: []string{"ctx:paths"}},
			},
		}},
		ScopeType: "container", ScopeSelector: "container-a", ObserveOnly: true,
	}

	domain := DomainCollectionPolicy(shared)
	if domain.Identity != (domainpolicy.Identity{ID: "collection-a", Version: 7}) {
		t.Fatalf("domain identity = %+v", domain.Identity)
	}
	if got := SharedCollectionPolicy(domain); !reflect.DeepEqual(got, shared) {
		t.Fatalf("round trip = %+v, want %+v", got, shared)
	}
}
