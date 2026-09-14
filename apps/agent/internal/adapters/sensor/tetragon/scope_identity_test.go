package tetragon

import (
	"reflect"
	"testing"

	sensorv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/sensor/v1"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

func TestBackendHasNoLegacyScopeFields(t *testing.T) {
	if _, ok := reflect.TypeOf(Backend{}).FieldByName("ContainerIDPrefix"); ok {
		t.Fatal("Backend still exposes legacy ContainerIDPrefix")
	}
}

const (
	containerID64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	containerID32 = "0123456789abcdef0123456789abcdef"
	containerID12 = "0123456789ab"
)

func TestContainerIDsMatch(t *testing.T) {
	tests := []struct {
		name     string
		eventID  string
		selector string
		want     bool
	}{
		{name: "full selector truncated event", eventID: containerID32, selector: containerID64, want: true},
		{name: "short selector full event", eventID: containerID32, selector: containerID12, want: true},
		{name: "case and whitespace", eventID: "  " + containerID32 + "  ", selector: "0123456789ABCDEF", want: true},
		{name: "legacy short forward prefix", eventID: "legacy-container", selector: "legacy", want: true},
		{name: "different containers", eventID: "abcdefabcdefabcdefabcdefabcdefab", selector: containerID64, want: false},
		{name: "invalid reverse prefix", eventID: "not-hex-id-12", selector: "not-hex-id-12-more", want: false},
		{name: "short reverse prefix", eventID: "012345", selector: containerID64, want: false},
		{name: "empty event", eventID: "", selector: containerID64, want: false},
		{name: "empty selector", eventID: containerID32, selector: "", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := containerIDsMatch(tt.eventID, tt.selector); got != tt.want {
				t.Fatalf("containerIDsMatch(%q, %q) = %v, want %v", tt.eventID, tt.selector, got, tt.want)
			}
		})
	}
}

func TestBackendContainerIDLengthCompatibility(t *testing.T) {
	event := &sensorv1.SensorEvent{ContainerId: containerID32}
	tests := []struct {
		name    string
		backend *Backend
	}{
		{name: "container scope", backend: &Backend{ScopeType: "container", ScopeSelector: containerID64}},
		{name: "namespace self", backend: &Backend{
			ScopeType:                "namespace",
			ScopeSelector:            "self",
			namespaceSelfContainerID: containerID64,
			intent:                   contract.CollectionIntent{NamespaceSelectors: []contract.NamespaceSelector{{Namespace: "Pid", Values: []string{"1"}}}},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.backend.matchesScope(event) {
				t.Fatalf("backend rejected 32-character event ID for 64-character selector")
			}
		})
	}
}
