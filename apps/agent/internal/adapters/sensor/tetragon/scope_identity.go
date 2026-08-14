package tetragon

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

var containerIDPattern = regexp.MustCompile(`[0-9a-fA-F]{32,64}`)
var validContainerIDPattern = regexp.MustCompile(`^[0-9a-f]+$`)

func resolveNamespaceSelfContainerID(intent contract.CollectionIntent) (string, error) {
	if intent.ScopeType != "namespace" || intent.ScopeSelector != "self" {
		return "", nil
	}
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", fmt.Errorf("resolve namespace/self cgroup: %w", err)
	}
	if id := containerIDFromCgroup(string(data)); id != "" {
		return id, nil
	}
	if runningInContainer() {
		return "", fmt.Errorf("resolve namespace/self container id: start the container with --cgroupns=host")
	}
	return "", nil
}

func containerIDFromCgroup(data string) string {
	var longest string
	for _, candidate := range containerIDPattern.FindAllString(data, -1) {
		if len(candidate) > len(longest) {
			longest = candidate
		}
	}
	return strings.ToLower(longest)
}

func runningInContainer() bool {
	for _, marker := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(marker); err == nil {
			return true
		}
	}
	return false
}

func containerIDsMatch(eventID, selector string) bool {
	eventID = strings.ToLower(strings.TrimSpace(eventID))
	selector = strings.ToLower(strings.TrimSpace(selector))
	if eventID == "" || selector == "" {
		return false
	}
	if strings.HasPrefix(eventID, selector) {
		return true
	}
	return len(eventID) >= 12 && validContainerIDPattern.MatchString(eventID) &&
		validContainerIDPattern.MatchString(selector) && strings.HasPrefix(selector, eventID)
}
