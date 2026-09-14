package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	controlplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/controlplane/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func policyPayload(args []string) (string, error) {
	file := flagValue(args, "--file")
	if strings.TrimSpace(file) != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return "", err
		}
		return string(data), nil
	}
	if len(args) > 2 && args[2] == "collection" {
		return collectionPolicyPayload(args)
	}
	return "", fmt.Errorf("--file is required")
}

func contentPayload(args []string) (string, error) {
	file := flagValue(args, "--file")
	if strings.TrimSpace(file) == "" {
		return "", fmt.Errorf("--file is required")
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func contentDiff(args []string) ([]byte, error) {
	files := flagValues(args, "--file")
	if len(files) != 2 {
		return nil, fmt.Errorf("content diff requires exactly two --file values")
	}
	oldEnv, oldValues, err := readContentValues(files[0])
	if err != nil {
		return nil, err
	}
	newEnv, newValues, err := readContentValues(files[1])
	if err != nil {
		return nil, err
	}
	if oldEnv.Kind != newEnv.Kind || oldEnv.Metadata.ID != newEnv.Metadata.ID {
		return nil, fmt.Errorf("content diff requires same kind and metadata.id")
	}
	oldSet := map[string]bool{}
	for _, value := range oldValues {
		oldSet[value] = true
	}
	newSet := map[string]bool{}
	for _, value := range newValues {
		newSet[value] = true
	}
	var ops []map[string]string
	for _, value := range newValues {
		if !oldSet[value] {
			ops = append(ops, map[string]string{"op": "add", "value": value})
		}
	}
	for _, value := range oldValues {
		if !newSet[value] {
			ops = append(ops, map[string]string{"op": "remove", "value": value})
		}
	}
	version := firstNonEmpty(flagValue(args, "--version"), newEnv.Metadata.Version)
	patch := map[string]any{
		"api_version": newEnv.APIVersion,
		"kind":        newEnv.Kind,
		"metadata": map[string]any{
			"id":      newEnv.Metadata.ID,
			"version": version,
		},
		"spec": map[string]any{
			"base_version":   oldEnv.Metadata.Version,
			"value_type":     contentValueType(newEnv),
			"merge_strategy": "patch",
			"ops":            ops,
		},
	}
	return json.MarshalIndent(patch, "", "  ")
}

type contentEnvelopeForCLI struct {
	APIVersion string `json:"api_version"`
	Kind       string `json:"kind"`
	Metadata   struct {
		ID      string `json:"id"`
		Version string `json:"version"`
	} `json:"metadata"`
	Spec json.RawMessage `json:"spec"`
}

func readContentValues(path string) (contentEnvelopeForCLI, []string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return contentEnvelopeForCLI{}, nil, err
	}
	var env contentEnvelopeForCLI
	if err := json.Unmarshal(data, &env); err != nil {
		return contentEnvelopeForCLI{}, nil, err
	}
	var spec struct {
		Values []string `json:"values"`
	}
	if err := json.Unmarshal(env.Spec, &spec); err != nil {
		return contentEnvelopeForCLI{}, nil, err
	}
	return env, uniqueSorted(spec.Values), nil
}

func contentValueType(env contentEnvelopeForCLI) string {
	var spec struct {
		ValueType string `json:"value_type"`
	}
	_ = json.Unmarshal(env.Spec, &spec)
	return spec.ValueType
}

func uniqueSorted(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func collectionPolicyPayload(args []string) (string, error) {
	behaviors := flagValues(args, "--behavior")
	if len(behaviors) == 0 {
		return "", fmt.Errorf("collection policy requires --behavior when --file is not used")
	}
	binaryPrefixes := flagValues(args, "--binary-prefix")
	filePrefixes := flagValues(args, "--file-prefix")
	socketFamilies := flagValues(args, "--socket-family")
	socketAddrs := flagValues(args, "--socket-addr")
	socketPorts := flagValues(args, "--socket-port")
	policy := map[string]any{
		"policy_id":      firstNonEmpty(flagValue(args, "--policy-id"), "local-collection-policy"),
		"version":        uint64Flag(args, "--policy-version", 1),
		"behaviors":      collectionBehaviorPayloads(behaviors, binaryPrefixes, filePrefixes, socketFamilies, socketAddrs, socketPorts),
		"scope_type":     flagValue(args, "--scope-type"),
		"scope_selector": flagValue(args, "--scope-selector"),
		"observe_only":   !hasFlag(args, "--enforce"),
	}
	data, err := json.Marshal(policy)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func collectionBehaviorPayloads(behaviors, binaryPrefixes, filePrefixes, socketFamilies, socketAddrs, socketPorts []string) []map[string]any {
	out := make([]map[string]any, 0, len(behaviors))
	for _, behavior := range behaviors {
		item := map[string]any{"id": behavior, "enabled": true}
		selectors := map[string]any{}
		switch behavior {
		case "process.exec", "process.fork":
			if len(binaryPrefixes) > 0 {
				selectors["binary"] = map[string]any{"prefixes": binaryPrefixes}
			}
		case "file.open", "file.read", "file.write", "file.chmod":
			if len(filePrefixes) > 0 {
				selectors["file"] = map[string]any{"prefixes": filePrefixes}
			}
		case "network.connect":
			socket := map[string]any{}
			if len(socketFamilies) > 0 {
				socket["families"] = socketFamilies
			}
			if len(socketAddrs) > 0 {
				socket["addrs"] = socketAddrs
			}
			if len(socketPorts) > 0 {
				socket["ports"] = socketPorts
			}
			if len(socket) > 0 {
				selectors["socket"] = socket
			}
		}
		if len(selectors) > 0 {
			item["selectors"] = selectors
		}
		out = append(out, item)
	}
	return out
}

func requestContext(args []string) *controlplanev1.RequestContext {
	return &controlplanev1.RequestContext{
		RequestId: flagValue(args, "--request-id"),
		TenantId:  flagValue(args, "--tenant-id"),
		AgentId:   flagValue(args, "--agent-id"),
		Scope: &controlplanev1.Scope{
			Type:     flagValue(args, "--scope-type"),
			Selector: flagValue(args, "--scope-selector"),
		},
	}
}

func watchFilter(args []string) *controlplanev1.WatchFilter {
	filter := &controlplanev1.WatchFilter{
		AfterSequence:   uint64Flag(args, "--after-seq", 0),
		SinceObservedAt: flagValue(args, "--since"),
		UntilObservedAt: flagValue(args, "--until"),
		AfterBatchId:    flagValue(args, "--after-batch-id"),
		Labels:          map[string]string{},
	}
	for _, item := range flagValues(args, "--label") {
		key, value, ok := strings.Cut(item, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		filter.Labels[key] = value
	}
	if filter.AfterSequence == 0 && filter.SinceObservedAt == "" && filter.UntilObservedAt == "" && filter.AfterBatchId == "" && len(filter.Labels) == 0 {
		return nil
	}
	return filter
}

func commandTimeout(args []string, fallback time.Duration) time.Duration {
	raw := flagValue(args, "--timeout")
	if raw == "" {
		if len(args) >= 1 && (args[0] == "enroll" || args[0] == "unenroll") {
			return 60 * time.Second
		}
		if len(args) >= 3 && args[0] == "debug" && args[1] == "profile" {
			seconds := uint64Flag(args, "--seconds", 10)
			return time.Duration(seconds+5) * time.Second
		}
		if len(args) >= 2 && args[1] == "watch" && flagValue(args, "--limit") == "" {
			return 24 * time.Hour
		}
		return fallback
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return fallback
	}
	return d
}

func uint32Flag(args []string, name string) uint32 {
	raw := flagValue(args, name)
	if raw == "" {
		return 0
	}
	n, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}

func uint64Flag(args []string, name string, fallback uint64) uint64 {
	raw := flagValue(args, name)
	if raw == "" {
		return fallback
	}
	n, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return fallback
	}
	return n
}

func flagValue(args []string, name string) string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == name {
			return args[i+1]
		}
	}
	return ""
}

func flagValues(args []string, name string) []string {
	var out []string
	for i := 0; i < len(args)-1; i++ {
		if args[i] == name {
			out = append(out, args[i+1])
		}
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func hasFlag(args []string, name string) bool {
	for _, arg := range args {
		if arg == name {
			return true
		}
	}
	return false
}

func marshalProtoJSON(msg proto.Message) ([]byte, error) {
	return protojson.MarshalOptions{}.Marshal(msg)
}

func marshalHealthJSON(msg proto.Message) ([]byte, error) {
	return protojson.MarshalOptions{EmitUnpopulated: true}.Marshal(msg)
}

func marshalProtoJSONLine(msg proto.Message) ([]byte, error) {
	return protojson.MarshalOptions{}.Marshal(msg)
}
