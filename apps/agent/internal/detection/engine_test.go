package detection

import (
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	agentpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/policy"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

func TestRepositoryDefaultPolicyCoversDefaultDetectionContent(t *testing.T) {
	raw, err := os.ReadFile("../../../../deployments/agent/policy.json")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := agentpolicy.ParseEndpointPolicy(raw)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := agentpolicy.CollectionPolicyIntent(policy.Collection)
	if err != nil {
		t.Fatal(err)
	}
	report := CheckCoverageWithContent(&policy.Detection, intent, testContentSnapshot(t))
	if report.Status != "covered" {
		t.Fatalf("default detection coverage = %+v, want covered", report)
	}
}

func TestEngineHasNoRuleSpecificLineageDetectors(t *testing.T) {
	source, err := os.ReadFile("engine.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, symbol := range []string{
		"lineageState",
		"observeDownloadEvidence",
		"observeControlConnection",
		"observePayloadEvidence",
		"detectPayloadExec",
		"detectPayloadConnect",
	} {
		if strings.Contains(string(source), symbol) {
			t.Errorf("engine.go still contains rule-specific symbol %q", symbol)
		}
	}
}

func TestDetectionRejectsPolicyWithoutExplicitRuleSet(t *testing.T) {
	policy := policymodel.DefaultDetectionPolicy()
	policy.RuleSets = nil
	_, report := NewWithRuntime(policy, contract.CollectionIntent{}, ContentSnapshot{})
	if report.Status != "rejected" || !strings.Contains(report.Message, "ruleset") {
		t.Fatalf("report = %+v, want rejected missing ruleset", report)
	}
}

func TestDetectionRejectsUnknownRuleSet(t *testing.T) {
	policy := policymodel.DefaultDetectionPolicy()
	policy.RuleSets = []policymodel.RuleSetRef{{Ref: "ruleset:missing"}}
	_, report := NewWithRuntime(policy, contract.CollectionIntent{}, ContentSnapshot{})
	if report.Status != "rejected" || !strings.Contains(strings.Join(report.Details, " "), "ruleset:missing") {
		t.Fatalf("report = %+v, want rejected unknown ruleset", report)
	}
}

func TestDetectionRejectsDuplicateRuleID(t *testing.T) {
	policy := policymodel.DefaultDetectionPolicy()
	policy.RuleSets = []policymodel.RuleSetRef{{Ref: "ruleset:test"}}
	content := ContentSnapshot{Rules: []RuleSpec{
		{RuleID: "duplicate", RuleSetRef: "ruleset:test", RuntimeType: "expr"},
		{RuleID: "duplicate", RuleSetRef: "ruleset:test", RuntimeType: "expr"},
	}}
	_, report := NewWithRuntime(policy, contract.CollectionIntent{}, content)
	if report.Status != "rejected" || !strings.Contains(strings.Join(report.Details, " "), "duplicate rule id") {
		t.Fatalf("report = %+v, want rejected duplicate rule id", report)
	}
}

func TestContentRuleSetEmitsMultiEventPayloadLifecycle(t *testing.T) {
	engine, report := newTestEngine(t)
	if report.Status != "applied" {
		t.Fatalf("report = %+v", report)
	}
	events := []*eventv1.CanonicalEvent{
		writeEvent("e1", "lin-a", "p1", "/usr/bin/curl", "/var/lib/app/plugins/helper"),
		chmodEvent("e2", "lin-a", "p2", "/usr/bin/chmod", "/var/lib/app/plugins/helper"),
		execEvent("e3", "lin-a", "helper-stable", "", "/var/lib/app/plugins/helper", nil),
		connectEventWithParent("e4", "lin-a", "child", "helper-stable", "/bin/bash", "10.66.0.99:443"),
	}
	var lifecycleRefs []string
	var lifecycleRuleVersion uint64
	var lifecycleRuleSet string
	for _, ev := range events {
		for _, sig := range engine.Process(ev) {
			if sig.GetName() == "payload_lifecycle" {
				lifecycleRefs = sig.GetEventRefs()
				lifecycleRuleVersion = sig.GetRuleVersion()
				lifecycleRuleSet = sig.GetRulesetRef()
			}
		}
	}
	for _, want := range []string{"e2", "e3", "e4"} {
		if !contains(lifecycleRefs, want) {
			t.Fatalf("payload_lifecycle refs = %v, want %s", lifecycleRefs, want)
		}
	}
	if len(lifecycleRefs) != 3 || contains(lifecycleRefs, "e1") {
		t.Fatalf("payload_lifecycle refs = %v, want latest evidence for each fact", lifecycleRefs)
	}
	if lifecycleRuleVersion != 2 || lifecycleRuleSet != testRuleSetRef {
		t.Fatalf("payload_lifecycle rule metadata version=%d ruleset=%q", lifecycleRuleVersion, lifecycleRuleSet)
	}
}

func TestPayloadLifecycleUsesCorrelateRule(t *testing.T) {
	for _, rule := range testContentSnapshot(t).Rules {
		if rule.RuleID != "payload_lifecycle" {
			continue
		}
		if rule.RuntimeType != "correlate" || len(rule.Correlate.Facts) != 3 {
			t.Fatalf("rule = %+v, want three-fact correlate", rule)
		}
		return
	}
	t.Fatal("payload_lifecycle rule not found")
}

func TestPayloadLifecycleCorrelateUsesDynamicContent(t *testing.T) {
	policy := testDetectionPolicy()
	content := ContentSnapshot{
		ContextRefs: map[string]ContentRef{
			"ctx:payload-path-prefixes": {Ref: "ctx:payload-path-prefixes", Version: "v2", Values: []string{"/opt/payloads/"}},
		},
		IOCRefs: map[string]ContentRef{
			"ioc:c2-control-port-feed": {Ref: "ioc:c2-control-port-feed", Version: "v2", Values: []string{"9443"}},
		},
	}
	engine, report := NewWithRuntime(policy, contract.CollectionIntent{}, mergeTestContent(t, content))
	if report.Status != "applied" {
		t.Fatalf("report = %+v", report)
	}
	events := []*eventv1.CanonicalEvent{
		connectEventWithParent("connect", "lin-a", "payload", "init", "/bin/other", "10.0.0.1:9443"),
		writeEvent("drop", "lin-a", "writer", "/bin/tool", "/opt/payloads/tool"),
		execEvent("exec", "lin-a", "payload", "init", "/bin/sh", []string{"/bin/sh", "/opt/payloads/tool"}),
	}
	var signals []*signalv1.Signal
	for _, event := range events {
		signals = append(signals, engine.Process(event)...)
	}
	var signal *signalv1.Signal
	for _, candidate := range signals {
		if candidate.GetName() == "payload_lifecycle" {
			signal = candidate
		}
	}
	if signal == nil || len(signal.GetEventRefs()) != 3 || len(signal.GetEntities()) < 3 {
		t.Fatalf("signal = %+v, want three facts and aggregated entities", signal)
	}
	for _, id := range []string{"drop", "exec", "connect"} {
		if !contains(signal.GetEventRefs(), id) {
			t.Fatalf("refs = %v, missing %s", signal.GetEventRefs(), id)
		}
	}
	if len(signal.GetContextRefs()) != 1 || len(signal.GetIocRefs()) != 1 {
		t.Fatalf("content refs = context:%v ioc:%v", signal.GetContextRefs(), signal.GetIocRefs())
	}
}

func TestContentRuleSetTreatsShellScriptArgAsPayloadExec(t *testing.T) {
	engine, report := newTestEngine(t)
	if report.Status != "applied" {
		t.Fatalf("report = %+v", report)
	}
	events := []*eventv1.CanonicalEvent{
		writeEvent("e1", "lin-a", "curl-stable", "/usr/bin/curl", "/dev/shm/x.sh"),
		execEvent("e2", "lin-a", "bash-stable", "parent", "/usr/bin/bash", []string{"/usr/bin/bash", "/dev/shm/x.sh"}),
		connectEventWithParent("e3", "lin-a", "child", "bash-stable", "/usr/bin/bash", "10.66.0.99:443"),
	}
	var lifecycleRefs []string
	for _, ev := range events {
		for _, sig := range engine.Process(ev) {
			if sig.GetName() == "payload_lifecycle" {
				lifecycleRefs = sig.GetEventRefs()
			}
		}
	}
	for _, want := range []string{"e1", "e2", "e3"} {
		if !contains(lifecycleRefs, want) {
			t.Fatalf("payload_lifecycle refs = %v, want %s", lifecycleRefs, want)
		}
	}
}

func TestContentRuleSetPayloadLifecycleToleratesShellReexecParentMismatch(t *testing.T) {
	engine, report := newTestEngine(t)
	if report.Status != "applied" {
		t.Fatalf("report = %+v", report)
	}
	events := []*eventv1.CanonicalEvent{
		writeEvent("e1", "lin-a", "curl-stable", "/usr/bin/curl", "/dev/shm/x.sh"),
		writeEvent("e2", "lin-a", "script-shell", "/usr/bin/bash", "/dev/shm/.beacon"),
		execEvent("e3", "lin-a", "payload-exec", "script-shell", "/usr/bin/bash", []string{"/usr/bin/bash", "/dev/shm/x.sh"}),
		connectEventWithParent("e4", "lin-a", "connect-shell", "script-shell", "/usr/bin/bash", "10.66.0.99:443"),
	}
	var lifecycleRefs []string
	for _, ev := range events {
		for _, sig := range engine.Process(ev) {
			if sig.GetName() == "payload_lifecycle" {
				lifecycleRefs = sig.GetEventRefs()
			}
		}
	}
	for _, want := range []string{"e2", "e3", "e4"} {
		if !contains(lifecycleRefs, want) {
			t.Fatalf("payload_lifecycle refs = %v, want %s", lifecycleRefs, want)
		}
	}
	if len(lifecycleRefs) != 3 || contains(lifecycleRefs, "e1") {
		t.Fatalf("payload_lifecycle refs = %v, want latest evidence for each fact", lifecycleRefs)
	}
}

func TestRuleOverrideDisablesContentRule(t *testing.T) {
	disabled := false
	policy := testDetectionPolicy()
	policy.RuleOverrides = append(policy.RuleOverrides, policymodel.RuleOverride{RuleID: "payload_dropped", Enabled: &disabled})
	engine, _ := NewWithRuntime(policy, contract.CollectionIntent{}, testContentSnapshot(t))
	signals := engine.Process(writeEvent("e1", "lin-a", "p1", "/usr/bin/curl", "/dev/shm/x.sh"))
	for _, sig := range signals {
		if sig.GetName() == "payload_dropped" {
			t.Fatalf("payload_dropped emitted despite override: %+v", sig)
		}
	}
}

func TestDependencyCheckReportsMissingCollectionInput(t *testing.T) {
	policy := testDetectionPolicy()
	_, report := NewWithRuntime(policy, contract.CollectionIntent{Behaviors: []string{"process.exec"}}, testContentSnapshot(t))
	if report.Status != "degraded" || len(report.Warnings) == 0 {
		t.Fatalf("report = %+v, want degraded with warnings", report)
	}
}

func TestDependencyCheckReportsMissingFields(t *testing.T) {
	enabled := true
	policy := &policymodel.DetectionPolicy{
		PolicyID: "field-dependency-test",
		Version:  1,
		Mode:     "observe",
		RuleSets: []policymodel.RuleSetRef{{Ref: "ruleset:field", Enabled: &enabled}},
	}
	content := ContentSnapshot{Rules: []RuleSpec{{
		RuleID:      "needs_socket_port",
		Version:     1,
		RuleSetRef:  "ruleset:field",
		Severity:    "medium",
		RuntimeType: "expr",
		Expr:        ExprSpec{Conditions: []ConditionSpec{{Field: "socket.port", Op: "eq", Value: "443"}}},
		RequiredEvents: []RequiredEventSpec{{
			Behavior: "network.connect",
			Fields:   []string{"socket.port", "process.binary"},
		}},
		RequiredBehaviors: []string{"network.connect"},
	}}}
	_, report := NewWithRuntime(policy, contract.CollectionIntent{Behaviors: []string{"process.exec"}}, content)
	if report.Status != "degraded" || !containsWarning(report.Warnings, "socket.port") {
		t.Fatalf("report = %+v, want missing socket.port", report)
	}
	_, report = NewWithRuntime(policy, contract.CollectionIntent{Behaviors: []string{"network.connect"}}, content)
	if report.Status != "applied" {
		t.Fatalf("report = %+v, want applied", report)
	}
}

func TestDependencyCheckUsesCollectionCapabilityFields(t *testing.T) {
	enabled := true
	policy := &policymodel.DetectionPolicy{
		PolicyID: "capability-field-test",
		Version:  1,
		Mode:     "observe",
		RuleSets: []policymodel.RuleSetRef{{Ref: "ruleset:field", Enabled: &enabled}},
	}
	content := ContentSnapshot{Rules: []RuleSpec{{
		RuleID:      "needs_socket_port",
		Version:     1,
		RuleSetRef:  "ruleset:field",
		Severity:    "medium",
		RuntimeType: "expr",
		Expr:        ExprSpec{Conditions: []ConditionSpec{{Field: "socket.port", Op: "eq", Value: "443"}}},
		RequiredEvents: []RequiredEventSpec{{
			Behavior: "network.connect",
			Fields:   []string{"socket.port"},
		}},
		RequiredBehaviors: []string{"network.connect"},
	}}}
	_, report := NewWithRuntime(policy, contract.CollectionIntent{
		Behaviors: []string{"network.connect"},
		Capabilities: []contract.CollectionBehaviorCapability{{
			Behavior: "network.connect",
			Fields:   []string{"process.binary"},
		}},
	}, content)
	if report.Status != "degraded" || !containsWarning(report.Warnings, "socket.port") {
		t.Fatalf("report = %+v, want capability missing socket.port", report)
	}
}

func TestRuleValidationRejectsUnknownFieldsAndOperators(t *testing.T) {
	tests := []struct {
		name string
		cond ConditionSpec
		want string
	}{
		{name: "field", cond: ConditionSpec{Field: "process.unknown", Op: "eq", Value: "x"}, want: "unsupported field"},
		{name: "operator", cond: ConditionSpec{Field: "process.binary", Op: "magic", Value: "x"}, want: "unsupported operator"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := ContentSnapshot{Rules: []RuleSpec{{
				RuleID: "invalid_" + tt.name, RuleSetRef: "ruleset:cep", RuntimeType: "expr",
				Expr: ExprSpec{Conditions: []ConditionSpec{tt.cond}},
			}}}
			_, report := NewWithRuntime(cepPolicy(), contract.CollectionIntent{}, content)
			if report.Status != "rejected" || !containsWarning(report.Details, tt.want) {
				t.Fatalf("report = %+v, want rejected with %q", report, tt.want)
			}
		})
	}
}

func TestRuleValidationRejectsInvalidSequenceReferences(t *testing.T) {
	content := ContentSnapshot{Rules: []RuleSpec{{
		RuleID: "invalid_sequence", RuleSetRef: "ruleset:cep", RuntimeType: "sequence",
		Sequence: SequenceSpec{Within: time.Minute, Steps: []StepSpec{
			{ID: "runtime", Behavior: "process.exec"},
			{ID: "shell", Behavior: "process.exec", Conditions: []ConditionSpec{{
				Field: "parent.stable_id", Op: "same_as", Step: "missing", StepField: "process.stable_id",
			}}},
		}},
	}}}
	_, report := NewWithRuntime(cepPolicy(), contract.CollectionIntent{}, content)
	if report.Status != "rejected" || !containsWarning(report.Details, "unknown prior step") {
		t.Fatalf("report = %+v, want rejected unknown prior step", report)
	}
}

func TestRuleValidationRejectsInvalidSuppression(t *testing.T) {
	tests := []struct {
		name        string
		suppression SuppressionSpec
		want        string
	}{
		{name: "zero window", suppression: SuppressionSpec{By: []string{"process.stable_id"}}, want: "suppression window"},
		{name: "excessive window", suppression: SuppressionSpec{Within: 25 * time.Hour, By: []string{"process.stable_id"}}, want: "suppression window"},
		{name: "missing key", suppression: SuppressionSpec{Within: time.Minute}, want: "suppression by field"},
		{name: "unknown field", suppression: SuppressionSpec{Within: time.Minute, By: []string{"process.unknown"}}, want: "unsupported suppression by field"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := ContentSnapshot{Rules: []RuleSpec{{
				RuleID: "invalid_suppression", RuleSetRef: "ruleset:cep", RuntimeType: "expr",
				Expr:        ExprSpec{Conditions: []ConditionSpec{{Field: "file.path", Op: "exists"}}},
				Suppression: tt.suppression,
			}}}
			_, report := NewWithRuntime(cepPolicy(), contract.CollectionIntent{}, content)
			if report.Status != "rejected" || !containsWarning(report.Details, tt.want) {
				t.Fatalf("report = %+v, want rejected with %q", report, tt.want)
			}
		})
	}
}

func TestRuleValidationRejectsInvalidConditionTree(t *testing.T) {
	leaf := conditionLeaf(ConditionSpec{Field: "file.path", Op: "exists"})
	tests := []struct {
		name string
		node *ConditionNodeSpec
		want string
	}{
		{name: "empty", node: &ConditionNodeSpec{}, want: "condition node must set exactly one kind"},
		{name: "multiple kinds", node: &ConditionNodeSpec{All: []ConditionNodeSpec{leaf}, Condition: leaf.Condition}, want: "condition node must set exactly one kind"},
		{name: "empty any", node: &ConditionNodeSpec{Any: []ConditionNodeSpec{}}, want: "any requires children"},
		{name: "empty not", node: &ConditionNodeSpec{Not: &ConditionNodeSpec{}}, want: "condition node must set exactly one kind"},
		{name: "unknown field", node: ptrConditionNode(conditionLeaf(ConditionSpec{Field: "file.unknown", Op: "exists"})), want: "unsupported field"},
	}
	deep := conditionLeaf(ConditionSpec{Field: "file.path", Op: "exists"})
	for i := 0; i < 9; i++ {
		deep = ConditionNodeSpec{Not: ptrConditionNode(deep)}
	}
	tests = append(tests, struct {
		name string
		node *ConditionNodeSpec
		want string
	}{name: "too deep", node: &deep, want: "maximum depth"})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := ContentSnapshot{Rules: []RuleSpec{{
				RuleID: "invalid_tree", RuleSetRef: "ruleset:cep", RuntimeType: "expr",
				Expr: ExprSpec{Conditions: []ConditionSpec{{Field: "file.path", Op: "exists"}}, ConditionGroup: tt.node},
			}}}
			_, report := NewWithRuntime(cepPolicy(), contract.CollectionIntent{}, content)
			if report.Status != "rejected" || !containsWarning(report.Details, tt.want) {
				t.Fatalf("report = %+v, want rejected with %q", report, tt.want)
			}
		})
	}
}

func TestExprRuleEvaluatesGenericConditionTree(t *testing.T) {
	rule := RuleSpec{
		RuleID: "neutral_boolean_rule", RuleSetRef: "ruleset:cep", RuntimeType: "expr", RequiredBehaviors: []string{"network.connect"},
		ContextRefs: []string{"ctx:test-tools", "ctx:test-markers"}, IOCRefs: []string{"ioc:test-ports"},
		Expr: ExprSpec{
			ConditionGroup: &ConditionNodeSpec{All: []ConditionNodeSpec{
				{Any: []ConditionNodeSpec{
					conditionLeaf(ConditionSpec{Field: "process.binary_name", Op: "in", Ref: "ctx:test-tools"}),
					conditionLeaf(ConditionSpec{Field: "process.argv", Op: "contains", Ref: "ctx:test-markers"}),
				}},
				conditionLeaf(ConditionSpec{Field: "socket.port", Op: "in", Ref: "ioc:test-ports"}),
				{Not: ptrConditionNode(conditionLeaf(ConditionSpec{Field: "process.binary_name", Op: "eq", Value: "blocked"}))},
			}},
		},
	}
	content := ContentSnapshot{
		ContextRefs: map[string]ContentRef{
			"ctx:test-tools":   {Ref: "ctx:test-tools", Values: []string{"fetcher"}},
			"ctx:test-markers": {Ref: "ctx:test-markers", Values: []string{"--probe"}},
		},
		IOCRefs: map[string]ContentRef{"ioc:test-ports": {Ref: "ioc:test-ports", Values: []string{"9443"}}},
		Rules:   []RuleSpec{rule},
	}
	engine, report := NewWithRuntime(cepPolicy(), contract.CollectionIntent{}, content)
	if report.Status != "applied" {
		t.Fatalf("report = %+v", report)
	}
	tests := []struct {
		name  string
		event *eventv1.CanonicalEvent
		want  int
	}{
		{name: "binary branch", event: connectEventWithParent("binary", "lin-a", "p1", "parent", "/opt/fetcher", "10.0.0.1:9443"), want: 1},
		{name: "wrong port", event: connectEventWithParent("port", "lin-b", "p2", "parent", "/opt/fetcher", "10.0.0.1:80"), want: 0},
		{name: "blocked", event: connectEventWithParent("blocked", "lin-c", "p3", "parent", "/opt/blocked", "10.0.0.1:9443"), want: 0},
	}
	argvEvent := connectEventWithParent("argv", "lin-d", "p4", "parent", "/opt/other", "10.0.0.1:9443")
	argvEvent.SubjectProc.Argv = []string{"/opt/other", "--probe"}
	tests = append(tests, struct {
		name  string
		event *eventv1.CanonicalEvent
		want  int
	}{name: "argv branch", event: argvEvent, want: 1})
	for _, tt := range tests {
		if got := countSignals(engine.Process(tt.event), "neutral_boolean_rule"); got != tt.want {
			t.Fatalf("%s signals = %d, want %d", tt.name, got, tt.want)
		}
	}
}

func TestRuleValidationRejectsInvalidCorrelate(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*CorrelateSpec)
		want   string
	}{
		{name: "invalid duration", mutate: func(spec *CorrelateSpec) { spec.Within = 0; spec.WithinText = "bad" }, want: "invalid correlate window"},
		{name: "zero window", mutate: func(spec *CorrelateSpec) { spec.Within = 0 }, want: "correlate window"},
		{name: "excessive window", mutate: func(spec *CorrelateSpec) { spec.Within = 25 * time.Hour }, want: "correlate window"},
		{name: "empty by", mutate: func(spec *CorrelateSpec) { spec.By = nil }, want: "correlate by field is required"},
		{name: "unknown by", mutate: func(spec *CorrelateSpec) { spec.By = []string{"process.unknown"} }, want: "unsupported correlate by field"},
		{name: "duplicate fact", mutate: func(spec *CorrelateSpec) { spec.Facts[1].ID = spec.Facts[0].ID }, want: "duplicate fact"},
		{name: "event conflict", mutate: func(spec *CorrelateSpec) { spec.Facts[0].Event = "file.write" }, want: "exactly one of event or events"},
		{name: "empty behaviors", mutate: func(spec *CorrelateSpec) { spec.Facts[0].Events = nil }, want: "exactly one of event or events"},
		{name: "blank behavior", mutate: func(spec *CorrelateSpec) { spec.Facts[0].Events = []string{" "} }, want: "behavior is required"},
		{name: "one fact", mutate: func(spec *CorrelateSpec) { spec.Facts = spec.Facts[:1] }, want: "at least two facts"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := neutralCorrelateSpec()
			tt.mutate(&spec)
			content := ContentSnapshot{Rules: []RuleSpec{{
				RuleID: "invalid_correlate", RuleSetRef: "ruleset:cep", RuntimeType: "correlate", Correlate: spec,
			}}}
			_, report := NewWithRuntime(cepPolicy(), contract.CollectionIntent{}, content)
			if report.Status != "rejected" || !containsWarning(report.Details, tt.want) {
				t.Fatalf("report = %+v, want rejected with %q", report, tt.want)
			}
		})
	}
}

func TestRuleValidationAcceptsValidCorrelate(t *testing.T) {
	content := ContentSnapshot{Rules: []RuleSpec{{
		RuleID: "neutral_correlate", RuleSetRef: "ruleset:cep", RuntimeType: "correlate", Correlate: neutralCorrelateSpec(),
	}}}
	_, report := NewWithRuntime(cepPolicy(), contract.CollectionIntent{}, content)
	if report.Status != "applied" {
		t.Fatalf("report = %+v, want applied", report)
	}
}

func neutralCorrelateSpec() CorrelateSpec {
	return CorrelateSpec{
		Within: 2 * time.Minute,
		By:     []string{"lineage_id"},
		Facts: []FactSpec{
			{ID: "change", Events: []string{"file.write", "file.chmod"}, Conditions: []ConditionSpec{{Field: "file.path", Op: "prefix", Value: "/tmp/test/"}}},
			{ID: "run", Event: "process.exec", Conditions: []ConditionSpec{{Field: "process.binary", Op: "prefix", Value: "/tmp/test/"}}},
		},
	}
}

func TestCorrelateRuntimeMatchesAllFactPermutations(t *testing.T) {
	permutations := [][]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}
	for _, order := range permutations {
		name := fmt.Sprintf("%d%d%d", order[0], order[1], order[2])
		t.Run(name, func(t *testing.T) {
			engine, report := newNeutralCorrelateEngine(EngineLimits{})
			if report.Status != "applied" {
				t.Fatalf("report = %+v", report)
			}
			events := neutralCorrelateEvents("lin-a", 1)
			var signals []*signalv1.Signal
			for _, index := range order {
				signals = append(signals, engine.Process(events[index])...)
			}
			if got := countSignals(signals, "neutral_three_fact"); got != 1 {
				t.Fatalf("signals = %d, want 1; all=%+v", got, signals)
			}
			for _, id := range []string{"change", "run", "access"} {
				if !contains(signals[0].GetEventRefs(), id) {
					t.Fatalf("refs = %v, missing %s", signals[0].GetEventRefs(), id)
				}
			}
		})
	}
}

func TestCorrelateRuntimeReplacesDuplicateFactEvidence(t *testing.T) {
	engine, _ := newNeutralCorrelateEngine(EngineLimits{})
	engine.Process(writeEventAt("change-old", "lin-a", "p1", "/bin/tool", "/tmp/test/item", 1))
	engine.Process(writeEventAt("change-new", "lin-a", "p1", "/bin/tool", "/tmp/test/item", 2))
	engine.Process(execEventAt("run", "lin-a", "p2", "parent", "/tmp/test/item", nil, 3))
	signals := engine.Process(connectEventAt("access", "lin-a", "p2", "parent", "/tmp/test/item", "10.0.0.1:9443", 4))
	if len(signals) != 1 || contains(signals[0].GetEventRefs(), "change-old") || !contains(signals[0].GetEventRefs(), "change-new") {
		t.Fatalf("signals = %+v, want latest fact evidence", signals)
	}
}

func TestCorrelateRuntimeExpiresAndIsolatesGroups(t *testing.T) {
	engine, _ := newNeutralCorrelateEngine(EngineLimits{})
	engine.Process(writeEventAt("change-a", "lin-a", "p1", "/bin/tool", "/tmp/test/a", 1))
	engine.Process(execEventAt("run-b", "lin-b", "p2", "parent", "/tmp/test/b", nil, 2))
	if signals := engine.Process(connectEventAt("access-a", "lin-a", "p1", "parent", "/tmp/test/a", "10.0.0.1:9443", 3)); len(signals) != 0 {
		t.Fatalf("cross-group signals = %+v", signals)
	}
	late := uint64((3 * time.Minute).Nanoseconds())
	if signals := engine.Process(execEventAt("run-a-late", "lin-a", "p1", "parent", "/tmp/test/a", nil, late)); len(signals) != 0 {
		t.Fatalf("expired signals = %+v", signals)
	}
	if engine.Metrics().ExpiredCEPGroups == 0 {
		t.Fatalf("metrics = %+v, want expired correlate group", engine.Metrics())
	}
}

func TestCorrelateRuntimeEnforcesGroupAndRefLimits(t *testing.T) {
	engine, _ := newNeutralCorrelateEngine(EngineLimits{MaxCEPGroups: 2, MaxCEPRefs: 2})
	for _, lineage := range []string{"lin-a", "lin-b", "lin-c"} {
		engine.Process(writeEventAt("change-"+lineage, lineage, "p1", "/bin/tool", "/tmp/test/"+lineage, 1))
	}
	if engine.Metrics().EvictedCEPGroups == 0 {
		t.Fatalf("metrics = %+v, want correlate eviction", engine.Metrics())
	}
	for _, event := range neutralCorrelateEvents("lin-c", 2)[1:] {
		signals := engine.Process(event)
		if len(signals) == 1 {
			if len(signals[0].GetEventRefs()) != 2 || engine.Metrics().DroppedEventRefs == 0 {
				t.Fatalf("signal=%+v metrics=%+v, want bounded refs", signals[0], engine.Metrics())
			}
		}
	}
}

func newNeutralCorrelateEngine(limits EngineLimits) (*Engine, ApplyReport) {
	rule := RuleSpec{
		RuleID: "neutral_three_fact", RuleSetRef: "ruleset:cep", RuntimeType: "correlate",
		RequiredBehaviors: []string{"file.write", "file.chmod", "process.exec", "network.connect"},
		Correlate: CorrelateSpec{Within: 2 * time.Minute, By: []string{"lineage_id"}, Facts: []FactSpec{
			{ID: "change", Events: []string{"file.write", "file.chmod"}, Conditions: []ConditionSpec{{Field: "file.path", Op: "prefix", Value: "/tmp/test/"}}},
			{ID: "run", Event: "process.exec", Conditions: []ConditionSpec{{Field: "process.binary", Op: "prefix", Value: "/tmp/test/"}}},
			{ID: "access", Event: "network.connect", Conditions: []ConditionSpec{{Field: "socket.port", Op: "in", Values: []string{"9443"}}}},
		}},
	}
	return NewWithRuntimeLimits(cepPolicy(), contract.CollectionIntent{}, ContentSnapshot{Rules: []RuleSpec{rule}}, limits)
}

func neutralCorrelateEvents(lineage string, start uint64) []*eventv1.CanonicalEvent {
	return []*eventv1.CanonicalEvent{
		writeEventAt("change", lineage, "p1", "/bin/tool", "/tmp/test/item", start),
		execEventAt("run", lineage, "p2", "parent", "/tmp/test/item", nil, start+1),
		connectEventAt("access", lineage, "p2", "parent", "/tmp/test/item", "10.0.0.1:9443", start+2),
	}
}

func conditionLeaf(condition ConditionSpec) ConditionNodeSpec {
	return ConditionNodeSpec{Condition: &condition}
}

func ptrConditionNode(node ConditionNodeSpec) *ConditionNodeSpec {
	return &node
}

func TestExprRuleSuppressesByDeclaredFieldsWithinWindow(t *testing.T) {
	rule := RuleSpec{
		RuleID: "suppressed_read", RuleSetRef: "ruleset:cep", RuntimeType: "expr", RequiredBehaviors: []string{"file.open"},
		Expr:        ExprSpec{Conditions: []ConditionSpec{{Field: "file.path", Op: "prefix", Value: "/secrets/"}}},
		Suppression: SuppressionSpec{Within: 5 * time.Minute, By: []string{"process.stable_id", "file.path"}},
	}
	engine, report := NewWithRuntime(cepPolicy(), contract.CollectionIntent{}, ContentSnapshot{Rules: []RuleSpec{rule}})
	if report.Status != "applied" {
		t.Fatalf("report = %+v", report)
	}
	events := []struct {
		event *eventv1.CanonicalEvent
		want  int
	}{
		{event: openEventAt("first", "lin-a", "proc-a", "/bin/cat", "/secrets/token", time.Second), want: 1},
		{event: openEventAt("duplicate", "lin-a", "proc-a", "/bin/cat", "/secrets/token", 2*time.Second), want: 0},
		{event: openEventAt("different-process", "lin-a", "proc-b", "/bin/cat", "/secrets/token", 3*time.Second), want: 1},
		{event: openEventAt("different-path", "lin-a", "proc-a", "/bin/cat", "/secrets/other", 4*time.Second), want: 1},
		{event: openEventAt("expired", "lin-a", "proc-a", "/bin/cat", "/secrets/token", 6*time.Minute), want: 1},
	}
	for _, item := range events {
		if got := countSignals(engine.Process(item.event), "suppressed_read"); got != item.want {
			t.Fatalf("%s signals = %d, want %d", item.event.GetId(), got, item.want)
		}
	}
}

func TestSuppressionEvictsAtKeyLimit(t *testing.T) {
	engine, _ := newTestEngine(t)
	now := time.Unix(100, 0)
	for i := 0; i <= maxSuppressionKeys; i++ {
		engine.suppressSignal("key-"+strconv.Itoa(i), now, time.Hour)
	}
	if got := len(engine.suppression); got > maxSuppressionKeys {
		t.Fatalf("suppression keys = %d, want <= %d", got, maxSuppressionKeys)
	}
	if engine.Metrics().SuppressionEvictions == 0 {
		t.Fatalf("metrics = %+v, want suppression eviction", engine.Metrics())
	}
}

func TestSuppressionCleanupRespectsOriginalWindows(t *testing.T) {
	engine, _ := newTestEngine(t)
	start := time.Unix(100, 0)
	engine.suppressSignal("long-window", start, 5*time.Minute)
	for i := 0; i < maxSuppressionKeys-1; i++ {
		engine.suppressSignal("short-"+strconv.Itoa(i), start.Add(2*time.Minute), time.Minute)
	}
	engine.suppressSignal("overflow", start.Add(2*time.Minute), time.Minute)
	if suppressed := engine.suppressSignal("long-window", start.Add(3*time.Minute), 5*time.Minute); !suppressed {
		t.Fatal("long-window key was expired using another rule's shorter window")
	}
}

func TestSignalCarriesContextAndIOCRefs(t *testing.T) {
	engine, _ := newTestEngine(t)
	var gotContext bool
	var gotIOC bool
	for _, sig := range engine.Process(writeEvent("e1", "lin-a", "p1", "/usr/bin/curl", "/dev/shm/x.sh")) {
		if sig.GetName() != "payload_dropped" {
			continue
		}
		for _, ref := range sig.GetContextRefs() {
			gotContext = gotContext || ref.GetRef() == "ctx:payload-path-prefixes"
		}
	}
	for _, sig := range engine.Process(connectEventWithParent("e2", "lin-a", "p2", "parent", "/bin/bash", "10.66.0.99:443")) {
		if sig.GetName() != "reverse_shell_pattern" {
			continue
		}
		for _, ref := range sig.GetIocRefs() {
			gotIOC = gotIOC || ref.GetRef() == "ioc:c2-control-port-feed"
		}
	}
	if !gotContext || !gotIOC {
		t.Fatalf("context=%t ioc=%t, want both refs on emitted signals", gotContext, gotIOC)
	}
}

func TestPayloadDroppedUsesDynamicExprSemantics(t *testing.T) {
	policy := policymodel.DefaultDetectionPolicy()
	policy.RuleSets = []policymodel.RuleSetRef{{Ref: "ruleset:custom-payload"}}
	content := ContentSnapshot{
		ContextRefs: map[string]ContentRef{
			"ctx:custom-payload-paths": {Ref: "ctx:custom-payload-paths", Version: "v2", Values: []string{"/opt/payloads/"}},
		},
		Rules: []RuleSpec{{
			RuleID: "payload_dropped", Version: 2, RuleSetRef: "ruleset:custom-payload", Severity: "high", RuntimeType: "expr",
			RequiredEvents: []RequiredEventSpec{
				{Behavior: "file.write", Fields: []string{"file.path"}},
				{Behavior: "file.chmod", Fields: []string{"file.path"}},
			},
			ContextRefs: []string{"ctx:custom-payload-paths"},
			Expr: ExprSpec{Conditions: []ConditionSpec{
				{Field: "behavior", Op: "in", Values: []string{"file.write", "file.chmod"}},
				{Field: "file.path", Op: "prefix", Ref: "ctx:custom-payload-paths"},
			}},
		}},
	}
	engine, report := NewWithRuntime(policy, contract.CollectionIntent{}, content)
	if report.Status != "applied" {
		t.Fatalf("report = %+v", report)
	}
	if got := countSignals(engine.Process(writeEvent("default", "lin-default", "p1", "/usr/bin/curl", "/dev/shm/x")), "payload_dropped"); got != 0 {
		t.Fatalf("default path signals = %d, want none under dynamic expr", got)
	}
	for _, event := range []*eventv1.CanonicalEvent{
		writeEvent("write", "lin-write", "p2", "/usr/bin/curl", "/opt/payloads/write.sh"),
		chmodEvent("chmod", "lin-chmod", "p3", "/usr/bin/chmod", "/opt/payloads/chmod.sh"),
	} {
		signals := engine.Process(event)
		if got := countSignals(signals, "payload_dropped"); got != 1 {
			t.Fatalf("%s signals = %d, want 1", event.GetId(), got)
		}
		var signal *signalv1.Signal
		for _, candidate := range signals {
			if candidate.GetName() == "payload_dropped" {
				signal = candidate
				break
			}
		}
		if !slices.Equal(signal.GetEventRefs(), []string{event.GetId()}) || len(signal.GetEntities()) != 2 {
			t.Fatalf("%s evidence = %+v, want event plus process/file entities", event.GetId(), signal)
		}
		if len(signal.GetContextRefs()) != 1 || signal.GetContextRefs()[0].GetRef() != "ctx:custom-payload-paths" || signal.GetContextRefs()[0].GetVersion() != "v2" {
			t.Fatalf("%s context refs = %+v", event.GetId(), signal.GetContextRefs())
		}
	}
}

func TestCredentialReadSuppressesDuplicateProcessPathSignals(t *testing.T) {
	enabled := true
	policy := testDetectionPolicy()
	policy.RuleOverrides = append(policy.RuleOverrides, policymodel.RuleOverride{RuleID: "credential_file_read", Enabled: &enabled})
	engine, _ := NewWithRuntime(policy, contract.CollectionIntent{}, testContentSnapshot(t))
	first := readEvent("e1", "lin-a", "proc-a", "/tmp/cat", "/etc/shadow")
	second := readEvent("e2", "lin-a", "proc-b", "/tmp/cat", "/etc/shadow")
	if got := countSignals(engine.Process(first), "credential_file_read"); got != 1 {
		t.Fatalf("first credential signal count = %d, want 1", got)
	}
	if got := countSignals(engine.Process(second), "credential_file_read"); got != 0 {
		t.Fatalf("duplicate credential signal count = %d, want 0", got)
	}
	third := readEvent("e3", "lin-a", "proc-a", "/tmp/cat", "/etc/sudoers")
	if got := countSignals(engine.Process(third), "credential_file_read"); got != 1 {
		t.Fatalf("different path credential signal count = %d, want 1", got)
	}
	fourth := readEvent("e4", "lin-b", "proc-c", "/tmp/cat", "/etc/shadow")
	if got := countSignals(engine.Process(fourth), "credential_file_read"); got != 1 {
		t.Fatalf("different lineage credential signal count = %d, want 1", got)
	}
}

func TestAccountDatabaseReadRequiresSuspiciousReader(t *testing.T) {
	tests := []struct {
		name string
		bin  string
		want int
	}{
		{name: "cat", bin: "/usr/bin/cat", want: 1},
		{name: "shell", bin: "/bin/bash", want: 1},
		{name: "account enumeration", bin: "/usr/bin/getent", want: 1},
		{name: "missing binary", want: 1},
		{name: "health curl", bin: "/usr/bin/curl", want: 0},
		{name: "sshd", bin: "/usr/sbin/sshd", want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine, _ := NewWithRuntime(testDetectionPolicy(), contract.CollectionIntent{}, testContentSnapshot(t))
			signals := engine.Process(readEvent("passwd-read", "lineage", "process", tt.bin, "/etc/passwd"))
			if got := countSignals(signals, "account_database_read"); got != tt.want {
				t.Fatalf("account database signals = %d, want %d", got, tt.want)
			}
			if got := countSignals(signals, "credential_file_read"); got != 0 {
				t.Fatalf("credential signals = %d, want 0 for /etc/passwd", got)
			}
			if tt.want == 1 {
				for _, signal := range signals {
					if signal.GetName() == "account_database_read" && signal.GetSeverity() != "low" {
						t.Fatalf("severity = %q, want low", signal.GetSeverity())
					}
				}
			}
		})
	}
}

func TestCredentialReadUsesExactSystemCommandBaselines(t *testing.T) {
	tests := []struct {
		name          string
		bin           string
		argv          []string
		untrustedArgv bool
		want          int
	}{
		{name: "sysarmor health", bin: "/usr/bin/sudo", argv: []string{"/usr/bin/sudo", "sysarmorctl", "--socket", "/run/sysarmor/agent/control.sock", "--json", "agent", "health"}, want: 0},
		{name: "sysarmor policy apply", bin: "/usr/bin/sudo", argv: []string{"/usr/bin/sudo", "sysarmorctl", "policy", "apply", "collection", "--file", "/tmp/policy.json"}, want: 0},
		{name: "absolute sysarmor path", bin: "/usr/bin/sudo", argv: []string{"/usr/bin/sudo", "/usr/local/bin/sysarmorctl", "content", "apply", "--file", "/tmp/content.json"}, want: 0},
		{name: "sudo user option", bin: "/usr/bin/sudo", argv: []string{"/usr/bin/sudo", "-u", "root", "sysarmorctl", "policy", "current"}, want: 0},
		{name: "sudo long user option", bin: "/usr/bin/sudo", argv: []string{"/usr/bin/sudo", "--user=root", "--", "sysarmorctl", "event", "watch"}, want: 0},
		{name: "sysarmor token in shell", bin: "/usr/bin/sudo", argv: []string{"/usr/bin/sudo", "bash", "-c", "echo sysarmorctl"}, want: 1},
		{name: "sysarmor token in quoted prompt", bin: "/usr/bin/sudo", argv: []string{"/usr/bin/sudo", "-p", "\"notice", "sysarmorctl", "tail\"", "cat", "/etc/shadow"}, want: 1},
		{name: "untrusted argv boundaries", bin: "/usr/bin/sudo", argv: []string{"/usr/bin/sudo", "sysarmorctl", "agent", "health"}, untrustedArgv: true, want: 1},
		{name: "sudo edit sysarmor path", bin: "/usr/bin/sudo", argv: []string{"/usr/bin/sudo", "-e", "sysarmorctl", "/etc/shadow"}, want: 1},
		{name: "sudo remove timestamp", bin: "/usr/bin/sudo", argv: []string{"/usr/bin/sudo", "-K", "sysarmorctl"}, want: 1},
		{name: "unknown sudo option", bin: "/usr/bin/sudo", argv: []string{"/usr/bin/sudo", "--unknown", "sysarmorctl", "agent", "health"}, want: 1},
		{name: "unknown sudo inline option", bin: "/usr/bin/sudo", argv: []string{"/usr/bin/sudo", "--unknown=value", "sysarmorctl", "agent", "health"}, want: 1},
		{name: "sudo dangerous command", bin: "/usr/bin/sudo", argv: []string{"/usr/bin/sudo", "cat", "/etc/shadow"}, want: 1},
		{name: "sudo missing argv", bin: "/usr/bin/sudo", want: 1},
		{name: "sshd daemon", bin: "/usr/sbin/sshd", argv: []string{"/usr/sbin/sshd", "-D", "-R"}, want: 0},
		{name: "sshd near miss", bin: "/usr/sbin/sshd", argv: []string{"sshd:", "user@pts/0"}, want: 1},
		{name: "cat", bin: "/usr/bin/cat", argv: []string{"cat", "/etc/shadow"}, want: 1},
		{name: "missing binary", argv: []string{"cat", "/etc/shadow"}, want: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine, _ := NewWithRuntime(testDetectionPolicy(), contract.CollectionIntent{}, testContentSnapshot(t))
			event := readEvent("read", "lineage", "process", tt.bin, "/etc/shadow")
			event.SubjectProc.Argv = tt.argv
			event.SubjectProc.ArgvBoundariesTrusted = !tt.untrustedArgv
			if got := countSignals(engine.Process(event), "credential_file_read"); got != tt.want {
				t.Fatalf("credential signals = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestCredentialReadIgnoresSudoAuthorizationFileReads(t *testing.T) {
	engine, _ := NewWithRuntime(testDetectionPolicy(), contract.CollectionIntent{}, testContentSnapshot(t))
	event := readEvent("sudoers", "lineage", "process", "/usr/bin/sudo", "/etc/sudoers")
	event.SubjectProc.Argv = []string{"/usr/bin/sudo", "bash", "-c", "echo workload"}
	if got := countSignals(engine.Process(event), "credential_file_read"); got != 0 {
		t.Fatalf("credential signals = %d, want 0 for sudo authorization file", got)
	}
}

func TestCredentialReadUsesDynamicExprSemantics(t *testing.T) {
	enabled := true
	policy := testDetectionPolicy()
	policy.RuleSets = []policymodel.RuleSetRef{{Ref: "ruleset:custom-credential"}}
	policy.RuleOverrides = append(policy.RuleOverrides, policymodel.RuleOverride{RuleID: "credential_file_read", Enabled: &enabled})
	content := ContentSnapshot{
		ContextRefs: map[string]ContentRef{
			"ctx:custom-credential-paths": {Ref: "ctx:custom-credential-paths", Version: "v2", Values: []string{"/opt/secrets/"}},
			"ctx:custom-trusted-binaries": {Ref: "ctx:custom-trusted-binaries", Version: "v2", Values: []string{"/opt/admin"}},
		},
		Rules: []RuleSpec{{
			RuleID: "credential_file_read", Version: 2, RuleSetRef: "ruleset:custom-credential", Severity: "medium", RuntimeType: "expr",
			RequiredEvents: []RequiredEventSpec{
				{Behavior: "file.read", Fields: []string{"file.path", "process.binary", "process.stable_id"}},
			},
			ContextRefs: []string{"ctx:custom-credential-paths", "ctx:custom-trusted-binaries"},
			Expr: ExprSpec{Conditions: []ConditionSpec{
				{Field: "file.path", Op: "prefix", Ref: "ctx:custom-credential-paths"},
				{Field: "process.binary", Op: "not_in", Ref: "ctx:custom-trusted-binaries"},
			}},
			Suppression: SuppressionSpec{Within: 5 * time.Minute, By: []string{"process.stable_id", "file.path"}},
		}},
	}
	engine, report := NewWithRuntime(policy, contract.CollectionIntent{}, mergeTestContent(t, content))
	if report.Status != "applied" {
		t.Fatalf("report = %+v", report)
	}
	if got := countSignals(engine.Process(readEvent("default", "lin-default", "p1", "/bin/cat", "/root/.ssh/id_rsa")), "credential_file_read"); got != 0 {
		t.Fatalf("default path signals = %d, want none under dynamic expr", got)
	}
	if got := countSignals(engine.Process(readEvent("trusted", "lin-trusted", "p2", "/opt/admin", "/opt/secrets/token")), "credential_file_read"); got != 0 {
		t.Fatalf("trusted binary signals = %d, want none", got)
	}
	signals := engine.Process(readEvent("read", "lin-read", "p3", "/bin/cat", "/opt/secrets/token"))
	if got := countSignals(signals, "credential_file_read"); got != 1 {
		t.Fatalf("credential signals = %d, want 1", got)
	}
	var signal *signalv1.Signal
	for _, candidate := range signals {
		if candidate.GetName() == "credential_file_read" {
			signal = candidate
			break
		}
	}
	if !slices.Equal(signal.GetEventRefs(), []string{"read"}) || len(signal.GetEntities()) != 2 || len(signal.GetContextRefs()) != 2 {
		t.Fatalf("signal = %+v, want event, process/file entities and contexts", signal)
	}
}

func countSignals(signals []*signalv1.Signal, name string) int {
	count := 0
	for _, sig := range signals {
		if sig.GetName() == name {
			count++
		}
	}
	return count
}

func TestWebRuntimeShellUsesObservedParentBinary(t *testing.T) {
	engine, _ := newTestEngine(t)
	engine.Process(execEvent("node", "lin-web", "stable-runtime", "init", "/usr/bin/node", []string{"/usr/bin/node", "/srv/server.js"}))
	shell := execEvent("shell", "lin-web", "stable-shell", "stable-runtime", "/bin/sh", []string{"/bin/sh", "-c", "id"})
	signals := engine.Process(shell)
	if got := countSignals(signals, "web_runtime_spawns_shell"); got != 1 {
		t.Fatalf("web runtime shell signals = %d, want 1", got)
	}
	for _, signal := range signals {
		if signal.GetName() == "web_runtime_spawns_shell" && !slices.Equal(signal.GetEventRefs(), []string{"node", "shell"}) {
			t.Fatalf("event refs = %v, want parent and shell events", signal.GetEventRefs())
		}
	}
}

func TestWebRuntimeRuleDeclaresSensorSourceFields(t *testing.T) {
	for _, rule := range testContentSnapshot(t).Rules {
		if rule.RuleID != "web_runtime_spawns_shell" {
			continue
		}
		fields := rule.RequiredEvents[0].Fields
		if !slices.Contains(fields, "process.binary") || slices.Contains(fields, "process.binary_name") {
			t.Fatalf("required fields = %v, want sensor process.binary without derived binary_name", fields)
		}
		return
	}
	t.Fatal("web_runtime_spawns_shell rule not found")
}

func TestCredentialReadDeclaresCollectedReadBehavior(t *testing.T) {
	for _, rule := range testContentSnapshot(t).Rules {
		if rule.RuleID != "credential_file_read" {
			continue
		}
		if len(rule.RequiredEvents) != 1 || rule.RequiredEvents[0].Behavior != "file.read" {
			t.Fatalf("required events = %+v, want only file.read", rule.RequiredEvents)
		}
		return
	}
	t.Fatal("credential_file_read rule not found")
}

func TestWebRuntimeShellKeepsAshCompatibility(t *testing.T) {
	engine, _ := newTestEngine(t)
	engine.Process(execEvent("node", "lin-ash", "runtime", "init", "/usr/bin/node", nil))
	signals := engine.Process(execEvent("ash", "lin-ash", "shell", "runtime", "/bin/ash", nil))
	if got := countSignals(signals, "web_runtime_spawns_shell"); got != 1 {
		t.Fatalf("ash web runtime shell signals = %d, want 1", got)
	}
}

func TestWebRuntimeShellRejectsRuntimeTokenOnlyInArgv(t *testing.T) {
	engine, _ := newTestEngine(t)
	shell := execEvent("shell", "lin-fake", "stable-shell", "opaque-parent", "/bin/sh", []string{"/bin/sh", "-c", ": # node marker"})
	if got := countSignals(engine.Process(shell), "web_runtime_spawns_shell"); got != 0 {
		t.Fatalf("forged argv web runtime signals = %d, want 0", got)
	}
}

func TestWebRuntimeShellRejectsObservedNonWebParent(t *testing.T) {
	engine, _ := newTestEngine(t)
	engine.Process(execEvent("worker", "lin-worker", "stable-worker", "init", "/usr/bin/sleep", []string{"/usr/bin/sleep", "infinity"}))
	shell := execEvent("shell", "lin-worker", "stable-shell", "stable-worker", "/bin/sh", []string{"/bin/sh", "-c", "id"})
	if got := countSignals(engine.Process(shell), "web_runtime_spawns_shell"); got != 0 {
		t.Fatalf("non-web parent signals = %d, want 0", got)
	}
}

func TestRuntimeContentSnapshotOverridesIOC(t *testing.T) {
	policy := testDetectionPolicy()
	engine, _ := NewWithRuntime(policy, contract.CollectionIntent{}, mergeTestContent(t, ContentSnapshot{
		IOCRefs: map[string]ContentRef{
			"ioc:c2-control-port-feed": {
				Ref:     "ioc:c2-control-port-feed",
				Version: "local-test",
				Digest:  "digest-a",
				Values:  []string{"9443"},
			},
		},
	}))
	if signals := engine.Process(connectEventWithParent("e1", "lin-a", "p1", "parent", "/bin/bash", "10.66.0.99:443")); len(signals) != 0 {
		t.Fatalf("443 signals = %+v, want none after IOC override", signals)
	}
	var gotVersion string
	for _, sig := range engine.Process(connectEventWithParent("e2", "lin-a", "p1", "parent", "/bin/bash", "10.66.0.99:9443")) {
		if sig.GetName() != "reverse_shell_pattern" {
			continue
		}
		for _, ref := range sig.GetIocRefs() {
			if ref.GetRef() == "ioc:c2-control-port-feed" {
				gotVersion = ref.GetVersion()
			}
		}
	}
	if gotVersion != "local-test" {
		t.Fatalf("ioc ref version = %q, want local-test", gotVersion)
	}
}

func TestReverseShellExprUsesDynamicContentAndPreciseEvidence(t *testing.T) {
	policy := testDetectionPolicy()
	content := ContentSnapshot{
		ContextRefs: map[string]ContentRef{
			"ctx:shell-binaries": {Ref: "ctx:shell-binaries", Version: "v2", Values: []string{"custom-shell"}},
		},
		IOCRefs: map[string]ContentRef{
			"ioc:c2-control-port-feed": {Ref: "ioc:c2-control-port-feed", Version: "v2", Values: []string{"9443"}},
		},
	}
	engine, report := NewWithRuntime(policy, contract.CollectionIntent{}, mergeTestContent(t, content))
	if report.Status != "applied" {
		t.Fatalf("report = %+v", report)
	}
	engine.Process(connectEventWithParent("download", "lin-a", "curl", "parent", "/usr/bin/curl", "10.0.0.1:8080"))
	if got := countSignals(engine.Process(connectEventWithParent("bash", "lin-a", "bash", "parent", "/bin/bash", "10.0.0.1:9443")), "reverse_shell_pattern"); got != 0 {
		t.Fatalf("bash signals = %d, want none after shell context replacement", got)
	}
	signals := engine.Process(connectEventWithParent("connect", "lin-a", "custom", "parent", "/opt/custom-shell", "10.0.0.1:9443"))
	if got := countSignals(signals, "reverse_shell_pattern"); got != 1 {
		t.Fatalf("custom shell signals = %d, want 1", got)
	}
	var signal *signalv1.Signal
	for _, candidate := range signals {
		if candidate.GetName() == "reverse_shell_pattern" {
			signal = candidate
			break
		}
	}
	if !slices.Equal(signal.GetEventRefs(), []string{"connect"}) || len(signal.GetEntities()) != 2 || !signal.GetTerminal() {
		t.Fatalf("signal = %+v, want precise terminal evidence", signal)
	}
	if signal.GetResponseIntent().GetResponseIntent() != "collect_evidence" || len(signal.GetContextRefs()) != 1 || len(signal.GetIocRefs()) != 1 {
		t.Fatalf("signal metadata = %+v", signal)
	}
}

func TestSuspiciousExecConnectUsesSequenceRule(t *testing.T) {
	for _, rule := range testContentSnapshot(t).Rules {
		if rule.RuleID != "suspicious_exec_connect" {
			continue
		}
		if rule.RuntimeType != "sequence" || len(rule.Sequence.Steps) != 2 {
			t.Fatalf("rule = %+v, want two-step sequence", rule)
		}
		return
	}
	t.Fatal("suspicious_exec_connect rule not found")
}

func TestSuspiciousExecConnectSequencePreservesAssociations(t *testing.T) {
	policy := testDetectionPolicy()
	content := ContentSnapshot{
		ContextRefs: map[string]ContentRef{
			"ctx:payload-path-prefixes": {Ref: "ctx:payload-path-prefixes", Version: "v2", Values: []string{"/opt/payloads/"}},
		},
		IOCRefs: map[string]ContentRef{
			"ioc:c2-control-port-feed": {Ref: "ioc:c2-control-port-feed", Version: "v2", Values: []string{"9443"}},
		},
	}
	tests := []struct {
		name          string
		connectStable string
		parentStable  string
		samePID       bool
		want          int
	}{
		{name: "direct", connectStable: "payload", parentStable: "init", want: 1},
		{name: "parent", connectStable: "child", parentStable: "payload", want: 1},
		{name: "same pid reexec", connectStable: "reexec", parentStable: "init", samePID: true, want: 1},
		{name: "unrelated", connectStable: "other", parentStable: "init", want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine, report := NewWithRuntime(policy, contract.CollectionIntent{}, mergeTestContent(t, content))
			if report.Status != "applied" {
				t.Fatalf("report = %+v", report)
			}
			exec := execEvent("exec", "lin-a", "payload", "init", "/opt/payloads/tool", nil)
			connect := connectEventWithParent("connect", "lin-a", tt.connectStable, tt.parentStable, "/bin/other", "10.0.0.1:9443")
			if tt.samePID {
				exec.SubjectProc.Pid = 42
				connect.SubjectProc.Pid = 42
			}
			engine.Process(exec)
			signals := engine.Process(connect)
			if got := countSignals(signals, "suspicious_exec_connect"); got != tt.want {
				t.Fatalf("signals = %d, want %d; all=%+v", got, tt.want, signals)
			}
			if tt.want == 1 {
				var signal *signalv1.Signal
				for _, candidate := range signals {
					if candidate.GetName() == "suspicious_exec_connect" {
						signal = candidate
					}
				}
				if !slices.Equal(signal.GetEventRefs(), []string{"exec", "connect"}) || len(signal.GetEntities()) < 3 {
					t.Fatalf("signal = %+v, want exec/connect evidence and process/file/socket entities", signal)
				}
			}
		})
	}
}

func TestSuspiciousExecConnectPreservesPayloadPathFromInterpreterArgv(t *testing.T) {
	policy := testDetectionPolicy()
	content := ContentSnapshot{
		ContextRefs: map[string]ContentRef{
			"ctx:payload-path-prefixes": {Ref: "ctx:payload-path-prefixes", Values: []string{"/opt/payloads/"}},
		},
		IOCRefs: map[string]ContentRef{
			"ioc:c2-control-port-feed": {Ref: "ioc:c2-control-port-feed", Values: []string{"9443"}},
		},
	}
	engine, report := NewWithRuntime(policy, contract.CollectionIntent{}, mergeTestContent(t, content))
	if report.Status != "applied" {
		t.Fatalf("report = %+v", report)
	}
	exec := execEvent("exec", "lin-a", "shell", "init", "/usr/bin/bash", []string{"/usr/bin/bash", "/opt/payloads/helper"})
	connect := connectEventWithParent("connect", "lin-a", "curl", "shell", "/usr/bin/curl", "10.0.0.1:9443")
	engine.Process(exec)

	for _, signal := range engine.Process(connect) {
		if signal.GetName() != "suspicious_exec_connect" {
			continue
		}
		for _, entity := range signal.GetEntities() {
			if entity.GetKind() == "file" && entity.GetKey() == "/opt/payloads/helper" {
				return
			}
		}
		t.Fatalf("signal entities = %+v, want payload path", signal.GetEntities())
	}
	t.Fatal("suspicious_exec_connect signal not emitted")
}

func TestSequenceEvidenceEntitiesIgnoreUnselectedAnyBranch(t *testing.T) {
	event := execEvent("exec", "lin-a", "shell", "init", "/usr/bin/bash", []string{"/usr/bin/bash", "/opt/unselected/helper"})
	group := ConditionNodeSpec{Any: []ConditionNodeSpec{
		conditionLeaf(ConditionSpec{Field: "process.binary", Op: "eq", Value: "/usr/bin/bash"}),
		conditionLeaf(ConditionSpec{Field: "process.argv", Op: "contains", Value: "/opt/unselected/"}),
	}}
	step := compiledStep{conditionGroup: compileConditionNode(&group, ContentSnapshot{})}

	entities := sequenceEvidenceEntities(newEventView(event), step, nil)

	for _, entity := range entities {
		if entity.GetKey() == "/opt/unselected/helper" {
			t.Fatalf("unselected any branch contributed evidence: %+v", entities)
		}
	}
}

func TestSequenceEvidenceEntitiesIgnoreNotBranches(t *testing.T) {
	event := execEvent("exec", "lin-a", "shell", "init", "/usr/bin/bash", []string{"/usr/bin/bash", "/opt/payload/helper"})
	leaf := conditionLeaf(ConditionSpec{Field: "process.argv", Op: "contains", Value: "/opt/payload/"})
	inner := ConditionNodeSpec{Not: &leaf}
	group := ConditionNodeSpec{Not: &inner}
	step := compiledStep{conditionGroup: compileConditionNode(&group, ContentSnapshot{})}

	entities := sequenceEvidenceEntities(newEventView(event), step, nil)

	if len(entities) != 0 {
		t.Fatalf("not branch contributed evidence: %+v", entities)
	}
}

func TestC2SocketRequiresConfiguredControlPort(t *testing.T) {
	policy := testDetectionPolicy()
	engine, _ := NewWithRuntime(policy, contract.CollectionIntent{}, mergeTestContent(t, ContentSnapshot{
		IOCRefs: map[string]ContentRef{
			"ioc:c2-ip-feed": {
				Ref:    "ioc:c2-ip-feed",
				Values: []string{"10.66.0.99"},
			},
			"ioc:c2-control-port-feed": {
				Ref:    "ioc:c2-control-port-feed",
				Values: []string{"443", "8443"},
			},
		},
	}))
	engine.Process(writeEvent("drop", "lin-a", "payload-proc", "/usr/bin/curl", "/var/lib/app/plugins/helper"))
	for _, sig := range engine.Process(connectEventWithParent("download", "lin-a", "curl-proc", "payload-proc", "/usr/bin/curl", "10.66.0.99:8080")) {
		if sig.GetName() == "suspicious_exec_connect" || sig.GetName() == "payload_lifecycle" || sig.GetName() == "reverse_shell_pattern" {
			t.Fatalf("download port emitted control-channel signal: %+v", sig)
		}
	}
}

func TestDownloadByLOLBinRequiresDownloadSocket(t *testing.T) {
	engine, _ := newTestEngine(t)
	if got := countSignals(engine.Process(connectEventWithParent("download", "lin-a", "curl-proc", "parent", "/usr/bin/curl", "10.66.0.99:8080")), "download_by_lolbin"); got != 1 {
		t.Fatalf("download_by_lolbin on download port = %d, want 1", got)
	}
	if got := countSignals(engine.Process(connectEventWithParent("benign", "lin-b", "curl-proc", "parent", "/usr/bin/curl", "198.51.100.25:80")), "download_by_lolbin"); got != 0 {
		t.Fatalf("download_by_lolbin on benign port = %d, want 0", got)
	}
}

func TestDownloadByLOLBinUsesDynamicClientContext(t *testing.T) {
	policy := testDetectionPolicy()
	engine, report := NewWithRuntime(policy, contract.CollectionIntent{}, mergeTestContent(t, ContentSnapshot{
		ContextRefs: map[string]ContentRef{
			"ctx:download-client-binaries": {
				Ref:     "ctx:download-client-binaries",
				Version: "v2",
				Values:  []string{"fetcher"},
			},
		},
	}))
	if report.Status != "applied" {
		t.Fatalf("report = %+v", report)
	}
	if got := countSignals(engine.Process(connectEventWithParent("curl", "lin-curl", "curl-proc", "parent", "/usr/bin/curl", "10.66.0.99:8080")), "download_by_lolbin"); got != 0 {
		t.Fatalf("curl signals = %d, want none after dynamic context replacement", got)
	}
	signals := engine.Process(connectEventWithParent("fetch", "lin-fetch", "fetch-proc", "parent", "/opt/fetcher", "10.66.0.99:8080"))
	if got := countSignals(signals, "download_by_lolbin"); got != 1 {
		t.Fatalf("fetcher signals = %d, want 1", got)
	}
	var signal *signalv1.Signal
	for _, candidate := range signals {
		if candidate.GetName() == "download_by_lolbin" {
			signal = candidate
			break
		}
	}
	if !slices.Equal(signal.GetEventRefs(), []string{"fetch"}) || len(signal.GetEntities()) != 2 {
		t.Fatalf("signal evidence = %+v, want event plus process/socket entities", signal)
	}
	if len(signal.GetContextRefs()) != 1 || signal.GetContextRefs()[0].GetRef() != "ctx:download-client-binaries" || signal.GetContextRefs()[0].GetVersion() != "v2" {
		t.Fatalf("context refs = %+v, want dynamic client context", signal.GetContextRefs())
	}
	if len(signal.GetIocRefs()) != 1 || signal.GetIocRefs()[0].GetRef() != "ioc:c2-download-port-feed" {
		t.Fatalf("ioc refs = %+v, want download port feed", signal.GetIocRefs())
	}
}

func TestRuntimeRulePackMetadataOverridesDefaultRule(t *testing.T) {
	enabled := true
	policy := &policymodel.DetectionPolicy{
		PolicyID:    "rulepack-test",
		Version:     1,
		Mode:        "observe",
		RuleSets:    []policymodel.RuleSetRef{{Ref: "ruleset:test", Version: "v1", Enabled: &enabled}},
		ContextRefs: []policymodel.ContentRef{{Ref: "ctx:shell-binaries", Version: "test"}},
		IOCRefs:     []policymodel.ContentRef{{Ref: "ioc:c2-control-port-feed", Version: "test"}},
	}
	content := testContentSnapshot(t)
	content.Rules = []RuleSpec{{
		RuleID:            "reverse_shell_pattern",
		Version:           7,
		RuleSetRef:        "ruleset:test",
		Severity:          "critical",
		RuntimeType:       "expr",
		RequiredBehaviors: []string{"network.connect"},
		ContextRefs:       []string{"ctx:shell-binaries"},
		IOCRefs:           []string{"ioc:c2-control-port-feed"},
		Expr: ExprSpec{Conditions: []ConditionSpec{
			{Field: "process.binary_name", Op: "in", Ref: "ctx:shell-binaries"},
			{Field: "socket.port", Op: "in", Ref: "ioc:c2-control-port-feed"},
		}},
	}}
	engine, _ := NewWithRuntime(policy, contract.CollectionIntent{}, content)
	for _, sig := range engine.Process(connectEventWithParent("e1", "lin-a", "p1", "parent", "/bin/bash", "10.66.0.99:443")) {
		if sig.GetName() == "reverse_shell_pattern" && sig.GetRuleVersion() == 7 && sig.GetRulesetRef() == "ruleset:test" {
			return
		}
	}
	t.Fatal("reverse_shell_pattern from external ruleset not emitted")
}

func TestCEPRuntimeExprRuleUsesContentRef(t *testing.T) {
	enabled := true
	policy := &policymodel.DetectionPolicy{
		PolicyID:    "cep-expr-test",
		Version:     1,
		Mode:        "observe",
		RuleSets:    []policymodel.RuleSetRef{{Ref: "ruleset:cep", Enabled: &enabled}},
		ContextRefs: []policymodel.ContentRef{{Ref: "ctx:credential-path-prefixes", Version: "v1"}},
	}
	engine, report := NewWithRuntime(policy, contract.CollectionIntent{}, ContentSnapshot{
		ContextRefs: map[string]ContentRef{
			"ctx:credential-path-prefixes": {Ref: "ctx:credential-path-prefixes", Version: "v1", Values: []string{"/run/secrets/"}},
		},
		Rules: []RuleSpec{{
			RuleID:      "cep_credential_read",
			Version:     3,
			RuleSetRef:  "ruleset:cep",
			Severity:    "high",
			RuntimeType: "expr",
			Expr: ExprSpec{Conditions: []ConditionSpec{
				{Field: "file.path", Op: "prefix", Ref: "ctx:credential-path-prefixes"},
			}},
			RequiredBehaviors: []string{"file.open"},
			ContextRefs:       []string{"ctx:credential-path-prefixes"},
		}},
	})
	if report.Status != "applied" {
		t.Fatalf("report = %+v", report)
	}
	signals := engine.Process(openEvent("e1", "lin-a", "p1", "/bin/cat", "/run/secrets/token"))
	if len(signals) != 1 || signals[0].GetName() != "cep_credential_read" {
		t.Fatalf("signals = %+v", signals)
	}
	if signals[0].GetRuleVersion() != 3 || signals[0].GetContextRefs()[0].GetVersion() != "v1" {
		t.Fatalf("signal metadata = %+v", signals[0])
	}
}

func TestRuntimeRejectsMissingProcessBinaryContext(t *testing.T) {
	content := ContentSnapshot{Rules: []RuleSpec{processBinaryContextRule()}}
	engine, report := NewWithRuntime(cepPolicy(), contract.CollectionIntent{}, content)
	if report.Status != "rejected" {
		t.Fatalf("report = %+v, want missing context rejection", report)
	}
	_ = engine
}

func TestRuntimeUsesExplicitProcessBinaryContext(t *testing.T) {
	content := ContentSnapshot{
		ContextRefs: map[string]ContentRef{
			"ctx:web-runtime-binaries": {Ref: "ctx:web-runtime-binaries", Version: "v2", Values: []string{"custom-web"}},
		},
		Rules: []RuleSpec{processBinaryContextRule()},
	}
	engine, report := NewWithRuntime(cepPolicy(), contract.CollectionIntent{}, content)
	if report.Status != "applied" {
		t.Fatalf("report = %+v", report)
	}
	if got := countSignals(engine.Process(execEvent("node", "lin-node", "node-stable", "init", "/usr/bin/node", nil)), "process_binary_context"); got != 0 {
		t.Fatalf("default context signals = %d, want dynamic context replacement", got)
	}
	if got := countSignals(engine.Process(execEvent("custom", "lin-custom", "custom-stable", "init", "/opt/custom-web", nil)), "process_binary_context"); got != 1 {
		t.Fatalf("custom context signals = %d, want 1", got)
	}
}

func TestDynamicWebRuntimeSequenceUsesContentContexts(t *testing.T) {
	enabled := true
	nonTerminal := false
	policy := &policymodel.DetectionPolicy{
		PolicyID: "dynamic-web", Version: 1, Mode: "observe",
		RuleSets: []policymodel.RuleSetRef{{Ref: "ruleset:dynamic-web", Enabled: &enabled}},
	}
	content := ContentSnapshot{
		ContextRefs: map[string]ContentRef{
			"ctx:web-runtime-binaries": {Ref: "ctx:web-runtime-binaries", Version: "v2", Values: []string{"custom-web"}},
			"ctx:shell-binaries":       {Ref: "ctx:shell-binaries", Version: "v2", Values: []string{"custom-shell"}},
		},
		Rules: []RuleSpec{webRuntimeSequenceRule("ruleset:dynamic-web", &nonTerminal)},
	}
	engine, report := NewWithRuntime(policy, contract.CollectionIntent{}, mergeTestContent(t, content))
	if report.Status != "applied" {
		t.Fatalf("report = %+v", report)
	}
	engine.Process(execEvent("runtime", "lin-web", "runtime-stable", "init", "/opt/custom-web", nil))
	signals := engine.Process(execEvent("shell", "lin-web", "shell-stable", "runtime-stable", "/opt/custom-shell", nil))
	if len(signals) != 1 || signals[0].GetName() != "web_runtime_spawns_shell" {
		t.Fatalf("signals = %+v", signals)
	}
	if signals[0].GetTerminal() || !slices.Equal(signals[0].GetEventRefs(), []string{"runtime", "shell"}) {
		t.Fatalf("signal = %+v, want non-terminal with parent and shell refs", signals[0])
	}
}

func webRuntimeSequenceRule(ruleSet string, terminal *bool) RuleSpec {
	return RuleSpec{
		RuleID: "web_runtime_spawns_shell", RuleSetRef: ruleSet, RuntimeType: "sequence", Terminal: terminal,
		ContextRefs: []string{"ctx:web-runtime-binaries", "ctx:shell-binaries"},
		Sequence: SequenceSpec{Within: time.Minute, By: []string{"lineage_id"}, Steps: []StepSpec{
			{ID: "runtime", Behavior: "process.exec", Conditions: []ConditionSpec{{Field: "process.binary_name", Op: "in", Ref: "ctx:web-runtime-binaries"}}},
			{ID: "shell", Behavior: "process.exec", Conditions: []ConditionSpec{
				{Field: "process.binary_name", Op: "in", Ref: "ctx:shell-binaries"},
				{Field: "parent.stable_id", Op: "same_as", Step: "runtime", StepField: "process.stable_id"},
			}},
		}},
	}
}

func processBinaryContextRule() RuleSpec {
	return RuleSpec{
		RuleID: "process_binary_context", RuleSetRef: "ruleset:cep", RuntimeType: "expr",
		RequiredBehaviors: []string{"process.exec"},
		ContextRefs:       []string{"ctx:web-runtime-binaries"},
		Expr: ExprSpec{Conditions: []ConditionSpec{{
			Field: "process.binary_name", Op: "in", Ref: "ctx:web-runtime-binaries",
		}}},
	}
}

func TestCEPRuntimeSequenceRuleEmitsMultipleEventRefs(t *testing.T) {
	enabled := true
	policy := &policymodel.DetectionPolicy{
		PolicyID: "cep-sequence-test",
		Version:  1,
		Mode:     "observe",
		RuleSets: []policymodel.RuleSetRef{{Ref: "ruleset:cep", Enabled: &enabled}},
	}
	engine, _ := NewWithRuntime(policy, contract.CollectionIntent{}, ContentSnapshot{
		Rules: []RuleSpec{{
			RuleID:      "cep_payload_lifecycle",
			Version:     2,
			RuleSetRef:  "ruleset:cep",
			Severity:    "critical",
			RuntimeType: "sequence",
			Sequence: SequenceSpec{
				Within: 60 * 1_000_000_000,
				By:     []string{"lineage_id"},
				Steps: []StepSpec{
					{ID: "drop", Behavior: "file.write", Conditions: []ConditionSpec{{Field: "file.path", Op: "prefix", Value: "/dev/shm/"}}},
					{ID: "chmod", Behavior: "file.chmod", Conditions: []ConditionSpec{{Field: "file.path", Op: "same_as", Step: "drop"}}},
					{ID: "exec", Behavior: "process.exec", Conditions: []ConditionSpec{{Field: "process.binary", Op: "same_as", Step: "drop", StepField: "file.path"}}},
					{ID: "connect", Behavior: "network.connect", Conditions: []ConditionSpec{{Field: "socket.port", Op: "in", Values: []string{"443"}}}},
				},
			},
			RequiredBehaviors: []string{"file.write", "file.chmod", "process.exec", "network.connect"},
		}},
	})
	events := []*eventv1.CanonicalEvent{
		writeEventAt("e1", "lin-a", "p1", "/usr/bin/curl", "/dev/shm/x", 1),
		chmodEventAt("e2", "lin-a", "p2", "/usr/bin/chmod", "/dev/shm/x", 2),
		execEventAt("e3", "lin-a", "p3", "", "/dev/shm/x", nil, 3),
		connectEventAt("e4", "lin-a", "p3", "", "/dev/shm/x", "10.0.0.1:443", 4),
	}
	var got []*signalv1.Signal
	for _, ev := range events {
		got = append(got, engine.Process(ev)...)
	}
	var refs []string
	for _, sig := range got {
		if sig.GetName() == "cep_payload_lifecycle" {
			refs = sig.GetEventRefs()
		}
	}
	for _, want := range []string{"e1", "e2", "e3", "e4"} {
		if !contains(refs, want) {
			t.Fatalf("cep refs = %v, want %s; signals=%+v", refs, want, got)
		}
	}
}

func TestCEPRuntimeSequenceExpiresWindow(t *testing.T) {
	engine, _ := NewWithRuntimeLimits(cepPolicy(), contract.CollectionIntent{}, ContentSnapshot{Rules: []RuleSpec{cepSequenceRule()}}, EngineLimits{})
	if signals := engine.Process(writeEventAt("e1", "lin-a", "p1", "/bin/curl", "/dev/shm/x", 1)); len(signals) != 0 {
		t.Fatalf("signals after first step = %+v", signals)
	}
	if signals := engine.Process(chmodEventAt("e2", "lin-a", "p2", "/bin/chmod", "/dev/shm/x", uint64(120*1_000_000_000))); len(signals) != 0 {
		t.Fatalf("signals after expired step = %+v", signals)
	}
	metrics := engine.Metrics()
	if metrics.ExpiredCEPGroups == 0 {
		t.Fatalf("metrics = %+v, want expired group", metrics)
	}
}

func TestCEPRuntimeEvictsGroupsAtLimit(t *testing.T) {
	engine, _ := NewWithRuntimeLimits(cepPolicy(), contract.CollectionIntent{}, ContentSnapshot{Rules: []RuleSpec{cepSequenceRule()}}, EngineLimits{MaxCEPGroups: 2, MaxCEPRefs: 8})
	for _, lineage := range []string{"lin-a", "lin-b", "lin-c"} {
		engine.Process(writeEventAt("drop-"+lineage, lineage, "p1", "/bin/curl", "/dev/shm/"+lineage, 1))
	}
	metrics := engine.Metrics()
	if metrics.EvictedCEPGroups == 0 || metrics.ActiveCEPGroups > 2 {
		t.Fatalf("metrics = %+v, want eviction and active <= 2", metrics)
	}
}

func TestCEPRuntimeDropsRefsAtLimit(t *testing.T) {
	engine, _ := NewWithRuntimeLimits(cepPolicy(), contract.CollectionIntent{}, ContentSnapshot{Rules: []RuleSpec{cepSequenceRule()}}, EngineLimits{MaxCEPGroups: 8, MaxCEPRefs: 2})
	events := []*eventv1.CanonicalEvent{
		writeEventAt("e1", "lin-a", "p1", "/bin/curl", "/dev/shm/x", 1),
		chmodEventAt("e2", "lin-a", "p2", "/bin/chmod", "/dev/shm/x", 2),
		execEventAt("e3", "lin-a", "p3", "", "/dev/shm/x", nil, 3),
		connectEventAt("e4", "lin-a", "p3", "", "/dev/shm/x", "10.0.0.1:443", 4),
	}
	var refs []string
	for _, ev := range events {
		for _, sig := range engine.Process(ev) {
			if sig.GetName() == "cep_payload_lifecycle" {
				refs = sig.GetEventRefs()
			}
		}
	}
	metrics := engine.Metrics()
	if len(refs) != 2 || metrics.DroppedEventRefs == 0 {
		t.Fatalf("refs=%v metrics=%+v, want 2 refs and dropped refs", refs, metrics)
	}
}

func execEvent(id, lineage, stable, parent, bin string, argv []string) *eventv1.CanonicalEvent {
	return &eventv1.CanonicalEvent{
		Id: id, Behavior: "process.exec", LineageId: lineage, ParentStableId: parent,
		SubjectProc: &eventv1.ProcessRef{StableId: stable, Binary: bin, Argv: argv},
	}
}

func connectEventWithParent(id, lineage, stable, parent, bin, dst string) *eventv1.CanonicalEvent {
	return &eventv1.CanonicalEvent{
		Id: id, Behavior: "network.connect", LineageId: lineage, ParentStableId: parent,
		SubjectProc: &eventv1.ProcessRef{StableId: stable, Binary: bin},
		Object:      &eventv1.ObjectRef{Kind: "socket", SocketAddr: dst},
	}
}

func writeEvent(id, lineage, stable, bin, file string) *eventv1.CanonicalEvent {
	return &eventv1.CanonicalEvent{
		Id: id, Behavior: "file.write", LineageId: lineage,
		SubjectProc: &eventv1.ProcessRef{StableId: stable, Binary: bin},
		Object:      &eventv1.ObjectRef{Kind: "file", FilePath: file},
	}
}

func chmodEvent(id, lineage, stable, bin, file string) *eventv1.CanonicalEvent {
	return &eventv1.CanonicalEvent{
		Id: id, Behavior: "file.chmod", LineageId: lineage,
		SubjectProc: &eventv1.ProcessRef{StableId: stable, Binary: bin},
		Object:      &eventv1.ObjectRef{Kind: "file", FilePath: file},
	}
}

func openEvent(id, lineage, stable, bin, file string) *eventv1.CanonicalEvent {
	return &eventv1.CanonicalEvent{
		Id: id, Behavior: "file.open", LineageId: lineage,
		SubjectProc: &eventv1.ProcessRef{StableId: stable, Binary: bin},
		Object:      &eventv1.ObjectRef{Kind: "file", FilePath: file},
	}
}

func readEvent(id, lineage, stable, bin, file string) *eventv1.CanonicalEvent {
	ev := openEvent(id, lineage, stable, bin, file)
	ev.Behavior = "file.read"
	return ev
}

func writeEventAt(id, lineage, stable, bin, file string, ts uint64) *eventv1.CanonicalEvent {
	ev := writeEvent(id, lineage, stable, bin, file)
	ev.OccurredAtNs = ts
	return ev
}

func chmodEventAt(id, lineage, stable, bin, file string, ts uint64) *eventv1.CanonicalEvent {
	ev := chmodEvent(id, lineage, stable, bin, file)
	ev.OccurredAtNs = ts
	return ev
}

func openEventAt(id, lineage, stable, bin, file string, ts time.Duration) *eventv1.CanonicalEvent {
	ev := openEvent(id, lineage, stable, bin, file)
	ev.OccurredAtNs = uint64(ts.Nanoseconds())
	return ev
}

func execEventAt(id, lineage, stable, parent, bin string, argv []string, ts uint64) *eventv1.CanonicalEvent {
	ev := execEvent(id, lineage, stable, parent, bin, argv)
	ev.OccurredAtNs = ts
	return ev
}

func connectEventAt(id, lineage, stable, parent, bin, dst string, ts uint64) *eventv1.CanonicalEvent {
	ev := connectEventWithParent(id, lineage, stable, parent, bin, dst)
	ev.OccurredAtNs = ts
	return ev
}

func contains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func containsWarning(items []string, want string) bool {
	for _, item := range items {
		if strings.Contains(item, want) {
			return true
		}
	}
	return false
}

func cepPolicy() *policymodel.DetectionPolicy {
	enabled := true
	return &policymodel.DetectionPolicy{
		PolicyID: "cep-test",
		Version:  1,
		Mode:     "observe",
		RuleSets: []policymodel.RuleSetRef{{Ref: "ruleset:cep", Enabled: &enabled}},
	}
}

func cepSequenceRule() RuleSpec {
	return RuleSpec{
		RuleID:      "cep_payload_lifecycle",
		Version:     2,
		RuleSetRef:  "ruleset:cep",
		Severity:    "critical",
		RuntimeType: "sequence",
		Sequence: SequenceSpec{
			Within: 60 * 1_000_000_000,
			By:     []string{"lineage_id"},
			Steps: []StepSpec{
				{ID: "drop", Behavior: "file.write", Conditions: []ConditionSpec{{Field: "file.path", Op: "prefix", Value: "/dev/shm/"}}},
				{ID: "chmod", Behavior: "file.chmod", Conditions: []ConditionSpec{{Field: "file.path", Op: "same_as", Step: "drop"}}},
				{ID: "exec", Behavior: "process.exec", Conditions: []ConditionSpec{{Field: "process.binary", Op: "same_as", Step: "drop", StepField: "file.path"}}},
				{ID: "connect", Behavior: "network.connect", Conditions: []ConditionSpec{{Field: "socket.port", Op: "in", Values: []string{"443"}}}},
			},
		},
	}
}
