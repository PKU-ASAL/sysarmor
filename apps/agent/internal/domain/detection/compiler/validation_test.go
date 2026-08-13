package compiler_test

import (
	"strings"
	"testing"
	"time"

	detection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection/compiler"
)

func TestValidateRejectsUnsupportedCondition(t *testing.T) {
	tests := []struct {
		name      string
		condition detection.Condition
		want      string
	}{
		{name: "field", condition: detection.Condition{Field: "process.unknown", Operator: "eq"}, want: "unsupported field"},
		{name: "operator", condition: detection.Condition{Field: "process.binary", Operator: "magic"}, want: "unsupported operator"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := expressionRule(tt.condition)
			assertValidationError(t, compiler.Validate([]detection.Rule{rule}), tt.want)
		})
	}
}

func TestValidateRejectsUnknownPriorSequenceStep(t *testing.T) {
	rule := detection.Rule{
		ID:          "invalid_sequence",
		RuntimeType: "sequence",
		Sequence: detection.Sequence{Within: time.Minute, Steps: []detection.Step{
			{ID: "runtime", Behavior: "process.exec"},
			{ID: "shell", Behavior: "process.exec", Conditions: []detection.Condition{{
				Field: "parent.stable_id", Operator: "same_as", Step: "missing", StepField: "process.stable_id",
			}}},
		}},
	}
	assertValidationError(t, compiler.Validate([]detection.Rule{rule}), "unknown prior step")
}

func TestValidateRejectsInvalidSuppression(t *testing.T) {
	tests := []struct {
		name        string
		suppression detection.Suppression
		want        string
	}{
		{name: "zero window", suppression: detection.Suppression{By: []string{"process.stable_id"}}, want: "suppression window"},
		{name: "excessive window", suppression: detection.Suppression{Within: 25 * time.Hour, By: []string{"process.stable_id"}}, want: "suppression window"},
		{name: "missing key", suppression: detection.Suppression{Within: time.Minute}, want: "suppression by field"},
		{name: "unknown field", suppression: detection.Suppression{Within: time.Minute, By: []string{"process.unknown"}}, want: "unsupported suppression by field"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := expressionRule(detection.Condition{Field: "file.path", Operator: "exists"})
			rule.Suppression = tt.suppression
			assertValidationError(t, compiler.Validate([]detection.Rule{rule}), tt.want)
		})
	}
}

func TestValidateRejectsInvalidConditionTree(t *testing.T) {
	leaf := conditionLeaf(detection.Condition{Field: "file.path", Operator: "exists"})
	tests := []struct {
		name string
		node *detection.ConditionNode
		want string
	}{
		{name: "empty", node: &detection.ConditionNode{}, want: "condition node must set exactly one kind"},
		{name: "multiple kinds", node: &detection.ConditionNode{All: []detection.ConditionNode{leaf}, Condition: leaf.Condition}, want: "condition node must set exactly one kind"},
		{name: "empty any", node: &detection.ConditionNode{Any: []detection.ConditionNode{}}, want: "any requires children"},
		{name: "unknown field", node: nodePtr(conditionLeaf(detection.Condition{Field: "file.unknown", Operator: "exists"})), want: "unsupported field"},
	}
	deep := leaf
	for range 9 {
		deep = detection.ConditionNode{Not: nodePtr(deep)}
	}
	tests = append(tests, struct {
		name string
		node *detection.ConditionNode
		want string
	}{name: "too deep", node: &deep, want: "maximum depth"})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := expressionRule(detection.Condition{Field: "file.path", Operator: "exists"})
			rule.Expression.ConditionGroup = tt.node
			assertValidationError(t, compiler.Validate([]detection.Rule{rule}), tt.want)
		})
	}
}

func TestValidateCorrelate(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*detection.Correlate)
		want   string
	}{
		{name: "invalid duration", mutate: func(spec *detection.Correlate) { spec.Within = 0; spec.WithinText = "bad" }, want: "invalid correlate window"},
		{name: "zero window", mutate: func(spec *detection.Correlate) { spec.Within = 0 }, want: "correlate window"},
		{name: "empty by", mutate: func(spec *detection.Correlate) { spec.By = nil }, want: "correlate by field is required"},
		{name: "unknown by", mutate: func(spec *detection.Correlate) { spec.By = []string{"process.unknown"} }, want: "unsupported correlate by field"},
		{name: "duplicate fact", mutate: func(spec *detection.Correlate) { spec.Facts[1].ID = spec.Facts[0].ID }, want: "duplicate fact"},
		{name: "event conflict", mutate: func(spec *detection.Correlate) { spec.Facts[0].Event = "file.write" }, want: "exactly one of event or events"},
		{name: "one fact", mutate: func(spec *detection.Correlate) { spec.Facts = spec.Facts[:1] }, want: "at least two facts"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := validCorrelate()
			tt.mutate(&spec)
			rule := detection.Rule{ID: "correlate", RuntimeType: "correlate", Correlate: spec}
			assertValidationError(t, compiler.Validate([]detection.Rule{rule}), tt.want)
		})
	}
}

func TestValidateAcceptsValidCorrelate(t *testing.T) {
	rule := detection.Rule{ID: "correlate", RuntimeType: "correlate", Correlate: validCorrelate()}
	if errors := compiler.Validate([]detection.Rule{rule}); len(errors) != 0 {
		t.Fatalf("Validate() errors = %v, want none", errors)
	}
}

func TestValidateRejectsInvalidRuntimeShape(t *testing.T) {
	tests := []struct {
		name string
		rule detection.Rule
		want string
	}{
		{name: "runtime type", rule: detection.Rule{ID: "invalid", RuntimeType: "custom"}, want: "unsupported runtime type"},
		{name: "empty expression", rule: detection.Rule{ID: "invalid", RuntimeType: "expr"}, want: "expr runtime requires conditions"},
		{name: "empty sequence", rule: detection.Rule{ID: "invalid", RuntimeType: "sequence"}, want: "sequence runtime requires steps"},
		{name: "missing step id", rule: detection.Rule{ID: "invalid", RuntimeType: "sequence", Sequence: detection.Sequence{Steps: []detection.Step{{Behavior: "process.exec"}}}}, want: "step id is required"},
		{name: "missing step behavior", rule: detection.Rule{ID: "invalid", RuntimeType: "sequence", Sequence: detection.Sequence{Steps: []detection.Step{{ID: "exec"}}}}, want: "behavior is required"},
		{name: "empty correlate", rule: detection.Rule{ID: "invalid", RuntimeType: "correlate"}, want: "correlate runtime requires facts"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertValidationError(t, compiler.Validate([]detection.Rule{tt.rule}), tt.want)
		})
	}
}

func TestValidateIgnoresLegacyRuntimeEntrypointWhenTypeIsEmpty(t *testing.T) {
	rule := detection.Rule{ID: "builtin", Runtime: "builtin.reverse_shell_pattern"}
	if errors := compiler.Validate([]detection.Rule{rule}); len(errors) != 0 {
		t.Fatalf("Validate() errors = %v, want none", errors)
	}
}

func expressionRule(condition detection.Condition) detection.Rule {
	return detection.Rule{
		ID:          "expression",
		RuntimeType: "expr",
		Expression:  detection.Expression{Conditions: []detection.Condition{condition}},
	}
}

func validCorrelate() detection.Correlate {
	return detection.Correlate{
		Within: 2 * time.Minute,
		By:     []string{"lineage_id"},
		Facts: []detection.Fact{
			{ID: "change", Events: []string{"file.write", "file.chmod"}, Conditions: []detection.Condition{{Field: "file.path", Operator: "prefix"}}},
			{ID: "run", Event: "process.exec", Conditions: []detection.Condition{{Field: "process.binary", Operator: "prefix"}}},
		},
	}
}

func conditionLeaf(condition detection.Condition) detection.ConditionNode {
	return detection.ConditionNode{Condition: &condition}
}

func nodePtr(node detection.ConditionNode) *detection.ConditionNode {
	return &node
}

func assertValidationError(t *testing.T, errors []string, want string) {
	t.Helper()
	for _, message := range errors {
		if strings.Contains(message, want) {
			return
		}
	}
	t.Fatalf("Validate() errors = %v, want substring %q", errors, want)
}
