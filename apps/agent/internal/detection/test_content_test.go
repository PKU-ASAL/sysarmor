package detection

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	contractmapper "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/contracts"
	agentcontent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/content"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

const testRuleSetRef = "ruleset:cep-endpoint"

func processWire(engine *Engine, event *eventv1.CanonicalEvent) []*signalv1.Signal {
	return engine.Process(contractmapper.DomainEvent(event))
}

func testDetectionPolicy() *policymodel.DetectionPolicy {
	policy := policymodel.DefaultDetectionPolicy()
	policy.RuleSets = []policymodel.RuleSetRef{{Ref: testRuleSetRef}}
	return policy
}

func testContentSnapshot(t testing.TB) ContentSnapshot {
	t.Helper()
	store := agentcontent.NewStore()
	paths, err := filepath.Glob(filepath.Join("..", "..", "..", "..", "deployments", "agent", "content", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Apply(string(raw), true, false); err != nil {
			t.Fatalf("load test content %s: %v", path, err)
		}
	}
	return convertTestSnapshot(store.Snapshot())
}

func convertTestSnapshot(snapshot agentcontent.Snapshot) ContentSnapshot {
	out := ContentSnapshot{ContextRefs: map[string]ContentRef{}, IOCRefs: map[string]ContentRef{}}
	for ref, set := range snapshot.ContextSets {
		out.ContextRefs[ref] = ContentRef{Ref: ref, Version: set.Version, Digest: set.Digest, Values: set.Values}
	}
	for ref, set := range snapshot.IOCPacks {
		out.IOCRefs[ref] = ContentRef{Ref: ref, Version: set.Version, Digest: set.Digest, Values: set.Values}
	}
	for _, rule := range snapshot.Rules {
		out.Rules = append(out.Rules, convertTestRule(rule))
	}
	return out
}

func convertTestRule(rule agentcontent.Rule) RuleSpec {
	return RuleSpec{
		RuleID: rule.RuleID, Version: rule.Version, RuleSetRef: rule.RuleSetRef, Severity: rule.Severity,
		Runtime: rule.RuntimeEntry, RuntimeType: rule.RuntimeType,
		Expr: convertTestExpr(rule.Expr), Sequence: convertTestSequence(rule.Sequence), Correlate: convertTestCorrelate(rule.Correlate),
		Suppression: convertTestSuppression(rule.Suppression), RequiredEvents: convertTestEvents(rule.RequiredEvents),
		RequiredBehaviors: testRequiredBehaviors(rule.RequiredEvents), ContextRefs: rule.ContextRefs, IOCRefs: rule.IOCRefs,
		ResponseIntent: &policymodel.ResponseIntentRef{Action: rule.ResponseIntent.Action, Confidence: rule.ResponseIntent.Confidence, Reason: rule.ResponseIntent.Reason},
		Terminal:       rule.Terminal,
	}
}

func convertTestExpr(expr agentcontent.RuntimeExpr) ExprSpec {
	out := ExprSpec{ConditionGroup: convertTestNode(expr.ConditionGroup)}
	for _, condition := range expr.Conditions {
		out.Conditions = append(out.Conditions, convertTestCondition(condition))
	}
	return out
}

func convertTestSequence(sequence agentcontent.RuntimeSequence) SequenceSpec {
	within, _ := time.ParseDuration(sequence.Within)
	out := SequenceSpec{Within: within, By: sequence.By}
	for _, step := range sequence.Steps {
		next := StepSpec{ID: step.ID, Behavior: firstNonEmpty(step.Behavior, step.Event), ConditionGroup: convertTestNode(step.ConditionGroup)}
		for _, condition := range step.Conditions {
			next.Conditions = append(next.Conditions, convertTestCondition(condition))
		}
		out.Steps = append(out.Steps, next)
	}
	return out
}

func convertTestCorrelate(correlate agentcontent.RuntimeCorrelate) CorrelateSpec {
	within, _ := time.ParseDuration(correlate.Within)
	out := CorrelateSpec{Within: within, WithinText: correlate.Within, By: correlate.By}
	for _, fact := range correlate.Facts {
		next := FactSpec{ID: fact.ID, Event: fact.Event, Events: fact.Events, ConditionGroup: convertTestNode(fact.ConditionGroup)}
		for _, condition := range fact.Conditions {
			next.Conditions = append(next.Conditions, convertTestCondition(condition))
		}
		out.Facts = append(out.Facts, next)
	}
	return out
}

func convertTestNode(node *agentcontent.RuntimeConditionNode) *ConditionNodeSpec {
	if node == nil {
		return nil
	}
	out := &ConditionNodeSpec{Not: convertTestNode(node.Not)}
	for i := range node.All {
		out.All = append(out.All, *convertTestNode(&node.All[i]))
	}
	for i := range node.Any {
		out.Any = append(out.Any, *convertTestNode(&node.Any[i]))
	}
	if node.Condition != nil {
		condition := convertTestCondition(*node.Condition)
		out.Condition = &condition
	}
	return out
}

func convertTestCondition(condition agentcontent.RuntimeCondition) ConditionSpec {
	return ConditionSpec{Field: condition.Field, Op: condition.Op, Value: condition.Value, Values: condition.Values, Ref: condition.Ref, Step: condition.Step, StepField: condition.StepField}
}

func convertTestSuppression(suppression agentcontent.RuntimeSuppression) SuppressionSpec {
	within, _ := time.ParseDuration(suppression.Within)
	return SuppressionSpec{Within: within, By: suppression.By}
}

func convertTestEvents(events []agentcontent.RequiredEvent) []RequiredEventSpec {
	out := make([]RequiredEventSpec, 0, len(events))
	for _, event := range events {
		out = append(out, RequiredEventSpec{Behavior: event.Behavior, Fields: event.Fields})
	}
	return out
}

func testRequiredBehaviors(events []agentcontent.RequiredEvent) []string {
	var out []string
	for _, event := range events {
		out = appendUnique(out, event.Behavior)
	}
	return out
}

func newTestEngine(t testing.TB) (*Engine, ApplyReport) {
	t.Helper()
	return NewWithRuntime(testDetectionPolicy(), contractCollectionIntent(), testContentSnapshot(t))
}

func newTestEngineWithContent(t testing.TB, content ContentSnapshot) (*Engine, ApplyReport) {
	t.Helper()
	return NewWithRuntime(testDetectionPolicy(), contract.CollectionIntent{}, mergeTestContent(t, content))
}

func mergeTestContent(t testing.TB, overrides ContentSnapshot) ContentSnapshot {
	t.Helper()
	content := testContentSnapshot(t)
	for ref, item := range overrides.ContextRefs {
		content.ContextRefs[ref] = item
	}
	for ref, item := range overrides.IOCRefs {
		content.IOCRefs[ref] = item
	}
	if len(overrides.Rules) > 0 {
		content.Rules = overrides.Rules
	}
	return content
}

func contractCollectionIntent() contract.CollectionIntent {
	return contract.CollectionIntent{}
}
