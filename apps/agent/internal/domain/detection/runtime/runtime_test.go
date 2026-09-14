package runtime

import (
	"testing"

	domaindetection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection"
	domainevent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/event"
)

func TestRuntimeProcessesDomainEventAndReturnsDomainSignal(t *testing.T) {
	program, report := Compile(ProgramInput{
		Rules: []RuleSpec{{
			RuleID: "r1", RuntimeType: "expr", Expr: ExprSpec{Conditions: []ConditionSpec{{Field: "process.binary", Op: "eq", Value: "/bin/sh"}}},
			Stage: domaindetection.SignalStageConclusion,
		}},
	})
	if report.Status != "applied" {
		t.Fatalf("compile status = %q, details=%v", report.Status, report.Details)
	}
	state := NewState(program, Limits{})
	signals := state.Process(domainevent.Event{SubjectPresent: true, ID: "evt-1", Behavior: "process_exec", Subject: domainevent.Process{Binary: "/bin/sh"}})
	if len(signals) != 1 || signals[0].RuleID != "r1" || signals[0].Stage != domaindetection.SignalStageConclusion || signals[0].DetectorKind != domaindetection.DetectorKindRule {
		t.Fatalf("signals = %#v", signals)
	}
}

func TestCompileRejectsRuleWithoutSignalStage(t *testing.T) {
	_, report := Compile(ProgramInput{Rules: []RuleSpec{{RuleID: "r1", RuntimeType: "expr"}}})
	if report.Status != "rejected" {
		t.Fatalf("compile status = %q, want rejected", report.Status)
	}
}
