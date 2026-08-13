package runtime

import (
	"testing"

	domainevent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/event"
)

func TestRuntimeProcessesDomainEventAndReturnsDomainSignal(t *testing.T) {
	terminal := true
	program, report := Compile(ProgramInput{
		Rules: []RuleSpec{{
			RuleID: "r1", RuntimeType: "expr", Expr: ExprSpec{Conditions: []ConditionSpec{{Field: "process.binary", Op: "eq", Value: "/bin/sh"}}},
			Terminal: &terminal,
		}},
	})
	if report.Status != "applied" {
		t.Fatalf("compile status = %q, details=%v", report.Status, report.Details)
	}
	state := NewState(program, Limits{})
	signals := state.Process(domainevent.Event{SubjectPresent: true, ID: "evt-1", Behavior: "process_exec", Subject: domainevent.Process{Binary: "/bin/sh"}})
	if len(signals) != 1 || signals[0].RuleID != "r1" {
		t.Fatalf("signals = %#v", signals)
	}
}
