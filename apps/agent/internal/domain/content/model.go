package content

import "time"

type Record struct {
	Ref     string
	Kind    string
	Version string
	Digest  string
	Status  string
}

type Snapshot struct {
	RulePacks              map[string]Record
	Rules                  []Rule
	ContextSets            map[string]ValueSet
	IOCPacks               map[string]ValueSet
	DefaultManifestVersion string
}

type Rule struct {
	RuleID         string
	Version        uint64
	RuleSetRef     string
	Severity       string
	RuntimeType    string
	RuntimeEntry   string
	Expr           RuntimeExpr
	Sequence       RuntimeSequence
	Correlate      RuntimeCorrelate
	Suppression    RuntimeSuppression
	RequiredEvents []RequiredEvent
	ContextRefs    []string
	IOCRefs        []string
	ResponseIntent ResponseIntent
	Stage          SignalStage
}

type SignalStage string

const (
	SignalStageCandidate  SignalStage = "candidate"
	SignalStageConclusion SignalStage = "conclusion"
)

type RuntimeExpr struct {
	Conditions     []RuntimeCondition
	ConditionGroup *RuntimeConditionNode
}
type RuntimeConditionNode struct {
	All       []RuntimeConditionNode
	Any       []RuntimeConditionNode
	Not       *RuntimeConditionNode
	Condition *RuntimeCondition
}
type RuntimeSequence struct {
	Within time.Duration
	By     []string
	Steps  []RuntimeStep
}
type RuntimeStep struct {
	ID, Behavior, Event string
	Conditions          []RuntimeCondition
	ConditionGroup      *RuntimeConditionNode
}
type RuntimeCorrelate struct {
	Within time.Duration
	By     []string
	Facts  []RuntimeFact
}
type RuntimeFact struct {
	ID, Event      string
	Events         []string
	Conditions     []RuntimeCondition
	ConditionGroup *RuntimeConditionNode
}
type RuntimeSuppression struct {
	Within time.Duration
	By     []string
}
type RuntimeCondition struct {
	Field, Op, Value, Ref, Step, StepField string
	Values                                 []string
}
type RequiredEvent struct {
	Behavior string
	Fields   []string
}
type ResponseIntent struct {
	Action, Reason string
	Confidence     uint32
}

type ValueSet struct {
	Ref       string
	Version   string
	Digest    string
	ValueType string
	Values    []string
}
