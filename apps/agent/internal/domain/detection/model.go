package detection

import "time"

type Rule struct {
	ID             string
	Runtime        string
	RuntimeType    string
	Expression     Expression
	Sequence       Sequence
	Correlate      Correlate
	Suppression    Suppression
	ContextRefs    []string
	IOCRefs        []string
	ResponseIntent *ResponseIntent
}

type ResponseIntent struct {
	Action     string
	Confidence uint32
	Reason     string
}

type Expression struct {
	Conditions     []Condition
	ConditionGroup *ConditionNode
}

type ConditionNode struct {
	All       []ConditionNode
	Any       []ConditionNode
	Not       *ConditionNode
	Condition *Condition
}

type Sequence struct {
	Within time.Duration
	By     []string
	Steps  []Step
}

type Correlate struct {
	Within     time.Duration
	WithinText string
	By         []string
	Facts      []Fact
}

type Fact struct {
	ID             string
	Event          string
	Events         []string
	Conditions     []Condition
	ConditionGroup *ConditionNode
}

type Suppression struct {
	Within time.Duration
	By     []string
}

type Step struct {
	ID             string
	Behavior       string
	Conditions     []Condition
	ConditionGroup *ConditionNode
}

type Condition struct {
	Field     string
	Operator  string
	Value     string
	Values    []string
	Ref       string
	Step      string
	StepField string
}
