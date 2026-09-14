package detection

type Policy struct {
	EndpointRules []string
	CloudRules    []string
	Converge      *ConvergePolicy
}

type ConvergePolicy struct {
	Mode                  string
	CrossLineage          bool
	AdditiveRiskThreshold uint32
}
