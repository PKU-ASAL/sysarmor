package content

type Record struct {
	Ref     string
	Kind    string
	Version string
	Digest  string
	Status  string
}

type Snapshot struct {
	RulePacks              map[string]Record
	ContextSets            map[string]ValueSet
	IOCPacks               map[string]ValueSet
	DefaultManifestVersion string
}

type ValueSet struct {
	Ref       string
	Version   string
	Digest    string
	ValueType string
	Values    []string
}
