package event

type Object struct {
	Kind                  string
	FilePath              string
	SocketAddress         string
	TargetProcessStableID string
}

type RuntimeScope struct {
	Type     string
	Selector string
}

type Event struct {
	ID             string
	Sequence       uint64
	AgentID        string
	HostID         string
	TenantID       string
	MonoNS         uint64
	OccurredAtNS   uint64
	Behavior       string
	Subject        Process
	Object         Object
	ParentStableID string
	LineageID      string
	RawRef         string
	Scope          RuntimeScope
	ContainerID    string
	Cgroup         string
	Namespace      string
	Pod            string
	Labels         map[string]string
}
