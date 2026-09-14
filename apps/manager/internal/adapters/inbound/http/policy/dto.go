package policy

type policyIdentity struct {
	PolicyID  string `json:"policy_id"`
	Version   uint64 `json:"version"`
	Published bool   `json:"published"`
}

type publishRequest struct {
	PolicyID  string `json:"policy_id"`
	Version   uint64 `json:"version"`
	Published bool   `json:"published"`
	Reason    string `json:"reason,omitempty"`
}

type assignmentRequest struct {
	AssignmentID  string   `json:"assignment_id"`
	AgentID       string   `json:"agent_id,omitempty"`
	Scope         scopeDTO `json:"scope,omitempty"`
	PolicyID      string   `json:"policy_id"`
	PolicyVersion uint64   `json:"policy_version"`
	Downlink      bool     `json:"downlink,omitempty"`
	CommandID     string   `json:"command_id,omitempty"`
	Reason        string   `json:"reason,omitempty"`
}

type scopeDTO struct {
	Type     string `json:"type,omitempty"`
	Selector string `json:"selector,omitempty"`
}
