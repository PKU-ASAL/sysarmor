package management

import "fmt"

type State string

const (
	StateStandalone  State = "standalone"
	StateEnrolling   State = "enrolling"
	StateManaged     State = "managed"
	StateUnenrolling State = "unenrolling"
)

type Authority string

const (
	AuthorityLocal   Authority = "local"
	AuthorityManager Authority = "manager"
)

type IdentitySource string

const (
	IdentityStandalone IdentitySource = "standalone"
	IdentityEnrollment IdentitySource = "enrollment"
)

type TransportMode string

const (
	TransportStandalone TransportMode = "standalone"
	TransportManaged    TransportMode = "managed"
)

type PolicyWriteOrigin string

const (
	PolicyWriteLocal   PolicyWriteOrigin = "local"
	PolicyWriteManager PolicyWriteOrigin = "manager"
)

type Context struct {
	State          State
	Authority      Authority
	IdentitySource IdentitySource
	Transport      TransportMode
}

func Resolve(state State) (Context, error) {
	switch state {
	case StateStandalone:
		return Context{State: state, Authority: AuthorityLocal, IdentitySource: IdentityStandalone, Transport: TransportStandalone}, nil
	case StateEnrolling, StateManaged, StateUnenrolling:
		return Context{State: state, Authority: AuthorityManager, IdentitySource: IdentityEnrollment, Transport: TransportManaged}, nil
	default:
		return Context{}, fmt.Errorf("unsupported management state %q", state)
	}
}

func (c Context) Authorize(origin PolicyWriteOrigin) error {
	if c.Authority == AuthorityLocal && origin == PolicyWriteLocal {
		return nil
	}
	if c.Authority == AuthorityManager && origin == PolicyWriteManager {
		return nil
	}
	if c.Authority == AuthorityManager {
		return fmt.Errorf("managed policy authority is active; %s policy mutation is not allowed", origin)
	}
	return fmt.Errorf("local policy authority is active; %s policy mutation is not allowed", origin)
}

func ValidateTransition(from, to State) error {
	valid := false
	switch from {
	case StateStandalone:
		valid = to == StateEnrolling
	case StateEnrolling:
		valid = to == StateManaged
	case StateManaged:
		valid = to == StateUnenrolling
	case StateUnenrolling:
		valid = to == StateStandalone
	default:
		return fmt.Errorf("unsupported management state %q", from)
	}
	if !valid {
		return fmt.Errorf("invalid management transition %s -> %s", from, to)
	}
	return nil
}
