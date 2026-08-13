package policy

import (
	"fmt"
	"strings"
)

type Identity struct {
	ID      string
	Version uint64
}

func (identity Identity) Validate() error {
	if strings.TrimSpace(identity.ID) == "" || identity.Version == 0 {
		return fmt.Errorf("policy id and positive version are required")
	}
	return nil
}

type ActivationCandidate struct {
	Identity   Identity
	Collection CollectionPolicy
	Sections   EndpointSections
}

type Source string

const (
	SourceStandalone Source = "standalone"
	SourceManaged    Source = "managed"
)

func ValidateSource(source Source) error {
	if source != SourceStandalone && source != SourceManaged {
		return fmt.Errorf("unsupported policy source %q", source)
	}
	return nil
}

type VersionTransition struct {
	Current      Identity
	Candidate    Identity
	SameDigest   bool
	SameDocument bool
}

func ValidateVersionTransition(value VersionTransition) error {
	currentID := strings.TrimSpace(value.Current.ID)
	candidateID := strings.TrimSpace(value.Candidate.ID)
	if currentID != "" && candidateID != "" && currentID != candidateID {
		return nil
	}
	if value.Candidate.Version < value.Current.Version {
		return fmt.Errorf("policy version rollback: current=%d requested=%d", value.Current.Version, value.Candidate.Version)
	}
	if value.Candidate.Version == value.Current.Version && !value.SameDigest {
		return fmt.Errorf("policy digest conflict at version %d", value.Candidate.Version)
	}
	if value.Candidate.Version == value.Current.Version && !value.SameDocument {
		return fmt.Errorf("policy document conflict at version %d", value.Candidate.Version)
	}
	return nil
}

type EndpointSections struct {
	Collection bool
	Detection  bool
	Telemetry  bool
	Response   bool
}

func (candidate ActivationCandidate) Validate() error {
	if err := candidate.Identity.Validate(); err != nil {
		return err
	}
	sections := candidate.Sections
	if !sections.Collection || !sections.Detection || !sections.Telemetry || !sections.Response {
		return fmt.Errorf("endpoint policy requires collection, detection, telemetry, and response sections")
	}
	return nil
}
