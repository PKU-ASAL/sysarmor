package runtime

import (
	"fmt"

	domaindetection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection"
	policymodel "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/policy"
	domainprocess "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/process"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/ports"
)

type policyProfileDetector struct {
	policy   *policyRuntime
	delegate ports.ProfileDetector
}

func (detector *policyProfileDetector) Enabled() bool {
	if detector == nil || detector.policy == nil || detector.delegate == nil {
		return false
	}
	ref := detector.policy.currentEndpointPolicy().Detection.LearningModel
	return ref != nil && validateLearningPolicy(ref, detector.delegate) == nil
}

func (detector *policyProfileDetector) Process(snapshot domainprocess.Snapshot) []*domaindetection.Signal {
	if !detector.Enabled() {
		return nil
	}
	return detector.delegate.Process(snapshot)
}

func validateLearningPolicy(ref *policymodel.LearningModelRef, detector ports.ProfileDetector) error {
	if ref == nil {
		return nil
	}
	if detector == nil {
		return fmt.Errorf("learning model %s@%s is not loaded", ref.Ref, ref.Version)
	}
	identified, ok := detector.(ports.IdentifiedProfileDetector)
	if !ok {
		return fmt.Errorf("loaded learning model has no verifiable identity")
	}
	identity := identified.Identity()
	if identity.Ref != ref.Ref || identity.Version != ref.Version || identity.Digest != ref.Digest {
		return fmt.Errorf("loaded learning model %s@%s (%s) does not match policy %s@%s (%s)",
			identity.Ref, identity.Version, identity.Digest, ref.Ref, ref.Version, ref.Digest)
	}
	return nil
}
