package runtime

import (
	"fmt"
	"strings"

	controlplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/controlplane/v1"
)

func (r *Runtime) validateControlContext(ctx *controlplanev1.RequestContext) error {
	if ctx == nil {
		return nil
	}
	return r.validateControlIdentity(ctx.GetTenantId(), ctx.GetAgentId())
}

func (r *Runtime) validateControlIdentity(requestTenantID, requestAgentID string) error {
	identity := r.currentIdentity()
	if tenantID := strings.TrimSpace(requestTenantID); tenantID != "" && tenantID != identity.TenantID {
		return fmt.Errorf("tenant mismatch: request=%s agent=%s", tenantID, identity.TenantID)
	}
	if agentID := strings.TrimSpace(requestAgentID); agentID != "" && agentID != identity.AgentID {
		return fmt.Errorf("agent mismatch: request=%s agent=%s", agentID, identity.AgentID)
	}
	return nil
}
