package runtime

import (
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/config"
	controlplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/controlplane/v1"
)

func rejectedAck(cfg config.Config, req *controlplanev1.RequestContext, section, message string) *controlplanev1.ControlAck {
	return &controlplanev1.ControlAck{
		RequestId: requestID(req),
		TenantId:  cfg.Agent.TenantID,
		AgentId:   cfg.Agent.ID,
		Status:    "rejected",
		Message:   message,
		Sections: []*controlplanev1.AppliedSection{{
			Name:    section,
			Status:  "rejected",
			Message: message,
		}},
	}
}

func requestID(req *controlplanev1.RequestContext) string {
	if req == nil {
		return ""
	}
	return req.GetRequestId()
}
