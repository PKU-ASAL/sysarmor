package daemon

import (
	"context"
	"fmt"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/localstore"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/telemetry/dataappend"
	"github.com/sysarmor/sysarmor-next-project/packages/tlsconfig"
)

func (r *AgentRuntime) batchSender() (dataappend.BatchSender, error) {
	if r.localStore != nil {
		return &localStoreBatchSender{store: r.localStore}, nil
	}
	return newBatchSender(r.Config.Manager.Address, r.Config.Manager.Transport, r.Config.Local.Export.RequestTimeout, r.Config.Agent.Token, r.managerTLS())
}

func (r *AgentRuntime) managerTLS() tlsconfig.ClientConfig {
	return tlsconfig.ClientConfig{
		CAFile:     r.Config.Manager.TLSCA,
		CertFile:   r.Config.Manager.TLSCert,
		KeyFile:    r.Config.Manager.TLSKey,
		ServerName: r.Config.Manager.TLSServerName,
		Insecure:   r.Config.Manager.TLSInsecure,
	}
}

func (r *AgentRuntime) runManagedNetwork(ctx context.Context, enrollment localstore.Enrollment) {
	tlsCfg := tlsconfig.ClientConfig{CAFile: enrollment.TLSCAPath, CertFile: enrollment.TLSCertPath, KeyFile: enrollment.TLSKeyPath, ServerName: enrollment.TLSServerName}
	sender := dataappend.NewGRPCAppenderWithTLS(enrollment.GatewayAddress, r.Config.Local.Export.RequestTimeout, "", tlsCfg)
	exportDone := make(chan struct{})
	go func() {
		defer close(exportDone)
		(&exportPipeline{store: r.localStore, exporter: &cloudExporter{sender: sender}, fromSequence: enrollment.ManagedFromSequence, tenantID: enrollment.TenantID, agentID: enrollment.AgentID}).Run(ctx)
	}()
	if r.managedControl != nil {
		r.managedControl.runControlFlowForEnrollment(ctx, enrollment, tlsCfg)
	}
	<-exportDone
}

func newBatchSender(manager, transport string, timeout time.Duration, token string, tlsCfg tlsconfig.ClientConfig) (dataappend.BatchSender, error) {
	switch transport {
	case "grpc":
		return dataappend.NewGRPCAppenderWithTLS(manager, timeout, token, tlsCfg), nil
	case "local":
		return newLocalBatchSender(), nil
	default:
		return nil, fmt.Errorf("unknown transport %q", transport)
	}
}
