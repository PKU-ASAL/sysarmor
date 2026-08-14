package runtime

import (
	"context"
	"fmt"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sqlite"
	telemetryadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/telemetry"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/telemetry/dataappend"
	applicationtelemetry "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/telemetry"
	"github.com/sysarmor/sysarmor-next-project/packages/tlsconfig"
)

func (r *managementRuntime) batchSender() (dataappend.BatchSender, error) {
	if r.localStore != nil {
		return &localStoreBatchSender{store: r.localStore}, nil
	}
	return newBatchSender(r.config.Manager.Address, r.config.Manager.Transport, r.config.Local.Export.RequestTimeout, r.config.Agent.Token, r.managerTLS())
}

func (r *managementRuntime) managerTLS() tlsconfig.ClientConfig {
	return tlsconfig.ClientConfig{
		CAFile:     r.config.Manager.TLSCA,
		CertFile:   r.config.Manager.TLSCert,
		KeyFile:    r.config.Manager.TLSKey,
		ServerName: r.config.Manager.TLSServerName,
		Insecure:   r.config.Manager.TLSInsecure,
	}
}

func (r *managementRuntime) runManagedNetwork(ctx context.Context, enrollment sqlite.Enrollment) {
	tlsCfg := tlsconfig.ClientConfig{CAFile: enrollment.TLSCAPath, CertFile: enrollment.TLSCertPath, KeyFile: enrollment.TLSKeyPath, ServerName: enrollment.TLSServerName}
	sender := dataappend.NewGRPCAppenderWithTLS(enrollment.GatewayAddress, r.config.Local.Export.RequestTimeout, "", tlsCfg)
	cloud := telemetryadapter.NewCloudSender(sender)
	exportDone := make(chan struct{})
	go func() {
		defer close(exportDone)
		defer cloud.Close()
		applicationtelemetry.NewDelivery(telemetryadapter.NewLocalSpool(r.localStore), cloud).Run(ctx, applicationtelemetry.DeliveryScope{
			FromSequence: enrollment.ManagedFromSequence, TenantID: enrollment.TenantID, AgentID: enrollment.AgentID,
		})
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
