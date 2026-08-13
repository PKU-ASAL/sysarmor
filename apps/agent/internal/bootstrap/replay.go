package bootstrap

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/telemetry/dataappend"
	tetragondecoder "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/sensors/linux/tetragon"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	"github.com/sysarmor/sysarmor-next-project/packages/tlsconfig"
)

type TLSOptions struct {
	CAFile     string
	CertFile   string
	KeyFile    string
	ServerName string
	Insecure   bool
}

type ReplayOptions struct {
	Manager       string
	Transport     string
	AgentID       string
	HostID        string
	TenantID      string
	PolicyID      string
	PolicyVersion uint64
	Labels        map[string]string
	Input         string
	Version       string
	BatchSize     int
	FlushInterval time.Duration
	TLS           TLSOptions
}

type ReplayStats struct {
	Events  int
	Signals int
	Batches int
}

func AppendJSONL(options ReplayOptions) error {
	input, err := os.Open(options.Input)
	if err != nil {
		return err
	}
	defer input.Close()
	batch, err := dataappend.ReadProtoJSONL(input, options.AgentID, options.HostID, options.PolicyID, options.PolicyVersion, options.Labels, tetragondecoder.ParseLine)
	if err != nil {
		return err
	}
	prepareReplayHeader(batch, options)
	uploader, err := newReplayUploader(options)
	if err != nil {
		return err
	}
	_, err = uploader.SendBatch(batch)
	return err
}

func StreamJSONL(ctx context.Context, options ReplayOptions) (ReplayStats, error) {
	input := os.Stdin
	if options.Input != "-" {
		file, err := os.Open(options.Input)
		if err != nil {
			return ReplayStats{}, err
		}
		defer file.Close()
		input = file
	}
	uploader, err := newReplayUploader(options)
	if err != nil {
		return ReplayStats{}, err
	}
	stats, err := dataappend.StreamJSONL(ctx, input, uploader, dataappend.StreamOptions{
		AgentID: options.AgentID, HostID: options.HostID, TenantID: options.TenantID,
		PolicyID: options.PolicyID, PolicyVersion: options.PolicyVersion, Labels: options.Labels,
		Version: options.Version, BatchSize: options.BatchSize, FlushInterval: options.FlushInterval,
		SensorParser: tetragondecoder.ParseLine,
	})
	return ReplayStats{Events: stats.Events, Signals: stats.Signals, Batches: stats.Batches}, err
}

func prepareReplayHeader(batch *dataplanev1.DataBatch, options ReplayOptions) {
	if batch.Header == nil {
		batch.Header = &dataplanev1.BatchHeader{}
	}
	batch.Header.AgentId, batch.Header.HostId, batch.Header.TenantId = options.AgentID, options.HostID, options.TenantID
	if batch.Header.Labels == nil {
		batch.Header.Labels = map[string]string{}
	}
	batch.Header.Labels["agent_version"] = options.Version
}

func newReplayUploader(options ReplayOptions) (dataappend.BatchSender, error) {
	if options.Transport != "grpc" {
		return nil, fmt.Errorf("unknown transport %q", options.Transport)
	}
	tlsOptions := options.TLS
	tlsConfig := tlsconfig.ClientConfig{
		CAFile: tlsOptions.CAFile, CertFile: tlsOptions.CertFile, KeyFile: tlsOptions.KeyFile,
		ServerName: tlsOptions.ServerName, Insecure: tlsOptions.Insecure,
	}
	return dataappend.NewGRPCAppenderWithTLS(options.Manager, 10*time.Second, "", tlsConfig), nil
}
