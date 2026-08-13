package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	agentconfig "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/config"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/daemon"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/telemetry/dataappend"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	"github.com/sysarmor/sysarmor-next-project/packages/tlsconfig"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version":
			fmt.Println(version)
			return
		case "run":
			if err := runDaemonCommand(os.Args[2:]); err != nil {
				fmt.Fprintf(os.Stderr, "sysarmor-agent run: %v\n", err)
				os.Exit(1)
			}
			return
		case "merge-release-config":
			if err := mergeReleaseConfigCommand(os.Args[2:]); err != nil {
				fmt.Fprintf(os.Stderr, "sysarmor-agent merge-release-config: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}

	manager := flag.String("manager", "127.0.0.1:9443", "sysarmor-manager address")
	transport := flag.String("transport", "grpc", "data append transport: grpc")
	agentID := flag.String("agent-id", "agent-dev", "agent identifier")
	hostID := flag.String("host-id", "host-dev", "host identifier")
	tenantID := flag.String("tenant-id", "default", "tenant identifier")
	policyID := flag.String("policy-id", "", "published policy identifier for replayed data")
	policyVersion := flag.Uint64("policy-version", 0, "published policy version for replayed data")
	labels := labelFlags{}
	tlsCA := flag.String("tls-ca", "", "CA bundle used to verify manager gRPC")
	tlsCert := flag.String("tls-cert", "", "agent client certificate for mTLS")
	tlsKey := flag.String("tls-key", "", "agent client private key for mTLS")
	tlsServerName := flag.String("tls-server-name", "", "optional manager certificate SAN override")
	tlsInsecure := flag.Bool("tls-insecure", false, "use insecure gRPC transport")
	input := flag.String("input-jsonl", "", "data append CanonicalEvent/Signal protojson lines from this file")
	stream := flag.String("stream-jsonl", "", "stream SensorEvent/Tetragon JSONL from this file, or '-' for stdin")
	batchSize := flag.Int("batch-size", 128, "stream data batch size")
	flushInterval := flag.Duration("flush-interval", time.Second, "stream append flush interval")
	flag.Var(&labels, "label", "label for replayed data, key=value; repeatable")
	flag.Parse()

	if flag.NArg() > 0 && flag.Arg(0) == "version" {
		fmt.Println(version)
		return
	}

	if *input != "" {
		if err := appendJSONL(*manager, *transport, *agentID, *hostID, *tenantID, *policyID, *policyVersion, labels.Map(), *input, cliTLS(*tlsCA, *tlsCert, *tlsKey, *tlsServerName, *tlsInsecure)); err != nil {
			fmt.Fprintf(os.Stderr, "sysarmor-agent: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *stream != "" {
		stats, err := streamJSONL(*manager, *transport, *agentID, *hostID, *tenantID, *policyID, *policyVersion, labels.Map(), *stream, *batchSize, *flushInterval, cliTLS(*tlsCA, *tlsCert, *tlsKey, *tlsServerName, *tlsInsecure))
		if err != nil {
			fmt.Fprintf(os.Stderr, "sysarmor-agent: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "sysarmor-agent stream complete: events=%d signals=%d batches=%d\n", stats.Events, stats.Signals, stats.Batches)
		return
	}

	fmt.Fprintf(os.Stderr, "sysarmor-agent skeleton: agent_id=%s host_id=%s manager=%s\n", *agentID, *hostID, *manager)
}

func mergeReleaseConfigCommand(args []string) error {
	fs := flag.NewFlagSet("merge-release-config", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	existingPath := fs.String("existing", "", "existing agent config path")
	releasePath := fs.String("release", "", "release agent config path")
	outputPath := fs.String("output", "", "merged config output path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *existingPath == "" || *releasePath == "" || *outputPath == "" {
		return fmt.Errorf("--existing, --release, and --output are required")
	}
	existing, err := os.ReadFile(*existingPath)
	if err != nil {
		return fmt.Errorf("read existing config: %w", err)
	}
	release, err := os.ReadFile(*releasePath)
	if err != nil {
		return fmt.Errorf("read release config: %w", err)
	}
	merged, err := agentconfig.MergeReleaseContent(existing, release)
	if err != nil {
		return err
	}
	output, err := os.OpenFile(*outputPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open merged config: %w", err)
	}
	if _, err := output.Write(merged); err != nil {
		_ = output.Close()
		return fmt.Errorf("write merged config: %w", err)
	}
	return output.Close()
}

func runDaemonCommand(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", "/etc/sysarmor/agent/agent.yaml", "agent config path")
	dryRun := fs.Bool("dry-run", false, "validate config and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := agentconfig.LoadFile(*configPath)
	if err != nil {
		return err
	}
	if *dryRun {
		fmt.Fprintf(os.Stdout, "config ok: agent=%s host=%s tenant=%s manager=%s sensor=%s/%s\n",
			cfg.Agent.ID, cfg.Agent.HostID, cfg.Agent.TenantID, cfg.Manager.Address, cfg.Sensor.Backend, cfg.Sensor.Mode)
		return nil
	}
	runner, err := daemon.New(cfg)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runner.Run(ctx, daemon.Options{Out: os.Stdout})
}

type labelFlags map[string]string

func (f *labelFlags) String() string {
	if f == nil || len(*f) == 0 {
		return ""
	}
	return fmt.Sprint(map[string]string(*f))
}

func (f *labelFlags) Set(value string) error {
	key, val, ok := strings.Cut(value, "=")
	if !ok || strings.TrimSpace(key) == "" {
		return fmt.Errorf("label must be key=value")
	}
	if *f == nil {
		*f = map[string]string{}
	}
	(*f)[strings.TrimSpace(key)] = val
	return nil
}

func (f labelFlags) Map() map[string]string {
	if len(f) == 0 {
		return nil
	}
	out := make(map[string]string, len(f))
	for key, value := range f {
		out[key] = value
	}
	return out
}

func appendJSONL(manager, transport, agentID, hostID, tenantID, policyID string, policyVersion uint64, labels map[string]string, input string, tlsCfg tlsconfig.ClientConfig) error {
	f, err := os.Open(input)
	if err != nil {
		return err
	}
	defer f.Close()
	batch, err := dataappend.ReadProtoJSONL(f, agentID, hostID, policyID, policyVersion, labels)
	if err != nil {
		return err
	}
	if batch.Header == nil {
		batch.Header = &dataplanev1.BatchHeader{}
	}
	batch.Header.AgentId = agentID
	batch.Header.HostId = hostID
	batch.Header.TenantId = tenantID
	if batch.Header.Labels == nil {
		batch.Header.Labels = map[string]string{}
	}
	batch.Header.Labels["agent_version"] = version
	up, err := newUploader(manager, transport, tlsCfg)
	if err != nil {
		return err
	}
	_, err = up.SendBatch(batch)
	return err
}

func streamJSONL(manager, transport, agentID, hostID, tenantID, policyID string, policyVersion uint64, labels map[string]string, input string, batchSize int, flushInterval time.Duration, tlsCfg tlsconfig.ClientConfig) (dataappend.StreamStats, error) {
	r := os.Stdin
	if input != "-" {
		f, err := os.Open(input)
		if err != nil {
			return dataappend.StreamStats{}, err
		}
		defer f.Close()
		r = f
	}
	up, err := newUploader(manager, transport, tlsCfg)
	if err != nil {
		return dataappend.StreamStats{}, err
	}
	return dataappend.StreamJSONL(context.Background(), r, up, dataappend.StreamOptions{
		AgentID:       agentID,
		HostID:        hostID,
		TenantID:      tenantID,
		PolicyID:      policyID,
		PolicyVersion: policyVersion,
		Labels:        labels,
		Version:       version,
		BatchSize:     batchSize,
		FlushInterval: flushInterval,
	})
}

func newUploader(manager, transport string, tlsCfg tlsconfig.ClientConfig) (dataappend.BatchSender, error) {
	switch transport {
	case "grpc":
		return dataappend.NewGRPCAppenderWithTLS(manager, 10*time.Second, "", tlsCfg), nil
	default:
		return nil, fmt.Errorf("unknown transport %q", transport)
	}
}

func cliTLS(ca, cert, key, serverName string, insecure bool) tlsconfig.ClientConfig {
	return tlsconfig.ClientConfig{CAFile: ca, CertFile: cert, KeyFile: key, ServerName: serverName, Insecure: insecure}
}
