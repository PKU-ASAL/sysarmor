package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/bootstrap"
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
		options := replayOptions(*manager, *transport, *agentID, *hostID, *tenantID, *policyID, *policyVersion, labels.Map(), *input, *batchSize, *flushInterval, *tlsCA, *tlsCert, *tlsKey, *tlsServerName, *tlsInsecure)
		if err := bootstrap.AppendJSONL(options); err != nil {
			fmt.Fprintf(os.Stderr, "sysarmor-agent: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *stream != "" {
		options := replayOptions(*manager, *transport, *agentID, *hostID, *tenantID, *policyID, *policyVersion, labels.Map(), *stream, *batchSize, *flushInterval, *tlsCA, *tlsCert, *tlsKey, *tlsServerName, *tlsInsecure)
		stats, err := bootstrap.StreamJSONL(context.Background(), options)
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
	return bootstrap.MergeReleaseConfig(*existingPath, *releasePath, *outputPath)
}

func runDaemonCommand(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", "/etc/sysarmor/agent/agent.yaml", "agent config path")
	dryRun := fs.Bool("dry-run", false, "validate config and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dryRun {
		summary, err := bootstrap.ValidateConfig(*configPath)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "config ok: agent=%s host=%s tenant=%s manager=%s sensor=%s/%s\n",
			summary.AgentID, summary.HostID, summary.TenantID, summary.Manager, summary.SensorBackend, summary.SensorMode)
		return nil
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	agent, err := bootstrap.NewAgentFromFile(ctx, *configPath)
	if err != nil {
		return err
	}
	runErr := agent.Run(ctx, os.Stdout)
	return errors.Join(runErr, agent.Close())
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

func replayOptions(manager, transport, agentID, hostID, tenantID, policyID string, policyVersion uint64, labels map[string]string, input string, batchSize int, flushInterval time.Duration, ca, cert, key, serverName string, insecure bool) bootstrap.ReplayOptions {
	return bootstrap.ReplayOptions{
		Manager: manager, Transport: transport, AgentID: agentID, HostID: hostID, TenantID: tenantID,
		PolicyID: policyID, PolicyVersion: policyVersion, Labels: labels, Input: input, Version: version,
		BatchSize: batchSize, FlushInterval: flushInterval,
		TLS: bootstrap.TLSOptions{CAFile: ca, CertFile: cert, KeyFile: key, ServerName: serverName, Insecure: insecure},
	}
}
