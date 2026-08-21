package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	controlplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/controlplane/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

func defaultAgentSock() string {
	if v := strings.TrimSpace(os.Getenv("SYSARMOR_AGENT_SOCK")); v != "" {
		return v
	}
	return "/run/sysarmor/agent/control.sock"
}

func isLocalAgentCommand(args []string) bool {
	if len(args) >= 1 && args[0] == "unenroll" {
		return true
	}
	if len(args) >= 1 && args[0] == "enroll" {
		return true
	}
	if len(args) < 2 {
		return false
	}
	switch args[0] {
	case "agent":
		return args[1] == "health" || args[1] == "capability"
	case "policy":
		return args[1] == "current" || args[1] == "apply" || args[1] == "explain"
	case "content":
		return args[1] == "apply" || args[1] == "list" || args[1] == "get"
	case "debug":
		return args[1] == "profile"
	case "event":
		return args[1] == "watch" || args[1] == "get"
	case "signal":
		return args[1] == "watch"
	default:
		return false
	}
}

func isStreamingWatchCommand(args []string) bool {
	if len(args) < 2 || hasFlag(args, "--snapshot") {
		return false
	}
	return (args[0] == "event" && args[1] == "watch") || (args[0] == "signal" && args[1] == "watch")
}

func streamLocalAgent(socketPath string, args []string) error {
	if strings.TrimSpace(socketPath) == "" {
		return fmt.Errorf("--socket is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout(args, 5*time.Second))
	defer cancel()
	conn, err := grpc.DialContext(ctx, "unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		}),
		grpc.WithBlock(),
	)
	if err != nil {
		return err
	}
	defer conn.Close()

	client := controlplanev1.NewAgentControlPlaneServiceClient(conn)
	reqCtx := requestContext(args)
	switch args[0] + " " + args[1] {
	case "event watch":
		stream, err := client.WatchEvents(ctx, &controlplanev1.WatchEventsRequest{
			Context:       reqCtx,
			Behavior:      flagValue(args, "--behavior"),
			Limit:         uint32Flag(args, "--limit"),
			IncludeRecent: hasFlag(args, "--include-recent"),
			SnapshotOnly:  hasFlag(args, "--snapshot"),
			Filter:        watchFilter(args),
		})
		if err != nil {
			return err
		}
		return writeEventFrames(stream)
	case "signal watch":
		stream, err := client.WatchSignals(ctx, &controlplanev1.WatchSignalsRequest{
			Context:       reqCtx,
			RuleId:        flagValue(args, "--rule-id"),
			Where:         flagValue(args, "--where"),
			Limit:         uint32Flag(args, "--limit"),
			IncludeRecent: hasFlag(args, "--include-recent"),
			SnapshotOnly:  hasFlag(args, "--snapshot"),
			Filter:        watchFilter(args),
		})
		if err != nil {
			return err
		}
		if hasFlag(args, "--include-events") {
			return writeSignalFramesWithEvents(ctx, client, reqCtx, stream)
		}
		return writeSignalFrames(stream)
	default:
		return fmt.Errorf("unsupported streaming local agent command %q", strings.Join(args, " "))
	}
}

func queryLocalAgent(socketPath string, args []string) ([]byte, error) {
	return queryLocalAgentWithManager(socketPath, defaultManagerURL(), args)
}

func queryLocalAgentWithManager(socketPath, managerURL string, args []string) ([]byte, error) {
	if strings.TrimSpace(socketPath) == "" {
		return nil, fmt.Errorf("--socket is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout(args, 5*time.Second))
	defer cancel()
	conn, err := grpc.DialContext(ctx, "unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		}),
		grpc.WithBlock(),
	)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	client := controlplanev1.NewAgentControlPlaneServiceClient(conn)
	reqCtx := requestContext(args)
	if len(args) > 0 && args[0] == "enroll" {
		return enrollLocalAgent(ctx, client, reqCtx, managerURL, args)
	}
	if len(args) >= 1 && args[0] == "unenroll" {
		resp, err := client.Unenroll(ctx, &controlplanev1.UnenrollRequest{Context: reqCtx})
		if err != nil {
			return nil, err
		}
		return marshalProtoJSON(resp)
	}
	switch args[0] + " " + args[1] {
	case "agent health":
		resp, err := client.Health(ctx, &controlplanev1.HealthRequest{Context: reqCtx})
		if err != nil {
			return nil, err
		}
		return marshalHealthJSON(resp)
	case "agent capability":
		resp, err := client.Capability(ctx, &controlplanev1.CapabilityRequest{Context: reqCtx})
		if err != nil {
			return nil, err
		}
		return marshalProtoJSON(resp)
	case "policy current":
		resp, err := client.CurrentPolicy(ctx, &controlplanev1.CurrentPolicyRequest{Context: reqCtx})
		if err != nil {
			return nil, err
		}
		return marshalProtoJSON(resp)
	case "policy apply":
		policyJSON, err := policyPayload(args)
		if err != nil {
			return nil, err
		}
		policyType := flagValue(args, "--type")
		if policyType == "" && len(args) > 2 && args[2] == "collection" {
			policyType = "collection"
		}
		resp, err := client.ApplyPolicy(ctx, &controlplanev1.ApplyPolicyRequest{
			Context:    reqCtx,
			PolicyType: policyType,
			PolicyJson: policyJSON,
			DryRun:     hasFlag(args, "--dry-run"),
		})
		if err != nil {
			return nil, err
		}
		return marshalProtoJSON(resp)
	case "policy explain":
		policyJSON, err := policyPayload(args)
		if err != nil {
			return nil, err
		}
		policyType := flagValue(args, "--type")
		if policyType == "" && len(args) > 2 && args[2] == "collection" {
			policyType = "collection"
		}
		resp, err := client.ApplyPolicy(ctx, &controlplanev1.ApplyPolicyRequest{
			Context:    reqCtx,
			PolicyType: policyType,
			PolicyJson: policyJSON,
			DryRun:     true,
		})
		if err != nil {
			return nil, err
		}
		if hasFlag(args, "--report-only") && resp.GetReportJson() != "" {
			return []byte(resp.GetReportJson()), nil
		}
		return marshalProtoJSON(resp)
	case "content apply":
		contentJSON, err := contentPayload(args)
		if err != nil {
			return nil, err
		}
		resp, err := client.ApplyContent(ctx, &controlplanev1.ApplyContentRequest{
			Context:       reqCtx,
			ContentJson:   contentJSON,
			DryRun:        hasFlag(args, "--dry-run"),
			AllowUnsigned: hasFlag(args, "--allow-unsigned"),
		})
		if err != nil {
			return nil, err
		}
		return marshalProtoJSON(resp)
	case "content list":
		resp, err := client.ListContent(ctx, &controlplanev1.ListContentRequest{
			Context: reqCtx,
			Kind:    flagValue(args, "--kind"),
		})
		if err != nil {
			return nil, err
		}
		return marshalProtoJSON(resp)
	case "content get":
		resp, err := client.GetContent(ctx, &controlplanev1.GetContentRequest{
			Context: reqCtx,
			Ref:     flagValue(args, "--ref"),
		})
		if err != nil {
			return nil, err
		}
		return marshalProtoJSON(resp)
	case "debug profile":
		profileType := "cpu"
		if len(args) > 2 && strings.TrimSpace(args[2]) != "" {
			profileType = strings.TrimSpace(args[2])
		}
		output := strings.TrimSpace(flagValue(args, "--output"))
		if output == "" {
			return nil, fmt.Errorf("--output is required for debug profile")
		}
		resp, err := client.DebugProfile(ctx, &controlplanev1.DebugProfileRequest{
			Context:     reqCtx,
			ProfileType: profileType,
			Seconds:     uint32Flag(args, "--seconds"),
			Label:       flagValue(args, "--label"),
		})
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(output, resp.GetProfile(), 0o644); err != nil {
			return nil, err
		}
		resp.Profile = nil
		return marshalProtoJSON(resp)
	case "event get":
		resp, err := client.GetEvent(ctx, &controlplanev1.GetEventRequest{
			Context: reqCtx,
			EventId: firstNonEmpty(flagValue(args, "--event-id"), flagValue(args, "--id")),
		})
		if err != nil {
			return nil, err
		}
		return marshalProtoJSON(resp)
	case "event watch":
		stream, err := client.WatchEvents(ctx, &controlplanev1.WatchEventsRequest{
			Context:       reqCtx,
			Behavior:      flagValue(args, "--behavior"),
			Limit:         uint32Flag(args, "--limit"),
			IncludeRecent: hasFlag(args, "--include-recent"),
			SnapshotOnly:  hasFlag(args, "--snapshot"),
			Filter:        watchFilter(args),
		})
		if err != nil {
			return nil, err
		}
		return collectEventFrames(stream)
	case "signal watch":
		stream, err := client.WatchSignals(ctx, &controlplanev1.WatchSignalsRequest{
			Context:       reqCtx,
			RuleId:        flagValue(args, "--rule-id"),
			Where:         flagValue(args, "--where"),
			Limit:         uint32Flag(args, "--limit"),
			IncludeRecent: hasFlag(args, "--include-recent"),
			SnapshotOnly:  hasFlag(args, "--snapshot"),
			Filter:        watchFilter(args),
		})
		if err != nil {
			return nil, err
		}
		if hasFlag(args, "--include-events") {
			return collectSignalFramesWithEvents(ctx, client, reqCtx, stream)
		}
		return collectSignalFrames(stream)
	default:
		return nil, fmt.Errorf("unsupported local agent command %q", strings.Join(args, " "))
	}
}

func collectEventFrames(stream controlplanev1.AgentControlPlaneService_WatchEventsClient) ([]byte, error) {
	var out strings.Builder
	for {
		frame, err := stream.Recv()
		if err == io.EOF {
			return []byte(out.String()), nil
		}
		if err != nil {
			if out.Len() > 0 && status.Code(err) == codes.DeadlineExceeded {
				return []byte(out.String()), nil
			}
			return []byte(out.String()), err
		}
		data, err := marshalProtoJSONLine(frame)
		if err != nil {
			return []byte(out.String()), err
		}
		out.Write(data)
		out.WriteByte('\n')
	}
}

func collectSignalFrames(stream controlplanev1.AgentControlPlaneService_WatchSignalsClient) ([]byte, error) {
	var out strings.Builder
	for {
		frame, err := stream.Recv()
		if err == io.EOF {
			return []byte(out.String()), nil
		}
		if err != nil {
			if out.Len() > 0 && status.Code(err) == codes.DeadlineExceeded {
				return []byte(out.String()), nil
			}
			return []byte(out.String()), err
		}
		data, err := marshalProtoJSONLine(frame)
		if err != nil {
			return []byte(out.String()), err
		}
		out.Write(data)
		out.WriteByte('\n')
	}
}

func collectSignalFramesWithEvents(ctx context.Context, client controlplanev1.AgentControlPlaneServiceClient, reqCtx *controlplanev1.RequestContext, stream controlplanev1.AgentControlPlaneService_WatchSignalsClient) ([]byte, error) {
	var out strings.Builder
	for {
		frame, err := stream.Recv()
		if err == io.EOF {
			return []byte(out.String()), nil
		}
		if err != nil {
			if out.Len() > 0 && status.Code(err) == codes.DeadlineExceeded {
				return []byte(out.String()), nil
			}
			return []byte(out.String()), err
		}
		data, err := marshalSignalEventEnvelope(ctx, client, reqCtx, frame)
		if err != nil {
			return []byte(out.String()), err
		}
		out.Write(data)
		out.WriteByte('\n')
	}
}

func writeEventFrames(stream controlplanev1.AgentControlPlaneService_WatchEventsClient) error {
	for {
		frame, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			if status.Code(err) == codes.DeadlineExceeded {
				return nil
			}
			return err
		}
		data, err := marshalProtoJSONLine(frame)
		if err != nil {
			return err
		}
		if _, err := os.Stdout.Write(append(data, '\n')); err != nil {
			return err
		}
	}
}

func writeSignalFrames(stream controlplanev1.AgentControlPlaneService_WatchSignalsClient) error {
	for {
		frame, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			if status.Code(err) == codes.DeadlineExceeded {
				return nil
			}
			return err
		}
		data, err := marshalProtoJSONLine(frame)
		if err != nil {
			return err
		}
		if _, err := os.Stdout.Write(append(data, '\n')); err != nil {
			return err
		}
	}
}

func writeSignalFramesWithEvents(ctx context.Context, client controlplanev1.AgentControlPlaneServiceClient, reqCtx *controlplanev1.RequestContext, stream controlplanev1.AgentControlPlaneService_WatchSignalsClient) error {
	for {
		frame, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			if status.Code(err) == codes.DeadlineExceeded {
				return nil
			}
			return err
		}
		data, err := marshalSignalEventEnvelope(ctx, client, reqCtx, frame)
		if err != nil {
			return err
		}
		if _, err := os.Stdout.Write(append(data, '\n')); err != nil {
			return err
		}
	}
}

func marshalSignalEventEnvelope(ctx context.Context, client controlplanev1.AgentControlPlaneServiceClient, reqCtx *controlplanev1.RequestContext, frame *controlplanev1.SignalFrame) ([]byte, error) {
	signalJSON, err := marshalProtoJSONLine(frame)
	if err != nil {
		return nil, err
	}
	var events []json.RawMessage
	var missing []string
	for _, eventID := range uniqueSignalEventRefs(frame) {
		resp, err := client.GetEvent(ctx, &controlplanev1.GetEventRequest{Context: reqCtx, EventId: eventID})
		if err != nil {
			missing = append(missing, eventID)
			continue
		}
		eventJSON, err := marshalProtoJSONLine(resp.GetFrame())
		if err != nil {
			return nil, err
		}
		events = append(events, json.RawMessage(eventJSON))
	}
	return json.Marshal(map[string]any{
		"signalFrame":      json.RawMessage(signalJSON),
		"eventFrames":      events,
		"missingEventRefs": missing,
	})
}

func uniqueSignalEventRefs(frame *controlplanev1.SignalFrame) []string {
	seen := map[string]bool{}
	var out []string
	if frame == nil || frame.GetSignal() == nil {
		return nil
	}
	for _, ref := range frame.GetSignal().GetEventRefs() {
		ref = strings.TrimSpace(ref)
		if ref == "" || seen[ref] {
			continue
		}
		seen[ref] = true
		out = append(out, ref)
	}
	return out
}
