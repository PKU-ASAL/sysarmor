package tetragon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	tetragonpb "github.com/cilium/tetragon/api/v1/tetragon"
	sensorv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/sensor/v1"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const defaultTetragonServerAddress = "unix:///var/run/tetragon/tetragon.sock"

func (b *Backend) subscribeManagedGRPC(ctx context.Context, stopSensor func()) (<-chan contract.EventEnvelope, error) {
	dialCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	conn, err := dialTetragonGRPC(dialCtx, firstNonEmpty(b.ServerAddress, defaultTetragonServerAddress))
	if err != nil {
		stopSensor()
		b.setError(err)
		return nil, err
	}
	client := tetragonpb.NewFineGuidanceSensorsClient(conn)
	stream, err := client.GetEvents(ctx, &tetragonpb.GetEventsRequest{
		AllowList: []*tetragonpb.Filter{{
			PolicyNames: []string{runtimeTracingPolicyName},
			EventSet:    []tetragonpb.EventType{tetragonpb.EventType_PROCESS_KPROBE},
		}},
	})
	if err != nil {
		_ = conn.Close()
		stopSensor()
		b.setError(err)
		return nil, err
	}

	b.mu.Lock()
	b.policyLoaded = true
	b.running = true
	b.lastError = ""
	b.mu.Unlock()

	out := make(chan contract.EventEnvelope)
	go func() {
		defer close(out)
		defer b.setRunning(false)
		defer b.cleanupRuntimePolicy()
		defer stopSensor()
		defer conn.Close()
		for {
			resp, err := stream.Recv()
			if err != nil {
				if !isBenignGRPCEventSourceError(err) {
					b.setError(err)
				}
				return
			}
			events, ok := eventsFromGRPCResponse(resp)
			if !ok {
				b.incParseError(fmt.Errorf("unrecognized tetragon grpc event"))
				continue
			}
			rawRef := rawRefForProto(resp)
			for _, event := range events {
				if !b.matchesIntentBehavior(event.GetBehavior()) {
					continue
				}
				if !b.matchesScope(event) {
					continue
				}
				if event.RawRef == "" {
					event.RawRef = rawRef
				}
				ev := contract.EventEnvelope{
					SensorEvent: event,
					RawRef:      event.GetRawRef(),
					ReceivedAt:  time.Now().UTC(),
				}
				select {
				case <-ctx.Done():
					return
				case out <- ev:
					b.incEvent(ev.ReceivedAt)
				}
			}
		}
	}()
	return out, nil
}

func dialTetragonGRPC(ctx context.Context, address string) (*grpc.ClientConn, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		address = defaultTetragonServerAddress
	}
	return grpc.DialContext(ctx, address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			if strings.HasPrefix(addr, "unix://") {
				return (&net.Dialer{}).DialContext(ctx, "unix", strings.TrimPrefix(addr, "unix://"))
			}
			return (&net.Dialer{}).DialContext(ctx, "tcp", strings.TrimPrefix(addr, "tcp://"))
		}),
		grpc.WithBlock(),
	)
}

func isBenignGRPCEventSourceError(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return true
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "context canceled") || strings.Contains(text, "client connection is closing")
}

func eventsFromGRPCResponse(resp *tetragonpb.GetEventsResponse) ([]*sensorv1.SensorEvent, bool) {
	if resp == nil {
		return nil, false
	}
	env := envelope{
		NodeName: resp.GetNodeName(),
		Time:     timestampString(resp.GetTime()),
	}
	switch {
	case resp.GetProcessExec() != nil:
		pe := resp.GetProcessExec()
		return execEvents(env, processEvent{
			Process: tetragonProcessFromProto(pe.GetProcess()),
			Parent:  tetragonProcessFromProto(pe.GetParent()),
		}, ""), true
	case resp.GetProcessExit() != nil:
		pe := resp.GetProcessExit()
		return []*sensorv1.SensorEvent{
			sensorEvent(env, tetragonProcessFromProto(pe.GetProcess()), tetragonProcessFromProto(pe.GetParent()), "process.exit", nil, ""),
		}, true
	case resp.GetProcessKprobe() != nil:
		kp := processKprobeFromProto(resp.GetProcessKprobe())
		if ev := kprobeEventToSensor(env, kp, ""); ev != nil {
			return []*sensorv1.SensorEvent{ev}, true
		}
		return nil, true
	default:
		return nil, false
	}
}

func processKprobeFromProto(kp *tetragonpb.ProcessKprobe) kprobeEvent {
	if kp == nil {
		return kprobeEvent{}
	}
	return kprobeEvent{
		Process:     tetragonProcessFromProto(kp.GetProcess()),
		Parent:      tetragonProcessFromProto(kp.GetParent()),
		Function:    kp.GetFunctionName(),
		Args:        kprobeArgsFromProto(kp.GetArgs()),
		PolicyName:  kp.GetPolicyName(),
		ReturnValue: kprobeArgFromProto(kp.GetReturn()),
	}
}

func kprobeArgsFromProto(args []*tetragonpb.KprobeArgument) []kprobeArg {
	out := make([]kprobeArg, 0, len(args))
	for _, arg := range args {
		out = append(out, kprobeArgFromProto(arg))
	}
	return out
}

func kprobeArgFromProto(arg *tetragonpb.KprobeArgument) kprobeArg {
	if arg == nil {
		return kprobeArg{}
	}
	if file := arg.GetFileArg(); file != nil {
		return kprobeArg{File: &fileArg{Path: file.GetPath(), Permission: file.GetPermission()}}
	}
	if path := arg.GetPathArg(); path != nil {
		return kprobeArg{File: &fileArg{Path: path.GetPath(), Permission: path.GetPermission()}}
	}
	if sock := arg.GetSockaddrArg(); sock != nil {
		return kprobeArg{Sockaddr: &sockaddrArg{Addr: sock.GetAddr(), Port: sock.GetPort()}}
	}
	if sock := arg.GetSockArg(); sock != nil {
		return kprobeArg{Sockaddr: &sockaddrArg{Addr: firstNonEmpty(sock.GetDaddr(), sock.GetSaddr()), Port: firstNonZero(sock.GetDport(), sock.GetSport())}}
	}
	if value := arg.GetIntArg(); value != 0 {
		v := value
		return kprobeArg{Int: &v}
	}
	if value := arg.GetUintArg(); value != 0 {
		v := int32(value)
		return kprobeArg{Int: &v}
	}
	return kprobeArg{}
}

func tetragonProcessFromProto(proc *tetragonpb.Process) tetragonProcess {
	if proc == nil {
		return tetragonProcess{}
	}
	return tetragonProcess{
		PID:          wrapperUint32(proc.GetPid()),
		UID:          wrapperUint32(proc.GetUid()),
		ExecID:       proc.GetExecId(),
		Binary:       proc.GetBinary(),
		Arguments:    proc.GetArguments(),
		Flags:        proc.GetFlags(),
		StartTime:    timestampString(proc.GetStartTime()),
		ParentExecID: proc.GetParentExecId(),
		Docker:       proc.GetDocker(),
	}
}

func wrapperUint32(value interface{ GetValue() uint32 }) uint32 {
	if value == nil {
		return 0
	}
	return value.GetValue()
}

func timestampString(ts *timestamppb.Timestamp) string {
	if ts == nil {
		return ""
	}
	return ts.AsTime().UTC().Format(time.RFC3339Nano)
}

func rawRefForProto(msg proto.Message) string {
	data, err := proto.Marshal(msg)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return "tetragon-grpc:" + hex.EncodeToString(sum[:8])
}

func firstNonZero(values ...uint32) uint32 {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}
