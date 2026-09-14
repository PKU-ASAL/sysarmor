package dataappend

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	"github.com/sysarmor/sysarmor-next-project/packages/tlsconfig"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type GRPCAppender struct {
	manager string
	timeout time.Duration
	token   string
	tls     tlsconfig.ClientConfig

	mu     sync.Mutex
	conn   *grpc.ClientConn
	stream dataplanev1.AgentDataPlaneService_StreamBatchesClient
	cancel context.CancelFunc
}

func NewGRPCAppender(manager string) *GRPCAppender {
	return NewGRPCAppenderWithTimeout(manager, 10*time.Second)
}

func NewGRPCAppenderWithTimeout(manager string, timeout time.Duration) *GRPCAppender {
	return NewGRPCAppenderWithOptions(manager, timeout, "")
}

func NewGRPCAppenderWithOptions(manager string, timeout time.Duration, token string) *GRPCAppender {
	return NewGRPCAppenderWithTLS(manager, timeout, token, tlsconfig.ClientConfig{})
}

func NewGRPCAppenderWithTLS(manager string, timeout time.Duration, token string, tlsCfg tlsconfig.ClientConfig) *GRPCAppender {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &GRPCAppender{manager: normalizeGRPCAddress(manager), timeout: timeout, token: token, tls: tlsCfg}
}

func (u *GRPCAppender) SendBatch(batch *dataplanev1.DataBatch) (*dataplanev1.DataAck, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	stream, err := u.streamClientLocked()
	if err != nil {
		u.closeLocked()
		return nil, err
	}
	if err := stream.Send(batch); err != nil {
		u.closeLocked()
		return nil, err
	}
	ack, err := stream.Recv()
	if err != nil {
		u.closeLocked()
		return nil, err
	}
	if !AckCommitted(ack) {
		return ack, fmt.Errorf("append batch rejected: %s", ack.GetMessage())
	}
	return ack, nil
}

func (u *GRPCAppender) streamClientLocked() (dataplanev1.AgentDataPlaneService_StreamBatchesClient, error) {
	if u.stream != nil {
		return u.stream, nil
	}
	dialCtx, cancelDial := context.WithTimeout(context.Background(), u.timeout)
	defer cancelDial()
	if u.token != "" {
		dialCtx = metadata.AppendToOutgoingContext(dialCtx, "x-sysarmor-agent-token", u.token)
	}
	creds, err := tlsconfig.ClientCredentials(u.tls)
	if err != nil {
		return nil, err
	}
	conn, err := grpc.DialContext(dialCtx, u.manager, grpc.WithTransportCredentials(creds), grpc.WithBlock())
	if err != nil {
		return nil, err
	}
	streamCtx := context.Background()
	var cancel context.CancelFunc
	streamCtx, cancel = context.WithCancel(streamCtx)
	if u.token != "" {
		streamCtx = metadata.AppendToOutgoingContext(streamCtx, "x-sysarmor-agent-token", u.token)
	}
	stream, err := dataplanev1.NewAgentDataPlaneServiceClient(conn).StreamBatches(streamCtx)
	if err != nil {
		cancel()
		_ = conn.Close()
		return nil, err
	}
	u.conn = conn
	u.stream = stream
	u.cancel = cancel
	return stream, nil
}

func (u *GRPCAppender) closeLocked() {
	if u.stream != nil {
		_ = u.stream.CloseSend()
		u.stream = nil
	}
	if u.cancel != nil {
		u.cancel()
		u.cancel = nil
	}
	if u.conn != nil {
		_ = u.conn.Close()
		u.conn = nil
	}
}

func normalizeGRPCAddress(manager string) string {
	manager = strings.TrimPrefix(manager, "http://")
	manager = strings.TrimPrefix(manager, "https://")
	return strings.TrimRight(manager, "/")
}
