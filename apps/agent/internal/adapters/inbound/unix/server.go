package localapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"

	controlplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/controlplane/v1"
	"google.golang.org/grpc"
)

type Server struct {
	socketPath string
	handler    controlplanev1.AgentControlPlaneServiceServer
	out        io.Writer
}

func New(socketPath string, handler controlplanev1.AgentControlPlaneServiceServer, out io.Writer) *Server {
	return &Server{socketPath: socketPath, handler: handler, out: out}
}

func (s *Server) Start(ctx context.Context) (func(), error) {
	if s.socketPath == "" {
		return func() {}, nil
	}
	if s.handler == nil {
		return nil, fmt.Errorf("local api handler is required")
	}
	if err := os.MkdirAll(filepath.Dir(s.socketPath), 0o755); err != nil {
		return nil, err
	}
	if err := os.Remove(s.socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(s.socketPath, 0o660); err != nil {
		_ = listener.Close()
		return nil, err
	}
	server := grpc.NewServer()
	controlplanev1.RegisterAgentControlPlaneServiceServer(server, s.handler)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := server.Serve(listener); err != nil && s.out != nil {
			fmt.Fprintf(s.out, "agent local control server stopped: %v\n", err)
		}
	}()
	go func() {
		<-ctx.Done()
		server.GracefulStop()
	}()
	return func() {
		server.GracefulStop()
		<-done
		_ = os.Remove(s.socketPath)
	}, nil
}
