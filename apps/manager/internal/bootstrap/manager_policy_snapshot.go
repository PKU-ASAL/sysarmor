package bootstrap

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"log"
	"time"

	kafkaadapter "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/kafka"
	policypostgres "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/postgres/policy"
	policyapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/policy"
)

type policySnapshotRuntime struct {
	cancel    context.CancelFunc
	done      chan struct{}
	publisher io.Closer
}

func startPolicySnapshotRuntime(db *sql.DB, brokers []string) (*policySnapshotRuntime, error) {
	publisher, err := kafkaadapter.NewPolicySnapshotPublisher(brokers)
	if err != nil {
		return nil, err
	}
	dispatcher := policyapp.NewSnapshotDispatcher(policypostgres.NewSnapshotOutbox(db), publisher)
	ctx, cancel := context.WithCancel(context.Background())
	runtime := &policySnapshotRuntime{cancel: cancel, done: make(chan struct{}), publisher: publisher}
	go func() {
		defer close(runtime.done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			if err := dispatcher.RunOnce(ctx); err != nil && ctx.Err() == nil {
				log.Printf("dispatch policy snapshot: %v", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return runtime, nil
}

func (runtime *policySnapshotRuntime) Close() error {
	if runtime == nil {
		return nil
	}
	runtime.cancel()
	<-runtime.done
	return runtime.publisher.Close()
}

type managerResources struct {
	db       io.Closer
	snapshot io.Closer
}

func (resources *managerResources) Close() error {
	if resources == nil {
		return nil
	}
	return errors.Join(closeIfPresent(resources.snapshot), closeIfPresent(resources.db))
}
