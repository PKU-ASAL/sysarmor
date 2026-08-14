package runtime

import (
	"context"
	"fmt"
	"sync"
	"time"

	adapterenrollment "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/enrollment"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sqlite"
)

type unenrollmentCompletionReporter struct {
	store        *sqlite.Store
	send         func(context.Context, sqlite.UnenrollmentCompletion) error
	retryInitial time.Duration
	retryMax     time.Duration
	mu           sync.Mutex
}

func newUnenrollmentCompletionReporter(store *sqlite.Store, send func(context.Context, sqlite.UnenrollmentCompletion) error, retryInitial, retryMax time.Duration) *unenrollmentCompletionReporter {
	if retryInitial <= 0 {
		retryInitial = time.Second
	}
	if retryMax < retryInitial {
		retryMax = 30 * time.Second
	}
	return &unenrollmentCompletionReporter{store: store, send: send, retryInitial: retryInitial, retryMax: retryMax}
}

func (r *Coordinator) configureUnenrollmentCompletionReporter() *unenrollmentCompletionReporter {
	if r.completionReporter != nil {
		return r.completionReporter
	}
	export := r.Config.Local.Export
	r.completionReporter = newUnenrollmentCompletionReporter(r.localStore, func(ctx context.Context, completion sqlite.UnenrollmentCompletion) error {
		return adapterenrollment.ReportCompletion(ctx, completion, r.Config.Manager.TLSInsecure, export.RequestTimeout)
	}, export.RetryInitial, export.RetryMax)
	return r.completionReporter
}

func (r *Coordinator) startUnenrollmentCompletionReporter(ctx context.Context) func() {
	reporterCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.configureUnenrollmentCompletionReporter().Run(reporterCtx)
	}()
	return func() {
		cancel()
		<-done
	}
}

func (r *unenrollmentCompletionReporter) ReportOnce(ctx context.Context) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	completion, ok, err := r.store.UnenrollmentCompletion(ctx)
	if err != nil || !ok || completion.Status != sqlite.CompletionReady {
		return false, err
	}
	if err := r.send(ctx, completion); err != nil {
		if recordErr := r.store.RecordCompletionAttempt(ctx, err.Error()); recordErr != nil {
			return false, fmt.Errorf("report unenrollment completion: %v; record attempt: %w", err, recordErr)
		}
		return false, fmt.Errorf("report unenrollment completion: %w", err)
	}
	if err := r.store.AcknowledgeUnenrollmentCompletion(ctx, completion.EnrollmentID); err != nil {
		return false, err
	}
	return true, nil
}

func (r *unenrollmentCompletionReporter) Run(ctx context.Context) {
	delay := r.retryInitial
	for {
		_, err := r.ReportOnce(ctx)
		if err != nil {
			delay = nextCompletionRetry(delay, r.retryMax)
		} else {
			delay = r.retryInitial
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func nextCompletionRetry(current, maximum time.Duration) time.Duration {
	next := current * 2
	if next > maximum {
		return maximum
	}
	return next
}
