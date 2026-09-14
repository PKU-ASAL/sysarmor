package bootstrap

import (
	"errors"
	"fmt"
	"sync"
)

type resourceCleanup struct {
	name  string
	close func() error
}

type Resources struct {
	mu        sync.Mutex
	items     []resourceCleanup
	closeOnce sync.Once
	closeErr  error
}

func (resources *Resources) Add(name string, close func() error) {
	if resources == nil || close == nil {
		return
	}
	resources.mu.Lock()
	defer resources.mu.Unlock()
	resources.items = append(resources.items, resourceCleanup{name: name, close: close})
}

func (resources *Resources) Close() error {
	if resources == nil {
		return nil
	}
	resources.closeOnce.Do(func() {
		resources.closeErr = resources.closeAll()
	})
	return resources.closeErr
}

func (resources *Resources) closeAll() error {
	resources.mu.Lock()
	items := append([]resourceCleanup(nil), resources.items...)
	resources.mu.Unlock()
	var failures []error
	for index := len(items) - 1; index >= 0; index-- {
		if err := items[index].close(); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", items[index].name, err))
		}
	}
	return errors.Join(failures...)
}
