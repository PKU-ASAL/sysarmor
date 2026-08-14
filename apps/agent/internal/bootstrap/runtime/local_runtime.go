package runtime

type LocalRuntime struct {
	stop func()
}

func NewLocalRuntime(stop func()) *LocalRuntime {
	return &LocalRuntime{stop: stop}
}

func (r *LocalRuntime) Close() {
	if r != nil && r.stop != nil {
		r.stop()
	}
}
