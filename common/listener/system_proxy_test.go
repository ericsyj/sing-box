package listener

import (
	"errors"
	"sync/atomic"
	"testing"
)

type stubSystemProxy struct {
	enableCount  atomic.Int32
	disableCount atomic.Int32
	enableErr    error
	disableErr   error
}

func (s *stubSystemProxy) IsEnabled() bool { return s.enableCount.Load() > s.disableCount.Load() }

func (s *stubSystemProxy) Enable() error {
	s.enableCount.Add(1)
	return s.enableErr
}

func (s *stubSystemProxy) Disable() error {
	s.disableCount.Add(1)
	return s.disableErr
}

type stubUserRunner struct {
	called atomic.Int32
	err    error
}

func (s *stubUserRunner) RunUserOperation(operation func() error) error {
	s.called.Add(1)
	if s.err != nil {
		return s.err
	}
	return operation()
}

func TestApplySystemProxyWithoutRunner(t *testing.T) {
	t.Parallel()

	proxy := &stubSystemProxy{}
	err := applySystemProxyWithRunner(proxy, true, nil)
	if err != nil {
		t.Fatalf("enable: %v", err)
	}
	if proxy.enableCount.Load() != 1 {
		t.Fatalf("enable count = %d, want 1", proxy.enableCount.Load())
	}

	err = applySystemProxyWithRunner(proxy, false, nil)
	if err != nil {
		t.Fatalf("disable: %v", err)
	}
	if proxy.disableCount.Load() != 1 {
		t.Fatalf("disable count = %d, want 1", proxy.disableCount.Load())
	}
}

func TestApplySystemProxyUsesOwnerRunner(t *testing.T) {
	t.Parallel()

	proxy := &stubSystemProxy{}
	runner := &stubUserRunner{}
	err := applySystemProxyWithRunner(proxy, true, runner)
	if err != nil {
		t.Fatalf("enable: %v", err)
	}
	if runner.called.Load() != 1 {
		t.Fatalf("runner called = %d, want 1", runner.called.Load())
	}
	if proxy.enableCount.Load() != 1 {
		t.Fatalf("enable count = %d, want 1", proxy.enableCount.Load())
	}
}

func TestApplySystemProxyRunnerError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("missing owner session")
	proxy := &stubSystemProxy{}
	runner := &stubUserRunner{err: wantErr}
	err := applySystemProxyWithRunner(proxy, true, runner)
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
	if proxy.enableCount.Load() != 0 {
		t.Fatalf("enable count = %d, want 0", proxy.enableCount.Load())
	}
}
