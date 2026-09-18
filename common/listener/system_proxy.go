package listener

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/settings"
	"github.com/sagernet/sing/service"
)

func applySystemProxy(ctx context.Context, proxy settings.SystemProxy, enable bool) error {
	return applySystemProxyWithRunner(proxy, enable, userOperationRunnerFromContext(ctx))
}

func userOperationRunnerFromContext(ctx context.Context) adapter.UserOperationRunner {
	platform := service.FromContext[adapter.PlatformInterface](ctx)
	runner, _ := platform.(adapter.UserOperationRunner)
	return runner
}

func applySystemProxyWithRunner(proxy settings.SystemProxy, enable bool, runner adapter.UserOperationRunner) error {
	operation := proxy.Enable
	if !enable {
		operation = proxy.Disable
	}
	if runner != nil {
		return runner.RunUserOperation(operation)
	}
	return operation()
}
