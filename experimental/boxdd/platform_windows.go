//go:build windows

package main

import (
	"context"
	"io"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/settings"
	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/tailscale/go-winio"
	"golang.org/x/sys/windows"
)

var regDisablePredefinedCacheEx = windows.NewLazySystemDLL("advapi32.dll").NewProc("RegDisablePredefinedCacheEx")

type windowsPlatformInterface struct {
	daemon             *Daemon
	access             sync.Mutex
	updateAccess       sync.Mutex
	updateInProgress   bool
	daemonSigner       []byte
	ownerUserID        string
	sessionID          uint32
	token              windows.Token
	systemProxy        *settings.WindowsSystemProxy
	systemProxyEnabled bool
}

func newPlatformInterface(daemonInstance *Daemon) (daemonPlatform, error) {
	result, _, _ := regDisablePredefinedCacheEx.Call()
	if result != 0 {
		return nil, E.Cause(syscall.Errno(result), "disable predefined registry handle cache")
	}
	return &windowsPlatformInterface{
		daemon:             daemonInstance,
		systemProxyEnabled: true,
	}, nil
}

func (p *windowsPlatformInterface) Initialize(networkManager adapter.NetworkManager) error {
	return nil
}

func (p *windowsPlatformInterface) UsePlatformAutoDetectInterfaceControl() bool {
	return false
}

func (p *windowsPlatformInterface) AutoDetectInterfaceControl(fd int) error {
	return os.ErrInvalid
}

func (p *windowsPlatformInterface) UsePlatformInterface() bool {
	return false
}

func (p *windowsPlatformInterface) OpenInterface(options *tun.Options, platformOptions option.TunPlatformOptions) (tun.Tun, error) {
	return nil, os.ErrInvalid
}

func (p *windowsPlatformInterface) ProcessPlatformOptions(options option.TunPlatformOptions) error {
	if options.HTTPProxy == nil || !options.HTTPProxy.Enabled {
		return nil
	}
	httpProxyOptions := options.HTTPProxy
	systemProxy, err := settings.NewSystemProxy(
		context.Background(),
		M.ParseSocksaddrHostPort(httpProxyOptions.Server, httpProxyOptions.ServerPort),
		false,
		[]string(httpProxyOptions.BypassDomain),
	)
	if err != nil {
		return E.Cause(err, "initialize system proxy")
	}
	p.access.Lock()
	if p.systemProxy != nil {
		p.access.Unlock()
		return E.New("only one enabled `tun.platform.http_proxy` is supported")
	}
	p.systemProxy = systemProxy
	err = p.applySystemProxyLocked()
	if err != nil {
		rollbackError := p.disableSystemProxyLocked()
		p.systemProxy = nil
		p.access.Unlock()
		return E.Errors(E.Cause(err, "set system proxy"), rollbackError)
	}
	p.access.Unlock()
	return nil
}

func (p *windowsPlatformInterface) UsePlatformDefaultInterfaceMonitor() bool {
	return false
}

func (p *windowsPlatformInterface) CreateDefaultInterfaceMonitor(logger logger.Logger) tun.DefaultInterfaceMonitor {
	return nil
}

func (p *windowsPlatformInterface) UsePlatformNetworkInterfaces() bool {
	return false
}

func (p *windowsPlatformInterface) NetworkInterfaces() ([]adapter.NetworkInterface, error) {
	return nil, os.ErrInvalid
}

func (p *windowsPlatformInterface) UnderNetworkExtension() bool {
	return false
}

func (p *windowsPlatformInterface) NetworkExtensionIncludeAllNetworks() bool {
	return false
}

func (p *windowsPlatformInterface) ClearDNSCache() {
}

func (p *windowsPlatformInterface) RequestPermissionForWIFIState() error {
	return nil
}

func (p *windowsPlatformInterface) ReadWIFIState(ctx context.Context) adapter.WIFIState {
	return adapter.WIFIState{}
}

func (p *windowsPlatformInterface) UsePlatformConnectionOwnerFinder() bool {
	return false
}

func (p *windowsPlatformInterface) FindConnectionOwner(request *adapter.FindConnectionOwnerRequest) (*adapter.ConnectionOwner, error) {
	return nil, os.ErrInvalid
}

func (p *windowsPlatformInterface) UsePlatformWIFIMonitor() bool {
	return false
}

func (p *windowsPlatformInterface) UsePlatformNotification() bool {
	return true
}

func (p *windowsPlatformInterface) SendNotification(notification *adapter.Notification) error {
	return p.daemon.startedService.SendNotification(notification)
}

func (p *windowsPlatformInterface) CancelNotification(identifier string, typeID int32) error {
	return p.daemon.startedService.CancelNotification(identifier, typeID)
}

func (p *windowsPlatformInterface) MyInterfaceAddress() []netip.Addr {
	return nil
}

func (p *windowsPlatformInterface) UsePlatformNeighborResolver() bool {
	return false
}

func (p *windowsPlatformInterface) StartNeighborMonitor(listener adapter.NeighborUpdateListener) error {
	return os.ErrInvalid
}

func (p *windowsPlatformInterface) CloseNeighborMonitor(listener adapter.NeighborUpdateListener) error {
	return nil
}

func (p *windowsPlatformInterface) UsePlatformShell() bool {
	return listenAddress == ""
}

func (p *windowsPlatformInterface) CheckPlatformShell() error {
	return nil
}

func (p *windowsPlatformInterface) OpenShellSession(user *adapter.PlatformUser, command string, environ []string, term string, rows int32, cols int32) (adapter.ShellSession, error) {
	return nil, os.ErrInvalid
}

func (p *windowsPlatformInterface) LookupUser(username string) (*adapter.PlatformUser, error) {
	requestedUser, err := user.Lookup(username)
	if err != nil {
		return nil, E.Cause(err, "lookup Windows user")
	}
	return &adapter.PlatformUser{
		Username: requestedUser.Username,
		Uid:      os.Getuid(),
		Gid:      os.Getgid(),
		HomeDir:  requestedUser.HomeDir,
	}, nil
}

func (p *windowsPlatformInterface) LookupSFTPServer() (string, error) {
	for _, sftpPath := range []string{
		filepath.Join(os.Getenv("SystemRoot"), "System32", "OpenSSH", "sftp-server.exe"),
		filepath.Join(os.Getenv("ProgramFiles"), "OpenSSH", "sftp-server.exe"),
	} {
		_, err := os.Stat(sftpPath)
		if err == nil {
			return sftpPath, nil
		}
	}
	return "", E.New("sftp-server not found")
}

func (p *windowsPlatformInterface) ReadSystemSSHHostKey() ([]byte, error) {
	return nil, os.ErrInvalid
}

func (p *windowsPlatformInterface) TailscaleHostname() string {
	return ""
}

func (p *windowsPlatformInterface) AcquireWindowsUserToken(localUser *adapter.PlatformUser) (windows.Token, io.Closer, error) {
	requestedUser, err := user.Lookup(localUser.Username)
	if err != nil {
		return 0, nil, E.Cause(err, "lookup Windows user")
	}
	return acquireWindowsUserSession(requestedUser)
}

func (p *windowsPlatformInterface) UsePlatformBridge() bool {
	return false
}

func (p *windowsPlatformInterface) CreateBridge(options adapter.BridgeOptions) (adapter.BridgeSession, error) {
	return nil, os.ErrInvalid
}

func (p *windowsPlatformInterface) UsePlatformAutoRedirect() bool {
	return false
}

func (p *windowsPlatformInterface) CreateAutoRedirect(options adapter.AutoRedirectOptions) (adapter.AutoRedirectSession, error) {
	return nil, os.ErrInvalid
}

func (p *windowsPlatformInterface) PrepareOwner(identity peerIdentity) error {
	p.access.Lock()
	defer p.access.Unlock()
	if listenAddress != "" {
		p.ownerUserID = identity.UserID
		p.sessionID = identity.SessionID
		return p.applySystemProxyLocked()
	}
	if p.token != 0 && p.ownerUserID == identity.UserID && p.sessionID == identity.SessionID {
		return p.applySystemProxyLocked()
	}
	token, err := p.ownerTokenForIdentity(identity)
	if err != nil {
		return err
	}
	err = p.replaceOwnerTokenLocked(identity.UserID, identity.SessionID, token)
	if err != nil {
		return err
	}
	return nil
}

func (p *windowsPlatformInterface) RestoreOwner(state ownerState) error {
	p.access.Lock()
	defer p.access.Unlock()
	if p.token != 0 {
		_ = p.closeOwnerTokenLocked()
	}
	p.ownerUserID = state.UserID
	p.sessionID = 0
	if listenAddress != "" {
		return nil
	}
	token, sessionID, err := restoreWindowsOwnerToken(state)
	if err != nil {
		return nil
	}
	p.sessionID = sessionID
	p.token = token
	return nil
}

func restoreWindowsOwnerToken(state ownerState) (windows.Token, uint32, error) {
	if settings.IsUsableWindowsSessionID(state.SessionID) {
		token, err := querySessionUserToken(state.SessionID)
		if err == nil {
			userID, tokenSessionID, idErr := impersonationTokenIdentity(token)
			if idErr == nil && tokenSessionID == state.SessionID && sameWindowsOwnerUser(userID, state.UserID) {
				return token, state.SessionID, nil
			}
			_ = token.Close()
		}
	}
	return settings.LookupWindowsUserSessionToken(state.UserID)
}

func sameWindowsOwnerUser(userID string, expectedUserID string) bool {
	return userID == expectedUserID || strings.EqualFold(userID, expectedUserID)
}

func (p *windowsPlatformInterface) ReleaseOwner() error {
	p.access.Lock()
	defer p.access.Unlock()
	return p.releaseOwnerLocked()
}

func (p *windowsPlatformInterface) ResetPlatformOptions() error {
	p.access.Lock()
	defer p.access.Unlock()
	err := p.disableSystemProxyLocked()
	if err == nil {
		p.systemProxy = nil
	}
	return err
}

func (p *windowsPlatformInterface) SetSystemProxyPreference(enabled bool) {
	p.access.Lock()
	p.systemProxyEnabled = enabled
	p.access.Unlock()
}

func (p *windowsPlatformInterface) SystemProxyStatus() (*daemon.SystemProxyStatus, error) {
	p.access.Lock()
	defer p.access.Unlock()
	available := p.systemProxy != nil
	return &daemon.SystemProxyStatus{
		Available: available,
		Enabled:   available && p.systemProxyEnabled,
	}, nil
}

func (p *windowsPlatformInterface) SetSystemProxyEnabled(enabled bool) error {
	p.access.Lock()
	defer p.access.Unlock()
	if p.systemProxy == nil {
		if !enabled {
			p.systemProxyEnabled = false
			return nil
		}
		return E.New("the system proxy is not available")
	}
	previousEnabled := p.systemProxyEnabled
	p.systemProxyEnabled = enabled
	err := p.applySystemProxyLocked()
	if err != nil {
		p.systemProxyEnabled = previousEnabled
		rollbackError := p.applySystemProxyLocked()
		return E.Errors(err, rollbackError)
	}
	return nil
}

func (p *windowsPlatformInterface) ClearOwnerSystemProxy(userID string) error {
	var err error
	if userID != "" {
		err = settings.ClearWindowsUserSystemProxy(userID)
	}
	persisted := settings.PersistedWindowsProxyUserSID()
	if persisted != "" && persisted != userID {
		err = E.Errors(err, settings.ClearWindowsUserSystemProxy(persisted))
	}
	return err
}

func (p *windowsPlatformInterface) HandleSessionChange(eventType uint32, sessionID uint32, state ownerState) (uint32, bool, error) {
	p.access.Lock()
	defer p.access.Unlock()
	if eventType == windows.WTS_SESSION_LOGOFF {
		if p.sessionID != sessionID {
			return 0, false, nil
		}
		clearErr := settings.ClearWindowsUserSystemProxy(p.ownerUserID)
		releaseErr := p.releaseOwnerLocked()
		return 0, false, E.Errors(clearErr, releaseErr)
	}
	if eventType != windows.WTS_SESSION_LOGON &&
		eventType != windows.WTS_CONSOLE_CONNECT &&
		eventType != windows.WTS_REMOTE_CONNECT &&
		eventType != windows.WTS_SESSION_UNLOCK {
		return 0, false, nil
	}
	token, err := querySessionUserToken(sessionID)
	if err != nil {
		return 0, false, err
	}
	userID, tokenSessionID, err := impersonationTokenIdentity(token)
	if err != nil {
		token.Close()
		return 0, false, err
	}
	if tokenSessionID != sessionID {
		token.Close()
		return 0, false, nil
	}
	if !sameWindowsOwnerUser(userID, state.UserID) {
		token.Close()
		return 0, false, nil
	}
	err = p.replaceOwnerTokenLocked(userID, sessionID, token)
	if err != nil {
		return 0, false, err
	}
	return sessionID, true, nil
}

func (d *Daemon) handlePlatformSessionChange(eventType uint32, sessionID uint32) error {
	d.lifecycleAccess.Lock()
	defer d.lifecycleAccess.Unlock()
	if d.closed || d.platform == nil {
		return nil
	}
	state, err := loadOwnerState()
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	newSessionID, changed, err := d.platform.HandleSessionChange(eventType, sessionID, state)
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}
	if d.startedService.Instance() == nil {
		clearErr := d.platform.ClearOwnerSystemProxy(state.UserID)
		if clearErr != nil {
			d.logger.Warn("clear leftover system proxy: ", clearErr)
		}
	} else {
		reapplyErr := settings.ReapplyPersistedWindowsSystemProxy()
		if reapplyErr != nil {
			d.logger.Warn("reapply system proxy: ", reapplyErr)
		}
	}
	return saveOwner(state.UserID, newSessionID)
}

func (p *windowsPlatformInterface) Close() error {
	p.access.Lock()
	defer p.access.Unlock()
	systemProxyError := p.disableSystemProxyLocked()
	p.systemProxy = nil
	ownerError := p.closeOwnerTokenLocked()
	return E.Errors(systemProxyError, ownerError)
}

func (p *windowsPlatformInterface) applySystemProxyLocked() error {
	if p.systemProxy == nil {
		return nil
	}
	if p.systemProxyEnabled {
		if p.systemProxy.IsEnabled() {
			return nil
		}
		return p.runUserOperationLocked(p.systemProxy.Enable)
	}
	return p.disableSystemProxyLocked()
}

func (p *windowsPlatformInterface) disableSystemProxyLocked() error {
	if p.systemProxy == nil || !p.systemProxy.IsEnabled() {
		return nil
	}
	return p.runUserOperationLocked(p.systemProxy.Disable)
}

func (p *windowsPlatformInterface) RunUserOperation(operation func() error) error {
	p.access.Lock()
	defer p.access.Unlock()
	return p.runUserOperationLocked(operation)
}

func (p *windowsPlatformInterface) runUserOperationLocked(operation func() error) error {
	if listenAddress != "" || p.token == 0 {
		return operation()
	}
	return runImpersonated(p.token, operation)
}

func (p *windowsPlatformInterface) replaceOwnerTokenLocked(userID string, sessionID uint32, token windows.Token) error {
	err := p.disableSystemProxyLocked()
	if err != nil {
		return E.Errors(err, token.Close())
	}
	err = p.closeOwnerTokenLocked()
	if err != nil {
		return E.Errors(err, token.Close())
	}
	p.ownerUserID = userID
	p.sessionID = sessionID
	p.token = token
	err = p.applySystemProxyLocked()
	if err != nil {
		return E.Errors(err, p.closeOwnerTokenLocked())
	}
	return nil
}

func (p *windowsPlatformInterface) releaseOwnerLocked() error {
	err := p.disableSystemProxyLocked()
	if err != nil {
		return err
	}
	err = p.closeOwnerTokenLocked()
	p.ownerUserID = ""
	p.sessionID = 0
	return err
}

func (p *windowsPlatformInterface) closeOwnerTokenLocked() error {
	if p.token == 0 {
		return nil
	}
	err := p.token.Close()
	p.token = 0
	return err
}

func runImpersonated(token windows.Token, operation func() error) error {
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		var impersonationToken windows.Token
		err := impersonateLoggedOnUser(token)
		if err != nil {
			err = windows.SetThreadToken(nil, token)
		}
		if err != nil {
			impersonationToken, err = duplicateImpersonationToken(token)
			if err == nil {
				err = windows.SetThreadToken(nil, impersonationToken)
				if err != nil {
					_ = impersonationToken.Close()
					impersonationToken = 0
				}
			}
		}
		if err != nil {
			runtime.UnlockOSThread()
			result <- E.Cause(err, "impersonate owner")
			return
		}
		operationError := operation()
		revertError := windows.RevertToSelf()
		if impersonationToken != 0 {
			_ = impersonationToken.Close()
		}
		if revertError == nil {
			runtime.UnlockOSThread()
		} else {
			revertError = E.Cause(revertError, "revert owner impersonation")
		}
		result <- E.Errors(operationError, revertError)
	}()
	return <-result
}

var procImpersonateLoggedOnUser = windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateLoggedOnUser")

func impersonateLoggedOnUser(token windows.Token) error {
	r1, _, err := syscall.SyscallN(procImpersonateLoggedOnUser.Addr(), uintptr(token))
	if r1 == 0 {
		if err == syscall.Errno(0) {
			return syscall.EINVAL
		}
		return err
	}
	return nil
}

func (p *windowsPlatformInterface) ownerTokenForIdentity(identity peerIdentity) (windows.Token, error) {
	processToken, err := p.daemon.duplicatePeerImpersonationToken(identity)
	if err != nil {
		return 0, err
	}
	err = validateImpersonationToken(processToken, identity.UserID, identity.SessionID)
	if err != nil {
		processToken.Close()
		return 0, err
	}
	sessionToken, sessionErr := querySessionUserToken(identity.SessionID)
	if sessionErr != nil {
		return processToken, nil
	}
	err = validateSessionToken(sessionToken, identity.SessionID)
	if err != nil {
		sessionToken.Close()
		return processToken, nil
	}
	processToken.Close()
	return sessionToken, nil
}

func querySessionUserToken(sessionID uint32) (windows.Token, error) {
	var primaryToken windows.Token
	err := winio.RunWithPrivileges([]string{seTcbPrivilege}, func() error {
		return windows.WTSQueryUserToken(sessionID, &primaryToken)
	})
	if err != nil {
		return 0, E.Cause(err, "query session user token")
	}
	return primaryToken, nil
}

func duplicateImpersonationToken(token windows.Token) (windows.Token, error) {
	var duplicatedToken windows.Token
	err := windows.DuplicateTokenEx(
		token,
		windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE,
		nil,
		windows.SecurityImpersonation,
		windows.TokenImpersonation,
		&duplicatedToken,
	)
	if err != nil {
		return 0, E.Cause(err, "duplicate owner impersonation token")
	}
	return duplicatedToken, nil
}

func validateImpersonationToken(token windows.Token, expectedUserID string, expectedSessionID uint32) error {
	userID, sessionID, err := impersonationTokenIdentity(token)
	if err != nil {
		return err
	}
	if sessionID != expectedSessionID {
		return E.New("owner token identity does not match authenticated application")
	}
	if !sameWindowsOwnerUser(userID, expectedUserID) {
		return E.New("owner token identity does not match authenticated application")
	}
	return nil
}

func validateSessionToken(token windows.Token, expectedSessionID uint32) error {
	_, sessionID, err := impersonationTokenIdentity(token)
	if err != nil {
		return err
	}
	if sessionID != expectedSessionID {
		return E.New("session token does not match authenticated application session")
	}
	return nil
}

func impersonationTokenIdentity(token windows.Token) (string, uint32, error) {
	user, err := token.GetTokenUser()
	if err != nil {
		return "", 0, E.Cause(err, "query owner token user")
	}
	userID := user.User.Sid.String()
	if userID == "" {
		return "", 0, E.New("owner token has an invalid user SID")
	}
	var sessionID uint32
	var returnLength uint32
	err = windows.GetTokenInformation(
		token,
		windows.TokenSessionId,
		(*byte)(unsafe.Pointer(&sessionID)),
		uint32(unsafe.Sizeof(sessionID)),
		&returnLength,
	)
	if err != nil {
		return "", 0, E.Cause(err, "query owner token session")
	}
	return userID, sessionID, nil
}

var (
	_ daemonPlatform              = (*windowsPlatformInterface)(nil)
	_ adapter.UserOperationRunner = (*windowsPlatformInterface)(nil)
)
