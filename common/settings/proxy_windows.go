package settings

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

type WindowsSystemProxy struct {
	serverAddr     M.Socksaddr
	supportSOCKS   bool
	bypassDomain   []string
	access         sync.Mutex
	isEnabled      bool
	pendingApply   bool
	appliedUserSID string
	waiterStop     chan struct{}
}

type windowsProxyTarget struct {
	sid   string
	token windows.Token
}

func NewSystemProxy(ctx context.Context, serverAddr M.Socksaddr, supportSOCKS bool, bypassDomain []string) (*WindowsSystemProxy, error) {
	return &WindowsSystemProxy{
		serverAddr:   serverAddr,
		supportSOCKS: supportSOCKS,
		bypassDomain: bypassDomain,
	}, nil
}

func (p *WindowsSystemProxy) IsEnabled() bool {
	p.access.Lock()
	defer p.access.Unlock()
	return p.isEnabled
}

func (p *WindowsSystemProxy) Enable() error {
	p.access.Lock()
	defer p.access.Unlock()
	p.stopWaiterLocked()
	return p.enableLocked()
}

func (p *WindowsSystemProxy) Close() error {
	return p.Disable()
}

func (p *WindowsSystemProxy) Disable() error {
	p.access.Lock()
	defer p.access.Unlock()
	p.stopWaiterLocked()
	p.pendingApply = false
	sid := p.appliedUserSID
	if sid == "" {
		sid = loadPersistedWindowsProxyUserSID()
	}
	target, err := resolveWindowsProxyTarget()
	if err != nil {
		if sid == "" {
			p.isEnabled = false
			p.appliedUserSID = ""
			return nil
		}
		target = windowsProxyTarget{sid: sid}
	} else if sid != "" && target.sid != sid {
		if target.token != 0 {
			_ = target.token.Close()
			target.token = 0
		}
		target.sid = sid
	}
	if target.token != 0 {
		defer target.token.Close()
	}
	err = applyWindowsUserProxy(target, false, "", "")
	p.isEnabled = false
	p.appliedUserSID = ""
	clearPersistedWindowsProxyUserSID()
	return err
}

func (p *WindowsSystemProxy) enableLocked() error {
	target, err := resolveWindowsProxyTarget()
	if err != nil {
		if !isWindowsInteractiveSessionUnavailable(err) {
			return err
		}
		return p.deferEnableLocked()
	}
	if target.token != 0 {
		defer target.token.Close()
	}
	err = applyWindowsUserProxy(target, true, p.proxyServer(), p.proxyBypass())
	if err != nil {
		return err
	}
	p.appliedUserSID = target.sid
	p.isEnabled = true
	p.pendingApply = false
	persistWindowsProxyState(target.sid, p.proxyServer())
	return nil
}

func (p *WindowsSystemProxy) deferEnableLocked() error {
	p.isEnabled = true
	p.pendingApply = true
	sid := p.appliedUserSID
	if sid == "" {
		sid = loadPersistedWindowsProxyUserSID()
	}
	if sid != "" {
		_ = applyWindowsUserProxy(windowsProxyTarget{sid: sid}, true, p.proxyServer(), p.proxyBypass())
		p.appliedUserSID = sid
		persistWindowsProxyState(sid, p.proxyServer())
	}
	p.startWaiterLocked()
	return nil
}

func (p *WindowsSystemProxy) proxyServer() string {
	return "http://" + p.serverAddr.String()
}

func (p *WindowsSystemProxy) proxyBypass() string {
	return strings.Join(p.bypassDomain, ";")
}

func (p *WindowsSystemProxy) startWaiterLocked() {
	stop := make(chan struct{})
	p.waiterStop = stop
	go p.waitForInteractiveSession(stop)
}

func (p *WindowsSystemProxy) stopWaiterLocked() {
	if p.waiterStop == nil {
		return
	}
	close(p.waiterStop)
	p.waiterStop = nil
}

func (p *WindowsSystemProxy) waitForInteractiveSession(stop <-chan struct{}) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			p.access.Lock()
			if !p.pendingApply {
				p.access.Unlock()
				return
			}
			err := p.enableOnceLocked()
			p.access.Unlock()
			if err == nil {
				return
			}
		}
	}
}

func (p *WindowsSystemProxy) enableOnceLocked() error {
	target, err := resolveWindowsProxyTarget()
	if err != nil {
		return err
	}
	if target.token != 0 {
		defer target.token.Close()
	}
	err = applyWindowsUserProxy(target, true, p.proxyServer(), p.proxyBypass())
	if err != nil {
		return err
	}
	p.appliedUserSID = target.sid
	p.isEnabled = true
	p.pendingApply = false
	persistWindowsProxyState(target.sid, p.proxyServer())
	p.stopWaiterLocked()
	return nil
}

func ClearWindowsUserSystemProxy(userSID string) error {
	err := validateWindowsSystemProxyUserSID(userSID)
	if err != nil {
		return err
	}
	err = applyWindowsUserProxy(windowsProxyTarget{sid: userSID}, false, "", "")
	if loadPersistedWindowsProxyUserSID() == userSID {
		clearPersistedWindowsProxyUserSID()
	}
	return err
}

func ReapplyPersistedWindowsSystemProxy() error {
	sid := loadPersistedWindowsProxyUserSID()
	server := loadPersistedWindowsProxyServer()
	if sid == "" || server == "" {
		return nil
	}
	return applyWindowsUserProxy(windowsProxyTarget{sid: sid}, true, server, "")
}

func LookupWindowsUserSessionToken(userSID string) (windows.Token, uint32, error) {
	err := validateWindowsSystemProxyUserSID(userSID)
	if err != nil {
		return 0, 0, err
	}
	_ = enableWindowsTCBPrivilege()
	var lastErr error
	for _, sessionID := range windowsSessionLookupOrder() {
		token, err := queryWindowsSessionToken(sessionID)
		if err != nil {
			lastErr = err
			continue
		}
		sid, err := tokenUserSID(token)
		if err != nil {
			_ = token.Close()
			lastErr = err
			continue
		}
		if sid == userSID || strings.EqualFold(sid, userSID) {
			return token, sessionID, nil
		}
		_ = token.Close()
	}
	if lastErr != nil {
		return 0, 0, lastErr
	}
	return 0, 0, errNoInteractiveWindowsSession
}

func resolveWindowsProxyTarget() (windowsProxyTarget, error) {
	sid, err := currentWindowsUserSID()
	if err != nil {
		return windowsProxyTarget{}, err
	}
	if !isWindowsServiceAccountSID(sid) {
		return windowsProxyTarget{sid: sid}, nil
	}
	return interactiveWindowsProxyTarget()
}

func currentWindowsUserSID() (string, error) {
	var token windows.Token
	err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token)
	if err != nil {
		err = windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
		if err != nil {
			return "", E.Cause(err, "open Windows user token")
		}
	}
	defer token.Close()
	return tokenUserSID(token)
}

func tokenUserSID(token windows.Token) (string, error) {
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return "", E.Cause(err, "query Windows user SID")
	}
	userSID := tokenUser.User.Sid.String()
	if userSID == "" {
		return "", E.New("Windows token has an invalid user SID")
	}
	return userSID, nil
}

func interactiveWindowsProxyTarget() (windowsProxyTarget, error) {
	_ = enableWindowsTCBPrivilege()
	sessionID, err := interactiveWindowsSessionID()
	if err != nil {
		return windowsProxyTarget{}, err
	}
	token, err := queryWindowsSessionToken(sessionID)
	if err != nil {
		return windowsProxyTarget{}, err
	}
	sid, err := tokenUserSID(token)
	if err != nil {
		_ = token.Close()
		return windowsProxyTarget{}, err
	}
	return windowsProxyTarget{sid: sid, token: token}, nil
}

func interactiveWindowsSessionID() (uint32, error) {
	sessionID, ok := pickInteractiveWindowsSessionID(windows.WTSGetActiveConsoleSessionId(), listWindowsSessions())
	if !ok {
		return 0, errNoInteractiveWindowsSession
	}
	return sessionID, nil
}

func listWindowsSessions() []windowsSessionCandidate {
	var info *windows.WTS_SESSION_INFO
	var count uint32
	err := windows.WTSEnumerateSessions(0, 0, 1, &info, &count)
	if err != nil || info == nil || count == 0 {
		return nil
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(info)))
	enumerated := unsafe.Slice(info, count)
	sessions := make([]windowsSessionCandidate, 0, len(enumerated))
	for _, session := range enumerated {
		sessions = append(sessions, windowsSessionCandidate{
			SessionID: session.SessionID,
			State:     session.State,
		})
	}
	return sessions
}

func windowsSessionLookupOrder() []uint32 {
	sessions := listWindowsSessions()
	consoleID := windows.WTSGetActiveConsoleSessionId()
	seen := make(map[uint32]bool, len(sessions)+1)
	order := make([]uint32, 0, len(sessions)+1)
	appendSession := func(sessionID uint32) {
		if !isUsableWindowsSessionID(sessionID) || seen[sessionID] {
			return
		}
		seen[sessionID] = true
		order = append(order, sessionID)
	}
	appendSession(consoleID)
	for _, session := range sessions {
		appendSession(session.SessionID)
	}
	return order
}

func queryWindowsSessionToken(sessionID uint32) (windows.Token, error) {
	var token windows.Token
	err := windows.WTSQueryUserToken(sessionID, &token)
	if err != nil {
		return 0, unavailableWindowsSessionError(err)
	}
	return token, nil
}

func enableWindowsTCBPrivilege() error {
	return enableWindowsPrivilege("SeTcbPrivilege")
}

func enableWindowsPrivilege(name string) error {
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token)
	if err != nil {
		return err
	}
	defer token.Close()
	privilegeName, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	var luid windows.LUID
	err = windows.LookupPrivilegeValue(nil, privilegeName, &luid)
	if err != nil {
		return err
	}
	privileges := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{{
			Luid:       luid,
			Attributes: windows.SE_PRIVILEGE_ENABLED,
		}},
	}
	return windows.AdjustTokenPrivileges(token, false, &privileges, uint32(unsafe.Sizeof(privileges)), nil, nil)
}

func applyWindowsUserProxy(target windowsProxyTarget, enabled bool, server string, bypass string) error {
	err := validateWindowsSystemProxyUserSID(target.sid)
	if err != nil {
		return err
	}
	err = writeWindowsInternetSettings(target.sid, enabled, server, bypass)
	if err != nil {
		return err
	}
	notify := func() error {
		return notifyWindowsProxySettings(enabled, server, bypass)
	}
	if target.token != 0 {
		_ = runImpersonatedToken(target.token, notify)
		return nil
	}
	_ = notify()
	return nil
}

func PersistedWindowsProxyUserSID() string {
	return loadPersistedWindowsProxyUserSID()
}

func writeWindowsInternetSettings(userSID string, enabled bool, server string, bypass string) error {
	return withWindowsUserHive(userSID, func() error {
		err := writeWindowsInternetSettingsLoaded(userSID, enabled, server, bypass)
		if err != nil {
			return err
		}
		return removeWindowsProxyCleanupRunOnce(userSID)
	})
}

func withWindowsUserHive(userSID string, fn func() error) error {
	err := fn()
	if err == nil {
		return nil
	}
	unload, loadErr := loadWindowsUserHive(userSID)
	if loadErr != nil {
		return err
	}
	defer unload()
	return fn()
}

func writeWindowsInternetSettingsLoaded(userSID string, enabled bool, server string, bypass string) error {
	key, _, err := registry.CreateKey(registry.USERS, windowsInternetSettingsRegistryPath(userSID), registry.SET_VALUE)
	if err != nil {
		return E.Cause(err, "open Internet Settings for ", userSID)
	}
	defer key.Close()
	if enabled {
		err = key.SetDWordValue("ProxyEnable", 1)
		if err != nil {
			return E.Cause(err, "set ProxyEnable")
		}
		err = key.SetStringValue("ProxyServer", server)
		if err != nil {
			return E.Cause(err, "set ProxyServer")
		}
		if bypass != "" {
			err = key.SetStringValue("ProxyOverride", bypass)
			if err != nil {
				return E.Cause(err, "set ProxyOverride")
			}
		}
		err = key.SetStringValue("AutoConfigURL", "")
		if err != nil {
			return E.Cause(err, "clear AutoConfigURL")
		}
		err = key.SetDWordValue("AutoDetect", 0)
		if err != nil {
			return E.Cause(err, "clear AutoDetect")
		}
		flushWindowsRegistryKey(key)
		return nil
	}
	err = key.SetDWordValue("ProxyEnable", 0)
	if err != nil {
		return E.Cause(err, "clear ProxyEnable")
	}
	err = key.SetDWordValue("AutoDetect", 1)
	if err != nil {
		return E.Cause(err, "restore AutoDetect")
	}
	flushWindowsRegistryKey(key)
	return nil
}

func removeWindowsProxyCleanupRunOnce(userSID string) error {
	key, err := registry.OpenKey(registry.USERS, windowsRunOnceRegistryPath(userSID), registry.SET_VALUE)
	if err != nil {
		if err == registry.ErrNotExist {
			return nil
		}
		return E.Cause(err, "open RunOnce for ", userSID)
	}
	defer key.Close()
	err = key.DeleteValue(windowsProxyCleanupRunOnceName)
	if err != nil && err != registry.ErrNotExist {
		return E.Cause(err, "clear system proxy cleanup RunOnce")
	}
	flushWindowsRegistryKey(key)
	return nil
}

func flushWindowsRegistryKey(key registry.Key) {
	_, _, _ = syscall.SyscallN(procRegFlushKey.Addr(), uintptr(key))
}

const (
	windowsProxyStateRegistryPath = `SOFTWARE\sing-box\SystemProxy`
	windowsProxyStateSIDValue     = "LastUserSID"
	windowsProxyStateServerValue  = "LastProxyServer"
)

func persistWindowsProxyState(userSID string, server string) {
	if validateWindowsSystemProxyUserSID(userSID) != nil {
		return
	}
	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, windowsProxyStateRegistryPath, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer key.Close()
	_ = key.SetStringValue(windowsProxyStateSIDValue, userSID)
	if server != "" {
		_ = key.SetStringValue(windowsProxyStateServerValue, server)
	}
}

func loadPersistedWindowsProxyUserSID() string {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, windowsProxyStateRegistryPath, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer key.Close()
	sid, _, err := key.GetStringValue(windowsProxyStateSIDValue)
	if err != nil || validateWindowsSystemProxyUserSID(sid) != nil {
		return ""
	}
	return sid
}

func loadPersistedWindowsProxyServer() string {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, windowsProxyStateRegistryPath, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer key.Close()
	server, _, err := key.GetStringValue(windowsProxyStateServerValue)
	if err != nil || server == "" {
		return ""
	}
	return server
}

func clearPersistedWindowsProxyUserSID() {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, windowsProxyStateRegistryPath, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer key.Close()
	_ = key.DeleteValue(windowsProxyStateSIDValue)
	_ = key.DeleteValue(windowsProxyStateServerValue)
}

func loadWindowsUserHive(userSID string) (func(), error) {
	if windowsUserHiveLoaded(userSID) {
		return func() {}, nil
	}
	profilePath, err := windowsUserProfileImagePath(userSID)
	if err != nil {
		return nil, err
	}
	hivePath := filepath.Join(profilePath, "NTUSER.DAT")
	_, err = os.Stat(hivePath)
	if err != nil {
		return nil, err
	}
	_ = enableWindowsPrivilege("SeRestorePrivilege")
	_ = enableWindowsPrivilege("SeBackupPrivilege")
	subKey, err := windows.UTF16PtrFromString(userSID)
	if err != nil {
		return nil, err
	}
	file, err := windows.UTF16PtrFromString(hivePath)
	if err != nil {
		return nil, err
	}
	err = regLoadKey(windows.Handle(windows.HKEY_USERS), subKey, file)
	if err != nil {
		return nil, err
	}
	return func() {
		_ = regUnLoadKey(windows.Handle(windows.HKEY_USERS), subKey)
	}, nil
}

func windowsUserHiveLoaded(userSID string) bool {
	key, err := registry.OpenKey(registry.USERS, userSID, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	_ = key.Close()
	return true
}

func windowsUserProfileImagePath(userSID string) (string, error) {
	key, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\`+userSID,
		registry.QUERY_VALUE,
	)
	if err != nil {
		return "", E.Cause(err, "open profile list for ", userSID)
	}
	defer key.Close()
	profilePath, _, err := key.GetStringValue("ProfileImagePath")
	if err != nil {
		return "", E.Cause(err, "query profile path for ", userSID)
	}
	return expandWindowsPath(profilePath)
}

func expandWindowsPath(path string) (string, error) {
	if !strings.Contains(path, "%") {
		return path, nil
	}
	src, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	n, err := windows.ExpandEnvironmentStrings(src, nil, 0)
	if err != nil {
		return "", err
	}
	buf := make([]uint16, n)
	_, err = windows.ExpandEnvironmentStrings(src, &buf[0], n)
	if err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf), nil
}

func regLoadKey(root windows.Handle, subKey *uint16, file *uint16) error {
	r0, _, _ := syscall.SyscallN(procRegLoadKeyW.Addr(), uintptr(root), uintptr(unsafe.Pointer(subKey)), uintptr(unsafe.Pointer(file)))
	if r0 != 0 {
		return syscall.Errno(r0)
	}
	return nil
}

func regUnLoadKey(root windows.Handle, subKey *uint16) error {
	r0, _, _ := syscall.SyscallN(procRegUnLoadKeyW.Addr(), uintptr(root), uintptr(unsafe.Pointer(subKey)))
	if r0 != 0 {
		return syscall.Errno(r0)
	}
	return nil
}

const (
	internetOptionPerConnectionOption  = 75
	internetOptionSettingsChanged      = 39
	internetOptionRefresh              = 37
	internetOptionProxySettingsChanged = 95

	internetPerConnFlags       = 1
	internetPerConnProxyServer = 2
	internetPerConnProxyBypass = 3
	internetPerConnFlagsUI     = 10

	proxyTypeDirect     = 1
	proxyTypeProxy      = 2
	proxyTypeAutoDetect = 8
)

type internetPerConnOptionList struct {
	dwSize        uint32
	pszConnection uintptr
	dwOptionCount uint32
	dwOptionError uint32
	pOptions      uintptr
}

type internetPerConnOption struct {
	dwOption uint32
	value    uint64
}

var (
	advapi32                    = windows.NewLazySystemDLL("advapi32.dll")
	procInternetSetOptionW      = windows.NewLazySystemDLL("wininet.dll").NewProc("InternetSetOptionW")
	procImpersonateLoggedOnUser = advapi32.NewProc("ImpersonateLoggedOnUser")
	procRegLoadKeyW             = advapi32.NewProc("RegLoadKeyW")
	procRegUnLoadKeyW           = advapi32.NewProc("RegUnLoadKeyW")
	procRegFlushKey             = advapi32.NewProc("RegFlushKey")
)

func notifyWindowsProxySettings(enabled bool, server string, bypass string) error {
	flags := uint32(proxyTypeDirect | proxyTypeAutoDetect)
	if enabled {
		flags = proxyTypeProxy | proxyTypeDirect
	}
	var keepAlive []*uint16
	options := []internetPerConnOption{
		{dwOption: internetPerConnFlags, value: uint64(flags)},
		{dwOption: internetPerConnFlagsUI, value: uint64(flags)},
	}
	if enabled {
		serverPtr, err := windows.UTF16PtrFromString(server)
		if err != nil {
			return err
		}
		keepAlive = append(keepAlive, serverPtr)
		var serverOption internetPerConnOption
		serverOption.dwOption = internetPerConnProxyServer
		*(*uintptr)(unsafe.Pointer(&serverOption.value)) = uintptr(unsafe.Pointer(serverPtr))
		options = append(options, serverOption)
		if bypass != "" {
			bypassPtr, err := windows.UTF16PtrFromString(bypass)
			if err != nil {
				return err
			}
			keepAlive = append(keepAlive, bypassPtr)
			var bypassOption internetPerConnOption
			bypassOption.dwOption = internetPerConnProxyBypass
			*(*uintptr)(unsafe.Pointer(&bypassOption.value)) = uintptr(unsafe.Pointer(bypassPtr))
			options = append(options, bypassOption)
		}
	}
	err := setInternetPerConnOptions(options...)
	if err != nil && enabled {
		filtered := make([]internetPerConnOption, 0, len(options)-1)
		for _, option := range options {
			if option.dwOption != internetPerConnFlagsUI {
				filtered = append(filtered, option)
			}
		}
		err = setInternetPerConnOptions(filtered...)
	}
	runtime.KeepAlive(keepAlive)
	return err
}

func setInternetPerConnOptions(options ...internetPerConnOption) error {
	optionList := internetPerConnOptionList{
		dwSize:        uint32(unsafe.Sizeof(internetPerConnOptionList{})),
		dwOptionCount: uint32(len(options)),
		pOptions:      uintptr(unsafe.Pointer(&options[0])),
	}
	err := internetSetOption(internetOptionPerConnectionOption, uintptr(unsafe.Pointer(&optionList)), uintptr(optionList.dwSize))
	if err != nil {
		return err
	}
	err = internetSetOption(internetOptionSettingsChanged, 0, 0)
	if err != nil {
		return err
	}
	err = internetSetOption(internetOptionProxySettingsChanged, 0, 0)
	if err != nil {
		return err
	}
	return internetSetOption(internetOptionRefresh, 0, 0)
}

func internetSetOption(option uintptr, lpBuffer uintptr, dwBufferSize uintptr) error {
	r0, _, err := syscall.SyscallN(procInternetSetOptionW.Addr(), 0, option, lpBuffer, dwBufferSize)
	if r0 != 1 {
		if err == syscall.Errno(0) {
			err = syscall.EINVAL
		}
		return os.NewSyscallError("InternetSetOption", err)
	}
	return nil
}

func runImpersonatedToken(token windows.Token, operation func() error) error {
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		err := impersonateLoggedOnUser(token)
		if err != nil {
			err = windows.SetThreadToken(nil, token)
		}
		if err != nil {
			runtime.UnlockOSThread()
			result <- E.Cause(err, "impersonate interactive user")
			return
		}
		operationError := operation()
		revertError := windows.RevertToSelf()
		if revertError == nil {
			runtime.UnlockOSThread()
		} else {
			revertError = E.Cause(revertError, "revert interactive user impersonation")
		}
		result <- E.Errors(operationError, revertError)
	}()
	return <-result
}

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
