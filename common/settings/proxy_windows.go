package settings

import (
	"context"
	"os"
	"runtime"
	"strings"
	"syscall"
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
	isEnabled      bool
	appliedUserSID string
}

func NewSystemProxy(ctx context.Context, serverAddr M.Socksaddr, supportSOCKS bool, bypassDomain []string) (*WindowsSystemProxy, error) {
	return &WindowsSystemProxy{
		serverAddr:   serverAddr,
		supportSOCKS: supportSOCKS,
		bypassDomain: bypassDomain,
	}, nil
}

func (p *WindowsSystemProxy) IsEnabled() bool {
	return p.isEnabled
}

func (p *WindowsSystemProxy) Enable() error {
	userSID, err := currentWindowsUserSID()
	if err != nil {
		return err
	}
	err = applyWindowsUserProxy(userSID, true, "http://"+p.serverAddr.String(), strings.Join(p.bypassDomain, ";"))
	if err != nil {
		return err
	}
	p.appliedUserSID = userSID
	p.isEnabled = true
	return nil
}

func (p *WindowsSystemProxy) Disable() error {
	userSID := p.appliedUserSID
	if userSID == "" {
		var err error
		userSID, err = currentWindowsUserSID()
		if err != nil {
			return err
		}
	}
	err := applyWindowsUserProxy(userSID, false, "", "")
	if err != nil {
		return err
	}
	p.isEnabled = false
	p.appliedUserSID = ""
	return nil
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

func applyWindowsUserProxy(userSID string, enabled bool, server string, bypass string) error {
	err := validateWindowsSystemProxyUserSID(userSID)
	if err != nil {
		return err
	}
	err = writeWindowsInternetSettings(userSID, enabled, server, bypass)
	if err != nil {
		return err
	}
	_ = notifyWindowsProxySettings(enabled, server, bypass)
	return nil
}

func writeWindowsInternetSettings(userSID string, enabled bool, server string, bypass string) error {
	path, _ := windowsInternetSettingsRegistryPath(userSID)
	key, _, err := registry.CreateKey(registry.USERS, path, registry.SET_VALUE)
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

var procInternetSetOptionW = windows.NewLazySystemDLL("wininet.dll").NewProc("InternetSetOptionW")

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
