package settings

import E "github.com/sagernet/sing/common/exceptions"

const (
	windowsSIDLocalSystem    = "S-1-5-18"
	windowsSIDLocalService   = "S-1-5-19"
	windowsSIDNetworkService = "S-1-5-20"
	windowsInternetSettings  = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
)

func isWindowsServiceAccountSID(userSID string) bool {
	switch userSID {
	case windowsSIDLocalSystem, windowsSIDLocalService, windowsSIDNetworkService:
		return true
	default:
		return false
	}
}

func windowsInternetSettingsRegistryPath(userSID string) (path string, useUsersHive bool) {
	if userSID == "" || isWindowsServiceAccountSID(userSID) {
		return windowsInternetSettings, false
	}
	return userSID + `\` + windowsInternetSettings, true
}

func validateWindowsSystemProxyUserSID(userSID string) error {
	if userSID == "" {
		return E.New("set system proxy: missing Windows user SID")
	}
	if isWindowsServiceAccountSID(userSID) {
		return E.New("set system proxy: refused to apply to a Windows service account; impersonate the logged-on user")
	}
	return nil
}
