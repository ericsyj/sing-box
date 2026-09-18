package settings

import (
	"errors"

	E "github.com/sagernet/sing/common/exceptions"
)

const (
	windowsSIDLocalSystem          = "S-1-5-18"
	windowsSIDLocalService         = "S-1-5-19"
	windowsSIDNetworkService       = "S-1-5-20"
	windowsInternetSettings        = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	windowsRunOnce                 = `Software\Microsoft\Windows\CurrentVersion\RunOnce`
	windowsProxyCleanupRunOnceName = "sing-box-clear-system-proxy"
	windowsInvalidSessionID        = 0xFFFFFFFF
)

var errNoInteractiveWindowsSession = errors.New("set system proxy: no interactive Windows session is available")

func isWindowsInteractiveSessionUnavailable(err error) bool {
	return errors.Is(err, errNoInteractiveWindowsSession)
}

func unavailableWindowsSessionError(cause error) error {
	if cause == nil {
		return errNoInteractiveWindowsSession
	}
	return errors.Join(errNoInteractiveWindowsSession, cause)
}

type windowsSessionCandidate struct {
	SessionID uint32
	State     uint32
}

func isWindowsServiceAccountSID(userSID string) bool {
	switch userSID {
	case windowsSIDLocalSystem, windowsSIDLocalService, windowsSIDNetworkService:
		return true
	default:
		return false
	}
}

func windowsInternetSettingsRegistryPath(userSID string) string {
	return userSID + `\` + windowsInternetSettings
}

func windowsRunOnceRegistryPath(userSID string) string {
	return userSID + `\` + windowsRunOnce
}

func validateWindowsSystemProxyUserSID(userSID string) error {
	if userSID == "" {
		return E.New("set system proxy: missing Windows user SID")
	}
	if isWindowsServiceAccountSID(userSID) {
		return E.New("set system proxy: refused to apply to a Windows service account")
	}
	return nil
}

func pickInteractiveWindowsSessionID(consoleID uint32, sessions []windowsSessionCandidate) (uint32, bool) {
	if isUsableWindowsSessionID(consoleID) {
		if len(sessions) == 0 {
			return consoleID, true
		}
		for _, session := range sessions {
			if session.SessionID == consoleID && isInteractiveWindowsSessionState(session.State) {
				return consoleID, true
			}
		}
	}
	var fallback uint32
	var found bool
	for _, session := range sessions {
		if !isUsableWindowsSessionID(session.SessionID) {
			continue
		}
		if session.State == windowsSessionStateActive {
			return session.SessionID, true
		}
		if !found && isInteractiveWindowsSessionState(session.State) {
			fallback = session.SessionID
			found = true
		}
	}
	return fallback, found
}

func IsUsableWindowsSessionID(sessionID uint32) bool {
	return isUsableWindowsSessionID(sessionID)
}

func isUsableWindowsSessionID(sessionID uint32) bool {
	return sessionID != 0 && sessionID != windowsInvalidSessionID
}

const (
	windowsSessionStateActive       = 0
	windowsSessionStateConnected    = 1
	windowsSessionStateDisconnected = 4
	windowsSessionStateIdle         = 5
)

func isInteractiveWindowsSessionState(state uint32) bool {
	switch state {
	case windowsSessionStateActive, windowsSessionStateConnected, windowsSessionStateIdle:
		return true
	default:
		return false
	}
}
