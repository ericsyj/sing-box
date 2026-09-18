package settings

import (
	"errors"
	"testing"
)

func TestIsWindowsServiceAccountSID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		userSID string
		want    bool
	}{
		{name: "local system", userSID: windowsSIDLocalSystem, want: true},
		{name: "local service", userSID: windowsSIDLocalService, want: true},
		{name: "network service", userSID: windowsSIDNetworkService, want: true},
		{name: "empty", userSID: "", want: false},
		{name: "local account", userSID: "S-1-5-21-2183837231-4032374486-3325986402-1001", want: false},
		{name: "microsoft account local shadow", userSID: "S-1-5-21-3623811015-3361044348-30300820-1013", want: false},
		{name: "entra id", userSID: "S-1-12-1-1449230713-1249052806-163775040-1037295804", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isWindowsServiceAccountSID(tt.userSID); got != tt.want {
				t.Fatalf("isWindowsServiceAccountSID(%q) = %v, want %v", tt.userSID, got, tt.want)
			}
		})
	}
}

func TestValidateWindowsSystemProxyUserSID(t *testing.T) {
	t.Parallel()

	if err := validateWindowsSystemProxyUserSID(""); err == nil {
		t.Fatal("empty SID: want error")
	}
	if err := validateWindowsSystemProxyUserSID(windowsSIDLocalSystem); err == nil {
		t.Fatal("LocalSystem SID: want error")
	}
	if err := validateWindowsSystemProxyUserSID("S-1-5-21-3623811015-3361044348-30300820-1013"); err != nil {
		t.Fatalf("microsoft account SID: %v", err)
	}
}

func TestPickInteractiveWindowsSessionID(t *testing.T) {
	t.Parallel()

	microsoftSession := uint32(1)
	rdpSession := uint32(2)
	sessions := []windowsSessionCandidate{
		{SessionID: 0, State: windowsSessionStateActive},
		{SessionID: microsoftSession, State: windowsSessionStateActive},
		{SessionID: rdpSession, State: windowsSessionStateConnected},
	}

	got, ok := pickInteractiveWindowsSessionID(microsoftSession, sessions)
	if !ok || got != microsoftSession {
		t.Fatalf("console session = %d ok=%v, want %d true", got, ok, microsoftSession)
	}

	got, ok = pickInteractiveWindowsSessionID(windowsInvalidSessionID, sessions)
	if !ok || got != microsoftSession {
		t.Fatalf("no console: session = %d ok=%v, want active session %d", got, ok, microsoftSession)
	}

	got, ok = pickInteractiveWindowsSessionID(0, []windowsSessionCandidate{
		{SessionID: 0, State: windowsSessionStateActive},
		{SessionID: rdpSession, State: windowsSessionStateConnected},
	})
	if !ok || got != rdpSession {
		t.Fatalf("rdp fallback = %d ok=%v, want %d true", got, ok, rdpSession)
	}

	_, ok = pickInteractiveWindowsSessionID(0, []windowsSessionCandidate{
		{SessionID: 0, State: windowsSessionStateActive},
	})
	if ok {
		t.Fatal("service session 0 must not be selected")
	}
}

func TestWindowsInternetSettingsRegistryPath(t *testing.T) {
	t.Parallel()

	sid := "S-1-5-21-3623811015-3361044348-30300820-1013"
	got := windowsInternetSettingsRegistryPath(sid)
	want := sid + `\` + windowsInternetSettings
	if got != want {
		t.Fatalf("path = %q, want %q", got, want)
	}
}

func TestWindowsRunOnceRegistryPath(t *testing.T) {
	t.Parallel()

	sid := "S-1-5-21-3623811015-3361044348-30300820-1013"
	got := windowsRunOnceRegistryPath(sid)
	want := sid + `\` + windowsRunOnce
	if got != want {
		t.Fatalf("path = %q, want %q", got, want)
	}
}

func TestIsWindowsInteractiveSessionUnavailable(t *testing.T) {
	t.Parallel()

	if isWindowsInteractiveSessionUnavailable(nil) {
		t.Fatal("nil error must not be treated as unavailable session")
	}
	if !isWindowsInteractiveSessionUnavailable(errNoInteractiveWindowsSession) {
		t.Fatal("sentinel: want unavailable")
	}
	wrapped := unavailableWindowsSessionError(errors.New("WTSQueryUserToken: access denied"))
	if !isWindowsInteractiveSessionUnavailable(wrapped) {
		t.Fatalf("wrapped query error: want unavailable, got %v", wrapped)
	}
	if isWindowsInteractiveSessionUnavailable(errors.New("open Internet Settings")) {
		t.Fatal("unrelated error must not be treated as unavailable session")
	}
}

func TestIsUsableWindowsSessionID(t *testing.T) {
	t.Parallel()

	if !IsUsableWindowsSessionID(1) {
		t.Fatal("session 1 must be usable")
	}
	if IsUsableWindowsSessionID(0) {
		t.Fatal("session 0 must not be usable")
	}
	if IsUsableWindowsSessionID(windowsInvalidSessionID) {
		t.Fatal("invalid session id must not be usable")
	}
}
