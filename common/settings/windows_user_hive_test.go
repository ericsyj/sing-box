package settings

import "testing"

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

func TestWindowsInternetSettingsRegistryPath(t *testing.T) {
	t.Parallel()

	microsoftAccountSID := "S-1-5-21-3623811015-3361044348-30300820-1013"
	path, useUsersHive := windowsInternetSettingsRegistryPath(microsoftAccountSID)
	wantPath := microsoftAccountSID + `\` + windowsInternetSettings
	if path != wantPath || !useUsersHive {
		t.Fatalf("microsoft account path = %q useUsersHive=%v, want %q true", path, useUsersHive, wantPath)
	}

	path, useUsersHive = windowsInternetSettingsRegistryPath(windowsSIDLocalSystem)
	if path != windowsInternetSettings || useUsersHive {
		t.Fatalf("local system path = %q useUsersHive=%v, want HKCU key false", path, useUsersHive)
	}
}

func TestValidateWindowsSystemProxyUserSID(t *testing.T) {
	t.Parallel()

	err := validateWindowsSystemProxyUserSID("")
	if err == nil {
		t.Fatal("empty SID: want error")
	}
	err = validateWindowsSystemProxyUserSID(windowsSIDLocalSystem)
	if err == nil {
		t.Fatal("LocalSystem SID: want error")
	}
	err = validateWindowsSystemProxyUserSID("S-1-5-21-3623811015-3361044348-30300820-1013")
	if err != nil {
		t.Fatalf("microsoft account SID: %v", err)
	}
	err = validateWindowsSystemProxyUserSID("S-1-12-1-1449230713-1249052806-163775040-1037295804")
	if err != nil {
		t.Fatalf("entra id SID: %v", err)
	}
}
