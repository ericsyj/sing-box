### Structure

```json
{
  "type": "http",
  "tag": "http-in",
  
  ... // Listen Fields
  
  "users": [
    {
      "username": "admin",
      "password": "admin"
    }
  ],
  "tls": {},
  "set_system_proxy": false
}
```

### Listen Fields

See [Listen Fields](/configuration/shared/listen/) for details.

### Fields

#### tls

TLS configuration, see [TLS](/configuration/shared/tls/#inbound).

#### users

HTTP users.

No authentication required if empty.

#### set_system_proxy

!!! quote ""

    Only supported on Linux, Android, Windows, and macOS.

!!! warning ""

    To work on Android and Apple platforms without privileges, use tun.platform.http_proxy instead.

    On Windows, `set_system_proxy` applies to the logged-on user even when
    sing-box runs as LocalSystem, including Microsoft accounts. If the
    interactive session is not available yet, the inbound still starts and
    the proxy is applied when a user logs on. Shutdown clears the user
    proxy even if the service does not start again after reboot.

Automatically set system proxy configuration when start and clean up when stop.
