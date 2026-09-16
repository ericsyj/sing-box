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

    On Windows, the graphical client daemon runs as LocalSystem. `set_system_proxy`
    is applied to the logged-on owner's user hive, including Microsoft accounts.

Automatically set system proxy configuration when start and clean up when stop.
