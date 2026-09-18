### 结构

```json
{
  "type": "http",
  "tag": "http-in",

  ... // 监听字段

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

### 监听字段

参阅 [监听字段](/zh/configuration/shared/listen/)。

### 字段

#### tls

TLS 配置, 参阅 [TLS](/zh/configuration/shared/tls/#入站)。

#### users

HTTP 用户

如果为空则不需要验证。

#### set_system_proxy

!!! quote ""

    仅支持 Linux、Android、Windows 和 macOS。

!!! warning ""

    要在无特权的 Android 和 iOS 上工作，请改用 tun.platform.http_proxy。

    在 Windows 上，即使 sing-box 以 LocalSystem 运行（CLI 服务或 GUI daemon），
    `set_system_proxy` 也会写入当前登录用户（包括微软账户）的 Internet Settings。
    若开机时还没有交互会话，入站仍会启动，并在用户登录后补写系统代理。
    关机时会清理用户系统代理，即使服务下次不会自启。

启动时自动设置系统代理，停止时自动清理。