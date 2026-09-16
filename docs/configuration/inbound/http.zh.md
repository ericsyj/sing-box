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

    在 Windows 上，图形客户端的 daemon 以 LocalSystem 运行。`set_system_proxy`
    会写入当前登录用户（包括微软账户）的 Internet Settings，而不是服务账户本身。

启动时自动设置系统代理，停止时自动清理。