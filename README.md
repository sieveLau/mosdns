# mosdns

功能概述、配置方式、教程等，详见: [wiki](https://irine-sistiana.gitbook.io/mosdns-wiki/mosdns-v4)

*注意：wiki中的 `servers` - `listener` 应为 `listeners`。 Reminder: the configuration of `servers` should be `listeners` instead of `listener`.*

下载预编译文件，见: [release](https://github.com/sieveLau/mosdns/releases)

docker 镜像: [dockerhub: sievelau/mosdns](https://hub.docker.com/r/sievelau/mosdns)

# 改动/Changes

## trust_ca

现在对upstream新增了一个配置项`trust_ca`，可以指定一个CA文件的路径，该CA所颁发的证书在**该插件**的范围内会被信任；系统已经信任的证书也会被信任。例如：

Now the upstream plugin has a new option `trust_ca`, in which you can set the path to a CA cert which will be trusted in addition to those trusted by the OS. For example:

```yaml
plugins:
  - tag: ""
    type: "forward"
    args:
      upstream:
        - addr: "quic://192.168.1.1"
      trust_ca: "/etc/mosdns/rootCA.crt"
```

那么用`rootCA.crt`所签发的证书将会被信任。

Certificates issued by `rootCA.crt` will be trusted.

## freebind

`servers` 中的 `listeners` 新增了一个配置选项 `freebind`。如果设置为 `true`，你可以在 `addr` 中填写任意 IP 地址。这在 mosdns 部署于路由器上且某个网络接口（特别是 LAN 口）会在 mosdns 启动后才会拥有IP的情况下非常有用。

`listeners` in `servers` has a new config option `freebind`. If set to `true`, you can put whatever IP in `addr`. This is helpful when mosdns is deployed on a router and one of its network interface will go online after mosdns starts. Example:

```yaml
servers:
  - exec: "test"
    listeners:     
      - protocol: udp
        addr: "192.168.240.100:1053"
        freebind: true
```

## check and no_private

`ecs` 插件新增了配置选项 `check` 和 `no_private`，用于检查 edns-client-subnet 是否包含私有地址或不合法地址。`no_private` 有五个合法值：
- `false` 和 `no` 以及 不指定：不作修改（除非 `check` 设置为 `true`）
- `true` 和 `yes`：在 `force_overwrite` 也是 `true` 的时候移除私有地址
- `strict`：无论 `force_overwrite` 是否为 `true`，都会移除私有地址或不合法地址

`check` 如果为 `true`，则 `no_private` 会被设置为 `strict`，且如果 ECS 地址非法会无视 `force_overwrite` 的值删除 ECS（但是不会新增 ECS）。

此外还有其他修改，使得 ecs 插件几乎完全符合 RFC 7871 的要求，例如 `_no_ecs` 只会对发往上游的请求删除 ECS，在回复客户端时会重新加上 ECS；同时启用 `auto` 和 `overwrite` 或者由于 ECS 不合法被内部删除时，会把上游回复的 ECS 替换成客户端请求时的 ECS 并修改对应的参数（特指 scope prefix）。

`ecs` 插件即使没有设置任何参数，放一个到sequence里（越前越好，至少要在forward插件之前）也会使你得到一致的ECS的好处。

The `ecs` plugin introduces two new configuration options, `check` and `no_private`, used to verify whether the `edns-client-subnet` contains private or invalid addresses. The `no_private` option has five valid values:

- `false`, `no`, or unspecified: No modification will be made (unless `check` is set to `true`).
- `true` and `yes`: Private addresses will be removed if `force_overwrite` is also `true`.
- `strict`: Private or invalid addresses will be removed regardless of whether `force_overwrite` is set to `true`.

If `check` is set to `true`, the `no_private` option will be enforced as `strict`. Moreover, if the ECS address is invalid, the ECS will be removed, ignoring the `force_overwrite` value (but no new ECS will be added in this case).

There are additional changes making the `ecs` plugin almost fully compliant with RFC 7871. For instance, `_no_ecs` will only remove ECS from requests sent to upstream servers, but it will add ECS back in responses to clients. When ECS is changed by the plugin, or when ECS is internally removed due to being invalid, the ECS from the upstream response will be replaced with the ECS from the client request, and the relevant parameters (specifically the scope prefix) will be updated accordingly. And many more senarios I won't enum here.

The ecs plugin, even without setting any parameters, will provide you with consistent ECS benefits simply by placing it in the sequence (the earlier, the better, but at least before the forward plugin).

```yaml
plugins:
  - tag: "ecs"
    type: "ecs"
    args:
      check: true
      no_private: strict # 可以同时启用这两个选项，但是 check: true 会覆盖 no_private
```

## generic_mode

`cache` plugin has a new option `generic_mode`, either `true` or `false`. If `true`, only a minimum part of the query, i.e. the question, qclass and qtyped, is used as cache key. If you don't want your cache rate dragged by the ecs, you can enable it. Note that this option has lower priority than `cache_everything`, so if the latter is true, this will have no effect.

`cache` 插件有一个新选项 `generic_mode`，可以为 `true` 或 `false`。如果为 `true`，则仅查询的最小部分（即question、qclass 和 qtype）将用作缓存键。如果不希望缓存命中率受到 ecs（edns-client-subnet）的影响，可以启用该选项。需要注意的是，该选项的优先级低于 `cache_everything`，因此如果后者为 true，此选项将不起作用。

## auto_retry

`forward` 插件有一个新的选项 `auto_retry`，可以设置为 `true` 或 `false`。如果设置为 `true` 并且满足以下所有条件：

1. 插件从上游收到 REFUSED 响应码
2. 原始查询包含 ECS

那么插件将移除 ECS 并再次尝试。请注意，插件在移除 ECS 后不会重新添加 ECS，因此建议您在 `forward` 插件之前放置一个 `ecs` 插件，即使不带参数。

`forward` plugin has a new option `auto_retry`, either `true` or `false`. If `true` and all of the following conditions are true:
1. the plugin gets a REFUSED rcode from upstream
2. the original query contains ECS

Then the plugin will remove the ECS and try again. Note that the plugin won't add back ECS if it removes ECS, so you are recommended to place a `ecs` plugin, even with no arguments, before the `forward` plugin.

```yaml
plugins:
  - tag: "forward"
    type: "forward"
    args:
      auto_retry: true
      upstream:
        - addr: "8.8.8.8"
```

# 配置文件结构/Configuration File Structure

```yaml
# 日志设置
log:
  level: info   # 日志级别。可选 "debug" "info" "warn" "error"。默认 "info"。
  file: "/path/to/log/file"      # 记录日志到文件。

# 从其他配置文件载入 include，数据源，插件和服务器设置
# include 的设置会比本配置文件中的设置先被初始化
include: []

# 数据源设置
data_providers:
  - tag: data1        # 数据源的 tag。由用户自由设定。不能重复。
    file: "/path/to/data/file"     # 文件位置
    auto_reload: false # 文件有变化时是否自动重载。

# 插件设置
plugins:
  - tag: tag1     # 插件的 tag。由用户自由设定。不能重复。
    type: type1   # 插件类型。详见下文。
    args:         # 插件参数。取决于插件类型。详见下文。
      key1: value1
      key2: value2

# 服务器设置
servers:
  - exec: plugin_tag1    # 本服务器运行插件的 tag。
    timeout: 5    # 请求处理超时时间。单位: 秒。默认: 5。
    listeners:     # 监听设置。是数组。可配置多个。
      - protocol: https           # 协议，支持 "udp", "tcp", "tls", "https" 和 "http"
        addr: ":443"              # 监听地址。
        cert: "/path/to/my/cert"  # TLS 所需证书文件。
        key: "/path/to/my/key"    # TLS 所需密钥文件。
        url_path: "/dns-query"    # DoH 路径。留空会跳过路径检查，任何请求路径会被处理。
        # DoH 从 HTTP 头获取用户 IP。需配合反向代理使用。(v4.3+) 配置后会屏蔽所有没有该头的请求。
        get_user_ip_from_header: "X-Forwarded-For"
        # (v4.3+) 启用 proxy protocol。需配合代理使用。UDP 服务器暂不支持。
        proxy_protocol: false
        idle_timeout: 10          # 连接复用空连接超时时间。单位: 秒。默认: 10。

      - protocol: udp
        addr: ":53"
      - protocol: tcp
        addr: ":53"
# API 入口设置     
api:
  http: "127.0.0.1:8080" # 在该地址启动 api 接口。
```

# Compile from source

Build dependencies:

1. go, minimum version 1.21
2. git, for cloning source code to local

Clone this repo:

```bash
git clone https://github.com/sieveLau/mosdns.git
```

Make a build directory:

```bash
cd mosdns
mkdir build
```

Then build:

```bash
cd build
go build ../
```

When the compilation is done, you will have a single `mosdns` executable in directory `build`.

# Todo

[ ] Create a wiki