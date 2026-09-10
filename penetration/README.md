# Penetration 笔记索引

本目录用于整理渗透测试过程中常用的操作笔记、命令速查和环境搭建方法。文档统一采用以下结构：

- `概述`：说明适用场景和目标。
- `前置条件`：说明权限、环境或依赖。
- `操作步骤`：给出常用流程和命令。
- `注意事项`：记录容易踩坑的点。
- `参考`：保留外部资料链接。

## 信息收集与扫描

- [PEN-Info.md](./PEN-Info.md)：外网信息收集思路（含 fofa/鹰图语法、子域名枚举、JS 信息分析）。
- [PEN-Scanner.md](./PEN-Scanner.md)：端口扫描、指纹识别和目录爆破。

## 会话建立与代理转发

- [PEN-ReShell.md](./PEN-ReShell.md)：反弹/正向 Shell、多语言变体、TTY 升级（Python3）。
- [PEN-ssh.md](./PEN-ssh.md)：SSH 本地转发、远程转发、动态代理。
- [PEN-Tun2socks.md](./PEN-Tun2socks.md)：Windows 下使用 tun2socks 接管流量。
- [PEN-Openwrt.md](./PEN-Openwrt.md)：OpenWrt 网关代理方案。
- [PEN-Reuse.md](./PEN-Reuse.md)：端口复用和转发思路。
- [PEN-Tunnel.md](./PEN-Tunnel.md)：内网穿透工具（frp/nps/chisel/Neo-reGeorg 选型与配置）。

## 凭证与权限提升

- [PEN-GetHash.md](./PEN-GetHash.md)：Windows Hash 获取（mimikatz/ntdsutil/secretsdump/RunAsPPL/NTLM Relay）。
- [PEN-GetHash-Linux.md](./PEN-GetHash-Linux.md)：Linux 凭证获取（shadow 破解/SSH 私钥/配置搜索/内存提取）。
- [PEN-Win-LPE.md](./PEN-Win-LPE.md)：Windows 提权（Potato 家族/服务/UAC Bypass/内核漏洞速查）。
- [PEN-Setuid-Linux.md](./PEN-Setuid-Linux.md)：Linux SUID 原理与经典利用命令。
- [PEN-Linux-LPE.md](./PEN-Linux-LPE.md)：Linux 提权枚举（LinPEAS/pspy）、经典内核漏洞清单（DirtyCow/DirtyPipe/PwnKit 等）。

## 域渗透与横向移动

- [PEN-BloodHound.md](./PEN-BloodHound.md)：域信息收集、BloodHound 图谱分析与自定义 Cypher 查询。
- [PEN-Kerberos.md](./PEN-Kerberos.md)：Kerberos 攻击全集（Roasting/票据伪造/委派/MS14-068/ADCS/密码喷洒/NTLM Relay）。
- [PEN-Lateral.md](./PEN-Lateral.md)：内网横向移动（impacket 全家桶/PsExec/WMI/WinRM/RDP 与检测对抗）。

## 云上攻防

- [PEN-Cloud.md](./PEN-Cloud.md)：AKSK 利用、元数据服务、对象存储、Kubernetes 攻击面。

## 痕迹与运维辅助

- [PEN-LinuxClear.md](./PEN-LinuxClear.md)：Linux 痕迹清理（日志/journal/auditd/history/时间戳），配套脚本 [logtamper.py](./logtamper.py)。
- [PEN-WinClear.md](./PEN-WinClear.md)：Windows 事件日志、RDP、USN Journal 与执行痕迹清理。
- [PEN-WinCmd.md](./PEN-WinCmd.md)：Windows 常用命令（cmd + PowerShell 对应）。
- [PEN-MSF.md](./PEN-MSF.md)：Metasploit 与 Meterpreter（多平台载荷、migrate/hashdump/kiwi）。
- [PEN-C2.md](./PEN-C2.md)：C2 框架速查（CobaltStrike/Sliver/MSF 选型、流量对抗）。

## WebShell 与近源专题

- [PEN-Webshell-Question.md](./PEN-Webshell-Question.md)：WebShell 命令执行异常排查与 disable_functions 绕过。
- [Webshell-Bypass.md](./Webshell-Bypass.md)：WebShell 免杀实例（PHP/JSP）、流量特征对抗与落地检查清单。
- [PEN-WiFi-Tool.md](./PEN-WiFi-Tool.md)：近源渗透硬件和随身 Wi-Fi 改造。
