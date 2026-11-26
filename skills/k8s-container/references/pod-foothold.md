# Pod 立足点

> 拿到 Pod/容器执行能力后，先只读枚举身份、挂载、能力与网络；写操作按 §14。
> 证据落 `evidence/src/`，token 脱敏。

## Service Account

```bash
ls -l /var/run/secrets/kubernetes.io/serviceaccount/
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
cat /var/run/secrets/kubernetes.io/serviceaccount/token | cut -c1-20   # 只留前缀记录
```

- token 用于 API 认证；只在授权范围内使用。
- 记录：namespace、SA 名、token 过期时间（JWT `exp`）、可用 API。

## 环境与挂载

```bash
env | sort
cat /proc/self/mountinfo | grep -Ei 'kube|secret|configmap|hostpath|docker|overlay'
findmnt -o TARGET,SOURCE,FSTYPE
ls -la /var/run/secrets /etc/kubernetes 2>/dev/null
```

关注：

- `hostPath`：宿主路径 → 可能写宿主（C7，L4）。
- ConfigMap/Secret 挂载：可能含凭据。
- `docker.sock` / `containerd.sock`：存在即高价值（L4）。

## Capabilities / 安全上下文

```bash
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)' /proc/self/status
cat /proc/1/status | grep -E 'Cap|Seccomp'
```

- 有 `CAP_SYS_ADMIN`、`CAP_SYS_PTRACE`、`CAP_NET_ADMIN` 等 → 逃逸候选（见 `escape-and-privesc.md`）。
- `Seccomp: 0`（未启用）也可能是条件。

## 网络与进程

```bash
ip addr; ip route; cat /etc/resolv.conf
ps auxww; ls -l /proc/*/exe 2>/dev/null | head
```

- 同 Pod 其他容器、service 网段、DNS 后缀（`*.svc.cluster.local`）。
- 宿主网络命名空间（hostNetwork）会直接暴露宿主端口。

## 元数据

```bash
curl -s --max-time 3 http://100.100.100.200/latest/meta-data/    # 阿里云
curl -s --max-time 3 http://169.254.169.254/latest/meta-data/    # 通用
```

- 只读；记录 instance-id、role、region；凭据使用按 `node-and-cloud.md`。

## 证据

- 身份（namespace/SA）、挂载表、caps、网络、进程、metadata 响应（脱敏）。
- 每项一行「来源 → 发现」；供权限账本引用。
