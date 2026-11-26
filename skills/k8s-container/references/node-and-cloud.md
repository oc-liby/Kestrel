# Node 与云

> Node/宿主与云控制面的只读枚举；凭据使用与基础设施变更按宪法 §14 L4。

## Node 层

```bash
# 从 Pod 内判断是否已到 Node（hostPID/hostNetwork/挂载）
hostname; cat /etc/hostname
ls -l /var/lib/kubelet /var/lib/docker /run/containerd 2>/dev/null
```

- Node root 后的枚举走 `../../pentest-flow/references/_shared/host/host-privesc.md`。
- 容器运行时 socket、kubelet 配置、静态 Pod manifest（`/etc/kubernetes/manifests`）。

## 云 metadata

```bash
# 阿里云
curl -s --max-time 3 http://100.100.100.200/latest/meta-data/
curl -s --max-time 3 http://100.100.100.200/latest/meta-data/ram/security-credentials/
# 通用
curl -s --max-time 3 http://169.254.169.254/latest/meta-data/
curl -s --max-time 3 -H 'Metadata-Flavor: Google' http://169.254.169.254/computeMetadata/v1/
```

- 只读：instance-id、region、role 名、临时凭据。
- 用凭据调云 API：只读枚举（L2/L3）；改基础设施（L4）。
- 记录：metadata 路径、响应字段、凭据来源与权限范围。

## OIDC / workload identity

- 检查 SA 注解（`eks.amazonaws.com/role-arn`、`azure.workload.identity/client-id`）。
- token 可换云角色 → 云 API；按 L4 使用。

## 云控制面

- 只读：列出实例/角色/策略/存储桶。
- 变更：安全组、IAM、快照、实例状态 → L4，需明确授权与回滚。
- 不做未授权写；不创建持久化资源。

## 证据

- metadata 响应、role/权限、云 API 返回、node identity。
- 每项一行「入口 → 发现 → 权限范围」。
