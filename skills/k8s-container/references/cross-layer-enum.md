# 跨层枚举表

> 每进入一层，先按本表枚举到下一层的入口；只读优先，写/逃逸按宪法 §14 L4。
> 记录：当前层能力 → 目标层入口 → 回滚/清理。

| 当前层 | 枚举 | 下一层入口 | L 级提示 |
|---|---|---|---|
| 容器 | capabilities、mounts、hostPath、docker.sock、SA token、metadata、内核/运行时版本 | 逃逸 / 宿主 / K8s / 云 | 读取 L2；逃逸 L4 |
| Pod | RBAC、kubelet、etcd、admission、node | cluster-admin / node / 云 | 给自己 SA 的 RoleBinding L3-⚠️；目标/集群级 RBAC L4 |
| Node | 内核 CVE、SUID、服务、凭据、instance role | 内网 / 云 | 内核提权 L4 |
| 内网 | SMB/WinRM/LDAP/ADCS/信任 | 域控 / 森林 | 域控写 L4 |
| 云 | metadata、CI/CD secrets、OIDC、role | subscription / tenant | 控制面变更 L4 |

## 容器内快速判定

```bash
cat /.dockerenv 2>/dev/null; cat /proc/1/cgroup | head
cat /proc/self/status | grep -i cap
cat /proc/self/mountinfo | grep -Ei 'kube|docker|hostpath|overlay'
ls -l /var/run/secrets/kubernetes.io/serviceaccount/ 2>/dev/null
```

## 每层记录模板

| 当前层 | 入口 | 能力 | 证据 | 下一层 | 状态 |
|---|---|---|---|---|---|
| pod | /api/exec | 命令执行 | `evidence/src/...` | k8s API | confirmed |
