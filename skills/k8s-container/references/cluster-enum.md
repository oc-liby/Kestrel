# 集群枚举

> 用 SA token 做只读枚举；结果写权限账本。写 RBAC 按 §14（自己 SA 的 RoleBinding L3-⚠️；目标/集群级 L4）。

## 身份与权限

```bash
kubectl auth whoami
kubectl auth can-i --list
kubectl auth can-i --list --as=system:serviceaccount:<ns>:<sa>
kubectl get clusterroles,clusterrolebindings -o wide
```

- `can-i --list` 直接给出当前身份能做什么；按资源/动词整理成表。
- 记录：可读 Secret、可 exec Pod、可创建 workload、可改 RBAC。

## 资源枚举

```bash
kubectl get ns
kubectl get pods -A -o wide
kubectl get svc -A
kubectl get secrets -A
kubectl get sa -A
kubectl get nodes -o wide
kubectl get pv,pvc -A
kubectl get ingress -A
```

- `get secrets` 成功 → 读取价值高；脱敏记录 key，不落明文。
- `nodes -o wide` 给宿主机 IP/主机名，衔接 `node-and-cloud.md`。

## 工具

| 工具 | 用途 | 注意 |
|---|---|---|
| `kubectl-who-can` | 谁对某资源有权限 | 只读 |
| KubiScan | 枚举高风险 RBAC | 只读；规则可能过时 |
| Peirates | 一站式枚举 + 利用 | 利用动作按 L4 |
| KubeHound | 集群攻击图 | 需 collector/JanusGraph；不可用时手工表 |

## 权限账本映射

每发现一个身份/凭据，追加一行：

| 身份/凭据 | 类型 | 来源 | 可达范围 | 当前层 | 权限 | 证据 | 状态 | 下一步 |
|---|---|---|---|---|---|---|---|---|
| default SA | K8s token | /var/run/secrets/... | namespace X | pod | list pods | `evidence/src/sa.json` | confirmed | 查 RBAC |
| clusterrole X | RBAC | get clusterroles | 全集群 | k8s | * (get/list) | `evidence/src/cr.json` | confirmed | 找绑定主体 |

## 注意

- 只读优先；不为了枚举创建对象。
- Secret/token 不落明文；记录 key 与来源。
- 发现集群管理员级权限时，先确认 RoE `highest_control` 与停止条件。
