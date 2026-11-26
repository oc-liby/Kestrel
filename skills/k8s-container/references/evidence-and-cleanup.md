# 证据与清理

> 容器/K8s 交战的证据格式、脱敏与对象清理；与 `cleanup.md` 联动。

## 证据格式

每个动作落盘：

| 类型 | 内容 | 路径 |
|---|---|---|
| API 响应 | JSON 原文（脱敏） | `evidence/src/` |
| manifest | `kubectl get -o yaml` | `evidence/src/` |
| token | 前缀 + 来源 + 过期 | `evidence/src/`（不落全量） |
| 挂载/caps | mountinfo、CapEff、status | `evidence/src/` |
| node/云 | instance-id、role、metadata 字段 | `evidence/src/` |
| 路径 | 攻击路径导出（KubeHound/手工表） | `attack-path.md` 引用 |

脱敏：token 只留前 8 位；secret 只记 key；metadata 隐去 account/subscription 全量。

## 清理对象

- **Pod/Job/CronJob/Deployment/Service**：`kubectl delete` 后 `kubectl get` 确认 `NotFound`。
- **SA/Role/RoleBinding/ClusterRole/ClusterRoleBinding**：同上；ClusterRole 删除前确认非目标原有。
- **ConfigMap/Secret/PV/PVC/Ingress/NetworkPolicy**：记录创建参数与删除命令。
- **Node 侧**：临时文件、systemd unit、计划任务、镜像/快照。
- **云**：临时 IAM/密钥、安全组规则、实例/快照、OIDC 信任。

## 清理顺序

1. 先清目标残留（通道还在）——K8s 对象、Node 临时文件、云临时资源；
2. 再做证据归档（不依赖通道）；
3. 最后停隧道/删本地代理。

反序会把清理拖到通道失效之后，只能标 `blocked`。

## 复测与披露

- 删除后复测：`kubectl get <res> -n <ns>` 返回 NotFound；云 API 查询确认。
- 无法删除：标 `blocked`，写已尝试，`findings.md` 披露。
- 通道（WebShell/C2）按约定保留或移交；`retained` 写原因。
