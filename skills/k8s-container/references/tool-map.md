# 工具映射

> 信号 → 首选 → 备选/注意。工具是线索，不是结论；结果按宪法 §11 证据标准。

| 信号 | 首选 | 备选 / 注意 |
|---|---|---|
| 6443 API | `kubectl auth can-i --list`、`kubectl-who-can`、KubiScan | 匿名先试；不写 |
| 10250 kubelet | Kubeletctl、Peirates | 只读 exec 先确认 |
| SA token | Peirates、kubectl | 记录来源与用途 |
| docker.sock | CDK、BotB、Deepce | 容器逃逸 L4 |
| privileged/hostPath | CDK、BotB、手工 mount | 先记录 mount/caps |
| 内核/运行时版本 | CDK evaluate、searchsploit、cve-triage | 不盲打 PoC |
| RBAC 风险 | KubiScan、kubectl-who-can | 只读 |
| 集群攻击图 | KubeHound（需 collector/JanusGraph） | 不可用时手工表 + kubectl |
| 镜像/配置 | Trivy、Kubescape、kube-bench | kube-hunter 已归档，不作主路径 |
| Node/云 | metadata、云 CLI、CloudFox、ROADtools | 只在授权范围 |
| AD/身份 | BloodHound、Certipy（若云身份） | 不在本技能展开 |

## 状态说明

- `kube-hunter`：已停更；仅作历史参考。
- `Havoc`：已归档；不推荐。
- KubeHound 与同名论文不是同一工具；引用时注意。

## 安装与授权

- 工具缺失按 `pentest-flow` 的获取顺序安装；优先系统包/镜像源。
- 安装只影响工作机，不改变对目标的 L* 授权；对目标执行仍按 §14。
