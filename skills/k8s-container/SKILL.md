---
name: k8s-container
description: Kubernetes/容器黑盒渗透 — 从 Pod 立足点到容器逃逸、Node/宿主、集群管理员与云 metadata 的跨层路径；含 K8s API/kubelet/RBAC/SA token/逃逸/清理。
metadata:
  version: "0.1.0"
  entry: false
  requires: ["pentest-flow"]
  triggers:
    - "发现明确的 K8s 迹象：6443/10250 端口、kubeconfig、service account token、docker.sock、hostPath、集群域名/证书"
    - "拿到 Pod/容器执行能力，或确认运行在 K8s 工作负载中（cgroup/SA token/挂载特征）"
  layer: "skill"
  risk: "high"
  phase: "post-exploitation,exploitation"
  target_types: "kubernetes,container,cloud"
  task_types: "pentest"
  tooling: "kubehound,peirates,cdk,botb,kubeletctl,kubectl-who-can,kube-bench,kubescape,trivy"
---

# K8s / 容器渗透

<!-- BEGIN GENERATED PREAMBLE -->
> **前置**：本技能不构成授权依据。首次加载先读
> `../pentest-flow/references/constitution.md` §1–§8；产物写入 `Work/OC-<target>/`。
> 路由与门禁见 `../pentest-flow/SKILL.md`。
<!-- END GENERATED PREAMBLE -->

## 定位与边界

- 只做 K8s / 容器 / Node / 云 metadata 的跨层路径；Web/AD 方法仍走对应技能。
- 单点手法库在 `../pentest-flow/references/_shared/k8s/claude-red-k8s-attacks.md`（808 行）与 `claude-red-container-escape.md`（672 行）；**先看 `## 目录`，按节读，不整读**。
- 授权按宪法 §14；内核提权、逃逸、目标 RBAC、etcd、云控制面属 L4。

## 何时加载

两个触发任一命中即加载；仅「容器化应用」不算（几乎所有 Web 都在容器里）。与 `redteam-playbooks` 的分工：本技能是工作流与门禁，后者是单点手法库。

## 入口判定

先分清外部面与 Pod 内：外部看 6443/10250/dashboard/ingress/etcd；Pod 内看 SA token/mount/caps/网络。**先只读，后写**；写操作按 §14 分级。

## 阶段 1：外部面

- 6443 API：匿名访问、版本、证书、`/api`、`/apis`、`/version`。
- 10250 kubelet：匿名读 `/pods`、`/metrics`；写/exec 按 L4。
- 2379/2380 etcd：未授权读写按 L4。
- dashboard / ingress / metrics / 云 LB：默认口令与未授权。
- 命令与证据见 `references/external-surface.md`。

## 阶段 2：Pod 立足点

- SA token：`/var/run/secrets/kubernetes.io/serviceaccount/{token,ca.crt,namespace}`。
- env、mount、capabilities、seccomp/AppArmor、network、process、metadata。
- 命令与证据见 `references/pod-foothold.md`。

## 阶段 3：集群枚举

- `kubectl auth can-i --list`、`kubectl get`、`kubectl-who-can`、KubiScan、Peirates。
- 枚举结果写权限账本；只读 L3。
- 见 `references/cluster-enum.md`。

## 阶段 4：逃逸 / 提权

- capabilities、hostPath、privileged、docker.sock、hostPID/Network、内核/运行时 CVE、kubelet exec、etcd。
- 每条给证据与 L 级；利用按 L4。
- 见 `references/escape-and-privesc.md`。

## 阶段 5：Node / 云

- node root、container runtime socket、instance role、`100.100.100.200`/`169.254.169.254`、OIDC/workload identity。
- 读取 L2；用凭据改基础设施 L4。
- 见 `references/node-and-cloud.md`。

## 阶段 6：集群控制面

- RBAC bind、SA token、etcd、admission。
- 给自己的 SA 在自己 namespace 加/改 RoleBinding = L3-⚠️；目标/集群级 RBAC = L4。
- 见 `references/cluster-enum.md` 与 `escape-and-privesc.md`。

## 证据与清理

- 每阶段落盘：API 响应、manifest、token、mount/caps、node identity、cloud metadata。
- 创建对象立即记 `cleanup.md`；删除后 `kubectl get` 复测。
- 见 `references/evidence-and-cleanup.md`。

## 工具映射

信号→工具表见 `references/tool-map.md`。注意：kube-hunter 已停更、Havoc 已归档，不作为主路径。

## 停止条件

- 按 RoE `goal.highest_control` 停止；没有定义就先补。
- 不持久化除非授权；不为了「拿宿主」扩大爆破。

## 参考文件

- `references/external-surface.md`
- `references/cross-layer-enum.md`
- `references/pod-foothold.md`
- `references/cluster-enum.md`
- `references/escape-and-privesc.md`
- `references/node-and-cloud.md`
- `references/evidence-and-cleanup.md`
- `references/tool-map.md`
- `../pentest-flow/references/_shared/host/host-privesc.md`（宿主提权 + 容器→宿主 C1–C7）
- `../pentest-flow/references/_shared/k8s/claude-red-k8s-attacks.md`
- `../pentest-flow/references/_shared/k8s/claude-red-container-escape.md`
