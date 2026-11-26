# 逃逸与提权

> 每条路径给：前置检查、利用方式、证据、L 级、清理。利用按宪法 §14 L4。
> 单点 payload 见 `../../pentest-flow/references/_shared/k8s/claude-red-container-escape.md`（按节读）。

## capabilities

```bash
grep -E 'CapEff|CapPrm|CapBnd' /proc/self/status
capsh --decode=$(grep CapEff /proc/self/status | awk '{print $2}')
```

- `CAP_SYS_ADMIN`：mount/cgroup 逃逸候选。
- `CAP_SYS_PTRACE`：注入宿主进程（若共享 PID namespace）。
- `CAP_NET_ADMIN`：网络路径操作。
- 验证前先记录当前 caps；利用失败即停，不反复试。

## hostPath

```bash
cat /proc/self/mountinfo | grep -Ei 'hostpath|/var/lib|/etc|/home|/data'
```

- 可写宿主路径 → 写宿主文件（C7，L4）；优先评估宿主侧是否有服务读取该目录。
- 只读挂载 → 读宿主敏感文件（凭据/配置），按 L2/L3。

## privileged / hostPID / hostNetwork

- privileged：`cat /proc/self/status | grep CapEff` 全 1；设备访问 → 逃逸候选。
- hostPID：`ps aux` 能看到宿主进程 → 注入/读环境。
- hostNetwork：直接访问宿主端口与 metadata。
- 判定后记录证据；利用 L4。

## docker.sock / containerd.sock

```bash
ls -l /var/run/docker.sock /run/containerd/containerd.sock 2>/dev/null
```

- 存在且可写 → 创建 privileged 容器挂载宿主根（L4）。
- 先用 `docker version`/`crictl version` 确认 socket 有效，再决定是否利用。

## 内核与运行时

```bash
uname -r
runc --version 2>/dev/null; containerd --version 2>/dev/null; docker --version 2>/dev/null
```

- 对照公开 CVE（如 runc 逃逸、内核本地提权）；版本不确定 → 不盲打。
- 利用按 L4；先记录版本与判定依据。

## kubelet exec / etcd

- kubelet 10250 `run`/`exec`：能 exec 到其他 Pod → 横向；L4。
- etcd 未授权：读数据面（敏感）；写 L4。

## 通用注意

- 每条路径先只读确认，再申请/执行 L4。
- 失败 3 次换路径；不重复同一 payload。
- 清理：创建的容器/文件/服务记 `cleanup.md`；删除后复测。
