# 外部面：API / kubelet / etcd / dashboard

> 从集群外部或初始入口可达的只读面；写/exec 按宪法 §14 L4。
> 证据落 `evidence/src/`，保留原文。

## 6443 API Server

```bash
# 版本与匿名访问
curl -k https://<host>:6443/version
curl -k https://<host>:6443/api
curl -k https://<host>:6443/apis

# 匿名可读时枚举
curl -k https://<host>:6443/api/v1/namespaces
curl -k https://<host>:6443/api/v1/pods

# 证书
openssl s_client -connect <host>:6443 -servername <host> </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates
```

判定：

- 401/403 → 需要凭据；记录响应与 `WWW-Authenticate`。
- 200 → 匿名开放，按只读枚举；记录可读资源清单。
- 版本与证书 issuer 可判断发行版（k3s/RKE/ACK 等）。

## 10250 kubelet

```bash
curl -k https://<host>:10250/pods
curl -k https://<host>:10250/metrics
curl -k https://<host>:10250/healthz
```

- 匿名 `pods` 可读 → 泄露 Pod 名、镜像、挂载、环境变量线索。
- `run`/`exec` 端点属写操作，按 L4；先确认授权与回滚。
- 10255 只读端口（若开放）：`/pods`、`/metrics`。

## 2379 / 2380 etcd

```bash
curl -k https://<host>:2379/version
curl -k https://<host>:2379/v2/keys/   # v2 未授权时
```

- 未授权可读 → 数据面暴露（L4 读取内容也按敏感处理）。
- 写 etcd 属 L4；不要未授权写。

## Dashboard / Ingress / Metrics

- dashboard：默认口令、token 登录页、跳过登录的旧版本。
- ingress：`/` 路由、host 头枚举、后端 service 名。
- metrics-server / Prometheus：`/metrics`、`/api/v1/query`，可能泄露 namespace/service/pod 名。

## 云 LB / 域名

- 解析集群域名、证书 SAN、ingress 后端，推断托管 K8s（ACK/EKS/GKE）。
- 记录云厂商与区域；云 metadata 路径见 `node-and-cloud.md`。

## 证据

- 每项：URL、状态码、响应片段、证书 subject/issuer、版本。
- 写成「入口 → 结果」一行，便于权限账本引用。
