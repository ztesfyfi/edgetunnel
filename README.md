# edgetunnel · TLS Fingerprint Edition

本项目基于上游 [cmliu/edgetunnel](https://github.com/cmliu/edgetunnel) 重建，保留上游原始 Worker 代码为 `_worker-core.js`，由新的 `_worker.js` 在订阅响应层增加 TLS 指纹兼容处理。

## 新增功能

- VLESS + TLS、Trojan + TLS：自动检测实际提供的 TLS 证书，向 Xray/v2rayN 分享链接添加 `pcs`（完整证书 DER SHA-256）和 `vcn`（证书名称校验）。
- Sing-box 1.13+：默认添加 `certificate_public_key_sha256`（SPKI SHA-256，Base64）。
- Sing-box 1.15+：订阅 URL 加 `sbcert=1` 或 `sbver=1.15`，同时添加 `certificate_sha256` 和 SPKI 指纹。
- SS 保持原样；Clash、Surge 等不支持的格式不会强行加入指纹字段。
- 证书指纹写入 KV 缓存，默认 6 小时；订阅 URL 加 `refreshfp=1` 可强制刷新。
- 检测失败、证书过期或 SAN 不匹配时，保留原节点，不生成虚假指纹。

## 部署说明

本增强版由 `_worker.js` 导入同目录的 `_worker-core.js`，**部署时必须同时保留这两个文件**。不要只复制 `_worker.js` 到 Cloudflare Dashboard 编辑器。

- **Cloudflare Workers**：从仓库根目录使用 Wrangler 部署（`wrangler.toml` 的入口仍是 `_worker.js`）。
- **Cloudflare Pages + GitHub**：将仓库连接到 Pages，确保项目输出目录包含 `_worker.js` 和 `_worker-core.js`；Pages Advanced Mode 会构建模块入口。
- **Pages 手动上传**：上传仓库完整 ZIP，不要只上传单个 Worker 文件。

原项目要求的 KV 绑定仍然保留，绑定名称为 `KV`。

## 可选环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `TLSFP_API` | `https://networkcalc.com/api/security/certificate` | 实时 TLS 检测 API 基础地址，需兼容 NetworkCalc 的 JSON 格式 |
| `TLSFP_TTL` | `21600` | KV 缓存秒数，范围 60–86400 |

检测服务会收到待检测的公开域名。默认使用 NetworkCalc 实时 TLS 证书 API；Worker 自己不具备读取出站 TLS 握手证书的接口，因此由外部检测服务完成 TLS 握手，Worker 再本地计算两种 SHA-256。

## 指纹格式与版本

| 输出 | 哈希对象 | 格式 | 兼容范围 |
|---|---|---|---|
| Xray `pcs` | 完整 DER 证书 | 冒号分隔 Hex | Xray / v2rayN |
| Sing-box 默认 | SPKI 公钥结构 | Base64 | Sing-box 1.13+ |
| Sing-box `sbcert=1` | 完整 DER 证书 + SPKI | Base64 | Sing-box 1.15+ |

注意：完整证书 SHA-256 与 SPKI SHA-256 不是同一个哈希对象，不能相互转换或互换。

## 上游与许可证

- 上游项目：[cmliu/edgetunnel](https://github.com/cmliu/edgetunnel)
- 本增强版保留上游 GPL-2.0 许可证及原作者署名；请同时遵守上游许可证和第三方依赖/API 服务条款。
- 上游更新请先同步 `_worker-core.js`，不要覆盖本仓库的 `_worker.js` 指纹包装层。
