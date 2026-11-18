# 公益节点自动收集 · 纯净度精选 Top 20 订阅

基于 [sinspired/subs-check-pro](https://github.com/sinspired/subs-check-pro) 与 **GitHub Actions** 搭建，无需 VPS 服务器，**每 6 小时自动运行一次**。

## 筛选策略
1. 自动汇总 30+ 个 GitHub 高频更新公益节点池；
2. 对所有节点进行真连接测活、流媒体/基础解锁检测与 **IP 欺诈风险（纯净度）检测**；
3. 按 **IP 纯净度优先（低风险优先）+ 下载速度最快** 进行综合排序，只保留 **Top 20 最快最纯净节点**。

## 订阅链接（可直接复制到客户端）

* **Clash Verge / Mihomo / FlClash（含完整分流规则，最推荐）**：
  `https://raw.githubusercontent.com/359073395/subs-check-auto/main/subs/mihomo.yaml`

* **v2rayN / Shadowrocket / Nekobox（通用 Base64 订阅）**：
  `https://raw.githubusercontent.com/359073395/subs-check-auto/main/subs/base64.txt`

* **纯节点列表（YAML proxies）**：
  `https://raw.githubusercontent.com/359073395/subs-check-auto/main/subs/all.yaml`

* **查看最近一次测速与节点详情**：[subs/STATUS.md](./subs/STATUS.md)

## 绑定自己的域名（Cloudflare Workers 加速直连）
仓库已内置 [cloudflare-worker/worker.js](./cloudflare-worker/worker.js)，无需任何代码改动即可直接部署到 Cloudflare Workers 并绑定自定义域名（支持 `https://你的域名/mihomo.yaml`、`https://你的域名/base64.txt`、`https://你的域名/all.yaml`）。

## 如何手动立即更新一次？
1. 打开本仓库顶部的 **Actions** 标签页；
2. 点击左侧的 **自动采集测速并更新 Top 20 订阅**；
3. 点击右侧 **Run workflow** 按钮即可立即开始新一轮测速更新。
