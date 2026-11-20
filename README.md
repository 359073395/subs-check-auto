# 公益节点采集与本地复测

本项目从公开订阅采集候选，再从运行电脑的网络复测真实导出链接。v2rayN 和 Shadowrocket 请导入 **Base64 订阅**。

## 当前订阅

- [v2rayN / Shadowrocket：base64.txt](https://raw.githubusercontent.com/359073395/subs-check-auto/main/subs/base64.txt)
- [Mihomo 基础分流配置：mihomo.yaml](https://raw.githubusercontent.com/359073395/subs-check-auto/main/subs/mihomo.yaml)
- [纯节点 YAML：all.yaml](https://raw.githubusercontent.com/359073395/subs-check-auto/main/subs/all.yaml)
- [最近检测状态](subs/STATUS.md)

请先看检测时间。公网公益节点可能迅速失效；IP 风险分数和云端测速不能证明泉州电信可用。Cloudflare Worker 只加速订阅文件下载，不改变节点线路。

## Windows 本机更新

双击 **双击本地测速并更新云端.bat**。也可执行：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/run_local.ps1
```

仅生成本地文件、不推送：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/run_local.ps1 -NoPush
```

脚本需要 Git、Python 3.10+。会优先使用项目虚拟环境或本机 Codex 附带的 Python，依赖安装在项目的 `.venv`；缺少解释器时明确报错。检测内核下载到 `bin/`。采集最多等待 20 分钟，随后逐条复测。

流程：

1. 每轮在独立的 `output/runs/<时间编号>/` 目录采集，保留日志。
2. 必须收到本轮完成信号，且初筛节点数大于零。
3. 将 Base64 中的实际分享链接交给独立 sing-box 内核，逐条执行两次 Google HTTPS 204 与一次 Cloudflare HTTPS 出口检查。验证进程不使用系统代理或 DIRECT 回退。
4. 仅保留通过复测的节点，统一生成三种订阅及 `verification.json`。不兼容节点不会为了凑数量而重新加入；数量可以少于 20。
5. 校验成功后才推送 `subs/`。超时、提前退出、旧文件、缺少链接或全部复测失败均会停止，已有订阅不会被改写成“新检测成功”。

下载订阅源、程序与推送 Git 可以使用本机已有代理；节点连通性由独立进程验证。检测期间请关闭客户端的 TUN 或路由器透明代理，以便结果代表本机直连线路。

## GitHub Actions

云端工作流只生成 **候选与日志附件**，不会覆盖正式 `subs/`。美国机房的测试结果不能代替国内运营商线路实测。目前没有每 6 小时自动发布任务。

在 Actions 手动运行“云端采集候选（不覆盖本地订阅）”，结束后下载 `cloud-candidates` 附件。正式更新仍需从使用节点的网络运行本机脚本。

## 检测与开发

```powershell
.venv/Scripts/python.exe -m unittest discover -s tests -v
.venv/Scripts/python.exe scripts/verify_nodes.py --core bin/sing-box.exe
```

独立复测报告默认位于 `output/verification.json`。报告会记录每条实际导出链接的通过状态；成功发布的 `subs/verification.json` 还记录订阅摘要和检测时间。

## 自定义域名

[cloudflare-worker/worker.js](cloudflare-worker/worker.js) 可部署到 Cloudflare Workers，代理 `/base64.txt`、`/mihomo.yaml`、`/all.yaml` 与 `/status`。修改 Worker 后需重新部署，客户端也需手动更新订阅。
