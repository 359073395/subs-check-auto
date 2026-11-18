#!/usr/bin/env python3
"""
从 subs-check-pro 输出的可用节点中，按“IP 纯净度优先 + 下载速度最快”
综合排序并精选 Top 20 节点，输出干净的 Clash/Mihomo、Base64 与通用 YAML 订阅。
"""

from __future__ import annotations

import base64
import json
import re
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

TOP_N = 20
OUTPUT_SUB_DIR = Path("output/sub")
PUBLISH_DIR = Path("subs")

SPEED_RE = re.compile(r"\|\s*([\d.]+)\s*(KB/s|MB/s)", re.IGNORECASE)
RISK_RE = re.compile(r"\|\s*(\d+)%")


def parse_metrics(name: str) -> tuple[int, float, int]:
    """返回 (纯净度等级, 下载速度KB/s, 风险百分比)。"""
    speed_kbps = 0.0
    m_speed = SPEED_RE.search(name)
    if m_speed:
        val = float(m_speed.group(1))
        unit = m_speed.group(2).upper()
        speed_kbps = val * 1024.0 if unit == "MB/S" else val

    risk = 999
    m_risk = RISK_RE.search(name)
    if m_risk:
        risk = int(m_risk.group(1))

    # 纯净度分级：同级别内按速度降序，确保“高纯净度 + 高速度”兼顾
    if risk <= 10:
        tier = 0  # 极高纯净度 (0%-10%)
    elif risk <= 30:
        tier = 1  # 高纯净度 (11%-30%)
    elif risk <= 60:
        tier = 2  # 中等纯净度 (31%-60%)
    elif risk <= 100:
        tier = 3  # 一般风险 (61%-100%)
    else:
        tier = 4  # 未检出风险值

    return tier, speed_kbps, risk


def extract_uri_name(uri: str) -> str:
    uri = uri.strip()
    if uri.startswith("vmess://"):
        payload = uri[len("vmess://") :]
        padded = payload + "=" * (-len(payload) % 4)
        try:
            data = json.loads(base64.b64decode(padded).decode("utf-8", errors="ignore"))
            return str(data.get("ps", "")).strip()
        except Exception:
            return ""
    if "#" in uri:
        return urllib.parse.unquote(uri.split("#", 1)[1]).strip()
    return ""


def filter_base64(top_names: list[str], src_path: Path, dst_path: Path) -> bool:
    if not src_path.exists():
        return False
    raw = src_path.read_text(encoding="utf-8", errors="ignore").strip()
    if not raw:
        return False

    padded = raw + "=" * (-len(raw) % 4)
    try:
        decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
    except Exception:
        decoded = raw

    uri_by_name: dict[str, str] = {}
    for line in decoded.splitlines():
        line = line.strip()
        if not line:
            continue
        name = extract_uri_name(line)
        if name and name not in uri_by_name:
            uri_by_name[name] = line

    selected_lines = [uri_by_name[n] for n in top_names if n in uri_by_name]
    if not selected_lines:
        return False

    joined = "\n".join(selected_lines)
    encoded = base64.b64encode(joined.encode("utf-8")).decode("ascii")
    dst_path.write_text(encoded + "\n", encoding="utf-8")
    return True


def filter_mihomo(top_proxies: list[dict[str, Any]], src_path: Path, dst_path: Path) -> bool:
    if not src_path.exists():
        return False
    data = yaml.safe_load(src_path.read_text(encoding="utf-8", errors="ignore"))
    if not isinstance(data, dict):
        return False

    top_names = [str(p.get("name", "")) for p in top_proxies]
    top_name_set = set(top_names)
    data["proxies"] = top_proxies

    groups = data.get("proxy-groups")
    if isinstance(groups, list):
        group_names = {g.get("name") for g in groups if isinstance(g, dict) and g.get("name")}
        builtins = {"DIRECT", "REJECT", "PASS", "COMPATIBLE"}
        for g in groups:
            if not isinstance(g, dict):
                continue
            plist = g.get("proxies")
            if isinstance(plist, list):
                filtered = [
                    item
                    for item in plist
                    if item in group_names or item in builtins or item in top_name_set
                ]
                if not filtered and not g.get("include-all"):
                    filtered = ["DIRECT"]
                g["proxies"] = filtered

    dst_path.write_text(
        yaml.safe_dump(data, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    return True


def main() -> int:
    all_yaml_path = OUTPUT_SUB_DIR / "all.yaml"
    if not all_yaml_path.exists():
        print("未找到 output/sub/all.yaml，跳过本轮精选。")
        return 0

    all_data = yaml.safe_load(all_yaml_path.read_text(encoding="utf-8", errors="ignore")) or {}
    proxies = all_data.get("proxies") or []
    if not proxies:
        print("本轮可用节点为空，保留已有订阅文件。")
        return 0

    ranked = sorted(
        proxies,
        key=lambda p: (
            parse_metrics(str(p.get("name", "")))[0],
            -parse_metrics(str(p.get("name", "")))[1],
            parse_metrics(str(p.get("name", "")))[2],
        ),
    )
    top_proxies = ranked[:TOP_N]
    top_names = [str(p.get("name", "")) for p in top_proxies]

    PUBLISH_DIR.mkdir(parents=True, exist_ok=True)

    # 1. 保存纯节点列表 all.yaml
    (PUBLISH_DIR / "all.yaml").write_text(
        yaml.safe_dump({"proxies": top_proxies}, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )

    # 2. 保存 Clash / Mihomo 完整分流配置 mihomo.yaml
    has_mihomo = filter_mihomo(top_proxies, OUTPUT_SUB_DIR / "mihomo.yaml", PUBLISH_DIR / "mihomo.yaml")

    # 3. 保存 v2rayN / 小火箭 Base64 通用订阅 base64.txt
    has_base64 = filter_base64(top_names, OUTPUT_SUB_DIR / "base64.txt", PUBLISH_DIR / "base64.txt")

    # 4. 生成中文节点状态清单
    beijing_tz = timezone(timedelta(hours=8))
    now_str = datetime.now(beijing_tz).strftime("%Y-%m-%d %H:%M:%S (北京时间)")
    lines = [
        "# 精选 Top 20 公益节点状态清单",
        "",
        f"- 最近更新时间：`{now_str}`",
        f"- 本轮通过初筛节点数：`{len(proxies)}`",
        f"- 精选保留节点数：`{len(top_proxies)}`",
        f"- 已生成订阅：`all.yaml` / `mihomo.yaml` ({'已更新' if has_mihomo else '跳过'}) / `base64.txt` ({'已更新' if has_base64 else '跳过'})",
        "",
        "| 序号 | 节点名称 | 纯净度(风险值) | 测速 |",
        "| :--- | :--- | :--- | :--- |",
    ]
    for idx, p in enumerate(top_proxies, start=1):
        name = str(p.get("name", "未命名"))
        _, speed_kbps, risk = parse_metrics(name)
        risk_str = f"{risk}%" if risk <= 100 else "未知"
        speed_str = f"{speed_kbps / 1024:.1f} MB/s" if speed_kbps >= 1024 else f"{speed_kbps:.0f} KB/s"
        safe_name = name.replace("|", "\\|")
        lines.append(f"| {idx} | {safe_name} | {risk_str} | {speed_str} |")

    (PUBLISH_DIR / "STATUS.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"精选完成：从 {len(proxies)} 个可用节点中选出 Top {len(top_proxies)}。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
