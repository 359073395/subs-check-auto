#!/usr/bin/env python3
"""
从 subs-check-pro 输出的可用节点中，剔除明文/低兼容/易被阻断节点，
按“IP 纯净度 + 国内线路友好度（CDN/TLS/Reality 优先）+ 下载速度”综合排序，
去重同源服务器后精选 Top 20，输出干净的 Mihomo / Base64 / YAML 订阅。
"""

from __future__ import annotations

import base64
import ipaddress
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
BAD_EXIT_RE = re.compile(r"YT-(?:IR|RU|CN|PK|EG)\b", re.IGNORECASE)
STD_TLS_PORTS = {443, 2053, 2083, 2087, 2096, 8443}


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


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

    if risk <= 10:
        tier = 0  # 极高纯净度 (0%-10%)
    elif risk <= 30:
        tier = 1  # 高纯净度 (11%-30%)
    elif risk <= 60:
        tier = 2  # 中等纯净度 (31%-60%)
    elif risk <= 100:
        tier = 3  # 一般风险 (61%-100%)
    else:
        tier = 4

    return tier, speed_kbps, risk


def is_allowed_proxy(p: dict[str, Any], strict: bool = True) -> bool:
    ptype = str(p.get("type", "")).lower()
    if ptype in {"http", "https", "socks5", "socks", "ss", "ssr"}:
        return False

    # vmess 必须开启 tls，避免明文被阻断
    if ptype == "vmess" and not p.get("tls"):
        return False

    # vless 非 reality 且未开启 tls 时跳过
    if ptype == "vless" and not p.get("tls") and not p.get("reality-opts"):
        return False

    name = str(p.get("name", ""))
    server = str(p.get("server", "")).lower().strip()
    sni = str(p.get("servername", "") or p.get("sni", "")).lower().strip()
    network = str(p.get("network", "tcp")).lower().strip()

    if not server:
        return False

    # 过滤伊朗/俄罗斯等高风险或跨区劣质出口
    if server.endswith((".ir", ".ru")) or sni.endswith((".ir", ".ru")):
        return False
    if BAD_EXIT_RE.search(name):
        return False

    if strict:
        # 剔除部分旧版 v2rayNG 不支持的实验性传输方式
        if network in {"xhttp", "splithttp"}:
            return False
        # 优先排除未知 IP 风险值的节点
        _, _, risk = parse_metrics(name)
        if risk > 100:
            return False

    return True


def china_friendliness_tier(p: dict[str, Any]) -> int:
    """国内网络穿透与客户端兼容性分级（越小越优）。"""
    ptype = str(p.get("type", "")).lower()
    network = str(p.get("network", "tcp")).lower().strip()
    server = str(p.get("server", "")).strip()
    has_tls = bool(p.get("tls"))
    has_reality = bool(p.get("reality-opts"))
    try:
        port = int(p.get("port", 0))
    except (TypeError, ValueError):
        port = 0

    # 0: 域名 CDN / WS / gRPC + TLS（国内直连抗封锁最稳）
    if has_tls and network in {"ws", "grpc"} and (not is_ip_literal(server) or port in STD_TLS_PORTS):
        return 0
    # 1: VLESS Reality 或标准端口 TLS Trojan/VLESS
    if (has_reality or (ptype in {"trojan", "vless"} and has_tls)) and port in STD_TLS_PORTS:
        return 1
    # 2: 其他 TLS 加密 TCP 节点
    if has_tls or has_reality:
        return 2
    # 3: Hysteria2 (UDP/QUIC，国内部分宽带/移动网络可能限速)
    return 3


def dedupe_and_rank(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ranked = sorted(
        candidates,
        key=lambda p: (
            parse_metrics(str(p.get("name", "")))[0],
            china_friendliness_tier(p),
            -parse_metrics(str(p.get("name", "")))[1],
            parse_metrics(str(p.get("name", "")))[2],
        ),
    )

    selected: list[dict[str, Any]] = []
    seen_servers: set[str] = set()
    for p in ranked:
        srv = str(p.get("server", "")).lower().strip()
        if srv in seen_servers:
            continue
        seen_servers.add(srv)
        selected.append(p)
        if len(selected) >= TOP_N:
            break
    return selected


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

    # 先按严格国内兼容性条件筛选
    strict_candidates = [p for p in proxies if isinstance(p, dict) and is_allowed_proxy(p, strict=True)]
    top_proxies = dedupe_and_rank(strict_candidates)

    # 若严格筛选不足 20 个，放宽部分传输/风险限制补充至 20 个
    if len(top_proxies) < TOP_N:
        relaxed_candidates = [p for p in proxies if isinstance(p, dict) and is_allowed_proxy(p, strict=False)]
        used_servers = {str(p.get("server", "")).lower().strip() for p in top_proxies}
        extra = [p for p in dedupe_and_rank(relaxed_candidates) if str(p.get("server", "")).lower().strip() not in used_servers]
        top_proxies.extend(extra[: TOP_N - len(top_proxies)])

    if not top_proxies:
        top_proxies = dedupe_and_rank([p for p in proxies if isinstance(p, dict)])

    top_names = [str(p.get("name", "")) for p in top_proxies]
    PUBLISH_DIR.mkdir(parents=True, exist_ok=True)

    (PUBLISH_DIR / "all.yaml").write_text(
        yaml.safe_dump({"proxies": top_proxies}, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )

    has_mihomo = filter_mihomo(top_proxies, OUTPUT_SUB_DIR / "mihomo.yaml", PUBLISH_DIR / "mihomo.yaml")
    has_base64 = filter_base64(top_names, OUTPUT_SUB_DIR / "base64.txt", PUBLISH_DIR / "base64.txt")

    beijing_tz = timezone(timedelta(hours=8))
    now_str = datetime.now(beijing_tz).strftime("%Y-%m-%d %H:%M:%S (北京时间)")
    lines = [
        "# 精选 Top 20 公益节点状态清单",
        "",
        f"- 最近更新时间：`{now_str}`",
        f"- 本轮通过初筛节点数：`{len(proxies)}`（过滤兼容后：`{len(strict_candidates)}`）",
        f"- 精选保留节点数：`{len(top_proxies)}`",
        f"- 已生成订阅：`all.yaml` / `mihomo.yaml` ({'已更新' if has_mihomo else '跳过'}) / `base64.txt` ({'已更新' if has_base64 else '跳过'})",
        "",
        "| 序号 | 节点名称 | 协议 | 纯净度(风险值) | 测速 |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ]
    for idx, p in enumerate(top_proxies, start=1):
        name = str(p.get("name", "未命名"))
        ptype = str(p.get("type", ""))
        _, speed_kbps, risk = parse_metrics(name)
        risk_str = f"{risk}%" if risk <= 100 else "未知"
        speed_str = f"{speed_kbps / 1024:.1f} MB/s" if speed_kbps >= 1024 else f"{speed_kbps:.0f} KB/s"
        safe_name = name.replace("|", "\\|")
        lines.append(f"| {idx} | {safe_name} | {ptype} | {risk_str} | {speed_str} |")

    (PUBLISH_DIR / "STATUS.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"精选完成：初筛 {len(proxies)} -> 兼容 {len(strict_candidates)} -> 精选 Top {len(top_proxies)}。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
