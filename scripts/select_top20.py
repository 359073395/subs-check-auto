#!/usr/bin/env python3
"""
从 subs-check-pro 输出的可用节点中：
1. 剔除明文协议、易被阻断协议（http/socks5/ss/非TLS vmess）与异常出口；
2. 剔除在国内大概率触发 SNI 阻断的公开免费域名（pages.dev/workers.dev/dpdns.org/de5.net 等）；
3. 按 IP 纯净度 + 协议稳定性（独立域名 CDN/TLS、VLESS Reality、Trojan）+ 速度精选 Top 100；
4. 按 IP/网段去重，避免同机房节点占满名额，并将名称简化为纯国家简写（如 US 01、SG 01）。
"""

from __future__ import annotations

import base64
import ipaddress
import json
import re
import urllib.parse
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

TOP_N = 100
OUTPUT_SUB_DIR = Path("output/sub")
PUBLISH_DIR = Path("subs")

SPEED_RE = re.compile(r"\|\s*([\d.]+)\s*(KB/s|MB/s)", re.IGNORECASE)
RISK_RE = re.compile(r"\|\s*(\d+)%")
BAD_EXIT_RE = re.compile(r"YT-(?:IR|RU|CN|PK|EG)\b", re.IGNORECASE)
COUNTRY_CODE_RE = re.compile(r"([A-Z]{2})(?=[¹²³⁰ˣ_\|\s]|$)")
STD_TLS_PORTS = {443, 2053, 2083, 2087, 2096, 8443}

# 在国内实测大面积被 SNI 重置/阻断的公开免费代理域名后缀
BLOCKED_SNI_SUFFIXES = (
    ".pages.dev",
    ".workers.dev",
    ".dpdns.org",
    ".de5.net",
    ".qzz.io",
    ".eu.cc",
    ".us.ci",
    ".ir",
    ".ru",
)

# Cloudflare 常见 Anycast 与 SaaS CDN IPv4 网段
CF_CIDRS = [
    ipaddress.ip_network(c)
    for c in (
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "172.64.0.0/13",
        "131.0.72.0/22",
        "8.34.0.0/15",
        "141.193.213.0/24",
    )
]


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def is_cf_cdn_ip(host: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(ip_obj in net for net in CF_CIDRS)


def get_ws_host(p: dict[str, Any]) -> str:
    ws_opts = p.get("ws-opts")
    if isinstance(ws_opts, dict):
        headers = ws_opts.get("headers")
        if isinstance(headers, dict):
            return str(headers.get("Host") or headers.get("host") or "").strip()
    return ""


def server_dedupe_key(p: dict[str, Any]) -> str:
    srv = str(p.get("server", "")).lower().strip()
    sni = str(p.get("servername", "") or p.get("sni", "")).lower().strip()
    if is_cf_cdn_ip(srv):
        return f"cf:{srv}:{sni}"
    if is_ip_literal(srv):
        parts = srv.split(".")
        if len(parts) == 4:
            return ".".join(parts[:3]) + ".0/24"
    return srv


def extract_country_code(name: str) -> str:
    head = name.split("|", 1)[0]
    m = COUNTRY_CODE_RE.search(head)
    if m:
        return m.group(1)
    return "GL"


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
        tier = 0
    elif risk <= 30:
        tier = 1
    elif risk <= 60:
        tier = 2
    elif risk <= 100:
        tier = 3
    else:
        tier = 4

    return tier, speed_kbps, risk


def has_blocked_domain(p: dict[str, Any]) -> bool:
    server = str(p.get("server", "")).lower().strip()
    sni = str(p.get("servername", "") or p.get("sni", "")).lower().strip()
    ws_host = get_ws_host(p).lower().strip()
    for d in (server, sni, ws_host):
        if d and d.endswith(BLOCKED_SNI_SUFFIXES):
            return True
    return False


def is_allowed_proxy(p: dict[str, Any], strict: bool = True) -> bool:
    ptype = str(p.get("type", "")).lower()
    if ptype in {"http", "https", "socks5", "socks", "ss", "ssr"}:
        return False

    if ptype == "vmess" and not p.get("tls"):
        return False

    if ptype == "vless" and not p.get("tls") and not p.get("reality-opts"):
        return False

    name = str(p.get("name", ""))
    server = str(p.get("server", "")).lower().strip()
    network = str(p.get("network", "tcp")).lower().strip()

    if not server:
        return False

    if has_blocked_domain(p):
        return False

    if BAD_EXIT_RE.search(name):
        return False

    if strict:
        if network in {"xhttp", "splithttp"}:
            return False
        _, _, risk = parse_metrics(name)
        if risk > 100:
            return False

    return True


def china_friendliness_tier(p: dict[str, Any]) -> int:
    """国内抗封锁与协议兼容性分级（越小越优先）。"""
    ptype = str(p.get("type", "")).lower()
    network = str(p.get("network", "tcp")).lower().strip()
    server = str(p.get("server", "")).strip()
    sni = str(p.get("servername", "") or p.get("sni", "")).lower().strip()
    ws_host = get_ws_host(p).lower()
    has_tls = bool(p.get("tls"))
    has_reality = bool(p.get("reality-opts"))
    try:
        port = int(p.get("port", 0))
    except (TypeError, ValueError):
        port = 0

    # 0: 独立自定义域名的 WS/gRPC + TLS（非免费子域，走 CDN/TLS 抗封锁稳）
    if has_tls and network in {"ws", "grpc"} and (not is_ip_literal(server) or is_cf_cdn_ip(server)):
        if sni or ws_host:
            return 0

    # 1: VLESS Reality（标准端口，不暴露敏感免费域名）
    if has_reality and port in STD_TLS_PORTS:
        return 1

    # 2: 标准端口 Trojan TLS / VLESS TLS
    if ptype in {"trojan", "vless"} and has_tls and port in STD_TLS_PORTS:
        return 2

    # 3: 其他 TLS / Reality 节点
    if has_tls or has_reality:
        return 3

    # 4: Hysteria2
    return 4


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
    seen_keys: set[str] = set()
    for p in ranked:
        key = server_dedupe_key(p)
        if key in seen_keys:
            continue
        seen_keys.add(key)
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


def rename_uri(uri: str, new_name: str) -> str:
    uri = uri.strip()
    if uri.startswith("vmess://"):
        payload = uri[len("vmess://") :]
        padded = payload + "=" * (-len(payload) % 4)
        try:
            data = json.loads(base64.b64decode(padded).decode("utf-8", errors="ignore"))
            data["ps"] = new_name
            encoded = base64.b64encode(
                json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            ).decode("ascii")
            return f"vmess://{encoded}"
        except Exception:
            return uri
    base_part = uri.split("#", 1)[0]
    return f"{base_part}#{urllib.parse.quote(new_name)}"


def filter_and_rename_base64(name_pairs: list[tuple[str, str]], src_path: Path, dst_path: Path) -> bool:
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

    selected_lines = [rename_uri(uri_by_name[orig], clean) for orig, clean in name_pairs if orig in uri_by_name]
    if not selected_lines:
        return False

    joined = "\n".join(selected_lines)
    encoded = base64.b64encode(joined.encode("utf-8")).decode("ascii")
    dst_path.write_text(encoded + "\n", encoding="utf-8")
    return True


def filter_mihomo(top_proxies: list[dict[str, Any]], orig_to_clean: dict[str, str], src_path: Path, dst_path: Path) -> bool:
    if not src_path.exists():
        return False
    data = yaml.safe_load(src_path.read_text(encoding="utf-8", errors="ignore"))
    if not isinstance(data, dict):
        return False

    clean_name_set = {str(p.get("name", "")) for p in top_proxies}
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
                filtered = []
                for item in plist:
                    if item in group_names or item in builtins:
                        filtered.append(item)
                    elif item in orig_to_clean:
                        filtered.append(orig_to_clean[item])
                    elif item in clean_name_set:
                        filtered.append(item)
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

    strict_candidates = [p for p in proxies if isinstance(p, dict) and is_allowed_proxy(p, strict=True)]
    top_proxies = dedupe_and_rank(strict_candidates)

    if len(top_proxies) < TOP_N:
        relaxed_candidates = [p for p in proxies if isinstance(p, dict) and is_allowed_proxy(p, strict=False)]
        used_keys = {server_dedupe_key(p) for p in top_proxies}
        extra = [p for p in dedupe_and_rank(relaxed_candidates) if server_dedupe_key(p) not in used_keys]
        top_proxies.extend(extra[: TOP_N - len(top_proxies)])

    if not top_proxies:
        top_proxies = dedupe_and_rank([p for p in proxies if isinstance(p, dict)])

    country_counter: dict[str, int] = defaultdict(int)
    name_pairs: list[tuple[str, str]] = []
    orig_to_clean: dict[str, str] = {}
    stats_rows: list[tuple[str, str, str, str, str]] = []

    for p in top_proxies:
        orig_name = str(p.get("name", ""))
        code = extract_country_code(orig_name)
        country_counter[code] += 1
        clean_name = f"{code} {country_counter[code]:02d}"

        p["name"] = clean_name
        name_pairs.append((orig_name, clean_name))
        orig_to_clean[orig_name] = clean_name

        ptype = str(p.get("type", ""))
        _, speed_kbps, risk = parse_metrics(orig_name)
        risk_str = f"{risk}%" if risk <= 100 else "未知"
        speed_str = f"{speed_kbps / 1024:.1f} MB/s" if speed_kbps >= 1024 else f"{speed_kbps:.0f} KB/s"
        tier = china_friendliness_tier(p)
        mode_tag = "CDN/TLS" if tier == 0 else ("Reality" if tier == 1 else "TLS/其他")
        stats_rows.append((clean_name, ptype, mode_tag, risk_str, speed_str))

    PUBLISH_DIR.mkdir(parents=True, exist_ok=True)

    (PUBLISH_DIR / "all.yaml").write_text(
        yaml.safe_dump({"proxies": top_proxies}, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )

    has_mihomo = filter_mihomo(top_proxies, orig_to_clean, OUTPUT_SUB_DIR / "mihomo.yaml", PUBLISH_DIR / "mihomo.yaml")
    has_base64 = filter_and_rename_base64(name_pairs, OUTPUT_SUB_DIR / "base64.txt", PUBLISH_DIR / "base64.txt")

    beijing_tz = timezone(timedelta(hours=8))
    now_str = datetime.now(beijing_tz).strftime("%Y-%m-%d %H:%M:%S (北京时间)")
    lines = [
        "# 精选公益节点状态清单 (Top 100)",
        "",
        f"- 最近更新时间：`{now_str}`",
        f"- 本轮通过初筛节点数：`{len(proxies)}`（剔除被阻断免费域名后：`{len(strict_candidates)}`）",
        f"- 精选保留节点数：`{len(top_proxies)}`",
        f"- 已生成订阅：`all.yaml` / `mihomo.yaml` ({'已更新' if has_mihomo else '跳过'}) / `base64.txt` ({'已更新' if has_base64 else '跳过'})",
        "",
        "| 序号 | 节点名称 | 协议 | 类型 | 纯净度(风险值) | 测速 |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ]
    for idx, (clean_name, ptype, mode_tag, risk_str, speed_str) in enumerate(stats_rows, start=1):
        lines.append(f"| {idx} | {clean_name} | {ptype} | {mode_tag} | {risk_str} | {speed_str} |")

    (PUBLISH_DIR / "STATUS.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"精选完成：初筛 {len(proxies)} -> 过滤后 {len(strict_candidates)} -> 精选 Top {len(top_proxies)}。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
