#!/usr/bin/env python3
"""
从本轮采集结果筛选节点，复测真实导出链接后统一生成订阅。
云端只生成候选；本地必须提供独立 sing-box 内核并通过 HTTPS 复测。
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import ipaddress
import json
import re
import sys
import tempfile
import urllib.parse
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

from verify_nodes import read_links, link_name, outbound_from_uri, verify_links

OUTPUT_SUB_DIR = Path("output/sub")
PUBLISH_DIR = Path("subs")

SPEED_RE = re.compile(r"\|\s*([\d.]+)\s*(KB/s|MB/s)", re.IGNORECASE)
RISK_RE = re.compile(r"\|\s*(\d+)%")
BAD_EXIT_RE = re.compile(r"YT-(?:IR|RU|CN|PK|EG)\b", re.IGNORECASE)
COUNTRY_CODE_RE = re.compile(r"([A-Z]{2})(?=[¹²³⁰ˣ_\|\s]|$)")
STD_TLS_PORTS = {443, 2053, 2083, 2087, 2096, 8443}

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


def has_blocked_domain(p: dict[str, Any], local_mode: bool) -> bool:
    server = str(p.get("server", "")).lower().strip()
    sni = str(p.get("servername", "") or p.get("sni", "")).lower().strip()
    ws_host = get_ws_host(p).lower().strip()
    # 本地模式下如果已经实测跑通，仅屏蔽 .ir/.ru 域；云端模式屏蔽全部易被 SNI 阻断免费域名
    suffixes = (".ir", ".ru") if local_mode else BLOCKED_SNI_SUFFIXES
    for d in (server, sni, ws_host):
        if d and d.endswith(suffixes):
            return True
    return False


def is_allowed_proxy(p: dict[str, Any], strict: bool = True, local_mode: bool = False) -> bool:
    ptype = str(p.get("type", "")).lower()
    if ptype in {"http", "https", "socks5", "socks", "ssr"}:
        return False
    if not local_mode and ptype == "ss":
        return False

    if ptype == "vmess" and not p.get("tls") and not local_mode:
        return False

    if ptype == "vless" and not p.get("tls") and not p.get("reality-opts") and not local_mode:
        return False

    name = str(p.get("name", ""))
    server = str(p.get("server", "")).lower().strip()
    network = str(p.get("network", "tcp")).lower().strip()

    if not server:
        return False

    if not local_mode and has_blocked_domain(p, local_mode=False):
        return False

    if not local_mode and BAD_EXIT_RE.search(name):
        return False
    if ptype == "ss" and p.get("cipher") not in {
        "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
        "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
    }:
        return False

    # Compatibility exclusions apply even when IP-risk information is unknown.
    if network not in {"tcp", "raw", "ws", "grpc"}:
        return False
    if ptype not in {"ss", "vmess", "vless", "trojan", "hysteria2", "hy2"}:
        return False
    if strict:
        _, _, risk = parse_metrics(name)
        if risk > 100:
            return False

    return True


def china_friendliness_tier(p: dict[str, Any]) -> int:
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

    if has_tls and network in {"ws", "grpc"} and (not is_ip_literal(server) or is_cf_cdn_ip(server)):
        if sni or ws_host:
            return 0
    if has_reality and port in STD_TLS_PORTS:
        return 1
    if ptype in {"trojan", "vless"} and has_tls and port in STD_TLS_PORTS:
        return 2
    if has_tls or has_reality:
        return 3
    return 4


def dedupe_and_rank(candidates: list[dict[str, Any]], top_n: int, local_mode: bool) -> list[dict[str, Any]]:
    if local_mode:
        # 本地已实测真实连通性，直接按“IP 纯净度优先 + 测速最快”排序
        key_fn = lambda p: (
            parse_metrics(str(p.get("name", "")))[0],
            -parse_metrics(str(p.get("name", "")))[1],
            parse_metrics(str(p.get("name", "")))[2],
        )
    else:
        key_fn = lambda p: (
            parse_metrics(str(p.get("name", "")))[0],
            china_friendliness_tier(p),
            -parse_metrics(str(p.get("name", "")))[1],
            parse_metrics(str(p.get("name", "")))[2],
        )

    ranked = sorted(candidates, key=key_fn)

    selected: list[dict[str, Any]] = []
    seen_keys: set[str] = set()
    for p in ranked:
        key = server_dedupe_key(p)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        selected.append(p)
        if len(selected) >= top_n:
            break
    return selected




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




def build_mihomo(proxies: list[dict[str, Any]]) -> dict[str, Any]:
    """A standalone configuration that needs no remote templates or Geo databases."""
    names = [p["name"] for p in proxies]
    return {
        "mixed-port": 7890, "allow-lan": False, "mode": "rule", "log-level": "warning",
        "ipv6": False, "proxies": proxies,
        "proxy-groups": [
            {"name": "PROXY", "type": "select", "proxies": ["AUTO"] + names},
            {"name": "AUTO", "type": "url-test", "proxies": names,
             "url": "https://www.gstatic.com/generate_204", "interval": 300},
        ],
        "rules": ["IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
                  "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
                  "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
                  "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
                  "DOMAIN-SUFFIX,cn,DIRECT", "MATCH,PROXY"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--top", type=int, default=20)
    parser.add_argument("--local", action="store_true", help="verify exported links on this machine")
    parser.add_argument("--core", type=Path, help="sing-box executable; required for local publication")
    parser.add_argument("--input-dir", type=Path, default=OUTPUT_SUB_DIR)
    parser.add_argument("--publish-dir", type=Path)
    parser.add_argument("--started-at", type=float, required=True, help="collection start Unix timestamp")
    args = parser.parse_args()
    if args.top < 1:
        parser.error("--top must be positive")
    if args.local and not args.core:
        parser.error("--local requires --core; unverified links cannot be published")
    publish_dir = args.publish_dir or (PUBLISH_DIR if args.local else Path("output/cloud-candidates"))
    source_paths = [args.input_dir / "all.yaml", args.input_dir / "base64.txt"]
    for path in source_paths:
        if not path.is_file() or path.stat().st_mtime < args.started_at:
            print(f"FAILED: missing/stale current-run output: {path}")
            return 1

    all_data = yaml.safe_load(source_paths[0].read_text(encoding="utf-8-sig"))
    if not isinstance(all_data, dict) or not isinstance(all_data.get("proxies"), list):
        print("FAILED: malformed all.yaml")
        return 1
    proxies = all_data["proxies"]
    uri_by_name = {}
    for uri in read_links(source_paths[1]):
        name = link_name(uri)
        if name in uri_by_name:
            print("FAILED: ambiguous duplicate share-link name")
            return 1
        uri_by_name[name] = uri
    candidates = []
    seen_names = set()
    for original in proxies:
        if not isinstance(original, dict):
            continue
        name = str(original.get("name", ""))
        if name in seen_names:
            print("FAILED: ambiguous duplicate YAML proxy name")
            return 1
        seen_names.add(name)
        if not is_allowed_proxy(original, strict=False, local_mode=args.local) or name not in uri_by_name:
            continue
        p = copy.deepcopy(original)
        uri = uri_by_name[name]
        # Normalize equivalent raw/tcp spelling before, rather than after, verification.
        if p.get("network") == "raw":
            p["network"] = "tcp"
            u = urllib.parse.urlsplit(uri)
            q = [(key, "tcp" if key == "type" and value == "raw" else value)
                 for key, value in urllib.parse.parse_qsl(u.query, keep_blank_values=True)]
            uri = urllib.parse.urlunsplit(u._replace(query=urllib.parse.urlencode(q)))
        try:
            outbound = outbound_from_uri(uri)
            kind = {"shadowsocks": "ss", "hy2": "hysteria2"}.get(outbound["type"], outbound["type"])
            p_kind = "hysteria2" if p["type"] == "hy2" else p["type"]
            identity = "uuid" if p_kind in {"vless", "vmess"} else "password"
            if (kind != p_kind or str(outbound["server"]).lower() != str(p["server"]).lower()
                    or outbound["server_port"] != int(p["port"])
                    or str(outbound[identity]) != str(p[identity])):
                continue
        except (KeyError, TypeError, ValueError):
            continue
        uri_by_name[name] = uri
        candidates.append(p)
    ranked = dedupe_and_rank(candidates, max(len(candidates), 1), local_mode=args.local)
    reports = []
    passed = []
    if args.local:
        # Test the exact share links, with a separate core and no DIRECT fallback.
        # Continue through ranked batches so failures never displace working links.
        for start in range(0, len(ranked), 6):
            batch = ranked[start:start + 6]
            checks = verify_links([uri_by_name[p["name"]] for p in batch], args.core)
            reports.extend(checks)
            for p, check in zip(batch, checks):
                print(p["name"], "PASS" if check["ok"] else "FAIL: " + check.get("error", "verification failed"), flush=True)
                if check["ok"]:
                    passed.append((p, check))
            if len(passed) >= args.top:
                break
    else:
        passed = [(p, None) for p in ranked]
    if args.local:
        (args.input_dir.parent / "verification_attempt.json").write_text(
            json.dumps(reports, ensure_ascii=False, indent=2), encoding="utf-8")
    if not passed:
        print("FAILED: no exported links passed; published subscriptions were not updated")
        return 1
    passed = passed[:args.top]

    country_counter = defaultdict(int)
    top_proxies = []
    links = []
    public_checks = []
    stats_rows = []
    for p, check in passed:
        original = p["name"]
        code = extract_country_code(original)
        country_counter[code] += 1
        clean = f"{code} {country_counter[code]:02d}"
        p["name"] = clean
        uri = rename_uri(uri_by_name[original], clean)
        top_proxies.append(p)
        links.append(uri)
        _, speed, risk = parse_metrics(original)
        stats_rows.append((clean, p["type"], f"{risk}%" if risk <= 100 else "未知", f"{speed / 1024:.2f} MB/s"))
        if check:
            public_checks.append({**check, "name": clean,
                "link_sha256": hashlib.sha256(uri.encode()).hexdigest()})
    encoded = base64.b64encode("\n".join(links).encode()).decode() + "\n"
    now = datetime.now(timezone(timedelta(hours=8)))
    source = "本机 sing-box 导出链接复测" if args.local else "GitHub 云端候选（未经本地复测）"
    lines = [
        f"# 公益节点状态清单（{len(top_proxies)} 条）", "",
        f"- 检测来源：{source}",
        f"- 最近更新时间：{now:%Y-%m-%d %H:%M:%S}（北京时间）",
        f"- 采集初筛：{len(proxies)}；兼容候选：{len(candidates)}；最终保留：{len(top_proxies)}",
        "- 发布条件：独立内核通过两次 Google HTTPS 204 和一次 Cloudflare HTTPS 出口检查。" if args.local
        else "- 此目录仅保存云端候选，不能覆盖正式订阅。",
        "- 结果仅代表检测当时的本机网络；公益节点可能随时失效。",
        "- Mihomo 使用无需远程数据库的基础分流；v2rayN / Shadowrocket 使用 base64.txt。", "",
        "| 节点 | 协议 | IP 风险参考 | 采集测速参考 |",
        "| --- | --- | --- | --- |",
    ]
    lines.extend(f"| {name} | {kind} | {risk} | {speed} |" for name, kind, risk, speed in stats_rows)
    verification = {"checked_at": now.isoformat(), "collection_started_at": args.started_at,
                    "source": source, "verified": args.local, "count": len(top_proxies),
                    "tested_count": len(reports), "nodes": public_checks,
                    "subscription_sha256": hashlib.sha256(encoded.encode()).hexdigest()}
    # Build and validate the complete set before replacing any published file.
    publish_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="subs-stage-") as tmp:
        stage = Path(tmp)
        (stage / "all.yaml").write_text(yaml.safe_dump({"proxies": top_proxies}, allow_unicode=True, sort_keys=False), encoding="utf-8", newline="\n")
        (stage / "mihomo.yaml").write_text(yaml.safe_dump(build_mihomo(top_proxies), allow_unicode=True, sort_keys=False), encoding="utf-8", newline="\n")
        (stage / "base64.txt").write_text(encoded, encoding="utf-8", newline="\n")
        (stage / "STATUS.md").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
        (stage / "verification.json").write_text(json.dumps(verification, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
        if len(read_links(stage / "base64.txt")) != len(top_proxies):
            raise ValueError("subscription count mismatch")
        for path in stage.iterdir():
            # Same-directory replace is atomic for each file.
            temporary = publish_dir / (path.name + ".tmp")
            temporary.write_bytes(path.read_bytes())
            temporary.replace(publish_dir / path.name)
    print(f"Generated {len(top_proxies)} {source} nodes in {publish_dir}")
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
