#!/usr/bin/env python3
"""Verify the actual exported share links with an isolated sing-box process.

No system proxy, routing rules, DIRECT fallback, or global client settings are used.
Unsupported share-link features fail closed rather than being silently discarded.
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures
import ipaddress
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse


def decode64(value: str) -> str:
    return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_").decode("utf-8")


def read_links(path: Path) -> list[str]:
    raw = path.read_text(encoding="utf-8-sig").strip()
    decoded = raw if "://" in raw else decode64("".join(raw.split()))
    return [line.strip() for line in decoded.splitlines() if line.strip()]


def link_name(uri: str) -> str:
    if uri.startswith("vmess://"):
        return str(json.loads(decode64(uri[8:])).get("ps", ""))
    return urllib.parse.unquote(urllib.parse.urlsplit(uri).fragment)


def outbound_from_uri(uri: str) -> dict:
    u = urllib.parse.urlsplit(uri)
    q = dict(urllib.parse.parse_qsl(u.query, keep_blank_values=True))
    kind = u.scheme.lower()
    if kind == "vmess":
        v = json.loads(decode64(uri[8:]))
        if v.get("type") not in (None, "", "none") or v.get("packetEncoding"):
            raise ValueError("unsupported VMess header/packet encoding")
        result = {"type": "vmess", "server": v["add"], "server_port": int(v["port"]),
                  "uuid": v["id"], "security": v.get("scy") or "auto", "alter_id": int(v.get("aid", 0))}
        network = str(v.get("net") or "tcp")
        q = {"type": network, "host": v.get("host", ""), "path": v.get("path", ""),
             "serviceName": v.get("path", ""), "sni": v.get("sni") or v.get("host", ""),
             "security": "tls" if v.get("tls") == "tls" else "none",
             "allowInsecure": str(v.get("allowInsecure", "0")), "fp": v.get("fp", "")}
    elif kind == "ss":
        if q.get("plugin"):
            raise ValueError("unsupported Shadowsocks plugin")
        # SIP002, including legacy whole-authority base64 links.
        if "@" not in u.netloc:
            u = urllib.parse.urlsplit("ss://" + decode64(u.netloc))
        userinfo = urllib.parse.unquote(u.netloc.rsplit("@", 1)[0])
        credentials = userinfo if ":" in userinfo else decode64(userinfo)
        method, password = credentials.split(":", 1)
        result = {"type": "shadowsocks", "server": u.hostname, "server_port": u.port,
                  "method": method, "password": password}
    elif kind in {"vless", "trojan", "hysteria2", "hy2"}:
        result = {"type": "hysteria2" if kind == "hy2" else kind,
                  "server": u.hostname, "server_port": u.port or 443}
        credential = urllib.parse.unquote(u.netloc.rsplit("@", 1)[0])
        result["uuid" if kind == "vless" else "password"] = credential
        if kind == "vless" and q.get("flow"):
            result["flow"] = q["flow"]
        if kind == "vless" and q.get("encryption", "none") not in ("", "none"):
            raise ValueError("unsupported VLESS encryption")
        if kind in {"hysteria2", "hy2"}:
            if q.get("obfs"):
                result["obfs"] = {"type": q["obfs"], "password": q.get("obfs-password", "")}
            if q.get("mport"):
                raise ValueError("unsupported Hysteria2 port hopping")
    else:
        raise ValueError("unsupported share-link protocol")

    network = q.get("type", "tcp") or "tcp"
    if network == "raw":
        network = "tcp"
    if network == "ws":
        transport = {"type": "ws", "path": q.get("path") or "/"}
        if q.get("host"):
            transport["headers"] = {"Host": q["host"]}
        if q.get("ed") or q.get("eh"):
            raise ValueError("unsupported WebSocket early data")
        result["transport"] = transport
    elif network == "grpc":
        if q.get("mode") not in (None, "", "gun"):
            raise ValueError("unsupported gRPC mode")
        result["transport"] = {"type": "grpc", "service_name": q.get("serviceName", "")}
    elif network != "tcp":
        raise ValueError("unsupported transport: " + network)
    if q.get("headerType") not in (None, "", "none"):
        raise ValueError("unsupported TCP header")

    security = q.get("security", "tls" if kind in {"trojan", "hysteria2", "hy2"} else "none")
    if security in {"tls", "reality"}:
        tls = {"enabled": True, "server_name": q.get("sni") or q.get("peer") or result["server"],
               "insecure": any(q.get(k, "").lower() in {"1", "true"} for k in ("insecure", "allowInsecure"))}
        if q.get("alpn"):
            tls["alpn"] = q["alpn"].split(",")
        if q.get("fp"):
            tls["utls"] = {"enabled": True, "fingerprint": q["fp"]}
        if security == "reality":
            tls["utls"] = {"enabled": True, "fingerprint": q.get("fp") or "chrome"}
            tls["reality"] = {"enabled": True, "public_key": q["pbk"], "short_id": q.get("sid", "")}
        result["tls"] = tls
    elif security not in {"none", ""}:
        raise ValueError("unsupported TLS security")
    if q.get("packetEncoding") in {"xudp", "packetaddr"} and kind in {"vless", "vmess"}:
        result["packet_encoding"] = q["packetEncoding"]
    result["tag"] = "candidate"
    return result


def verify_link(uri: str, core: Path, timeout: float = 10) -> dict:
    name = link_name(uri)
    report = {"name": name, "ok": False}
    process = None
    started = time.monotonic()
    try:
        outbound = outbound_from_uri(uri)
        with tempfile.TemporaryDirectory(prefix="subs-verify-") as tmp:
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            config = {"log": {"disabled": True},
                      "inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": port}],
                      "outbounds": [outbound], "route": {"final": "candidate"}}
            path = Path(tmp) / "config.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            clean_env = {k: v for k, v in os.environ.items() if k.lower() not in {
                "http_proxy", "https_proxy", "all_proxy", "no_proxy"}}
            with (Path(tmp) / "core.log").open("w+", encoding="utf-8") as log:
                process = subprocess.Popen([str(core.resolve()), "run", "-c", str(path)],
                    stdout=log, stderr=log, env=clean_env,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
                try:
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline:
                        if process.poll() is not None:
                            log.seek(0)
                            # Do not include potentially sensitive raw core logs in published reports.
                            raise RuntimeError("core rejected share-link configuration")
                        try:
                            with socket.create_connection(("127.0.0.1", port), timeout=.15):
                                break
                        except OSError:
                            time.sleep(.05)
                    else:
                        raise TimeoutError("core startup timeout")
                    for target, status in [("https://www.gstatic.com/generate_204", 204),
                                           ("https://www.cloudflare.com/cdn-cgi/trace", 200),
                                           ("https://www.gstatic.com/generate_204", 204)]:
                        target_url = urllib.parse.urlsplit(target)
                        # Explicit CONNECT prevents environment/registry proxy bypass rules.
                        connection = http.client.HTTPSConnection("127.0.0.1", port, timeout=timeout,
                                                                 context=ssl.create_default_context())
                        connection.set_tunnel(target_url.hostname, 443)
                        try:
                            connection.request("GET", target_url.path, headers={"User-Agent": "subs-local-verify/1"})
                            response = connection.getresponse()
                            body = response.read(16384)
                            if response.status != status or (status == 204 and body):
                                raise RuntimeError("unexpected HTTPS response")
                            if status == 200:
                                fields = dict(line.split("=", 1) for line in body.decode().splitlines() if "=" in line)
                                exit_ip = ipaddress.ip_address(fields["ip"])
                                if not exit_ip.is_global or not fields.get("colo"):
                                    raise RuntimeError("invalid exit-IP response")
                                report["exit_ip"] = str(exit_ip)
                        finally:
                            connection.close()
                    report["ok"] = True
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
    except Exception as exc:
        report["error"] = type(exc).__name__ + ": " + str(exc)
    report["elapsed_ms"] = round((time.monotonic() - started) * 1000)
    return report


def verify_links(links: list[str], core: Path, workers: int = 3, timeout: float = 10) -> list[dict]:
    if not core.is_file():
        raise FileNotFoundError("sing-box executable not found: " + str(core))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(lambda uri: verify_link(uri, core, timeout), links))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--subscription", type=Path, default=Path("subs/base64.txt"))
    parser.add_argument("--core", type=Path, required=True)
    parser.add_argument("--report", type=Path, default=Path("output/verification.json"))
    args = parser.parse_args()
    reports = verify_links(read_links(args.subscription), args.core)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(reports, ensure_ascii=False, indent=2), encoding="utf-8")
    for r in reports:
        print(r["name"], "PASS" if r["ok"] else r.get("error", "FAIL"), flush=True)
    print(f"Verified {sum(r['ok'] for r in reports)}/{len(reports)} exported links")
    return 0 if reports and all(r["ok"] for r in reports) else 1


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
