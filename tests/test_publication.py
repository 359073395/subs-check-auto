import base64
import hashlib
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import select_top20 as select
import verify_nodes as verify
import run_check


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "input"
        self.source.mkdir()
        self.published = self.root / "subs"
        self.published.mkdir()
        (self.published / "base64.txt").write_text("old subscription")
        self.started = time.time() - 2
        self.proxies = [
            {"name": f"US {i}|0%|2 MB/s", "type": "vless", "server": f"203.0.{i}.1",
             "port": 443, "uuid": "12345678-1234-1234-1234-123456789abc", "tls": True}
            for i in (1, 2)]
        self.links = [f"vless://{p['uuid']}@{p['server']}:443?security=tls#{verify.urllib.parse.quote(p['name'])}"
                      for p in self.proxies]
        self.write_input()

    def write_input(self):
        (self.source / "all.yaml").write_text(yaml.safe_dump({"proxies": self.proxies}))
        (self.source / "base64.txt").write_text(base64.b64encode("\n".join(self.links).encode()).decode())

    def run_select(self, extra=()):
        args = ["select", "--local", "--core", "unused-core", "--top", "20",
                "--input-dir", str(self.source), "--publish-dir", str(self.published),
                "--started-at", str(self.started)] + list(extra)
        with patch.object(sys, "argv", args):
            return select.main()

    def assert_old_preserved(self):
        self.assertEqual((self.published / "base64.txt").read_text(), "old subscription")
        self.assertFalse((self.published / "STATUS.md").exists())

    def test_stale_run_cannot_refresh_published_subscription(self):
        self.started = time.time() + 60
        with patch.object(select, "verify_links") as verifier:
            self.assertEqual(self.run_select(), 1)
            verifier.assert_not_called()
        self.assert_old_preserved()

    def test_failed_verification_cannot_publish_or_fake_new_status(self):
        with patch.object(select, "verify_links", return_value=[{"ok": False}, {"ok": False}]):
            self.assertEqual(self.run_select(), 1)
        self.assert_old_preserved()

    def test_excluded_transport_is_not_reintroduced_to_fill_quota(self):
        for p in self.proxies:
            p["network"] = "xhttp"
        self.write_input()
        with patch.object(select, "verify_links") as verifier:
            self.assertEqual(self.run_select(), 1)
            verifier.assert_not_called()
        self.assert_old_preserved()

    def test_only_verified_links_are_published_in_every_format(self):
        with patch.object(select, "verify_links", return_value=[
            {"name": self.proxies[0]["name"], "ok": True, "exit_ip": "8.8.8.8"},
            {"name": self.proxies[1]["name"], "ok": False}]):
            self.assertEqual(self.run_select(), 0)
        nodes = yaml.safe_load((self.published / "all.yaml").read_text())["proxies"]
        config = yaml.safe_load((self.published / "mihomo.yaml").read_text())
        links = verify.read_links(self.published / "base64.txt")
        report = json.loads((self.published / "verification.json").read_text(encoding="utf-8"))
        self.assertEqual(len(nodes), 1)
        self.assertEqual(config["proxies"], nodes)
        self.assertEqual(verify.link_name(links[0]), nodes[0]["name"])
        self.assertEqual(report["count"], 1)
        self.assertTrue(report["verified"])
        self.assertEqual(report["nodes"][0]["link_sha256"], hashlib.sha256(links[0].encode()).hexdigest())
        self.assertEqual(report["subscription_sha256"], hashlib.sha256((self.published / "base64.txt").read_bytes()).hexdigest())
        self.assertFalse("rule-providers" in config)

    def test_missing_share_link_is_never_backfilled_from_previous_subscription(self):
        self.links = []
        self.write_input()
        with patch.object(select, "verify_links") as verifier:
            self.assertEqual(self.run_select(), 1)
            verifier.assert_not_called()
        self.assert_old_preserved()

    def test_duplicate_share_link_names_are_rejected(self):
        self.links = [self.links[0], self.links[0]]
        self.write_input()
        self.assertEqual(self.run_select(), 1)
        self.assert_old_preserved()

    def test_share_link_cannot_be_matched_to_a_different_server_by_name(self):
        for p in self.proxies:
            p["server"] = "different.example"
        self.write_input()
        with patch.object(select, "verify_links") as verifier:
            self.assertEqual(self.run_select(), 1)
            verifier.assert_not_called()
        self.assert_old_preserved()

    def test_legacy_cipher_is_not_reintroduced_to_fill_quota(self):
        proxy = {"type": "ss", "server": "example.com", "cipher": "aes-256-cfb"}
        self.assertFalse(select.is_allowed_proxy(proxy, strict=False, local_mode=True))


class ShareLinkTests(unittest.TestCase):
    def test_callback_records_single_digit_counts_atomically(self):
        with tempfile.TemporaryDirectory(prefix="callback with spaces ") as directory:
            callback = Path(directory) / ("complete.bat" if os.name == "nt" else "complete.sh")
            flag = Path(directory) / "complete.flag"
            run_check.write_callback(callback, flag)
            for count in (0, 1, 3, 9, 44):
                with self.subTest(count=count):
                    env = dict(os.environ, SUCCESS_COUNT=str(count))
                    command = ["cmd", "/c", str(callback)] if os.name == "nt" else ["sh", str(callback)]
                    subprocess.run(command, env=env, check=True, stdout=subprocess.DEVNULL,
                                   creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
                    self.assertEqual(int(flag.read_text().strip()), count)
                    self.assertFalse(Path(str(flag) + ".tmp").exists())

    def test_reality_parameters_and_escaped_credentials_survive(self):
        uri = "vless://12345678-1234-1234-1234-123456789abc@example.com:8443?security=reality&type=tcp&sni=cover.example&pbk=public&sid=abcd&fp=firefox&flow=xtls-rprx-vision#sample"
        outbound = verify.outbound_from_uri(uri)
        self.assertEqual(outbound["tls"]["reality"], {"enabled": True, "public_key": "public", "short_id": "abcd"})
        self.assertEqual(outbound["flow"], "xtls-rprx-vision")
        self.assertEqual(outbound["tls"]["server_name"], "cover.example")

    def test_unsupported_features_fail_closed(self):
        for suffix in ("type=xhttp", "type=tcp&encryption=mlkem", "type=tcp&headerType=http"):
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                verify.outbound_from_uri("vless://uuid@example.com:443?" + suffix)

    def test_core_startup_failure_cannot_look_like_success(self):
        result = verify.verify_link("trojan://password@example.com:443#test", Path("missing-core-executable"), timeout=.1)
        self.assertFalse(result["ok"])

    def test_vmess_tls_host_and_path_are_preserved(self):
        payload = {"ps": "test", "add": "example.com", "port": "443", "id": "uuid", "aid": "0",
                   "net": "ws", "host": "host.example", "path": "/path?key=value", "tls": "tls", "sni": "cover.example"}
        outbound = verify.outbound_from_uri("vmess://" + base64.b64encode(json.dumps(payload).encode()).decode())
        self.assertEqual(outbound["transport"]["path"], payload["path"])
        self.assertEqual(outbound["transport"]["headers"]["Host"], payload["host"])
        self.assertEqual(outbound["tls"]["server_name"], payload["sni"])


if __name__ == "__main__":
    unittest.main()
