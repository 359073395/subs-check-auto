#!/usr/bin/env python3
"""Run one collection in a fresh directory, then verify and publish locally."""
from __future__ import annotations

import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

import yaml


def write_callback(callback: Path, flag: Path) -> None:
    temporary = str(flag) + ".tmp"
    if os.name == "nt":
        # Put redirection before echo: `echo 3> file` redirects file descriptor 3.
        callback.write_text('@echo off\n> "' + temporary + '" echo %SUCCESS_COUNT%\n'
                            + 'move /Y "' + temporary + '" "' + str(flag) + '" >nul\n', encoding="utf-8")
    else:
        callback.write_text('#!/bin/sh\nprintf "%s" "$SUCCESS_COUNT" > "' + temporary + '"\n'
                            + 'mv "' + temporary + '" "' + str(flag) + '"\n', encoding="utf-8")
        callback.chmod(0o700)


def collect(collector: Path, config_path: Path, max_wait: int) -> tuple[Path, float]:
    run_dir = (Path("output/runs") / (datetime.now().strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:8])).resolve()
    run_dir.mkdir(parents=True)
    started = time.time()
    flag = run_dir / "complete.flag"
    callback = run_dir / ("complete.bat" if os.name == "nt" else "complete.sh")
    write_callback(callback, flag)
    config = yaml.safe_load(config_path.read_text(encoding="utf-8-sig"))
    config.update({"output-dir": str(run_dir), "callback-script": str(callback),
                   "use-last-result": False, "use-history-result": False})
    runtime_config = run_dir / "config.yaml"
    runtime_config.write_text(yaml.safe_dump(config, allow_unicode=True, sort_keys=False), encoding="utf-8")
    (run_dir / "run.json").write_text(json.dumps({"started_at": started, "config": str(config_path)}), encoding="utf-8")
    print("Collector log: " + str(run_dir / "collector.log"), flush=True)
    with (run_dir / "collector.log").open("w", encoding="utf-8") as log:
        process = subprocess.Popen([str(collector.resolve()), "-f", str(runtime_config)], stdout=log, stderr=log,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        try:
            deadline = time.monotonic() + max_wait
            while not flag.exists():
                if process.poll() is not None:
                    raise RuntimeError("collector exited before completion; see " + str(run_dir / "collector.log"))
                if time.monotonic() >= deadline:
                    raise TimeoutError("collector did not finish; previous results will not be published")
                time.sleep(1)
            count = int(flag.read_text().strip())
            if count <= 0:
                raise RuntimeError("collector found no available nodes")
        finally:
            if process.poll() is None:
                if os.name == "nt":
                    subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                else:
                    process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
    return run_dir / "sub", started


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--collector", type=Path, default=Path("bin/subs-check-pro.exe"))
    parser.add_argument("--core", type=Path, default=Path("bin/sing-box.exe"))
    parser.add_argument("--config", type=Path, default=Path("config/config.local.yaml"))
    parser.add_argument("--max-wait", type=int, default=1200)
    parser.add_argument("--collect-only", action="store_true")
    parser.add_argument("--cloud", action="store_true", help="generate unpublished cloud candidates only")
    parser.add_argument("--push", action="store_true")
    args = parser.parse_args()
    if args.cloud and args.push:
        parser.error("cloud candidates cannot be pushed as local results")
    if args.push:
        branch = subprocess.check_output(["git", "branch", "--show-current"], text=True).strip()
        if branch != "main":
            raise RuntimeError("automatic publication requires the main branch")
    if not args.collector.is_file() or (not args.collect_only and not args.cloud and not args.core.is_file()):
        raise FileNotFoundError("collector/sing-box missing; run scripts/run_local.ps1 to prepare binaries")
    input_dir, started = collect(args.collector, args.config, args.max_wait)
    if args.collect_only:
        print("Collected fresh results: " + str(input_dir), flush=True)
        return 0
    select_args = [sys.executable, "scripts/select_top20.py", "--top", "20",
                   "--input-dir", str(input_dir), "--started-at", str(started)]
    if not args.cloud:
        select_args += ["--local", "--core", str(args.core)]
    subprocess.run(select_args, check=True)
    if args.push:
        staged = subprocess.check_output(["git", "diff", "--cached", "--name-only"], text=True).strip()
        if staged:
            raise RuntimeError("existing staged changes; subscriptions are ready locally, push them separately")
        subprocess.run(["git", "add", "--", "subs/"], check=True)
        changed = subprocess.run(["git", "diff", "--cached", "--quiet"]).returncode
        if changed == 1:
            subprocess.run(["git", "commit", "-m", "fix: publish locally verified subscription"], check=True)
            subprocess.run(["git", "push", "origin", "HEAD:main"], check=True)
        elif changed != 0:
            raise RuntimeError("git diff failed")
    if args.cloud:
        print("Finished: cloud candidates saved; published subscriptions were not changed")
    else:
        print("Finished: fresh share links verified and generated" + (", pushed to GitHub" if args.push else " locally"))
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError, ValueError, subprocess.CalledProcessError) as exc:
        print("FAILED: " + str(exc), file=sys.stderr)
        raise SystemExit(1)
