#!/usr/bin/env bash
set -euo pipefail

rm -f /tmp/subs_check.done
chmod +x ./subs-check-pro ./scripts/on_check_done.sh

echo "启动 subs-check-pro 执行本轮检测..."
./subs-check-pro -f ./config/config.yaml &
APP_PID=$!

MAX_WAIT=1200  # 最长等待 20 分钟
ELAPSED=0

while true; do
  if [[ -f /tmp/subs_check.done ]]; then
    echo "收到回调完成信号，等待文件写入收尾..."
    sleep 3
    kill -TERM "$APP_PID" 2>/dev/null || true
    for _ in $(seq 1 15); do
      if ! kill -0 "$APP_PID" 2>/dev/null; then
        break
      fi
      sleep 1
    done
    kill -KILL "$APP_PID" 2>/dev/null || true
    wait "$APP_PID" 2>/dev/null || true
    break
  fi

  if ! kill -0 "$APP_PID" 2>/dev/null; then
    echo "subs-check-pro 进程提前退出"
    wait "$APP_PID" || true
    break
  fi

  if (( ELAPSED >= MAX_WAIT )); then
    echo "达到最大等待时间 (${MAX_WAIT}s)，终止进程..."
    kill -TERM "$APP_PID" 2>/dev/null || true
    sleep 5
    kill -KILL "$APP_PID" 2>/dev/null || true
    break
  fi

  sleep 2
  ELAPSED=$((ELAPSED + 2))
done

echo "本轮检测流程结束。"
