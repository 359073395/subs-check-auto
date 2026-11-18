#!/usr/bin/env bash
set -euo pipefail

echo "${SUCCESS_COUNT:-0}" > /tmp/subs_check.done
echo "[callback] 检测与保存已完成，可用节点数: ${SUCCESS_COUNT:-0}"
