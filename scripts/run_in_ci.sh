#!/usr/bin/env bash
set -euo pipefail
python3 ./scripts/run_check.py --cloud --collector ./subs-check-pro --config ./config/config.yaml
