#!/usr/bin/env bash
# One command from an empty account to the full proof. Run from the repo root:  bash deploy/run_all.sh
# Order matters: preflight, model, deploy, Gateway + Cedar, Runtime session, full scenario, each cut alone.
set -euo pipefail
unset AWS_PROFILE || true
pip install -q -U boto3
python deploy/preflight.py || { echo "Fix the problems above and run again."; exit 1; }
if [ -z "${TQ_MODEL:-}" ]; then
  line=$(python deploy/pick_model.py | grep '^export TQ_MODEL=' || true)
  if [ -n "$line" ]; then eval "$line"; echo "Using model $TQ_MODEL"; else echo "No Bedrock model callable: the plan will be rule-based."; fi
fi
python deploy/deploy.py
python deploy/agentcore_step1.py
python deploy/runtime_step4.py
python deploy/scenario_full.py
python deploy/cuts_alone.py
echo "All steps finished. Results are in the current folder (*_results.json)."
