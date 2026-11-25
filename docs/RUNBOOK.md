# Tourniquet runbook

## Deploy and prove (CloudShell, ap-southeast-2)
```
unset AWS_PROFILE
python deploy/pick_model.py            # optional: finds a Bedrock model; then:  export TQ_MODEL=<id>
python deploy/deploy.py                # TQ_NARROW=1 for the narrow Act role; TQ_APPROVERS=role1,role2
python deploy/agentcore_step1.py       # gateway, policy engine, step 1 proof
python deploy/runtime_step4.py         # real AgentCore Runtime agent, step 4 proof
python deploy/scenario_full.py         # full pipeline + undo
python deploy/cuts_alone.py            # each cut alone, role lock off
python deploy/load_aws.py              # 24 simultaneous signals
python deploy/approver_ui.py           # live approver page; use --snapshot file.html in CloudShell
```
Do not run `cleanup.py` until the evidence is saved. It removes everything.

## When Tourniquet raises a plan
1. Open the approver page. You see the agent, its owner, the evidence, who made the plan (Bedrock or rules) and why, and which steps will run.
2. Press **Approve and cut** only if you are on the approver list and you are not the agent's owner. The cut takes about a minute.
3. To undo, press **Lift the cut**. Steps 4 (sessions) and 8 (rotation) and the deactivated key stay as they are, on purpose.

## If something goes wrong
- **Plan stuck waiting:** it expires after 24 hours (the Alert becomes `expired`; a new signal plans again).
- **Cut ended "with errors":** the Step Functions run is red and shows which steps failed; the Alert is `contained_with_errors`. Fix the cause and press Lift, then approve a new plan, or cut the failed step by hand.
- **Approve says "not on the approver list":** add the role name (or the full session ARN) to `TQ_APPROVERS` and redeploy.
- **Audit chain check:** `python -c "from tourniquet_slice import core; print(core.verify_audit())"` with `TQ_AUDIT_BUCKET` set.
- **Orchestrator not usable:** the audit log shows `orchestrator_fallback`; the plan is rule-based and says so.
