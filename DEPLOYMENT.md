# Deployment

Tested in AWS CloudShell, region `ap-southeast-2`. Everything is created in one CloudFormation stack, `tourniquet-slice`, plus two S3 buckets named from your account ID, so it does not clash with anyone else's.

## Prerequisites

1. An AWS account where you can create IAM roles, Lambda, Step Functions, DynamoDB, API Gateway, S3 and CloudFormation (an admin role is simplest).
2. **CloudTrail** management events on (the default trail is enough). Tourniquet reads `CreateAccessKey` and `GetSecretValue` from it.
3. **Amazon Bedrock AgentCore** available in the region (used by the proof scripts for the Gateway, Cedar policy and Runtime).
4. **Bedrock model access** for the Orchestrator (optional). Submit the Anthropic use-case form once in the Bedrock console. Without it the Orchestrator falls back to rules and says so in the plan.
5. Python 3.9 or newer with `pip`.

Cost is small: DynamoDB on demand, Lambda, one poll per minute. The proof scripts create an AgentCore Gateway and Runtime, which cost a little while they exist. Run `cleanup.py` when finished.

## What gets created

One CloudFormation stack `tourniquet-slice` containing: seven DynamoDB tables (`tq-reach`, `tq-alerts`, `tq-sessions`, `tq-signals`, `tq-approvals`, `tq-seen`, `tq-baselines`), the Lambda functions (detect, match, plan, act, approve, lift, poll and others), the `tq-contain` Step Functions state machine, an IAM-authenticated HTTP API, IAM roles, an S3 Object Lock audit bucket `tq-audit-<account>`, a code bucket `tq-code-<account>`, and a one-minute schedule for the poller. The proof scripts also create a demo shop (roles, a tool Lambda, a secret), an AgentCore Gateway with a Cedar policy engine, and a Runtime agent.

## Permissions you need

An administrator role is simplest. At minimum the deploying identity must be able to create IAM roles and policies (`CAPABILITY_NAMED_IAM`), CloudFormation stacks, Lambda, Step Functions, DynamoDB, API Gateway, S3 with Object Lock, EventBridge rules, Secrets Manager, and Bedrock AgentCore. The Act role is broad (`bedrock-agentcore:*`) by default; set `TQ_NARROW=1` before `deploy.py` to use exact AgentCore permissions instead.

## Fast path

From the repo root, in AWS CloudShell (or any shell with admin credentials):

```bash
bash deploy/run_all.sh
```

It runs, in the right order: `preflight.py` (checks the account and region and changes nothing), model selection, `deploy.py`, `agentcore_step1.py`, `runtime_step4.py`, `scenario_full.py`, `cuts_alone.py`. It stops at the first failure. About 25 to 35 minutes in total, mostly waiting for CloudTrail and AgentCore. Run `python deploy/preflight.py` on its own first if you only want to check that the account is ready. The steps below are the same thing done by hand.

## Deploy

```bash
unset AWS_PROFILE                  # CloudShell: use the shell's own credentials
export TQ_REGION=ap-southeast-2    # optional; this is the default
git clone <repo-url> tourniquet && cd tourniquet
pip install -U boto3

python deploy/pick_model.py        # optional: prints a Bedrock model id you can call
export TQ_MODEL=<the id it printed>          # without this the Orchestrator uses rules
export TQ_APPROVERS=tq-demo-sec-lead         # roles allowed to approve (default shown)
python deploy/deploy.py            # TQ_NARROW=1 for exact AgentCore permissions on Act
```

Replace `<the id it printed>` with the real id; do not paste the angle brackets.

`deploy.py` builds the Lambda package, uploads it to `tq-code-<account>`, and creates or updates the stack. It prints the audit bucket, the approval API URL, the Orchestrator mode and the approvers. Running it again is safe ("Stack already up to date" if nothing changed).

## Verify

Expected results on a clean deploy (24 Nov 2026 run): `agentcore_step1.py` 11 of 11, `runtime_step4.py` 4 of 4, `cuts_alone.py` 12 of 12, `scenario_full.py` 45 of 45.

```bash
python deploy/agentcore_step1.py   # 11 checks: Gateway + Cedar forbid
python deploy/runtime_step4.py     # 4 checks: a real Runtime session is stopped
python deploy/cuts_alone.py        # 12 checks: each cut on its own, with undo
python deploy/scenario_full.py     # full pipeline: real secret reads from CloudTrail, plan, signed approval, cuts, undo
```

`scenario_full.py` waits for CloudTrail to deliver the event (1 to 4 minutes). It ends with a count of passed checks and timings. If a run fails, `python deploy/last_failure.py` shows why the latest Step Functions run failed.

Offline tests need no AWS: `pip install pytest moto && python -m pytest tests -q`

## Look at it

```bash
python deploy/approver_ui.py --snapshot tourniquet_live.html   # reads live data once, writes a page you download from CloudShell and open
python deploy/approver_ui.py --export sample.html             # the same page with sample data, no AWS
```

Without `--snapshot` it serves on `127.0.0.1:8080`, only reachable from the machine running it, and has no login of its own.

## Approving a plan by hand

Approval is an IAM-signed call to the API URL printed by `deploy.py`: `POST /approve` and `POST /lift`, `GET /plans`. The caller must be a role on `TQ_APPROVERS` and must not be the agent's owner. To change approvers, set `TQ_APPROVERS` and run `deploy.py` again. With IAM Identity Center, use full session ARNs to name one person; a role name admits everyone on that permission set.

## Teardown

```bash
python deploy/cleanup.py           # removes the stack, both buckets, the AgentCore Gateway, policy engine and Runtime, and the demo roles, functions and secret the proofs created
```

This deletes the evidence too. Save `results/` and anything you want to keep first.

## Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| `AccessDenied` or profile errors | Run `unset AWS_PROFILE` in CloudShell, or set `AWS_PROFILE` to a profile with admin rights |
| Plan says it was made by rules, not Bedrock | `TQ_MODEL` unset or the model use-case form not submitted; run `pick_model.py` |
| Stack create fails on a bucket name | Bucket names are `tq-code-<account>` and `tq-audit-<account>`; a leftover bucket from an earlier install must be emptied or reused |
| Scenario waits a long time at "not yet" | CloudTrail delivery can take several minutes; wait, then check `last_failure.py` |
| Approve says "not on the approver list" | Add the role to `TQ_APPROVERS` and run `deploy.py` again |
| Different region | Set `TQ_REGION` for every script, in the same shell, before deploying |

## Security notes

- The approval API is IAM-authenticated. Give approvers `execute-api:Invoke` only, never `lambda:InvokeFunction` on the approve or lift functions.
- The dashboard has no login of its own and binds to `127.0.0.1`. Do not expose it.
- The audit bucket uses S3 Object Lock in governance mode with one day of default retention; `cleanup.py` bypasses it on purpose. Use a longer, compliance-mode retention for real use.
- Start with `TQ_APPROVERS` set to named roles, and use full session ARNs if your approvers come from IAM Identity Center.

## Re-running and updating

`deploy.py` is safe to re-run; it updates the stack in place and prints "Stack already up to date" when nothing changed. The scenario recreates its demo shop each time, and a previous containment must be lifted first (a signed `POST /lift` for `supervisor-agent`, or the Lift button on the dashboard) or the scenario's "before" checks will fail.
