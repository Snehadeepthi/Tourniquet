# Proof results, run of 19 Nov 2026 (ap-southeast-2)

Version run: v5.5. v5.6 changes step 8 (see README) and needs scenario_full.py re-run; see bottom.

| # | Stage | Check | Result |
|---|---|---|---|
| 1 | Step 1: Gateway (agentcore_step1.py) | AgentCore policy engine is ACTIVE | PASS |
| 2 | Step 1: Gateway (agentcore_step1.py) | Gateway is READY with the engine in ENFORCE mode | PASS |
| 3 | Step 1: Gateway (agentcore_step1.py) | Order tool target is READY | PASS |
| 4 | Step 1: Gateway (agentcore_step1.py) | Permit policy accepted by AgentCore validation | PASS |
| 5 | Step 1: Gateway (agentcore_step1.py) | Before: supervisor-agent can place an order through the gateway | PASS |
| 6 | Step 1: Gateway (agentcore_step1.py) | Before: helper agents can place an order too | PASS |
| 7 | Step 1: Gateway (agentcore_step1.py) | Cedar forbid accepted in the exact-pattern form (broader forms refused) | PASS |
| 8 | Step 1: Gateway (agentcore_step1.py) | After: the same supervisor session is refused by the gateway (its IAM rights untouched) | PASS |
| 9 | Step 1: Gateway (agentcore_step1.py) | After: helper agents still get through | PASS |
| 10 | Step 1: Gateway (agentcore_step1.py) | After: the forbidden tool is hidden from the supervisor's tool list | PASS |
| 11 | Step 1: Gateway (agentcore_step1.py) | After: helpers still see the tool | PASS |
| 12 | Step 4: Runtime session (runtime_step4.py) | The Runtime agent is READY | PASS |
| 13 | Step 4: Runtime session (runtime_step4.py) | A live session keeps state between calls (1, 2, 3) | PASS |
| 14 | Step 4: Runtime session (runtime_step4.py) | Step 4 stops the session | PASS |
| 15 | Step 4: Runtime session (runtime_step4.py) | The same session id now starts from scratch (count 1) | PASS |
| 16 | Each cut alone (cuts_alone.py) | Step 2 before: supervisor reads the secret | PASS |
| 17 | Each cut alone (cuts_alone.py) | Step 2 alone: supervisor refused by the vault, no role lock | PASS |
| 18 | Each cut alone (cuts_alone.py) | Step 2 alone: a helper still reads the secret | PASS |
| 19 | Each cut alone (cuts_alone.py) | Step 2 undo: supervisor reads the secret again | PASS |
| 20 | Each cut alone (cuts_alone.py) | Step 8 alone: the secret has a new value | PASS |
| 21 | Each cut alone (cuts_alone.py) | Step 8 alone: old value is not AWSPREVIOUS any more | PASS |
| 22 | Each cut alone (cuts_alone.py) | Step 8 alone: a helper reads the NEW value | PASS |
| 23 | Each cut alone (cuts_alone.py) | Step 3 before: supervisor can call another agent | PASS |
| 24 | Each cut alone (cuts_alone.py) | Step 3 alone: supervisor can no longer call another agent | PASS |
| 25 | Each cut alone (cuts_alone.py) | Step 3 alone: supervisor can still read the secret | PASS |
| 26 | Each cut alone (cuts_alone.py) | Step 3 undo: supervisor can call another agent again | PASS |
| 27 | Each cut alone (cuts_alone.py) | Step 4 alone: the live Runtime session stopped and its state is gone | PASS |
| 28 | Setup and signals (scenario_full.py) | Before: supervisor session works | PASS |
| 29 | Setup and signals (scenario_full.py) | Before: helper session works | PASS |
| 30 | Setup and signals (scenario_full.py) | Before: supervisor reads the vault secret | PASS |
| 31 | Setup and signals (scenario_full.py) | Before: helper reads the vault secret | PASS |
| 32 | Setup and signals (scenario_full.py) | Before: supervisor can call another agent | PASS |
| 33 | Setup and signals (scenario_full.py) | Collector discovered the reach map (secret, shared role, tool Lambda, owner) | PASS |
| 34 | Setup and signals (scenario_full.py) | Before: supervisor's Runtime session is live and holds state | PASS |
| 35 | Setup and signals (scenario_full.py) | Signal 1: a real Bedrock Guardrail flagged the injected text | PASS |
| 36 | Setup and signals (scenario_full.py) | Signal 2: a GuardDuty-shaped finding becomes a signal (GuardDuty itself not enabled) | PASS |
| 37 | Trigger and plan | Poller started the pipeline from the real CloudTrail event; plan waiting for approval | PASS |
| 38 | Trigger and plan | Approver data route lists the waiting plan for the security person | PASS |
| 39 | Trigger and plan | Plan says who made it (Bedrock Orchestrator, with the safety floor) and why | PASS |
| 40 | Trigger and plan | Run input is the real CloudTrail record | PASS |
| 41 | Approval | A typed name is refused (no verified identity) | PASS |
| 42 | Approval | An approver cannot call the Lambda directly | PASS |
| 43 | Approval | A signed caller not on the approver list is refused | PASS |
| 44 | Approval | The agent's owner is refused | PASS |
| 45 | Approval | The Orchestrator's own identity is refused | PASS |
| 46 | Approval | A security person approves | PASS |
| 47 | Approval | Approval records the real IAM ARN of the approver | PASS |
| 48 | Approval | Step Functions finished the cut | PASS |
| 49 | Cuts | Old supervisor session is denied | PASS |
| 50 | Cuts | A NEW supervisor session is denied too | PASS |
| 51 | Cuts | Helpers keep running | PASS |
| 52 | Cuts | Step 1: Cedar forbid is in the gateway engine | PASS |
| 53 | Cuts | Key the agent created is Inactive | PASS |
| 54 | Cuts | Tool Lambda concurrency is 0 | PASS |
| 55 | Cuts | Helper role has no quarantine policy | PASS |
| 56 | Cuts | Step 2: vault secret has a deny for the supervisor | PASS |
| 57 | Cuts | Step 8: left out by the Orchestrator, secret not rotated (proven alone) | PASS |
| 58 | Cuts | Step 2: the supervisor cannot read the secret | PASS |
| 59 | Cuts | Step 3: supervisor has the agent-calls cut policy | PASS |
| 60 | Cuts | Step 4: Runtime session stopped, state gone | PASS |
| 61 | Undo | Non-approver cannot lift | PASS |
| 62 | Undo | Owner cannot lift | PASS |
| 63 | Undo | Orchestrator cannot lift | PASS |
| 64 | Undo | Security person lifts the cut | PASS |
| 65 | Undo | Supervisor session works again | PASS |
| 66 | Undo | Cedar forbid gone | PASS |
| 67 | Undo | Vault deny gone, supervisor reads the secret again | PASS |
| 68 | Undo | Agent-calls cut gone | PASS |
| 69 | Undo | Secret unchanged (step 8 not in plan) | PASS |
| 70 | Undo | Tool Lambda concurrency limit removed | PASS |
| 71 | Undo | Created key stays Inactive on purpose | PASS |
| 72 | Undo | Lifting again is refused | PASS |
| 73 | Load and failure (load_aws.py) | 24 simultaneous signals: no execution failed | PASS |
| 74 | Load and failure (load_aws.py) | Exactly one Alert for the agent | PASS |
| 75 | Load and failure (load_aws.py) | Every signal is evidence on that Alert (24 of 24) | PASS |
| 76 | Load and failure (load_aws.py) | Exactly one plan waiting for approval | PASS |
| 77 | Load and failure (load_aws.py) | Audit chain intact after the burst | PASS |

**77 of 77 PASS**

## Timings

- Real event to cut done: 205.3 s. CloudTrail delay, poll and pipeline, then approval and the cut. Approval was scripted, so a person's time is not included.
- Real event to plan waiting: 108.5 s. CloudTrail delivery plus the one-minute poll plus the pipeline
- Pipeline start to plan waiting: 11.1 s. Detect, match, Bedrock plan, request approval
- Approval to cut done: 81.9 s. Steps 1 to 7 across Cedar validation, IAM, Lambda, vault and Runtime
- Lift call: 7.2 s. Undo of steps 1, 2, 3, 5, 6

## After v5.6
Step 8 now rotates only secrets no helper uses. In the demo the one secret is shared, so scenario_full.py expects it NOT rotated. Rotation itself is still proven by cuts_alone.py. Re-run after redeploying to confirm; this file is the v5.5 run.

## v5.6 re-run of scenario_full.py (19 Nov 2026, 22:17)
43 of 43 PASS. Run with the rule-based Orchestrator (TQ_MODEL was not set in that shell), so the Bedrock plan was proven in the v5.5 run above, not in this one.
Step 8 was correctly not in the plan: the secret is shared with subagents-role, and it was left unchanged.
Timings: real event to plan waiting 208.4 s (CloudTrail was slower this time), pipeline start to plan waiting 17.5 s, approval to cut done 67.0 s, real event to cut done 290.5 s, lift 7.0 s.
Note: the lift list printed "step 8 left rotated" although step 8 did not run. Fixed afterwards in core.py (label only; no cut changed).


## 24 Nov 2026 run (alert types 1 and 3), scenario_full.py: 45 of 45

- Type 1: a GuardDuty-shaped finding sent into the pipeline (GuardDuty itself not enabled).
- Type 3: the supervisor role made 30 real GetSecretValue calls; the poller counted them from CloudTrail (10 in the minute, normal about 1.0) and raised the spike. The same hijacked role also created an access key, which became the target of cut 7.
- Plan made by Bedrock (au.anthropic.claude-haiku-4-5-20251001-v1:0) with the safety floor adding steps 1, 2, 5, 6.
- Approval refusals (typed name, direct Lambda call, stranger, owner, Orchestrator) all refused; sec-lead approved with the real IAM ARN.
- Cuts 1 to 7 verified; step 8 correctly not run (the secret is shared with helpers). Undo verified; key stays Inactive.
- Timings (s): secret reads to plan waiting 82.8, pipeline start to plan waiting 18.9, approval to cut done 63.8, real event to cut done 232.3, lift 6.9.
- Earlier the same day two scenario defects were found and fixed (not product bugs): the scenario followed the wrong pipeline and lifted before the Alert was contained; and it called a just-created Lambda while it was still Pending.

- Same day, other scripts re-run on the final code: agentcore_step1 11/11, runtime_step4 4/4, cuts_alone 12/12 (step 4 included). load_aws (5 checks) not re-run since 19 Nov.
