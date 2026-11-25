# Tourniquet threat model (what it defends, what it does not)

| Threat | Defence | Proven |
|---|---|---|
| Someone types a fake approver name | Approver is the caller API Gateway verified; typed names are refused | scenario_full |
| An approver forges the caller by invoking the Lambda | Approvers hold execute-api:Invoke only; direct Lambda call is AccessDenied | scenario_full |
| The agent's owner or the Orchestrator approves | Refused by name in approve and lift | scenario_full |
| A signed stranger approves or lifts | Allowlist `TQ_APPROVERS` (empty list refuses everyone) | scenario_full, tests |
| Two approvals, two lifts, two plans at once | Conditional claims; tested with threads | tests, load_aws |
| The model proposes a harmful plan | The Orchestrator only chooses among set-up steps, must include the role lock, and people approve | tests |
| Plan edited after approval | Plan hash is checked in act | tests |
| The audit log is edited | Hash chain; S3 Object Lock | tests, deploy |

## Not defended (read this before relying on it)
- Anyone with `lambda:InvokeFunction` on tq-approve or tq-lift can send a made-up caller straight to the Lambda.
- With IAM Identity Center, a role-name allowlist admits everyone on that permission set; use full session ARNs.
- Step 8 rotates the value in the vault only, not the downstream credential.
- The Act role is broad unless deployed with `TQ_NARROW=1`.
- Detection is three signal types with stand-in weights; a quiet attacker who creates no key and trips no Guardrail is not seen.
- Lift is not a separate approval of the specific lift.
