"""Small real-AWS load and failure test. Fires 24 signals for a made-up agent at the SAME time through the real Step
Functions pipeline and checks the races: one Alert, one plan, one waiting approval, an intact audit chain. Then cleans up.
It does not touch the shop. Writes load_aws_results.json."""
import json, os, sys, time, datetime
from concurrent.futures import ThreadPoolExecutor
import boto3
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from tourniquet_slice import core

REGION = os.environ.get("TQ_REGION", "ap-southeast-2")
s = boto3.Session(region_name=REGION, profile_name=os.environ.get("AWS_PROFILE"))
acct = s.client("sts").get_caller_identity()["Account"]
os.environ.setdefault("TQ_AUDIT_BUCKET", f"tq-audit-{acct}")
core.AUDIT_BUCKET = os.environ["TQ_AUDIT_BUCKET"]
sfn, db = s.client("stepfunctions"), s.resource("dynamodb")
MACHINE = f"arn:aws:states:{REGION}:{acct}:stateMachine:tq-contain"
AGENT, ROLE, N = "load-test-agent", "tq-load-role", 24
results = []


def ok(name, passed, note=""):
    results.append((name, "PASS" if passed else "FAIL", note))
    print(f"[{'PASS' if passed else 'FAIL'}] {name} {note}")


def purge():
    for it in db.Table("tq-alerts").scan()["Items"]:
        if it["agent"] == AGENT:
            db.Table("tq-alerts").delete_item(Key={"alert_id": it["alert_id"]})
    for it in db.Table("tq-approvals").scan()["Items"]:
        if json.loads(it["plan_json"]).get("agent") == AGENT:
            db.Table("tq-approvals").delete_item(Key={"plan_id": it["plan_id"]})


purge()
db.Table("tq-reach").put_item(Item={"role_name": ROLE, "agent": AGENT, "owner": "load-owner", "shared": []})
t0 = time.time()
rec = {"source": "guardrails", "prompt_attack": True, "role_name": ROLE, "access_key_id": "AKIALOADTEST"}
with ThreadPoolExecutor(max_workers=N) as ex:
    arns = list(ex.map(lambda i: sfn.start_execution(stateMachineArn=MACHINE, name=f"load-{int(t0)}-{i}", input=json.dumps({"record": rec}))["executionArn"], range(N)))
status = {}
for _ in range(90):
    status = {a: sfn.describe_execution(executionArn=a)["status"] for a in arns}
    if sum(1 for v in status.values() if v == "RUNNING") <= 1 and all(v != "FAILED" for v in status.values()) and sum(1 for v in status.values() if v == "SUCCEEDED") >= N - 1:
        break
    time.sleep(3)
took = round(time.time() - t0, 1)
count = lambda st: sum(1 for v in status.values() if v == st)
for a, v in status.items():
    if v in ("FAILED", "TIMED_OUT"):
        d = sfn.describe_execution(executionArn=a)
        print("  failed:", d.get("error"), (d.get("cause") or "")[:300])
ok(f"{N} simultaneous signals: no execution failed", count("FAILED") == 0 and count("TIMED_OUT") == 0, f"{count('SUCCEEDED')} succeeded, {count('RUNNING')} running, {count('FAILED')} failed, in {took}s")
alerts = [a for a in db.Table("tq-alerts").scan()["Items"] if a["agent"] == AGENT]
ok("exactly one Alert for the agent", len(alerts) == 1, f"{len(alerts)} alert(s)")
ok("every signal is evidence on that Alert", len(alerts) == 1 and len(alerts[0]["evidence"]) == N, f"{len(alerts[0]['evidence']) if alerts else 0} of {N}")
for _ in range(30):                       # the one run that won the plan may still be asking Bedrock for it
    waiting = [it for it in db.Table("tq-approvals").scan()["Items"] if json.loads(it["plan_json"]).get("agent") == AGENT]
    status = {a: sfn.describe_execution(executionArn=a)["status"] for a in arns}
    if waiting:
        break
    time.sleep(3)
count = lambda st: sum(1 for v in status.values() if v == st)
print("  final states:", {v: count(v) for v in set(status.values())})
for a, v in status.items():
    if v not in ("SUCCEEDED", "RUNNING"):
        d = sfn.describe_execution(executionArn=a)
        print("  ", v, d.get("error"), (d.get("cause") or "")[:500])
        break
ok("exactly one plan waiting for approval (no second plan for the same Alert)", len(waiting) == 1 and count("RUNNING") == 1, f"{len(waiting)} plan(s), {count('RUNNING')} waiting execution(s)")
ok("the audit chain is intact after the burst", core.verify_audit() is True)
for a, v in status.items():
    if v == "RUNNING":
        sfn.stop_execution(executionArn=a, cause="load test cleanup")
purge()
db.Table("tq-reach").delete_item(Key={"role_name": ROLE})
json.dump({"results": results, "seconds": took}, open("load_aws_results.json", "w"), indent=1)
print(f"\n{sum(1 for r in results if r[1]=='PASS')} of {len(results)} checks passed. Saved load_aws_results.json")
