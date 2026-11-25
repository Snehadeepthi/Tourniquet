"""Each cut on its OWN, with the role lock off, so the effect of that one cut is what you see. Uses the shop that
scenario_full.py builds (run it once first). Then lifts each cut. Writes cuts_alone_results.json."""
import json, os, sys, time
import boto3
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from tourniquet_slice import core

REGION = os.environ.get("TQ_REGION", "ap-southeast-2")
session = boto3.Session(region_name=REGION, profile_name=os.environ.get("AWS_PROFILE"))
acct = session.client("sts").get_caller_identity()["Account"]
sts, iam, sm = session.client("sts"), session.client("iam"), session.client("secretsmanager")
SECRET = "tq-demo/orders-db-password"
results = []


def ok(name, passed, note=""):
    results.append((name, "PASS" if passed else "FAIL", note))
    print(f"[{'PASS' if passed else 'FAIL'}] {name} {note}")


def sess(role, svc):
    c = sts.assume_role(RoleArn=f"arn:aws:iam::{acct}:role/{role}", RoleSessionName="alone")["Credentials"]
    return boto3.client(svc, region_name=REGION, aws_access_key_id=c["AccessKeyId"], aws_secret_access_key=c["SecretAccessKey"], aws_session_token=c["SessionToken"])


def denied(fn, wait=40):
    """True once the call is AccessDenied (IAM changes take a few seconds to reach every endpoint)."""
    end = time.time() + wait
    while True:
        try:
            fn()
        except Exception as e:
            if "AccessDenied" in str(e):
                return True
            raise
        if time.time() > end:
            return False
        time.sleep(4)


def works(fn, wait=40):
    end = time.time() + wait
    while True:
        try:
            fn(); return True
        except Exception as e:
            if "AccessDenied" not in str(e) or time.time() > end:
                return False
        time.sleep(4)


for pn in ("TourniquetQuarantine", "TourniquetCutCalls"):
    try:
        iam.delete_role_policy(RoleName="supervisor-role", PolicyName=pn)
    except iam.exceptions.NoSuchEntityException:
        pass
try:
    core.secret_allow_again(SECRET, "supervisor-role")
except Exception:
    pass
time.sleep(5)
read = lambda role: (lambda: sess(role, "secretsmanager").get_secret_value(SecretId=SECRET))
call = lambda role: (lambda: sess(role, "lambda").invoke(FunctionName="tq-helper-agent", Payload=b"{}"))

# ---- step 2 alone: vault deny
ok("step 2 before: supervisor reads the secret", works(read("supervisor-role")))
core.secret_deny(SECRET, "supervisor-role")
ok("step 2 alone: supervisor is now refused by the vault (no role lock in place)", denied(read("supervisor-role")))
ok("step 2 alone: a helper still reads the secret", works(read("subagents-role")))
core.secret_allow_again(SECRET, "supervisor-role")
ok("step 2 undo: supervisor reads the secret again", works(read("supervisor-role")))

# ---- step 8 alone: rotate
old = sm.get_secret_value(SecretId=SECRET)["SecretString"]
core.secret_rotate(SECRET)
import time as _t
for _ in range(15):                      # the vault can answer from its old value for a few seconds after a change
    new = sm.get_secret_value(SecretId=SECRET)["SecretString"]
    if new != old:
        break
    _t.sleep(2)
stages = sm.describe_secret(SecretId=SECRET)["VersionIdsToStages"]
ok("step 8 alone: the secret has a new value", new != old)
ok("step 8 alone: the old value is not the AWSPREVIOUS version any more", not any("AWSPREVIOUS" in v for v in stages.values()))
ok("step 8 alone: a helper reads the NEW value", sess("subagents-role", "secretsmanager").get_secret_value(SecretId=SECRET)["SecretString"] == new)

# ---- step 3 alone: agent calls
ok("step 3 before: supervisor can call another agent", works(call("supervisor-role")))
core.cut_calls("supervisor-role")
ok("step 3 alone: supervisor can no longer call another agent (no role lock in place)", denied(call("supervisor-role")))
ok("step 3 alone: supervisor can still read the secret (only calls are cut)", works(read("supervisor-role")))
core.restore_calls("supervisor-role")
ok("step 3 undo: supervisor can call another agent again", works(call("supervisor-role")))

# ---- step 4 alone: Runtime session
RT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "runtime_state.json")
if os.path.exists(RT):
    rt = json.load(open(RT))
    agc = session.client("bedrock-agentcore")

    def cnt():
        r = agc.invoke_agent_runtime(agentRuntimeArn=rt["runtime_arn"], runtimeSessionId=rt["session_id"], payload=b'{"ping":1}', contentType="application/json")
        return json.loads(r["response"].read())["count"]
    cnt(); before = cnt()
    core.stop_sessions(rt["runtime_arn"], [rt["session_id"]])
    time.sleep(5)
    ok("step 4 alone: the live Runtime session was stopped and its state is gone", before >= 2 and cnt() == 1, f"count before stop {before}")
else:
    print("step 4: skipped (run deploy/runtime_step4.py first to prove it on a real Runtime agent)")

json.dump({"results": results}, open("cuts_alone_results.json", "w"), indent=1)
print(f"\n{sum(1 for r in results if r[1]=='PASS')} of {len(results)} checks passed. Saved cuts_alone_results.json")
