"""Full run on real AWS: CloudTrail trigger (nobody starts the pipeline), signed approver identities, the cut, then UNDO.
Needs deploy.py and agentcore_step1.py first. Prints PASS/FAIL, TIMINGS, and writes scenario_full_results.json."""
import json, os, sys, time, datetime
import boto3
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from tourniquet_slice import core, collector

REGION = os.environ.get("TQ_REGION", "ap-southeast-2")
session = boto3.Session(region_name=REGION, profile_name=os.environ.get("AWS_PROFILE"))
acct = session.client("sts").get_caller_identity()["Account"]
iam, lam, sts, ddb = (session.client(x) for x in ("iam", "lambda", "sts", "dynamodb"))
sfn = session.client("stepfunctions")
db = session.resource("dynamodb")
MACHINE = f"arn:aws:states:{REGION}:{acct}:stateMachine:tq-contain"
TRUST_LAMBDA = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
TRUST_ME = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{acct}:root"}, "Action": "sts:AssumeRole"}]}
results = []


def ok(name, passed, note=""):
    results.append((name, "PASS" if passed else "FAIL", note))
    print(f"[{'PASS' if passed else 'FAIL'}] {name} {note}")


def ensure_role(name, perms):
    try:
        iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(TRUST_ME if name != "x" else TRUST_LAMBDA))
    except iam.exceptions.EntityAlreadyExistsException:
        iam.update_assume_role_policy(RoleName=name, PolicyDocument=json.dumps(TRUST_ME))
    iam.put_role_policy(RoleName=name, PolicyName="shop-perms", PolicyDocument=json.dumps(perms))


SECRET = "tq-demo/orders-db-password"
SECRET_ARN = f"arn:aws:secretsmanager:{REGION}:{acct}:secret:tq-demo/*"
HELPER_ARN = f"arn:aws:lambda:{REGION}:{acct}:function:tq-helper-agent"
# ---- app plane: stand-in shop (supervisor-role, subagents-role, a backdoor user, a tool Lambda)
ensure_role("supervisor-role", {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Action": ["iam:ListUsers", "iam:CreateAccessKey"], "Resource": "*"},
    {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": SECRET_ARN},
    {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": HELPER_ARN}]})
ensure_role("subagents-role", {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "iam:ListUsers", "Resource": "*"},
    {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": SECRET_ARN}]})
for pn in ("TourniquetQuarantine", "TourniquetCutCalls"):
    try:
        iam.delete_role_policy(RoleName="supervisor-role", PolicyName=pn)
    except iam.exceptions.NoSuchEntityException:
        pass
sm = session.client("secretsmanager")
BASE_SECRET = "baseline-password-1"
try:
    sm.create_secret(Name=SECRET, SecretString=BASE_SECRET)
except sm.exceptions.ResourceExistsException:
    try:
        sm.delete_resource_policy(SecretId=SECRET)
    except Exception:
        pass
    sm.put_secret_value(SecretId=SECRET, SecretString=BASE_SECRET)
try:
    iam.create_user(UserName="backdoor-user")
except iam.exceptions.EntityAlreadyExistsException:
    pass
for k in iam.list_access_keys(UserName="backdoor-user")["AccessKeyMetadata"]:
    iam.delete_access_key(UserName="backdoor-user", AccessKeyId=k["AccessKeyId"])
try:
    lam.delete_function(FunctionName="tq-helper-agent")
except lam.exceptions.ResourceNotFoundException:
    pass
try:
    lam.delete_function(FunctionName="order-tools")
except lam.exceptions.ResourceNotFoundException:
    pass
time.sleep(10)  # IAM propagation
import io, zipfile
zb = io.BytesIO()
with zipfile.ZipFile(zb, "w") as z:
    z.writestr("x.py", "def y(e, c):\n    return 'order tool'\n")
iam.create_role(RoleName="order-tools-exec", AssumeRolePolicyDocument=json.dumps(TRUST_LAMBDA)) if "order-tools-exec" not in [r["RoleName"] for r in iam.list_roles()["Roles"]] else None
time.sleep(10)
lam.create_function(FunctionName="order-tools", Runtime="python3.12", Handler="x.y", Code={"ZipFile": zb.getvalue()},
                    Role=f"arn:aws:iam::{acct}:role/order-tools-exec")
lam.create_function(FunctionName="tq-helper-agent", Runtime="python3.12", Handler="x.y", Code={"ZipFile": zb.getvalue()},
                    Role=f"arn:aws:iam::{acct}:role/order-tools-exec")     # a stand-in "other agent" the supervisor calls
for _fn in ("order-tools", "tq-helper-agent"):       # a new Lambda is Pending for a moment; calling it too early fails
    lam.get_waiter("function_active_v2").wait(FunctionName=_fn)

sup = sts.assume_role(RoleArn=f"arn:aws:iam::{acct}:role/supervisor-role", RoleSessionName="supervisor")["Credentials"]
sub = sts.assume_role(RoleArn=f"arn:aws:iam::{acct}:role/subagents-role", RoleSessionName="helper")["Credentials"]


def client_with(creds, svc):
    return boto3.client(svc, region_name=REGION, aws_access_key_id=creds["AccessKeyId"],
                        aws_secret_access_key=creds["SecretAccessKey"], aws_session_token=creds["SessionToken"])


ok("before: supervisor session works", bool(client_with(sup, "iam").list_users()))
ok("before: helper session works", bool(client_with(sub, "iam").list_users()))
ok("before: supervisor reads the vault secret", client_with(sup, "secretsmanager").get_secret_value(SecretId=SECRET)["SecretString"] == BASE_SECRET)
ok("before: helper reads the vault secret", client_with(sub, "secretsmanager").get_secret_value(SecretId=SECRET)["SecretString"] == BASE_SECRET)
ok("before: supervisor can call another agent (tq-helper-agent)", client_with(sup, "lambda").invoke(FunctionName="tq-helper-agent", Payload=b"{}")["StatusCode"] == 200)

# ---- real identities for approvers: four roles. Each may only call the two API routes (execute-api:Invoke);
# none may invoke the Lambdas directly, which is what makes the caller identity unforgeable.
cfn = session.client("cloudformation")
API_URL = {o["OutputKey"]: o["OutputValue"] for o in cfn.describe_stacks(StackName="tourniquet-slice")["Stacks"][0]["Outputs"]}["ApiUrl"].rstrip("/")
API_ID = API_URL.split("//")[1].split(".")[0]
routes = [f"arn:aws:execute-api:{REGION}:{acct}:{API_ID}/*/POST/{n}" for n in ("approve", "lift")] + [f"arn:aws:execute-api:{REGION}:{acct}:{API_ID}/*/GET/plans"]
for r in ("tq-demo-owner", "tq-demo-sec-lead", "tq-orchestrator-role", "tq-demo-stranger"):
    ensure_role(r, {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "execute-api:Invoke", "Resource": routes}]})
time.sleep(12)

# ---- control plane tables: reach graph + sessions
reach_item = {"role_name": "supervisor-role", "agent": "supervisor-agent", "owner": "tq-demo-owner",
    "tool_lambda": "order-tools", "secrets": [SECRET], "shared": ["subagents-role", "orders-db-password", "customer-notes"]}
RT_STATE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "runtime_state.json")
rt = json.load(open(RT_STATE)) if os.path.exists(RT_STATE) else None
agc = session.client("bedrock-agentcore")


def rt_count(arn, sid):
    r = agc.invoke_agent_runtime(agentRuntimeArn=arn, runtimeSessionId=sid, payload=json.dumps({"ping": 1}).encode(), contentType="application/json")
    return json.loads(r["response"].read())["count"]

AC_STATE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "agentcore_state.json")
ac = session.client("bedrock-agentcore-control")
st = None
if os.path.exists(AC_STATE):
    st = json.load(open(AC_STATE))
else:                                     # no state file: find the gateway and engine in AWS by name
    eng = [e for e in ac.list_policy_engines().get("policyEngines", []) if e["name"] == "tq_engine"]
    gws = [g for g in ac.list_gateways().get("items", []) if g["name"] == "tq-gateway"]
    if eng and gws:
        st = {"engine_id": eng[0]["policyEngineId"], "gateway_arn": ac.get_gateway(gatewayIdentifier=gws[0]["gatewayId"])["gatewayArn"]}
print("AgentCore gateway found, step 1 will run in the plan" if st else "No AgentCore gateway found: step 1 will not be in the plan (run agentcore_step1.py first)")
if st:
    reach_item.update(policy_engine_id=st["engine_id"], gateway_arn=st["gateway_arn"], tool_actions=["OrderTarget___place_order"])
    for p in ac.list_policies(policyEngineId=st["engine_id"]).get("policies", []):      # start with the agent NOT yet cut
        if p["name"].startswith("tq_forbid"):
            ac.delete_policy(policyEngineId=st["engine_id"], policyId=p["policyId"])
    time.sleep(10)
old = db.Table("tq-reach").get_item(Key={"role_name": "supervisor-role"}).get("Item") or {}
if old.get("cedar_pattern"):
    reach_item["cedar_pattern"] = old["cedar_pattern"]
# the reach map is DISCOVERED from the account (roles, policies, secrets, tagged tool Lambda), not typed
iam.tag_role(RoleName="supervisor-role", Tags=[{"Key": "tq-owner", "Value": "tq-demo-owner"}] + ([{"Key": "tq-runtime", "Value": "tq_demo_agent"}] if rt else []))
lam.tag_resource(Resource=lam.get_function(FunctionName="order-tools")["Configuration"]["FunctionArn"], Tags={"tq-tool-of": "supervisor-agent"})
disc = collector.discover("supervisor-role", "supervisor-agent")
ok("the Collector discovered the reach map (secret, helper role that shares it, tool Lambda, owner)",
   disc["secrets"] == [SECRET] and "subagents-role" in disc["shared"] and disc.get("tool_lambda") == "order-tools" and disc["owner"] == "tq-demo-owner",
   json.dumps({k: disc[k] for k in ("secrets", "shared", "calls", "owner")}))
reach_item.update({k: v for k, v in disc.items() if k not in ("runtime_arn",) or rt})
if rt:
    reach_item["runtime_arn"] = rt["runtime_arn"]
db.Table("tq-reach").put_item(Item=json.loads(json.dumps(reach_item), parse_float=str))
db.Table("tq-sessions").put_item(Item={"access_key_id": sup["AccessKeyId"], "agent": "supervisor-agent"})
if rt:                                    # a live Runtime session of the supervisor, with some state in it
    for _ in range(2):
        before_count = rt_count(rt["runtime_arn"], rt["session_id"])
    db.Table("tq-sessions").put_item(Item={"access_key_id": "runtime-" + rt["session_id"], "agent": "supervisor-agent", "runtime_session_id": rt["session_id"]})
    ok("before: the supervisor's Runtime session is live and holds state", before_count >= 2, f"count {before_count}")

# ---- clean slate: stop old waiting executions, drop stale approvals and unfinished alerts (finished ones stay)
for e in sfn.list_executions(stateMachineArn=MACHINE, statusFilter="RUNNING")["executions"]:
    sfn.stop_execution(executionArn=e["executionArn"], cause="new scenario run")
for it in ddb.scan(TableName="tq-approvals")["Items"]:
    ddb.delete_item(TableName="tq-approvals", Key={"plan_id": it["plan_id"]})
for it in ddb.scan(TableName="tq-alerts")["Items"]:
    if it["state"]["S"] in ("open", "planned", "approved"):
        ddb.delete_item(TableName="tq-alerts", Key={"alert_id": it["alert_id"]})


# ---- the trigger: the poller marks what CloudTrail already holds, so only the NEW event starts a run
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
import urllib.request, urllib.error
ev_rule = session.client("events")
ev_rule.enable_rule(Name="tq-poll-every-minute")
mark = json.loads(lam.invoke(FunctionName="tq-poll", Payload=json.dumps({"mark_seen": True}))["Payload"].read())
print("poller marked existing CloudTrail events:", mark)


def signed_post(url, role, body):
    c = sts.assume_role(RoleArn=f"arn:aws:iam::{acct}:role/{role}", RoleSessionName=role)["Credentials"]
    data = json.dumps(body)
    req = AWSRequest(method="POST", url=url, data=data, headers={"Content-Type": "application/json"})
    SigV4Auth(Credentials(c["AccessKeyId"], c["SecretAccessKey"], c["SessionToken"]), "execute-api", REGION).add_auth(req)
    r = urllib.request.Request(url, data=data.encode(), headers=dict(req.headers), method="POST")
    try:
        with urllib.request.urlopen(r, timeout=60) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return {"ok": False, "why": f"HTTP {e.code} {e.read().decode()[:200]}"}


APPROVE_URL = API_URL + "/approve"
LIFT_URL = API_URL + "/lift"
utc = lambda: datetime.datetime.now(datetime.timezone.utc)

def run_signal(record):
    ex = sfn.start_execution(stateMachineArn=MACHINE, input=json.dumps({"record": record}))["executionArn"]
    for _ in range(60):
        if sfn.describe_execution(executionArn=ex)["status"] != "RUNNING":
            break
        time.sleep(2)
    return sfn.describe_execution(executionArn=ex)["status"]


# Alert types in this release: 1 (threat finding, sent in below) and 3 (secret misuse, real GetSecretValue calls read from CloudTrail).
# The hijacked role also creates an access key (real): that gives step 7 its target. Prompt injection (type 6) is left out for now.
# ---- signal 1 (type 1): a GuardDuty-shaped finding about the supervisor's session goes through the same pipeline
ok("signal 1 (type 1): a GuardDuty finding about the supervisor role becomes a signal, no plan yet", run_signal({"source": "aws.guardduty",
   "detail-type": "GuardDuty Finding", "detail": {"type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration", "severity": 8,
   "resource": {"accessKeyDetails": {"userType": "AssumedRole", "userName": "supervisor-role", "accessKeyId": sup["AccessKeyId"]}}}}) == "SUCCEEDED",
   "shape of a GuardDuty finding, sent into the pipeline directly (GuardDuty itself is not enabled in this demo)")

# ---- the hijack: the supervisor role really creates a key. NOTHING below starts the pipeline.
T_HIJACK = utc()
sup_sm = client_with(sup, "secretsmanager")
for _ in range(30):                                   # a burst of secret reads, far above the agent's normal of a few
    sup_sm.get_secret_value(SecretId=SECRET)
new = client_with(sup, "iam").create_access_key(UserName="backdoor-user")["AccessKey"]   # the hijacked role also makes itself a key
print("hijack done (30 secret reads + a new access key); waiting for CloudTrail and the poller to start the pipeline by themselves (usually 1 to 4 minutes)...")
plan_id, ex2 = None, None
for i in range(300):
    time.sleep(3)
    items = [x for x in ddb.scan(TableName="tq-approvals")["Items"] if x["state"]["S"] == "waiting"]
    if items:
        plan_id = items[0]["plan_id"]["S"]; break
    if i % 10 == 9:
        print(f"  not yet ({int((utc() - T_HIJACK).total_seconds())}s)")
T_PLAN = utc()
ok("the poller counted the real secret reads from CloudTrail, saw a spike, started the pipeline and a plan is waiting for approval", plan_id is not None,
   f"after {int((T_PLAN - T_HIJACK).total_seconds())}s")
if plan_id is None:
    sys.exit(1)
running = sfn.list_executions(stateMachineArn=MACHINE, statusFilter="RUNNING")["executions"]
ex2 = running[0]["executionArn"] if running else None
inp = json.loads(sfn.describe_execution(executionArn=ex2)["input"]) if ex2 else {}
rec = inp.get("record", {})
def signed_get(url, role):
    c = sts.assume_role(RoleArn=f"arn:aws:iam::{acct}:role/{role}", RoleSessionName=role)["Credentials"]
    req = AWSRequest(method="GET", url=url, data="", headers={})
    SigV4Auth(Credentials(c["AccessKeyId"], c["SecretAccessKey"], c["SessionToken"]), "execute-api", REGION).add_auth(req)
    with urllib.request.urlopen(urllib.request.Request(url, headers=dict(req.headers), method="GET"), timeout=60) as resp:
        return json.loads(resp.read())


lst = signed_get(API_URL + "/plans", "tq-demo-sec-lead")
ok("the approver page's data route lists the waiting plan for the security person", lst.get("ok") and any(w["plan_id"] == plan_id for w in lst.get("waiting", [])),
   f"{len(lst.get('waiting', []))} waiting, seen as {lst.get('you')}")
_plan_row = ddb.get_item(TableName="tq-approvals", Key={"plan_id": {"S": plan_id}})["Item"]
_pj = json.loads(_plan_row["plan_json"]["S"])
print("Plan made by:", _pj.get("plan_source"), "-", _pj.get("rationale"))
ok("the plan says who made it (Bedrock Orchestrator or rules) and why", bool(_pj.get("plan_source")) and bool(_pj.get("rationale")), f"{_pj.get('plan_source')}: {_pj.get('rationale', '')[:160]}")
# Both the secret-read spike (type 3) and the create-key (type 2) reach the same Alert; either one's pipeline may be the one that
# made the plan. Wait until the Alert has the type 3 evidence and the key, let the other pipeline finish ("already planned"), then
# follow the one pipeline that is still waiting for the approval.
_have = None
for _ in range(100):
    al = [a for a in ddb.scan(TableName="tq-alerts")["Items"] if a.get("agent", {}).get("S") == "supervisor-agent" and a["state"]["S"] not in ("lifted", "expired")]
    txt = json.dumps(al)
    if new["AccessKeyId"] in txt and "secret reads in a minute" in txt:
        _have = True; break
    time.sleep(3)
ok("the Alert has the type 3 secret-read spike AND the key the hijacked role created as evidence", bool(_have), new["AccessKeyId"])
time.sleep(25)
running = sfn.list_executions(stateMachineArn=MACHINE, statusFilter="RUNNING")["executions"]
ex2 = running[0]["executionArn"] if running else ex2
ok("exactly one pipeline is still waiting for the approval", len(running) == 1, f"{len(running)} running")
_plan_row = ddb.get_item(TableName="tq-approvals", Key={"plan_id": {"S": plan_id}})["Item"]
ok("the waiting plan includes the key to deactivate (step 7 has its target)", new["AccessKeyId"] in _plan_row["plan_json"]["S"], new["AccessKeyId"])

# ---- approvals: identity comes from the signed request
r = json.loads(lam.invoke(FunctionName="tq-approve", Payload=json.dumps({"plan_id": plan_id, "approver": "sec-lead"}))["Payload"].read())
ok("a typed name is refused (no verified identity)", r.get("ok") is False, r.get("why", ""))
sl = sts.assume_role(RoleArn=f"arn:aws:iam::{acct}:role/tq-demo-sec-lead", RoleSessionName="direct")["Credentials"]
try:
    client_with(sl, "lambda").invoke(FunctionName="tq-approve", Payload=b"{}")
    direct = "not blocked"
except Exception as e:
    direct = "blocked" if "AccessDenied" in str(e) else str(e)[:120]
ok("an approver cannot call the Lambda directly (no way to forge the caller)", direct == "blocked", direct)
r = signed_post(APPROVE_URL, "tq-demo-stranger", {"plan_id": plan_id})
ok("a signed caller who is not on the approver list is refused", r.get("ok") is False and "approver list" in r.get("why", ""), r.get("why", ""))
r = signed_post(APPROVE_URL, "tq-demo-owner", {"plan_id": plan_id})
ok("the agent's owner (signed as tq-demo-owner) is refused", r.get("ok") is False, r.get("why", ""))
r = signed_post(APPROVE_URL, "tq-orchestrator-role", {"plan_id": plan_id})
ok("the Orchestrator's own identity is refused", r.get("ok") is False, r.get("why", ""))
T_APPR = utc()
r = signed_post(APPROVE_URL, "tq-demo-sec-lead", {"plan_id": plan_id})
ok("a security person (signed as tq-demo-sec-lead) approves", r.get("ok") is True, r.get("approver", ""))
row = ddb.get_item(TableName="tq-approvals", Key={"plan_id": {"S": plan_id}})["Item"]
ok("the approval records the real IAM ARN of the approver", "tq-demo-sec-lead" in row.get("approver_arn", {}).get("S", ""), row.get("approver_arn", {}).get("S", ""))
for _ in range(150):
    d2 = sfn.describe_execution(executionArn=ex2)
    if d2["status"] != "RUNNING": break
    time.sleep(2)
ok("Step Functions finished the cut", d2["status"] == "SUCCEEDED", d2["status"])
_c = None
for _ in range(60):                                   # the Alert is the truth: wait until it says contained
    _c = [a["state"]["S"] for a in ddb.scan(TableName="tq-alerts")["Items"] if a.get("agent", {}).get("S") == "supervisor-agent" and a["state"]["S"] in ("contained", "contained_with_errors")]
    if _c: break
    time.sleep(2)
ok("the Alert for supervisor-agent is marked contained", bool(_c), str(_c))
timings = {}
if d2.get("stopDate"):
    timings["approval_to_cut_done_s"] = round((d2["stopDate"] - T_APPR).total_seconds(), 1)
ev_t = T_HIJACK
if ev_t:
    timings["real_event_to_plan_waiting_s"] = round((T_PLAN - ev_t).total_seconds(), 1)
    timings["real_event_to_cut_done_s"] = round((d2["stopDate"] - ev_t).total_seconds(), 1) if d2.get("stopDate") else None
timings["hijack_to_plan_waiting_s"] = round((T_PLAN - T_HIJACK).total_seconds(), 1)
timings["pipeline_start_to_plan_waiting_s"] = round((T_PLAN - d2["startDate"]).total_seconds(), 1)

time.sleep(15)
cut = False
try:
    client_with(sup, "iam").list_users()
except Exception as e:
    cut = "AccessDenied" in str(e)
ok("POC check A: the old supervisor session is now denied", cut)
try:
    client_with(sts.assume_role(RoleArn=f"arn:aws:iam::{acct}:role/supervisor-role", RoleSessionName="again")["Credentials"], "iam").list_users()
    new_denied = False
except Exception as e:
    new_denied = "AccessDenied" in str(e)
ok("POC check A: a NEW supervisor session is denied too", new_denied)
ok("helpers keep running", bool(client_with(sub, "iam").list_users()))
ok("step 1: a Cedar forbid for supervisor-role is in the gateway's engine", "policy_engine_id" in reach_item and any(
    p["name"].startswith("tq_forbid_supervisor_role") for p in ac.list_policies(policyEngineId=reach_item["policy_engine_id"]).get("policies", [])))
keys = iam.list_access_keys(UserName="backdoor-user")["AccessKeyMetadata"]
ok("the key the agent created is Inactive", all(k["Status"] == "Inactive" for k in keys) and bool(keys))
ok("tool Lambda concurrency is 0", lam.get_function_concurrency(FunctionName="order-tools").get("ReservedConcurrentExecutions") == 0)
ok("subagents-role has no quarantine policy", "TourniquetQuarantine" not in iam.list_role_policies(RoleName="subagents-role")["PolicyNames"])
pol = (sm.get_resource_policy(SecretId=SECRET).get("ResourcePolicy") or "")
ok("step 2: the vault secret has a deny for supervisor-role", "TourniquetDenysupervisorrole" in pol)
new_val = sm.get_secret_value(SecretId=SECRET)["SecretString"]
stages = sm.describe_secret(SecretId=SECRET)["VersionIdsToStages"]
STEP8 = any(s["n"] == 8 and s["implemented"] for s in _pj["steps"])     # the Orchestrator may leave step 8 out on purpose
if STEP8:
    ok("step 8: the secret was rotated (new value, old value not AWSPREVIOUS)", new_val != BASE_SECRET and not any("AWSPREVIOUS" in v for v in stages.values()))
    ok("step 8: helpers read the NEW value", client_with(sub, "secretsmanager").get_secret_value(SecretId=SECRET)["SecretString"] == new_val)
else:
    ok("step 8: the secret is shared with helpers (or the Orchestrator left rotation out), so it was NOT rotated", new_val == BASE_SECRET, "rotation mechanics are proven on their own in cuts_alone.py")
try:
    client_with(sup, "secretsmanager").get_secret_value(SecretId=SECRET); sup_secret = False
except Exception as e:
    sup_secret = "AccessDenied" in str(e)
ok("step 2: the supervisor cannot read the secret", sup_secret)
ok("step 3: the supervisor has the agent-calls cut policy", "TourniquetCutCalls" in iam.list_role_policies(RoleName="supervisor-role")["PolicyNames"])
if rt:
    after_count = rt_count(rt["runtime_arn"], rt["session_id"])
    ok("step 4: the supervisor's Runtime session was stopped (its state is gone)", after_count == 1, f"count {after_count}")

# ---- UNDO: lift the cut with the same identity rules
r = signed_post(LIFT_URL, "tq-demo-stranger", {"agent": "supervisor-agent"})
ok("undo: a caller who is not on the approver list cannot lift", r.get("ok") is False and "approver list" in r.get("why", ""), r.get("why", ""))
r = signed_post(LIFT_URL, "tq-demo-owner", {"agent": "supervisor-agent"})
ok("undo: the owner cannot lift the cut", r.get("ok") is False, r.get("why", ""))
r = signed_post(LIFT_URL, "tq-orchestrator-role", {"agent": "supervisor-agent"})
ok("undo: the Orchestrator cannot lift the cut", r.get("ok") is False, r.get("why", ""))
T_LIFT = utc()
r = signed_post(LIFT_URL, "tq-demo-sec-lead", {"agent": "supervisor-agent"})
ok("undo: a security person lifts the cut", r.get("ok") is True, json.dumps([(x["n"], x["status"]) for x in r.get("results", [])]))
timings["lift_call_s"] = round((utc() - T_LIFT).total_seconds(), 1)
time.sleep(15)
try:
    again = client_with(sts.assume_role(RoleArn=f"arn:aws:iam::{acct}:role/supervisor-role", RoleSessionName="back")["Credentials"], "iam").list_users()
    back = bool(again)
except Exception as e:
    back = False
ok("undo: a supervisor session works again", back)
ok("undo: the Cedar forbid is gone from the engine", not any(p["name"].startswith("tq_forbid_supervisor_role") for p in
   ac.list_policies(policyEngineId=reach_item["policy_engine_id"]).get("policies", [])) if "policy_engine_id" in reach_item else True)
ok("undo: the vault deny is gone, supervisor reads the (rotated) secret again", client_with(sts.assume_role(RoleArn=f"arn:aws:iam::{acct}:role/supervisor-role", RoleSessionName="vault")["Credentials"], "secretsmanager").get_secret_value(SecretId=SECRET)["SecretString"] == new_val)
ok("undo: the agent-calls cut is gone, supervisor can call tq-helper-agent", client_with(sts.assume_role(RoleArn=f"arn:aws:iam::{acct}:role/supervisor-role", RoleSessionName="calls")["Credentials"], "lambda").invoke(FunctionName="tq-helper-agent", Payload=b"{}")["StatusCode"] == 200)
ok("undo: the secret stays rotated" if STEP8 else "undo: the secret is unchanged (step 8 was not in the plan)",
   sm.get_secret_value(SecretId=SECRET)["SecretString"] == new_val and (not STEP8 or new_val != BASE_SECRET))
ok("undo: tool Lambda concurrency limit removed", "ReservedConcurrentExecutions" not in lam.get_function_concurrency(FunctionName="order-tools"))
keys = iam.list_access_keys(UserName="backdoor-user")["AccessKeyMetadata"]
ok("undo: the key the agent created stays Inactive", all(k["Status"] == "Inactive" for k in keys) and bool(keys))
r = signed_post(LIFT_URL, "tq-demo-sec-lead", {"agent": "supervisor-agent"})
ok("undo: lifting again is refused (nothing left to lift)", r.get("ok") is False, r.get("why", ""))

print("\nTIMINGS (seconds):", json.dumps(timings, indent=1))
json.dump({"results": results, "timings": timings}, open("scenario_full_results.json", "w"), indent=1)
p_ = sum(1 for r in results if r[1] == "PASS")
print(f"\n{p_} of {len(results)} checks passed. Saved scenario_full_results.json")
