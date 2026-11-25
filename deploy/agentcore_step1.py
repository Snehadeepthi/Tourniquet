"""Step 1 on real AgentCore: an IAM-secured Gateway with a Policy Engine, one order tool, and the Cedar forbid.

Run AFTER deploy.py (it creates supervisor-role and subagents-role itself if they are missing). Region ap-southeast-2.
It proves step 1 on its own: while supervisor-role still has full IAM rights, the Gateway refuses it,
and subagents-role (the helpers) still gets through.   python deploy/agentcore_step1.py
Writes agentcore_state.json and agentcore_results.json.
"""
import io, json, os, sys, time, zipfile, urllib.request, urllib.error
import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tourniquet_slice import core

REGION = core.REGION
session = boto3.Session(region_name=REGION, profile_name=os.environ.get("AWS_PROFILE"))
acct = session.client("sts").get_caller_identity()["Account"]
iam, lam, sts, ac = (session.client(x) for x in ("iam", "lambda", "sts", "bedrock-agentcore-control"))
ddb = session.resource("dynamodb")
os.environ.setdefault("TQ_AUDIT_BUCKET", f"tq-audit-{acct}")
core.AUDIT_BUCKET = os.environ["TQ_AUDIT_BUCKET"]
results = []
ENGINE, GATEWAY, TARGET, TOOL_LAMBDA, GW_ROLE = "tq_engine", "tq-gateway", "OrderTarget", "tq-gw-tool", "tq-gateway-role"
ACTION = f"{TARGET}___place_order"
TRUST = lambda svc: json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": svc}, "Action": "sts:AssumeRole"}]})


def ok(name, passed, note=""):
    results.append((name, "PASS" if passed else "FAIL", note))
    print(f"[{'PASS' if passed else 'FAIL'}] {name} {note}")


def stop(msg):
    print("STOPPED:", msg)
    json.dump(results, open("agentcore_results.json", "w"), indent=1)
    sys.exit(1)


# ---- 1. the tool Lambda behind the gateway (separate from order-tools so concurrency 0 does not interfere)
zb = io.BytesIO()
with zipfile.ZipFile(zb, "w") as z:
    z.writestr("t.py", "import json\ndef h(e, c):\n    return {'order': 'placed', 'item': e.get('item')}\n")
try:
    iam.create_role(RoleName="tq-gw-tool-exec", AssumeRolePolicyDocument=TRUST("lambda.amazonaws.com"))
    iam.attach_role_policy(RoleName="tq-gw-tool-exec", PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")
    time.sleep(12)
except iam.exceptions.EntityAlreadyExistsException:
    pass
try:
    lam.delete_function(FunctionName=TOOL_LAMBDA)
except lam.exceptions.ResourceNotFoundException:
    pass
tool_arn = lam.create_function(FunctionName=TOOL_LAMBDA, Runtime="python3.12", Handler="t.h", Code={"ZipFile": zb.getvalue()},
                               Role=f"arn:aws:iam::{acct}:role/tq-gw-tool-exec")["FunctionArn"]
lam.get_waiter("function_active_v2").wait(FunctionName=TOOL_LAMBDA)       # a new Lambda is Pending for a moment

# ---- 2. gateway service role
try:
    iam.create_role(RoleName=GW_ROLE, AssumeRolePolicyDocument=TRUST("bedrock-agentcore.amazonaws.com"))
except iam.exceptions.EntityAlreadyExistsException:
    pass
iam.put_role_policy(RoleName=GW_ROLE, PolicyName="gw", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": tool_arn},
    {"Effect": "Allow", "Action": ["bedrock-agentcore:AuthorizeAction", "bedrock-agentcore:PartiallyAuthorizeActions",
                                   "bedrock-agentcore:GetPolicyEngine"], "Resource": "*"}]}))
time.sleep(12)

# ---- 3. policy engine, then the gateway with the engine attached in ENFORCE mode
engine = next((e for e in ac.list_policy_engines().get("policyEngines", []) if e["name"] == ENGINE), None)
if not engine:
    engine = ac.create_policy_engine(name=ENGINE, description="Tourniquet step 1 demo")
engine = core._wait(lambda: ac.get_policy_engine(policyEngineId=engine["policyEngineId"]))
ok("policy engine is ACTIVE", engine["status"] == "ACTIVE", engine["status"])
if engine["status"] != "ACTIVE":
    stop(f"policy engine {engine.get('statusReasons')}")
gw = next((g for g in ac.list_gateways().get("items", []) if g["name"] == GATEWAY), None)
if gw:
    gw = ac.get_gateway(gatewayIdentifier=gw["gatewayId"])
else:
    gw = ac.create_gateway(name=GATEWAY, protocolType="MCP", authorizerType="AWS_IAM",
                           roleArn=f"arn:aws:iam::{acct}:role/{GW_ROLE}",
                           policyEngineConfiguration={"mode": "ENFORCE", "arn": engine["policyEngineArn"]})
gw = core._wait(lambda: ac.get_gateway(gatewayIdentifier=gw["gatewayId"]))
ok("gateway is READY with the engine in ENFORCE mode", gw["status"] == "READY" and gw.get("policyEngineConfiguration", {}).get("mode") == "ENFORCE", gw["status"])
if gw["status"] != "READY":
    stop(f"gateway {gw.get('statusReasons')}")
GW_ARN, GW_URL = gw["gatewayArn"], gw["gatewayUrl"]

tgt = next((t for t in ac.list_gateway_targets(gatewayIdentifier=gw["gatewayId"]).get("items", []) if t["name"] == TARGET), None)
if not tgt:
    tgt = ac.create_gateway_target(gatewayIdentifier=gw["gatewayId"], name=TARGET,
        targetConfiguration={"mcp": {"lambda": {"lambdaArn": tool_arn, "toolSchema": {"inlinePayload": [{
            "name": "place_order", "description": "Place a shop order",
            "inputSchema": {"type": "object", "properties": {"item": {"type": "string"}}, "required": ["item"]}}]}}}},
        credentialProviderConfigurations=[{"credentialProviderType": "GATEWAY_IAM_ROLE"}])
tgt = core._wait(lambda: ac.get_gateway_target(gatewayIdentifier=gw["gatewayId"], targetId=tgt["targetId"]))
ok("order tool target is READY", tgt["status"] == "READY", tgt["status"])
if tgt["status"] != "READY":
    stop(f"target {tgt.get('statusReasons')}")

# ---- 4. a permit for every assumed-role caller in this account (default is deny; forbid will win over this)
def policies():
    return ac.list_policies(policyEngineId=engine["policyEngineId"]).get("policies", [])


for p in policies():
    if p["name"].startswith("tq_forbid"):
        ac.delete_policy(policyEngineId=engine["policyEngineId"], policyId=p["policyId"])   # remove forbids from earlier runs
permit = (f'permit(principal is AgentCore::IamEntity, action == AgentCore::Action::"{ACTION}",\n'
          f'  resource == AgentCore::Gateway::"{GW_ARN}")\nwhen {{ principal.id like "arn:aws:sts::{acct}:assumed-role/*" }};')
pr = None
for _ in range(20):                       # reuse the permit if one is already there; wait out any delete in progress
    found = [p for p in policies() if p["name"] == "tq_permit_agents"]
    if found and found[0]["status"] == "ACTIVE":
        pr = found[0]; print("permit already in place"); break
    if not found:
        try:
            pr = ac.create_policy(policyEngineId=engine["policyEngineId"], name="tq_permit_agents", validationMode="FAIL_ON_ANY_FINDINGS",
                                  description="Agents may place orders", definition={"cedar": {"statement": permit}})
            pid = pr["policyId"]
            pr = core._wait(lambda: ac.get_policy(policyEngineId=engine["policyEngineId"], policyId=pid))
            break
        except Exception as e:
            if "ConflictException" not in str(e):
                ok("permit policy accepted by AgentCore validation", False, str(e)[:300]); stop("permit refused. See the line above.")
    time.sleep(6)
ok("permit policy accepted by AgentCore validation", bool(pr) and pr["status"] == "ACTIVE", f"{pr and pr['status']}")
if not pr or pr["status"] != "ACTIVE":
    stop("permit not active. See the line above.")

# ---- 5. callers: both roles may use the gateway at IAM level (so a denial can only be Cedar)
for r in ("supervisor-role", "subagents-role"):
    try:                                                                            # on a fresh account the demo roles do not exist yet
        iam.create_role(RoleName=r, AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{acct}:root"}, "Action": "sts:AssumeRole"}]}))
    except iam.exceptions.EntityAlreadyExistsException:
        pass
    try:
        iam.delete_role_policy(RoleName=r, PolicyName="TourniquetQuarantine")      # undo any earlier role lock
    except iam.exceptions.NoSuchEntityException:
        pass
    iam.put_role_policy(RoleName=r, PolicyName="gateway-call", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "bedrock-agentcore:InvokeGateway", "Resource": GW_ARN}]}))
time.sleep(15)


def creds_for(role):
    return sts.assume_role(RoleArn=f"arn:aws:iam::{acct}:role/{role}", RoleSessionName=role.split("-")[0])["Credentials"]


def mcp(creds, method, params=None):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}})
    req = AWSRequest(method="POST", url=GW_URL, data=body, headers={"Content-Type": "application/json"})
    SigV4Auth(Credentials(creds["AccessKeyId"], creds["SecretAccessKey"], creds["SessionToken"]), "bedrock-agentcore", REGION).add_auth(req)
    r = urllib.request.Request(GW_URL, data=body.encode(), headers=dict(req.headers), method="POST")
    try:
        with urllib.request.urlopen(r, timeout=40) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def order(creds):
    st, txt = mcp(creds, "tools/call", {"name": ACTION, "arguments": {"item": "poisoned-order"}})
    try:
        j = json.loads(txt)
        good = st == 200 and "error" not in j and not j.get("result", {}).get("isError") and "placed" in txt
    except ValueError:
        good = False
    return st, txt, good


sup, sub = creds_for("supervisor-role"), creds_for("subagents-role")
st, txt, good = order(sup)
for _ in range(10):                      # permit takes a few seconds to take effect
    if good: break
    time.sleep(6); sup = creds_for("supervisor-role"); st, txt, good = order(sup)
ok("before: supervisor-agent can place an order through the gateway", good, f"HTTP {st} {txt[:160]}")
st, txt, good_h = order(sub)
ok("before: helper agents can place an order too", good_h, f"HTTP {st} {txt[:160]}")
if not good:
    stop("the permitted call failed, so the forbid cannot be tested yet. See the lines above.")

# ---- 6. STEP 1: the Cedar forbid, through the same code Step Functions calls.
# Exact match first (assumed-role/supervisor-role, no wildcard), then role/*, then role*. A pattern that does not match
# still creates fine but refuses nobody, so the supervisor is tested and a non-matching forbid is removed.
res, denied, used = None, False, None
for pattern in ("exact", "strict", "lenient"):
    try:
        res = core.cedar_forbid("supervisor-role", engine["policyEngineId"], GW_ARN, [ACTION], pattern)
        ok(f"step 1: AgentCore accepted the Cedar forbid ({pattern} pattern)", True, f"form: {res['form']}; refused before it: {json.dumps(res['refused_forms'])[:300]}")
    except Exception as e:
        ok(f"step 1: AgentCore accepted the Cedar forbid ({pattern} pattern)", False, str(e)[:400])
        continue
    tries = 0
    while tries < 12 and not denied:
        time.sleep(5); tries += 1
        st, txt, good = order(sup)
        denied = not good
    if denied:
        used = pattern
        break
    print(f"  {pattern} pattern did not refuse the supervisor; removing it and trying the wider pattern")
    core.delete_forbids("supervisor-role", engine["policyEngineId"]); time.sleep(10)
ok("after: the SAME supervisor session is now refused by the gateway (its IAM rights are untouched)", denied, f"pattern used: {used}; HTTP {st} {txt[:200]}")
if not denied:
    stop("no forbid pattern refused the supervisor. See the lines above.")
st, txt, good_h = order(sub)
ok("after: helper agents still get through", good_h, f"HTTP {st} {txt[:160]}")
st, txt = mcp(sup, "tools/list")
ok("after: the forbidden tool is hidden from supervisor-agent's tool list", ACTION not in txt, txt[:160])
st, txt = mcp(sub, "tools/list")
ok("after: helpers still see the tool", ACTION in txt)

# ---- 7. save config so the Step Functions run uses step 1 too
ddb.Table("tq-reach").update_item(Key={"role_name": "supervisor-role"},
    UpdateExpression="SET policy_engine_id = :e, gateway_arn = :g, tool_actions = :a, cedar_pattern = :p", ExpressionAttributeValues={":e": engine["policyEngineId"], ":g": GW_ARN, ":a": [ACTION], ":p": used})
json.dump({"engine_id": engine["policyEngineId"], "gateway_arn": GW_ARN, "gateway_url": GW_URL, "forbid": res, "cedar_pattern": used}, open("agentcore_state.json", "w"), indent=1)
json.dump(results, open("agentcore_results.json", "w"), indent=1)
print(f"\n{sum(1 for r in results if r[1]=='PASS')} of {len(results)} passed. Saved agentcore_results.json")
