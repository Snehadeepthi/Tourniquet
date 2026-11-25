"""Step 4 on a REAL AgentCore Runtime agent. Deploys a tiny agent (pure Python, no packages) whose memory holds a counter,
starts a session, stops it with Tourniquet's own stop_sessions(), and shows the session state is gone.
Run after deploy.py. Writes runtime_state.json (used by scenario_full.py) and runtime_results.json."""
import io, json, os, sys, time, uuid, zipfile
import boto3
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from tourniquet_slice import core

REGION = os.environ.get("TQ_REGION", "ap-southeast-2")
session = boto3.Session(region_name=REGION, profile_name=os.environ.get("AWS_PROFILE"))
acct = session.client("sts").get_caller_identity()["Account"]
s3, iam = session.client("s3"), session.client("iam")
ctl, rt = session.client("bedrock-agentcore-control"), session.client("bedrock-agentcore")
results = []


def ok(name, passed, note=""):
    results.append((name, "PASS" if passed else "FAIL", note))
    print(f"[{'PASS' if passed else 'FAIL'}] {name} {note}")


MAIN = '''import json, time, http.server
COUNT = 0
class H(http.server.BaseHTTPRequestHandler):
    def _send(self, obj):
        b = json.dumps(obj).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        self._send({"status": "Healthy", "time_of_last_update": int(time.time())})
    def do_POST(self):
        global COUNT
        n = int(self.headers.get("Content-Length", 0)); self.rfile.read(n)
        COUNT += 1
        self._send({"count": COUNT})
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()
'''
bucket = f"tq-runtime-code-{acct}"
try:
    if REGION == "us-east-1":                       # this one region must not be given a LocationConstraint
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": REGION})
except Exception as e:
    if "BucketAlreadyOwnedByYou" not in str(e):
        raise
zb = io.BytesIO()
with zipfile.ZipFile(zb, "w") as z:
    z.writestr("main.py", MAIN)
s3.put_object(Bucket=bucket, Key="agent.zip", Body=zb.getvalue())

trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "bedrock-agentcore.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
try:
    iam.create_role(RoleName="tq-runtime-role", AssumeRolePolicyDocument=json.dumps(trust))
except iam.exceptions.EntityAlreadyExistsException:
    pass
iam.put_role_policy(RoleName="tq-runtime-role", PolicyName="rt", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], "Resource": "*"},
    {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": f"arn:aws:s3:::{bucket}/*"}]}))
time.sleep(15)

NAME = "tq_demo_agent"
art = {"codeConfiguration": {"code": {"s3": {"bucket": bucket, "prefix": "agent.zip"}}, "runtime": "PYTHON_3_12", "entryPoint": ["main.py"]}}
existing = [r for r in ctl.list_agent_runtimes().get("agentRuntimes", []) if r["agentRuntimeName"] == NAME]
if existing:
    rid = existing[0]["agentRuntimeId"]
    ctl.update_agent_runtime(agentRuntimeId=rid, agentRuntimeArtifact=art, roleArn=f"arn:aws:iam::{acct}:role/tq-runtime-role", networkConfiguration={"networkMode": "PUBLIC"})
else:
    rid = ctl.create_agent_runtime(agentRuntimeName=NAME, agentRuntimeArtifact=art, roleArn=f"arn:aws:iam::{acct}:role/tq-runtime-role",
                                   networkConfiguration={"networkMode": "PUBLIC"})["agentRuntimeId"]
status = ""
time.sleep(8)
for i in range(60):
    r = ctl.get_agent_runtime(agentRuntimeId=rid)
    status = r["status"]
    if status in ("READY", "CREATE_FAILED", "UPDATE_FAILED"):
        break
    time.sleep(10)
arn = r["agentRuntimeArn"]
ok("the Runtime agent is READY", status == "READY", f"{status} {r.get('failureReason', '')}")
if status != "READY":
    json.dump({"results": results}, open("runtime_results.json", "w"), indent=1)
    sys.exit(1)

sid = "tq-demo-session-" + uuid.uuid4().hex


def count():
    last = None
    for i in range(8):                              # the first call starts a microVM and can take a while
        try:
            resp = rt.invoke_agent_runtime(agentRuntimeArn=arn, runtimeSessionId=sid, payload=json.dumps({"ping": 1}).encode(), contentType="application/json")
            return json.loads(resp["response"].read())["count"]
        except Exception as e:
            last = e
            time.sleep(15)
    raise last


c = [count(), count(), count()]
ok("a live session keeps state between calls", c == [1, 2, 3], str(c))
t0 = time.time()
out = core.stop_sessions(arn, [sid])
ok("Tourniquet's step 4 stops the session", out and out[0]["stopped"] in (True, "already gone"), json.dumps(out))
time.sleep(5)
after = count()
ok("the same session id now starts from scratch (the old session and its state are gone)", after == 1, f"count {after}")
json.dump({"runtime_arn": arn, "session_id": sid}, open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "runtime_state.json"), "w"))
json.dump({"results": results, "runtime_arn": arn}, open("runtime_results.json", "w"), indent=1)
print(f"\n{sum(1 for r in results if r[1]=='PASS')} of {len(results)} passed. Saved runtime_results.json and runtime_state.json")
