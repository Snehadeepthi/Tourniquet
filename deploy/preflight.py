"""Checks that this account and region can run Tourniquet, before you deploy. Changes nothing.
Usage: python deploy/preflight.py     (prints OK / WARN / FAIL per check, exits 1 on any FAIL)"""
import os, sys
import boto3
import botocore
REGION = os.environ.get("TQ_REGION", "ap-southeast-2")
s = boto3.Session(region_name=REGION, profile_name=os.environ.get("AWS_PROFILE"))
bad = 0


def show(level, what, why=""):
    global bad
    bad += level == "FAIL"
    print(f"[{level}] {what}" + (f": {why}" if why else ""))


def need(name, fn, fail_msg):
    try:
        return fn()
    except Exception as e:
        show("FAIL", name, f"{fail_msg} ({str(e)[:120]})")


print(f"Region {REGION}")
who = need("AWS credentials", lambda: s.client("sts").get_caller_identity(), "no working credentials; in CloudShell run: unset AWS_PROFILE")
if not who:
    sys.exit(1)
acct = who["Account"]
show("OK", "AWS credentials", who["Arn"].split("/")[-1] if "assumed-role" in who["Arn"] else who["Arn"])

if tuple(int(x) for x in boto3.__version__.split(".")[:2]) < (1, 40):
    show("WARN", "boto3 is old", f"{boto3.__version__}; run: pip install -U boto3 (AgentCore calls need a recent version)")
else:
    show("OK", "boto3 version", boto3.__version__)

if need("AgentCore is available in this region", lambda: s.client("bedrock-agentcore-control").list_gateways(maxResults=1), "AgentCore is not reachable here, or you lack permission; pick a region where Bedrock AgentCore exists (TQ_REGION)") is not None:
    show("OK", "AgentCore is available in this region")

try:
    s.client("cloudtrail").lookup_events(MaxResults=1)
    show("OK", "CloudTrail events can be read")
except Exception as e:
    show("FAIL", "CloudTrail events cannot be read", str(e)[:120])

try:
    s.client("iam").list_roles(MaxItems=1)
    show("OK", "IAM is readable (an admin role is needed to deploy)")
except Exception as e:
    show("FAIL", "IAM is not readable", str(e)[:120])

for b in (f"tq-code-{acct}", f"tq-audit-{acct}"):
    try:
        s.client("s3").head_bucket(Bucket=b)
        show("OK", f"bucket {b} already exists and is yours (a re-run)")
    except botocore.exceptions.ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("404", "NoSuchBucket"):
            show("OK", f"bucket name {b} is free")
        else:
            show("FAIL", f"bucket name {b} is taken by someone else or not accessible", code)

model = os.environ.get("TQ_MODEL")
if not model:
    show("WARN", "TQ_MODEL is not set", "the Orchestrator will use rules only; run: python deploy/pick_model.py")
else:
    try:
        s.client("bedrock-runtime").converse(modelId=model, messages=[{"role": "user", "content": [{"text": "OK"}]}], inferenceConfig={"maxTokens": 5})
        show("OK", "Bedrock model can be called", model)
    except Exception as e:
        show("WARN", "Bedrock model cannot be called", f"{model}: {str(e)[:100]}; the plan will fall back to rules")

clash = []
iam = s.client("iam")
for r in ("supervisor-role", "subagents-role", "tq-demo-owner", "tq-demo-sec-lead", "tq-orchestrator-role"):
    try:
        iam.get_role(RoleName=r); clash.append(r)
    except Exception:
        pass
if clash:
    show("WARN", "demo roles already exist in this account", ", ".join(clash) + " (fine if this is a re-run; otherwise they belong to something else)")
print("\nReady." if not bad else f"\n{bad} problem(s) to fix before deploying.")
sys.exit(1 if bad else 0)
