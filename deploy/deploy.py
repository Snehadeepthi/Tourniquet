"""Deploy the Tourniquet slice (layer 1) to the account in your AWS profile. Region: ap-southeast-2."""
import io, os, sys, zipfile, time
import boto3

REGION = os.environ.get("TQ_REGION", "ap-southeast-2")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
session = boto3.Session(region_name=REGION, profile_name=os.environ.get("AWS_PROFILE"))
acct = session.client("sts").get_caller_identity()["Account"]
code_bucket, audit_bucket = f"tq-code-{acct}", f"tq-audit-{acct}"
s3, cfn = session.client("s3"), session.client("cloudformation")

try:
    s3.head_bucket(Bucket=code_bucket)
except Exception:
    if REGION == "us-east-1":                                  # this one region must not be given a LocationConstraint
        s3.create_bucket(Bucket=code_bucket)
    else:
        s3.create_bucket(Bucket=code_bucket, CreateBucketConfiguration={"LocationConstraint": REGION})
import subprocess, tempfile
buf = io.BytesIO()
vend = tempfile.mkdtemp()
# The Lambda runtime's built-in boto3 may be too old for AgentCore Policy calls, so ship a current one.
subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", "boto3", "-t", vend])
with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
    for dp, dn, fn in os.walk(vend):
        dn[:] = [d for d in dn if d != "__pycache__" and not d.endswith(".dist-info") and d != "bin"]
        for f in fn:
            if not f.endswith(".pyc"):
                full = os.path.join(dp, f); z.write(full, os.path.relpath(full, vend))
    for f in os.listdir(os.path.join(ROOT, "tourniquet_slice")):
        if f.endswith(".py"):
            z.write(os.path.join(ROOT, "tourniquet_slice", f), f"tourniquet_slice/{f}")
print("code package MB:", round(len(buf.getvalue()) / 1e6, 1))
import hashlib
code_key = f"tq-code-{hashlib.sha256(buf.getvalue()).hexdigest()[:16]}.zip"   # new name per content, so Lambda code really updates
s3.put_object(Bucket=code_bucket, Key=code_key, Body=buf.getvalue())

body = open(os.path.join(ROOT, "deploy", "template.yaml")).read()
params = [{"ParameterKey": "CodeBucket", "ParameterValue": code_bucket},
          {"ParameterKey": "AuditBucketName", "ParameterValue": audit_bucket},
          {"ParameterKey": "CodeKey", "ParameterValue": code_key},
          {"ParameterKey": "Approvers", "ParameterValue": os.environ.get("TQ_APPROVERS", "tq-demo-sec-lead")},
          {"ParameterKey": "OrchestratorModel", "ParameterValue": os.environ.get("TQ_MODEL", "")},
          {"ParameterKey": "ActNarrow", "ParameterValue": "true" if os.environ.get("TQ_NARROW") == "1" else "false"}]
kw = dict(StackName="tourniquet-slice", TemplateBody=body, Parameters=params, Capabilities=["CAPABILITY_NAMED_IAM"])
try:
    status = cfn.describe_stacks(StackName="tourniquet-slice")["Stacks"][0]["StackStatus"]; exists = True
except Exception:
    status, exists = None, False
if status in ("ROLLBACK_COMPLETE", "CREATE_FAILED", "DELETE_FAILED"):    # a failed first deploy cannot be updated, only removed
    print(f"The stack is in {status} from an earlier failed deploy; removing it and starting again")
    cfn.delete_stack(StackName="tourniquet-slice")
    cfn.get_waiter("stack_delete_complete").wait(StackName="tourniquet-slice", WaiterConfig={"Delay": 5, "MaxAttempts": 60})
    exists = False
try:
    (cfn.update_stack if exists else cfn.create_stack)(**kw)
except Exception as e:
    if "No updates are to be performed" not in str(e):
        raise
    print("Stack already up to date"); sys.exit(0)
waiter = cfn.get_waiter("stack_update_complete" if exists else "stack_create_complete")
try:
    waiter.wait(StackName="tourniquet-slice", WaiterConfig={"Delay": 5, "MaxAttempts": 60})
except Exception:
    print("The stack did not finish. What CloudFormation reported:")
    for ev in cfn.describe_stack_events(StackName="tourniquet-slice")["StackEvents"][:40]:
        if "FAILED" in ev["ResourceStatus"]:
            print(" -", ev["LogicalResourceId"], ev["ResourceStatus"], ev.get("ResourceStatusReason", "")[:200])
    print("Fix the cause, then run deploy.py again (a failed first deploy is removed and retried automatically).")
    sys.exit(1)
out = {o["OutputKey"]: o["OutputValue"] for o in cfn.describe_stacks(StackName="tourniquet-slice")["Stacks"][0].get("Outputs", [])}
print("Deployed. Audit bucket:", audit_bucket)
print("Act role mode:", "NARROW (exact AgentCore permissions)" if os.environ.get("TQ_NARROW") == "1" else "broad (bedrock-agentcore:*)")
print("Approval API:", out.get("ApiUrl"), "(POST /approve, POST /lift, IAM-signed, service execute-api)")
print("Orchestrator:", os.environ.get("TQ_MODEL") or "rule-based (set TQ_MODEL to a Bedrock model id to use the Bedrock Orchestrator)")
print("Approvers allowed:", os.environ.get("TQ_APPROVERS", "tq-demo-sec-lead"))
