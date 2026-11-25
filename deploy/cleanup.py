"""Remove everything the slice created. Run when you are done to stop all charges."""
import os, boto3
REGION = os.environ.get("TQ_REGION", "ap-southeast-2")
s = boto3.Session(region_name=REGION, profile_name=os.environ.get("AWS_PROFILE"))
acct = s.client("sts").get_caller_identity()["Account"]
s3, cfn, iam, lam = s.client("s3"), s.client("cloudformation"), s.client("iam"), s.client("lambda")
for b in (f"tq-audit-{acct}", f"tq-code-{acct}"):
    try:
        for v in s3.list_object_versions(Bucket=b).get("Versions", []) + s3.list_object_versions(Bucket=b).get("DeleteMarkers", []):
            s3.delete_object(Bucket=b, Key=v["Key"], VersionId=v["VersionId"], BypassGovernanceRetention=True)
    except Exception as e:
        print("bucket", b, e)
ac = s.client("bedrock-agentcore-control")
import time
try:
    for g in ac.list_gateways().get("items", []):
        if g["name"] == "tq-gateway":
            for t in ac.list_gateway_targets(gatewayIdentifier=g["gatewayId"]).get("items", []):
                ac.delete_gateway_target(gatewayIdentifier=g["gatewayId"], targetId=t["targetId"])
            time.sleep(15)
            ac.delete_gateway(gatewayIdentifier=g["gatewayId"])
    time.sleep(20)
    for e in ac.list_policy_engines().get("policyEngines", []):
        if e["name"] == "tq_engine":
            for p in ac.list_policies(policyEngineId=e["policyEngineId"]).get("policies", []):
                ac.delete_policy(policyEngineId=e["policyEngineId"], policyId=p["policyId"])
            time.sleep(10)
            ac.delete_policy_engine(policyEngineId=e["policyEngineId"])
except Exception as e:
    print("agentcore", e)
cfn.delete_stack(StackName="tourniquet-slice"); cfn.get_waiter("stack_delete_complete").wait(StackName="tourniquet-slice")
try: s3.delete_bucket(Bucket=f"tq-code-{acct}")
except Exception as e: print(e)
try:
    s.client("secretsmanager").delete_secret(SecretId="tq-demo/orders-db-password", ForceDeleteWithoutRecovery=True)
except Exception as e: print("secret", e)
try:
    for rt in ac.list_agent_runtimes().get("agentRuntimes", []):
        if rt["agentRuntimeName"].startswith("tq_"):
            ac.delete_agent_runtime(agentRuntimeId=rt["agentRuntimeId"])
except Exception as e: print("runtime", e)
try:
    b = f"tq-runtime-code-{acct}"
    for v in s3.list_object_versions(Bucket=b).get("Versions", []): s3.delete_object(Bucket=b, Key=v["Key"], VersionId=v["VersionId"])
    s3.delete_bucket(Bucket=b)
except Exception as e: print(e)
for fn in ("order-tools", "tq-gw-tool", "tq-helper-agent"):
    try: lam.delete_function(FunctionName=fn)
    except Exception: pass
for r in ("supervisor-role", "subagents-role", "order-tools-exec", "tq-gateway-role", "tq-gw-tool-exec", "tq-runtime-role", "tq-demo-owner", "tq-demo-sec-lead", "tq-orchestrator-role", "tq-demo-stranger"):
    try:
        for p in iam.list_role_policies(RoleName=r)["PolicyNames"]: iam.delete_role_policy(RoleName=r, PolicyName=p)
        for a in iam.list_attached_role_policies(RoleName=r)["AttachedPolicies"]: iam.detach_role_policy(RoleName=r, PolicyArn=a["PolicyArn"])
        iam.delete_role(RoleName=r)
    except Exception as e: print(r, e)
try:
    for k in iam.list_access_keys(UserName="backdoor-user")["AccessKeyMetadata"]: iam.delete_access_key(UserName="backdoor-user", AccessKeyId=k["AccessKeyId"])
    iam.delete_user(UserName="backdoor-user")
except Exception as e: print(e)
print("Cleaned up.")
