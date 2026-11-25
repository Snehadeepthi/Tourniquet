"""Finds a Bedrock model you can call in this account and region, for the Orchestrator.
Usage: python deploy/pick_model.py   then   export TQ_MODEL=<printed id>   then   python deploy/deploy.py"""
import os, boto3
REGION = os.environ.get("TQ_REGION", "ap-southeast-2")
s = boto3.Session(region_name=REGION, profile_name=os.environ.get("AWS_PROFILE"))
br, rt = s.client("bedrock"), s.client("bedrock-runtime")
cands = []
try:
    for p in br.list_inference_profiles(typeEquals="SYSTEM_DEFINED").get("inferenceProfileSummaries", []):
        if "anthropic" in p["inferenceProfileId"]:
            cands.append(p["inferenceProfileId"])
except Exception as e:
    print("profiles:", e)
try:
    for m in br.list_foundation_models(byProvider="anthropic").get("modelSummaries", []):
        cands.append(m["modelId"])
except Exception as e:
    print("models:", e)
cands.sort(key=lambda x: ("haiku" not in x, x))             # cheap and quick first
for c in cands:
    try:
        r = rt.converse(modelId=c, messages=[{"role": "user", "content": [{"text": "Reply with the word OK."}]}], inferenceConfig={"maxTokens": 10})
        print("WORKS:", c, "->", r["output"]["message"]["content"][0]["text"].strip())
        print(f"\nexport TQ_MODEL={c}")
        break
    except Exception as e:
        print("no:", c, str(e)[:90])
else:
    print("No Anthropic model callable here. Enable model access in the Bedrock console (Model access), or leave TQ_MODEL unset: the plan stays rule-based.")
