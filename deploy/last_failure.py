"""Prints the status of the latest tq-contain run and, if it failed, the reason."""
import json, os, boto3
sf = boto3.Session(region_name=os.environ.get("TQ_REGION", "ap-southeast-2"), profile_name=os.environ.get("AWS_PROFILE")).client("stepfunctions")
m = [x for x in sf.list_state_machines()["stateMachines"] if x["name"] == "tq-contain"][0]["stateMachineArn"]
e = sf.list_executions(stateMachineArn=m, maxResults=1)["executions"][0]
print("latest run:", e["status"], e["startDate"])
for ev in sf.get_execution_history(executionArn=e["executionArn"], reverseOrder=True, maxResults=10)["events"]:
    d = ev.get("lambdaFunctionFailedEventDetails") or ev.get("executionFailedEventDetails") or ev.get("taskFailedEventDetails")
    if d:
        print(ev["type"], (d.get("cause") or json.dumps(d))[:3000]); break
