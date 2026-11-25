"""Lambda entry points for the Step Functions pipeline."""
import json, os
import boto3
from . import core


def _plain(x):
    return json.loads(json.dumps(x, default=core._dec))


def detect(event, ctx=None):
    sig = core.detect(event["record"])
    return {"signal": _plain(sig)} if sig else {"signal": None}


def read_cloudtrail(event, ctx=None):
    """Reads the CreateAccessKey record back from real CloudTrail. found=False means not delivered yet."""
    rec = core.read_cloudtrail(event.get("created_key_id"), int(event.get("minutes", 60)))
    return {"found": bool(rec), "record": rec}


def match(event, ctx=None):
    if not event.get("signal"):
        return {"alert": None}
    a = core.match(event["signal"])
    return {"alert": _plain(a)}


def plan(event, ctx=None):
    p = core.plan(event["alert"]["alert_id"], event.get("run"))     # None when another run already made this alert's plan
    return {"plan": _plain(p) if p else None}


def expire(event, ctx=None):
    """Called when the approval wait times out: the alert goes to 'expired' so a new signal can start a fresh plan."""
    p = (event.get("p") or {}).get("plan") or {}
    if p.get("plan_id"):
        d = boto3.resource("dynamodb", region_name=core.REGION)
        d.Table(core.T_ALERTS).update_item(Key={"alert_id": p["alert_id"]}, UpdateExpression="SET #s=:e ADD version :one",
                                           ExpressionAttributeNames={"#s": "state"}, ExpressionAttributeValues={":e": "expired", ":one": 1})
        d.Table(core.T_APPROVALS).update_item(Key={"plan_id": p["plan_id"]}, UpdateExpression="SET #s=:e",
                                              ExpressionAttributeNames={"#s": "state"}, ExpressionAttributeValues={":e": "expired"})
        core.audit("approval_expired", {"plan": p["plan_id"]})
    return {}


def request_approval(event, ctx=None):
    """Called by Step Functions with a task token. Stores the plan and the token and waits."""
    p = event["plan"]
    boto3.resource("dynamodb", region_name=core.REGION).Table("tq-approvals").put_item(Item={
        "plan_id": p["plan_id"], "task_token": event["token"], "state": "waiting", "plan_json": json.dumps(p)})
    core.audit("approval_requested", {"plan": p["plan_id"]})
    return {}


def _caller(event):
    """The verified IAM caller of an API Gateway request (HTTP API, IAM auth), or None for anything else."""
    iam = (event.get("requestContext") or {}).get("authorizer", {}).get("iam")
    if not iam or not iam.get("userArn"):
        return None, None
    return core.principal_name(iam["userArn"]), iam["userArn"]


def _body(event):
    import base64
    raw = event.get("body") or "{}"
    if event.get("isBase64Encoded"):
        raw = base64.b64decode(raw).decode()
    return json.loads(raw)


def approve(event, ctx=None):
    """API Gateway HTTP API route with AWS_IAM auth. The approver is the caller API Gateway verified, never a typed
    name. Body: {"plan_id": ...}. The row is claimed (waiting -> deciding) first, so two approvals cannot both run;
    a refusal puts it back to waiting and does not release the token."""
    who, arn = _caller(event)
    if not who:
        return {"ok": False, "why": "no verified identity: approvals come through the signed API"}
    plan_id = _body(event).get("plan_id")
    d = boto3.resource("dynamodb", region_name=core.REGION).Table(core.T_APPROVALS)
    if not plan_id:
        return {"ok": False, "why": "no waiting plan"}
    names = {"#s": "state"}

    def set_state(new, old, extra="", vals=None):
        d.update_item(Key={"plan_id": plan_id}, UpdateExpression="SET #s=:n" + extra, ConditionExpression="#s=:o",
                      ExpressionAttributeNames=names, ExpressionAttributeValues={":n": new, ":o": old, **(vals or {})})

    try:
        set_state("deciding", "waiting")
    except d.meta.client.exceptions.ConditionalCheckFailedException:
        return {"ok": False, "why": "no waiting plan"}
    state = {"now": "deciding"}
    try:                                       # any error after the claim puts the row back to waiting
        row = d.get_item(Key={"plan_id": plan_id})["Item"]
        p = _plain(json.loads(row["plan_json"]))
        try:
            ap = core.approve(p, who, approver_arn=arn)
        except core.ApprovalRefused as e:
            set_state("waiting", "deciding")
            return {"ok": False, "why": str(e), "approver": who}
        set_state("approved", "deciding", ", approver=:a, approver_arn=:r", {":a": who, ":r": arn})
        state["now"] = "approved"
        try:
            boto3.client("stepfunctions", region_name=core.REGION).send_task_success(
                taskToken=row["task_token"], output=json.dumps({"approval": ap}))
        except Exception as e:
            d.update_item(Key={"plan_id": plan_id}, UpdateExpression="SET #s=:x", ExpressionAttributeNames=names,
                          ExpressionAttributeValues={":x": "expired"})
            return {"ok": False, "why": "the approval wait is over: " + str(e)[:120], "approver": who}
        return {"ok": True, "approver": who}
    except BaseException:
        if state["now"] == "deciding":
            try:
                set_state("waiting", "deciding")
            except Exception:
                pass
        raise


def lift(event, ctx=None):
    """API Gateway route with AWS_IAM auth. Body: {"agent": "supervisor-agent"}. Same identity and allowlist rules as approve."""
    who, arn = _caller(event)
    if not who:
        return {"ok": False, "why": "no verified identity: lifting comes through the signed API"}
    try:
        res = core.lift(_body(event).get("agent"), who, approver_arn=arn)
    except core.LiftRefused as e:
        return {"ok": False, "why": str(e), "approver": who}
    return {"ok": not any(r["status"] == "failed" for r in res), "approver": who, "results": res}


def poll(event, ctx=None):
    """Runs every minute. {"mark_seen": true} marks what is already in CloudTrail without starting anything."""
    sf = boto3.client("stepfunctions", region_name=core.REGION)
    arn = os.environ["STATE_MACHINE_ARN"]
    def start(rec):
        try:                                   # the name is the eventID: starting the same event twice is a no-op
            sf.start_execution(stateMachineArn=arn, name=rec["eventID"], input=json.dumps({"record": rec}))
        except sf.exceptions.ExecutionAlreadyExists:
            pass

    return core.poll(start,
                     minutes=int((event or {}).get("minutes", 15)), mark_only=bool((event or {}).get("mark_seen")))


def act(event, ctx=None):
    return {"results": _plain(core.act(event["plan"], event["approval"]))}


def plans(event, ctx=None):
    """GET /plans (IAM auth): what a security person needs on screen: plans waiting for approval and agents that are
    contained (can be lifted). Needs a verified caller, like approve and lift."""
    who, arn = _caller(event)
    if not who:
        return {"ok": False, "why": "no verified identity"}
    d = boto3.resource("dynamodb", region_name=core.REGION)
    alerts = {a["alert_id"]: a for a in d.Table(core.T_ALERTS).scan()["Items"]}
    waiting = []
    for r in d.Table(core.T_APPROVALS).scan()["Items"]:
        if r.get("state") != "waiting":
            continue
        p = json.loads(r["plan_json"])
        a = alerts.get(p.get("alert_id"), {})
        waiting.append({"plan_id": p["plan_id"], "agent": p["agent"], "role": p["role"], "owner": p["owner"],
                        "level": a.get("level"), "severity": int(a.get("severity", 0)) if a.get("severity") is not None else None,
                        "evidence": [{"type": int(e["type"]), "txt": e["txt"]} for e in a.get("evidence", [])],
                        "source": p.get("plan_source", "rules"), "why": p.get("rationale", ""),
                        "steps": [{"n": s["n"], "name": s["name"], "implemented": s["implemented"]} for s in p["steps"]]})
    contained = sorted({a["agent"] for a in alerts.values() if a["state"] in ("contained", "contained_with_errors")})
    return {"ok": True, "you": who, "waiting": waiting, "contained": contained}


def guard(event, ctx=None):
    """Checks agent input with a real Bedrock Guardrail. Returns {"record": ...} (what detect() takes) or {"record": None}."""
    rec = core.guard_check(event["text"], event["role_name"], event.get("access_key_id"), event["guardrail_id"], event["guardrail_version"])
    return {"record": rec}
