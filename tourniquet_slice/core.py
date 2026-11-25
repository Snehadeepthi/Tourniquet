"""Tourniquet slice: one poisoned-order scenario through both planes.

Plain AWS services only (IAM, Lambda, DynamoDB, S3). Steps 1 to 4 (Cedar forbid,
vault deny, cut agent calls, stop Runtime sessions) need AgentCore and are NOT
implemented here; the plan lists them as 'not in this slice'.
"""
import datetime, hashlib, json, os, time, uuid
import boto3

# One region for everything: TQ_REGION if set, else the Lambda's own region, else ap-southeast-2 (where it was proven).
REGION = os.environ.get("TQ_REGION") or (os.environ.get("AWS_REGION") if os.environ.get("AWS_LAMBDA_FUNCTION_NAME") else None) or "ap-southeast-2"
T_ALERTS, T_SESSIONS, T_REACH, T_SIGNALS = "tq-alerts", "tq-sessions", "tq-reach", "tq-signals"
T_APPROVALS, T_SEEN, T_BASELINES = "tq-approvals", "tq-seen", "tq-baselines"
ORCHESTRATOR = "tq-orchestrator-role"            # the identity the Orchestrator runs as
REFUSED_APPROVERS = ("orchestrator", ORCHESTRATOR, "tq-control-role")
AUDIT_BUCKET = os.environ.get("TQ_AUDIT_BUCKET", "tq-audit")
BLAST_RADIUS = 2                      # stand-in; real weights belong in AppConfig
STRENGTH = {1: 1, 2: 3, 3: 3, 4: 1, 5: 2, 6: 1, 7: 3}   # stand-in weights; type numbers as in the design:
# 1 threat finding (GuardDuty) · 2 identity change · 3 secret misuse · 4 tool or call shift · 5 gateway denies · 6 prompt injection · 7 manual
SECRET_MIN, SECRET_X = 10, 5          # type 3 fires at this many secret reads in one minute AND this many times the agent's normal
DENY_MIN = 5                          # type 5 fires at this many Gateway denies for one agent in one minute
HIGH_AT = 6                           # severity >= 6 is High
STEP_NAMES = {1: "Cedar forbid", 2: "Vault deny", 3: "Cut agent calls", 4: "Stop sessions",
              5: "Tool Lambda concurrency 0", 6: "Role lock", 7: "Deactivate keys it created",
              8: "Rotate secrets"}
ALWAYS = (3, 5, 6, 7)                 # steps that need nothing special; 1, 2, 4, 8 depend on what the agent's reach row names
CALL_ACTIONS = ["lambda:InvokeFunction", "lambda:InvokeFunctionUrl", "lambda:InvokeAsync", "bedrock-agentcore:InvokeAgentRuntime"]


def _c(kind, svc):
    return getattr(boto3, kind)(svc, region_name=REGION)


def _ddb():
    return boto3.resource("dynamodb", region_name=REGION)


def _dec(o):
    from decimal import Decimal
    if isinstance(o, Decimal):
        return int(o) if o == o.to_integral_value() else float(o)
    raise TypeError(type(o))


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def principal_name(arn):
    """Name of the IAM principal behind a caller ARN: assumed-role/NAME/session -> NAME, user/path/NAME -> NAME."""
    tail = arn.split(":", 5)[-1]
    parts = tail.split("/")
    if parts[0] == "assumed-role" and len(parts) >= 2:
        return parts[1]
    if parts[0] == "user" and len(parts) >= 2:
        return parts[-1]
    return tail if tail != "root" else "root"


# ---------------------------------------------------------------- setup (test and POC use)
def create_tables():
    d = _ddb()
    for name, key in [(T_ALERTS, "alert_id"), (T_SESSIONS, "access_key_id"),
                      (T_REACH, "role_name"), (T_SIGNALS, "signal_id"), (T_APPROVALS, "plan_id"), (T_SEEN, "event_id"), (T_BASELINES, "k")]:
        d.create_table(TableName=name, KeySchema=[{"AttributeName": key, "KeyType": "HASH"}],
                       AttributeDefinitions=[{"AttributeName": key, "AttributeType": "S"}],
                       BillingMode="PAY_PER_REQUEST")


# ---------------------------------------------------------------- audit (S3, hash chain)
def audit(action, detail):
    """Appends to the hash chain. The write fails if another writer took the same sequence number (S3 conditional
    write); this then retries on top of the newer record, so parallel steps cannot fork the chain."""
    s3 = _c("client", "s3")
    for attempt in range(15):
        keys = []
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=AUDIT_BUCKET):
            keys += [o["Key"] for o in page.get("Contents", [])]
        keys.sort()
        prev = "0" * 64
        if keys:
            prev = json.loads(s3.get_object(Bucket=AUDIT_BUCKET, Key=keys[-1])["Body"].read())["hash"]
        rec = {"seq": len(keys) + 1, "time": now(), "action": action, "detail": detail, "prev": prev}
        rec["hash"] = hashlib.sha256(json.dumps(rec, sort_keys=True, default=_dec).encode()).hexdigest()
        try:
            s3.put_object(Bucket=AUDIT_BUCKET, Key=f"audit/{rec['seq']:06d}.json",
                          Body=json.dumps(rec, default=_dec).encode(), IfNoneMatch="*")
            return rec
        except Exception as e:
            code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
            if code in ("PreconditionFailed", "ConditionalRequestConflict"):
                time.sleep(0.05 + 0.1 * (attempt % 5))
                continue
            raise
    raise RuntimeError("audit chain busy: could not append")


def verify_audit():
    s3 = _c("client", "s3")
    prev = "0" * 64
    for o in sorted(x["Key"] for pg in s3.get_paginator("list_objects_v2").paginate(Bucket=AUDIT_BUCKET) for x in pg.get("Contents", [])):
        rec = json.loads(s3.get_object(Bucket=AUDIT_BUCKET, Key=o)["Body"].read())
        h = rec.pop("hash")
        if rec["prev"] != prev or hashlib.sha256(json.dumps(rec, sort_keys=True, default=_dec).encode()).hexdigest() != h:
            return False
        prev = h
    return True


# ---------------------------------------------------------------- detection (control plane)
def detect(record):
    """Three questions: did AWS already judge it, is it always suspicious, is it a sharp change.
    The slice implements Q1 for Guardrails (type 6) and Q2 for CreateAccessKey (type 2)."""
    sig = None
    if record.get("source") == "guardrails" and record.get("prompt_attack"):
        sig = {"type": 6, "rule": "pass-through (Guardrails)", "role_name": record.get("role_name"),
               "access_key_id": record.get("access_key_id"), "txt": "Prompt attack flagged"}
    elif record.get("source") == "aws.guardduty" and record.get("detail-type") == "GuardDuty Finding":
        det = record.get("detail", {})
        ak = det.get("resource", {}).get("accessKeyDetails", {})
        if ak.get("userType") == "AssumedRole" and ak.get("userName"):
            sig = {"type": 1, "rule": "pass-through (GuardDuty)", "role_name": ak["userName"],
                   "access_key_id": ak.get("accessKeyId"), "txt": "GuardDuty: " + str(det.get("type", "finding"))[:80]}
    elif record.get("eventName") == "CreateAccessKey":
        issuer = record.get("userIdentity", {}).get("sessionContext", {}).get("sessionIssuer", {})
        if issuer.get("type") == "Role":
            new_key = record.get("responseElements", {}).get("accessKey", {})
            sig = {"type": 2, "rule": "fixed rule (always suspicious)", "role_name": issuer.get("userName"),
                   "access_key_id": record.get("userIdentity", {}).get("accessKeyId"),
                   "created_key": {"id": new_key.get("accessKeyId"), "user": new_key.get("userName")},
                   "txt": "An agent role created an access key"}
    elif record.get("source") == "tourniquet.baseline" and record.get("kind") == "secret_read_spike":   # type 3: the poller counted
        sig = {"type": 3, "rule": "baseline (secret read rate)", "role_name": record["role_name"],
               "access_key_id": record.get("access_key_id"),
               "txt": f"{record['count']} secret reads in a minute (normal about {record['normal']})"}
    elif record.get("source") == "agentcore.gateway" and record.get("tool") and record.get("role_name"):   # type 4: Q3 baseline, new tool or agent
        sig = _shift(record)
    elif record.get("source") == "agentcore.policy" and str(record.get("decision", "")).upper() == "DENY" and record.get("role_name"):   # type 5
        n, _ = _count(f"deny#{record['role_name']}", learn=False)
        if n == DENY_MIN:
            sig = {"type": 5, "rule": "baseline (gateway denies)", "role_name": record["role_name"],
                   "access_key_id": record.get("access_key_id"), "txt": f"{n} Gateway denies in a minute"}
    elif record.get("source") == "manual" and record.get("agent"):          # type 7: a person names the agent
        rows = [r for r in _ddb().Table(T_REACH).scan()["Items"] if r["agent"] == record["agent"]]
        if rows:
            sig = {"type": 7, "rule": "manual", "role_name": rows[0]["role_name"], "access_key_id": None,
                   "txt": "Raised by " + str(record.get("raised_by", "a person"))[:40] + ": " + str(record.get("reason", ""))[:80]}
    if sig is None:
        return None
    sig.update(signal_id=str(uuid.uuid4()), time=now(), strength=STRENGTH[sig["type"]])
    _ddb().Table(T_SIGNALS).put_item(Item=json.loads(json.dumps(sig)))   # baselines + signals table
    return sig


# ---------------------------------------------------------------- baselines (Q3): per-agent normal, kept in tq-baselines
def _minute(when=None):
    when = when or datetime.datetime.now(datetime.timezone.utc)
    return when.strftime("%Y%m%d%H%M")


def _event_minute(rec):
    try:
        return _minute(datetime.datetime.fromisoformat(rec["eventTime"].replace("Z", "+00:00")))
    except Exception:
        return _minute()


def _count(key, learn=True, minute=None):
    """Counts one event in that minute's bucket (atomic). Returns (count that minute, normal rate for the agent).
    When a new minute starts, the minute before is folded into the agent's normal (a slow average) unless it was
    already a spike, so an attack does not teach Tourniquet that attacks are normal."""
    t, m = _ddb().Table(T_BASELINES), minute or _minute()
    r = t.update_item(Key={"k": f"{key}#{m}"}, UpdateExpression="ADD n :one SET expires = :t",
                      ExpressionAttributeValues={":one": 1, ":t": int(time.time()) + 7200}, ReturnValues="UPDATED_NEW")
    n = int(r["Attributes"]["n"])
    nk = f"{key}#normal"
    row = t.get_item(Key={"k": nk}).get("Item") or {}
    normal = float(row.get("rate", 1))
    if learn and n == 1:                                  # first event of a new minute
        prev = (datetime.datetime.strptime(m, "%Y%m%d%H%M") - datetime.timedelta(minutes=1)).strftime("%Y%m%d%H%M")
        pv = t.get_item(Key={"k": f"{key}#{prev}"}).get("Item")
        if pv and int(pv["n"]) < max(SECRET_MIN, int(SECRET_X * normal) + 1):
            normal = round(0.8 * normal + 0.2 * int(pv["n"]), 3)
            t.put_item(Item={"k": nk, "rate": str(normal), "expires": int(time.time()) + 7 * 86400})
    return n, normal


def secret_spike(rec):
    """Type 3, called by the poller once per new GetSecretValue record by an agent role. Counts the read in the minute it
    happened. Returns a record for the pipeline when the agent's reads that minute reach the threshold and this spike
    was not already raised; otherwise None."""
    issuer = rec.get("userIdentity", {}).get("sessionContext", {}).get("sessionIssuer", {})
    role = issuer.get("userName") if issuer.get("type") == "Role" else None
    if not role or role.startswith("tq-"):
        return None                                       # Tourniquet's own roles are never judged
    m = _event_minute(rec)
    n, normal = _count(f"secret#{role}", minute=m)
    if n < max(SECRET_MIN, int(SECRET_X * normal) + 1):
        return None
    if _ddb().Table(T_BASELINES).get_item(Key={"k": f"fired#{role}#{m}"}).get("Item"):
        return None
    return {"source": "tourniquet.baseline", "kind": "secret_read_spike", "role_name": role, "count": n, "normal": round(normal, 1),
            "access_key_id": rec.get("userIdentity", {}).get("accessKeyId"), "eventID": rec["eventID"], "minute": m}


def secret_spike_fired(spike):
    _ddb().Table(T_BASELINES).put_item(Item={"k": f"fired#{spike['role_name']}#{spike['minute']}",
                                             "expires": int(time.time()) + 7200})


def _shift(record):
    """Type 4: a tool or another agent this agent has never used. The known set is what the Collector found in the reach
    row plus what was seen before; the first time an agent is seen with nothing known, it is only learned."""
    role, tool = record["role_name"], str(record["tool"])
    t = _ddb().Table(T_BASELINES)
    row = t.get_item(Key={"k": f"tools#{role}"}).get("Item") or {}
    known = set(row.get("tools", []))
    reach = _ddb().Table(T_REACH).get_item(Key={"role_name": role}).get("Item") or {}
    known |= {str(x) for x in reach.get("tool_actions", [])} | {str(x) for x in reach.get("calls", [])}
    new = tool not in known and not any(tool.endswith(k) or k.endswith(tool) for k in known)
    t.put_item(Item={"k": f"tools#{role}", "tools": sorted(known | {tool})})
    if known and new:
        return {"type": 4, "rule": "baseline (new tool or agent)", "role_name": role, "access_key_id": record.get("access_key_id"),
                "txt": "First use of " + tool[:60]}
    return None


# ---------------------------------------------------------------- Guardrails (real ApplyGuardrail)
def ensure_guardrail(name="tq-demo-guardrail"):
    """Creates (once) a Bedrock Guardrail with the prompt-attack filter and returns (id, version)."""
    br = _c("client", "bedrock")
    for g in br.list_guardrails().get("guardrails", []):
        if g["name"] == name:
            return g["id"], g.get("version") if g.get("version") != "DRAFT" else br.create_guardrail_version(guardrailIdentifier=g["id"])["version"]
    g = br.create_guardrail(name=name, description="Tourniquet demo: prompt attacks on agent input",
                            contentPolicyConfig={"filtersConfig": [{"type": "PROMPT_ATTACK", "inputStrength": "HIGH", "outputStrength": "NONE"}]},
                            blockedInputMessaging="Blocked by guardrail", blockedOutputsMessaging="Blocked by guardrail")
    return g["guardrailId"], br.create_guardrail_version(guardrailIdentifier=g["guardrailId"])["version"]


def guard_check(text, role_name, access_key_id, guardrail_id, guardrail_version):
    """Runs the text an agent received through a real Bedrock Guardrail. Returns the record detect() expects when the
    prompt-attack filter fires, else None. The text itself is not stored."""
    r = _c("client", "bedrock-runtime").apply_guardrail(guardrailIdentifier=guardrail_id, guardrailVersion=guardrail_version,
                                                         source="INPUT", content=[{"text": {"text": text, "qualifiers": ["guard_content"]}}])
    hit = r.get("action") == "GUARDRAIL_INTERVENED" and any(
        f.get("type") == "PROMPT_ATTACK" and f.get("detected")
        for a in r.get("assessments", []) for f in a.get("contentPolicy", {}).get("filters", []))
    if not hit:
        return None
    return {"source": "guardrails", "prompt_attack": True, "role_name": role_name, "access_key_id": access_key_id}


# ---------------------------------------------------------------- CloudTrail read-back (the real source of type 2)
CT_REGIONS = ("us-east-1", REGION)    # IAM is a global service: its CloudTrail events are recorded in us-east-1


def read_cloudtrail(created_key_id=None, minutes=60):
    """Read CreateAccessKey records back from CloudTrail (LookupEvents). Returns the record in the
    same shape detect() takes, or None if CloudTrail has not delivered it yet (usually 1 to 15 min)."""
    start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=minutes)
    best = None
    for region in CT_REGIONS:
        ct = boto3.client("cloudtrail", region_name=region)
        pages = ct.get_paginator("lookup_events").paginate(
            LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": "CreateAccessKey"}], StartTime=start)
        for page in pages:
            for ev in page["Events"]:
                rec = json.loads(ev["CloudTrailEvent"])
                got = (rec.get("responseElements") or {}).get("accessKey", {}).get("accessKeyId")
                if created_key_id and got != created_key_id:
                    continue
                if best is None or rec["eventTime"] > best["eventTime"]:
                    best = rec
        if best:
            break
    if best:
        audit("cloudtrail_record_read", {"eventID": best.get("eventID"), "eventTime": best.get("eventTime"),
              "by": best.get("userIdentity", {}).get("arn")})
    return best


# ---------------------------------------------------------------- step 1: Cedar forbid on the AgentCore Gateway
def _wait(get, done=("ACTIVE", "READY"), bad=("CREATE_FAILED", "FAILED", "UPDATE_FAILED"), tries=60, every=3):
    for _ in range(tries):
        r = get()
        if r["status"] in done:
            return r
        if r["status"] in bad:
            return r
        time.sleep(every)
    return r


def forbid_statements(role_name, gateway_arn, actions=None, pattern="lenient"):
    """Candidate Cedar forbids for one agent role, most general first. AgentCore validates each one;
    the first the validator accepts is used. (Which form it accepts is confirmed by the real run.)"""
    acct = gateway_arn.split(":")[4]
    base = f"arn:aws:sts::{acct}:assumed-role/{role_name}"
    if pattern == "exact":      # AgentCore's caller id is the role ARN without a session name: match it exactly, no wildcard
        who = f'principal.id == "{base}"'
    else:                       # strict: role/*   lenient: role*
        who = f'principal.id like "{base}/*"' if pattern == "strict" else f'principal.id like "{base}*"'
    forms = [
        ("any action", f'forbid(principal is AgentCore::IamEntity, action, resource is AgentCore::Gateway)\nwhen {{ {who} }};'),
        ("one gateway", f'forbid(principal is AgentCore::IamEntity, action, resource == AgentCore::Gateway::"{gateway_arn}")\nwhen {{ {who} }};'),
    ]
    if actions:
        acts = ", ".join(f'AgentCore::Action::"{a}"' for a in actions)
        forms.append(("named tools", f'forbid(principal is AgentCore::IamEntity, action in [{acts}],\n  resource == AgentCore::Gateway::"{gateway_arn}")\nwhen {{ {who} }};'))
    return forms


def cedar_forbid(role_name, engine_id, gateway_arn, actions=None, pattern="lenient"):
    """Step 1. Adds a forbid for this one agent role to the Gateway's policy engine (forbid wins over permit).
    Each attempt has its own name (a deleted policy's name stays busy for a while). Returns policy id and form."""
    ac = _c("client", "bedrock-agentcore-control")
    tried = []
    for attempt in (1, 2):                    # a second pass: the engine may still be busy with an earlier delete
        for i, (label, stmt) in enumerate(forbid_statements(role_name, gateway_arn, actions, pattern)):
            name = f"tq_forbid_{role_name.replace('-', '_')}_{int(time.time())}_{i}"
            try:
                r = ac.create_policy(policyEngineId=engine_id, name=name, validationMode="FAIL_ON_ANY_FINDINGS",
                                     description=f"Tourniquet step 1: cut {role_name}", definition={"cedar": {"statement": stmt}})
            except Exception as e:
                tried.append(f"try{attempt} {label}: {str(e)[:260]}")
                continue
            pid = r["policyId"]
            r = _wait(lambda: ac.get_policy(policyEngineId=engine_id, policyId=pid))
            if r["status"] == "ACTIVE":
                audit("step_1_cedar_forbid", {"role": role_name, "policy": pid, "form": label})
                return {"policy_id": pid, "form": label, "pattern": pattern, "refused_forms": tried}
            tried.append(f"try{attempt} {label}: {r['status']} " + " | ".join(x[:110] for x in (r.get("statusReasons") or [])))
            try:
                ac.delete_policy(policyEngineId=engine_id, policyId=pid)
            except Exception:
                pass
        if attempt == 1:
            time.sleep(20)
    raise RuntimeError("AgentCore refused every forbid form: " + " // ".join(tried))


def delete_forbids(role_name, engine_id):
    """Removes this role's Cedar forbids from the engine (undo of step 1). Returns how many.
    Matches the exact generated name tq_forbid_<role>_<10-digit time>_<digit> and, when the engine reports it, the
    description, so a role whose name starts with this role's name (supervisor-role-2) is never touched."""
    import re
    ac = _c("client", "bedrock-agentcore-control")
    n = 0
    rx = re.compile("^tq_forbid_" + re.escape(role_name.replace("-", "_")) + r"_\d{10}_\d+$")
    want = f"Tourniquet step 1: cut {role_name}"
    token = None
    while True:
        kw = {"policyEngineId": engine_id}
        if token:
            kw["nextToken"] = token
        r = ac.list_policies(**kw)
        for p in r.get("policies", []):
            if not rx.match(p["name"]):
                continue
            if p.get("description") not in (None, "", want):
                continue                       # another role whose name maps to the same underscored form
            ac.delete_policy(policyEngineId=engine_id, policyId=p["policyId"])
            n += 1
        token = r.get("nextToken")
        if not token:
            return n


# ---------------------------------------------------------------- matcher
def match(sig):
    """Access key id, then role name. No match: stored, shown, nothing cut."""
    d = _ddb()
    agent = None
    if sig.get("access_key_id"):
        r = d.Table(T_SESSIONS).get_item(Key={"access_key_id": sig["access_key_id"]}).get("Item")
        agent = r["agent"] if r else None
    if not agent and sig.get("role_name"):
        r = d.Table(T_REACH).get_item(Key={"role_name": sig["role_name"]}).get("Item")
        agent = r["agent"] if r else None
    if not agent:
        audit("signal_unmatched", {"signal": sig["signal_id"], "type": sig["type"]})
        return None
    alerts = d.Table(T_ALERTS)
    ev = {"time": sig["time"], "type": int(sig["type"]), "rule": sig["rule"], "txt": sig["txt"],
          "created_key": sig.get("created_key"), "signal_id": sig["signal_id"]}
    import random, re as _re
    for attempt in range(40):                  # optimistic lock: a concurrent writer makes this retry on fresh data
        if attempt:
            time.sleep(random.uniform(0.01, 0.05) * min(attempt, 10))
        mine = [a for a in alerts.scan()["Items"] if a["agent"] == agent]
        open_ = [a for a in mine if a["state"] in ("open", "planned", "approved")]
        if open_:
            a = open_[0]
            if any(e.get("signal_id") == sig["signal_id"] for e in a["evidence"]):
                return a                       # a retried step: this signal is already on the Alert, count it once
            ver = a.get("version")
            a["evidence"].append(ev)
            a["version"] = int(ver or 0) + 1
            cond = {"ConditionExpression": "version = :v", "ExpressionAttributeValues": {":v": ver}} if ver is not None \
                else {"ConditionExpression": "attribute_not_exists(version)"}
        else:
            # One id per (agent, sequence number): two first signals at the same instant compute the same id, only one
            # put succeeds, and the loser retries, finds the open Alert and adds its evidence to it.
            seq = max([int(m.group(1)) for x in mine for m in [_re.search(r"-(\d{4})$", x["alert_id"])] if m] + [0]) + 1
            a = {"alert_id": f"{agent}-{seq:04d}", "agent": agent, "state": "open", "evidence": [ev], "version": 1}
            cond = {"ConditionExpression": "attribute_not_exists(alert_id)"}
        a["severity"] = sum(STRENGTH[e["type"]] for e in a["evidence"]) * BLAST_RADIUS
        a["level"] = "High" if a["severity"] >= HIGH_AT else "Low"
        try:
            alerts.put_item(Item=json.loads(json.dumps(a, default=_dec), parse_float=str), **cond)
        except alerts.meta.client.exceptions.ConditionalCheckFailedException:
            continue
        audit("alert_updated", {"alert": a["alert_id"], "agent": agent, "level": a["level"]})
        return a
    raise RuntimeError("alert busy: could not update after 40 tries")


# ---------------------------------------------------------------- cuts 2, 3, 4, 8 (each one usable alone)
def _secret_sid(role_name):
    return "TourniquetDeny" + "".join(ch for ch in role_name if ch.isalnum())


def _secret_policy(sm, secret_id):
    try:
        return json.loads(sm.get_resource_policy(SecretId=secret_id).get("ResourcePolicy") or "{}")
    except Exception:
        return {}


def secret_deny(secret_id, role_name):
    """Step 2 (vault deny): an explicit Deny for this role in the secret's resource policy. The statement is added to
    whatever policy the secret already has, so it can be taken out again without touching anything else."""
    sm, acct = _c("client", "secretsmanager"), _c("client", "sts").get_caller_identity()["Account"]
    sid = _secret_sid(role_name)
    pol = _secret_policy(sm, secret_id)
    pol["Version"] = "2012-10-17"
    pol["Statement"] = [x for x in pol.get("Statement", []) if x.get("Sid") != sid] + [{
        "Sid": sid, "Effect": "Deny", "Principal": {"AWS": f"arn:aws:iam::{acct}:role/{role_name}"},
        "Action": "secretsmanager:GetSecretValue", "Resource": "*"}]
    sm.put_resource_policy(SecretId=secret_id, ResourcePolicy=json.dumps(pol))


def secret_allow_again(secret_id, role_name):
    """Undo of step 2: removes only this role's deny statement."""
    sm = _c("client", "secretsmanager")
    sid = _secret_sid(role_name)
    pol = _secret_policy(sm, secret_id)
    keep = [x for x in pol.get("Statement", []) if x.get("Sid") != sid]
    if len(keep) == len(pol.get("Statement", [])):
        raise _NotSet()
    if keep:
        pol["Statement"] = keep
        sm.put_resource_policy(SecretId=secret_id, ResourcePolicy=json.dumps(pol))
    else:
        sm.delete_resource_policy(SecretId=secret_id)


class _NotSet(Exception):
    response = {"Error": {"Code": "ResourceNotFoundException"}}


def secret_rotate(secret_id):
    """Step 8: puts a new random value in the vault as the current version and takes the old one out of AWSPREVIOUS, so
    a copy of the old value is no longer returned by a normal read. Changing the password at the database itself is
    the application's own rotation job and is not done here."""
    import secrets as _secrets
    sm = _c("client", "secretsmanager")
    sm.put_secret_value(SecretId=secret_id, SecretString=_secrets.token_urlsafe(24))
    stages = sm.describe_secret(SecretId=secret_id)["VersionIdsToStages"]
    for vid, st in stages.items():
        if "AWSPREVIOUS" in st:
            sm.update_secret_version_stage(SecretId=secret_id, VersionStage="AWSPREVIOUS", RemoveFromVersionId=vid)


def cut_calls(role_name):
    """Step 3 (cut agent calls): the agent role may no longer invoke other agents or functions."""
    _c("client", "iam").put_role_policy(RoleName=role_name, PolicyName="TourniquetCutCalls", PolicyDocument=json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": CALL_ACTIONS, "Resource": "*"}]}))


def restore_calls(role_name):
    _c("client", "iam").delete_role_policy(RoleName=role_name, PolicyName="TourniquetCutCalls")


def stop_sessions(runtime_arn, session_ids):
    """Step 4: ends the agent's live AgentCore Runtime sessions. A session that is already gone counts as stopped."""
    ac, out = _c("client", "bedrock-agentcore"), []
    for sid in session_ids:
        try:
            ac.stop_runtime_session(agentRuntimeArn=runtime_arn, runtimeSessionId=sid)
            out.append({"session": sid, "stopped": True})
        except Exception as e:
            if getattr(e, "response", {}).get("Error", {}).get("Code") == "ResourceNotFoundException":
                out.append({"session": sid, "stopped": "already gone"})
            else:
                raise
    return out


def runtime_session_ids(agent):
    return sorted(r["runtime_session_id"] for r in _ddb().Table(T_SESSIONS).scan()["Items"]
                  if r.get("agent") == agent and r.get("runtime_session_id"))


# ---------------------------------------------------------------- orchestrator (plan; rule-based stub)
def orchestrate(alert, reach, steps, model_id):
    """The Orchestrator: a Bedrock model reads the Alert and says which of the available steps to run and why. It only
    chooses from steps that are set up; the code below checks the answer (a plan without the role lock is rejected) and
    the people still have to approve. The model can never add an action, change who approves, or skip approval."""
    avail = [s for s in steps if s["implemented"]]
    prompt = ("You are the Orchestrator of Tourniquet, which contains a compromised AI agent in AWS. Choose which of the "
              "AVAILABLE STEPS to run now and give a one or two sentence reason. Cutting too little leaves the attacker "
              "in; cutting too much stops the shop. Answer with JSON only: {\"steps\": [step numbers], \"rationale\": \"...\"}.\n"
              f"AGENT: {alert['agent']} (role {reach['role_name']}); it also shares {reach.get('shared', [])} with helpers that must keep running.\n"
              "EVIDENCE:\n" + "\n".join(f"- type {e['type']}: {e['txt']}" for e in alert["evidence"]) +
              "\nAVAILABLE STEPS:\n" + "\n".join(f"- {s['n']}: {s['name']}" for s in avail))
    r = _c("client", "bedrock-runtime").converse(modelId=model_id, messages=[{"role": "user", "content": [{"text": prompt}]}],
                                                  inferenceConfig={"maxTokens": 400, "temperature": 0})
    text = r["output"]["message"]["content"][0]["text"]
    a, b = text.find("{"), text.rfind("}")
    out = json.loads(text[a:b + 1])
    chosen = sorted({int(x) for x in out["steps"]})
    ok_set = {s["n"] for s in avail}
    if not chosen or not set(chosen) <= ok_set:
        raise ValueError(f"Orchestrator answer rejected by the safety check: steps {chosen}, allowed {sorted(ok_set)}")
    # Safety floor: every containment step that only touches this agent always runs. The model can only decide about
    # the disruptive one (rotating a secret that helpers also read) and explain; it can never leave the attacker in.
    floor = ok_set - {8}
    dropped = sorted(floor - set(chosen))
    chosen = sorted(set(chosen) | floor)
    note = str(out.get("rationale", ""))[:420]
    if dropped:
        note += f" [Safety floor kept steps {dropped} that the model left out.]"
    return chosen, note


def _exclusive(reach):
    """Secrets only this agent reads. Rotating a secret a helper also uses would break the helper (the database keeps the
    old password), so step 8 touches these only. Rows without the field: all secrets if no helper shares any, else none."""
    if "exclusive_secrets" in reach:
        return [str(x) for x in reach["exclusive_secrets"]]
    return [] if reach.get("shared") else [str(x) for x in reach.get("secrets", [])]


def plan(alert_id, claimer=None):
    d = _ddb()
    alert = d.Table(T_ALERTS).get_item(Key={"alert_id": alert_id})["Item"]
    reach = [r for r in d.Table(T_REACH).scan()["Items"] if r["agent"] == alert["agent"]][0]
    keys = [e["created_key"] for e in alert["evidence"] if e.get("created_key")]
    cedar_cfg = reach.get("policy_engine_id") and reach.get("gateway_arn")
    ready = {1: bool(cedar_cfg), 2: bool(reach.get("secrets")), 4: bool(reach.get("runtime_arn")), 8: bool(_exclusive(reach))}
    steps = [{"n": n, "name": STEP_NAMES[n], "implemented": n in ALWAYS or ready.get(n, False),
              "needs_non_owner": n >= 4} for n in range(1, 9)]
    plan_source, rationale = "rules", "Rule-based: every step that is set up for this agent."
    model = os.environ.get("TQ_MODEL")
    if model:
        try:
            chosen, rationale = orchestrate(alert, reach, steps, model)
            for st_ in steps:
                if st_["implemented"] and st_["n"] not in chosen:
                    st_["implemented"] = False
                    st_["skipped_by_orchestrator"] = True
            plan_source = "bedrock:" + model
        except Exception as e:
            audit("orchestrator_fallback", {"alert": alert_id, "error": str(e)[:300]})
            rationale = "Rule-based (the Bedrock Orchestrator was not usable: " + str(e)[:400] + ")"
    p = {"plan_id": str(uuid.uuid4()), "alert_id": alert_id, "plan_source": plan_source, "rationale": rationale, "agent": alert["agent"], "role": reach["role_name"],
         "owner": reach["owner"], "tool_lambda": reach.get("tool_lambda"), "keys_to_deactivate": keys,
         "policy_engine_id": reach.get("policy_engine_id"), "gateway_arn": reach.get("gateway_arn"),
         "tool_actions": reach.get("tool_actions"), "cedar_pattern": reach.get("cedar_pattern", "lenient"),
         "secrets": [str(x) for x in reach.get("secrets", [])], "exclusive_secrets": _exclusive(reach), "runtime_arn": reach.get("runtime_arn"),
         "runtime_sessions": runtime_session_ids(alert["agent"]) if reach.get("runtime_arn") else [],
         "steps": steps, "left_alone": reach.get("shared", []), "created_by": ORCHESTRATOR}
    p["hash"] = hashlib.sha256(json.dumps(p, sort_keys=True, default=_dec).encode()).hexdigest()
    try:                                       # only one plan per alert: the second caller finds it already planned
        d.Table(T_ALERTS).update_item(Key={"alert_id": alert_id},
                                      UpdateExpression="SET #s=:p, planner=:c, plan_json=:j ADD version :one",
                                      ConditionExpression="#s=:o", ExpressionAttributeNames={"#s": "state"},
                                      ExpressionAttributeValues={":p": "planned", ":o": "open", ":one": 1, ":c": claimer or "-",
                                                                 ":j": json.dumps(p, default=_dec)})
    except d.meta.client.exceptions.ConditionalCheckFailedException:
        cur = d.Table(T_ALERTS).get_item(Key={"alert_id": alert_id}).get("Item", {})
        if claimer and cur.get("planner") == claimer and cur.get("plan_json"):
            audit("plan_resumed", {"alert": alert_id, "why": "retry of the run that made the plan"})
            return json.loads(cur["plan_json"])        # this run made the plan, then a step failed and was retried
        audit("plan_skipped", {"alert": alert_id, "why": "already planned"})
        return None
    audit("plan_created", {"plan": p["plan_id"], "hash": p["hash"]})
    return p


# ---------------------------------------------------------------- approve
class ApprovalRefused(Exception):
    pass


def approvers():
    """Names (or full session ARNs) allowed to approve and lift, from TQ_APPROVERS. Empty means nobody (fail closed)."""
    return {x.strip() for x in os.environ.get("TQ_APPROVERS", "").split(",") if x.strip()}


def is_approver(name, arn):
    allow = approvers()
    return name in allow or (arn is not None and arn in allow)


def approve(p, approver, approvals=None, approver_arn=None):
    """Approver must not be the agent's owner and not the Orchestrator. Critical severity does not skip this.
    `approver` is the IAM principal name taken from the signed request (see handlers.approve), never typed text."""
    if approver == p["owner"]:
        audit("approval_refused", {"plan": p["plan_id"], "approver": approver, "why": "owner"})
        raise ApprovalRefused("the agent's owner cannot approve")
    if approver == p["created_by"] or approver in REFUSED_APPROVERS:
        audit("approval_refused", {"plan": p["plan_id"], "approver": approver, "why": "orchestrator"})
        raise ApprovalRefused("the Orchestrator cannot approve its own plans")
    if not is_approver(approver, approver_arn):
        audit("approval_refused", {"plan": p["plan_id"], "approver": approver, "why": "not an approver"})
        raise ApprovalRefused("not on the approver list")
    rec = {"plan_id": p["plan_id"], "plan_hash": p["hash"], "approver": approver, "approver_arn": approver_arn, "time": now()}
    audit("plan_approved", rec)
    return rec


# ---------------------------------------------------------------- act (Step Functions in the real build)
def act(p, approval):
    """Steps 5, 6, 7 are fast and run first; step 1 (Cedar forbid, about a minute of AgentCore validation) runs beside
    them in a thread, so the role lock does not wait for it. A failed step does not stop the others."""
    from concurrent.futures import ThreadPoolExecutor
    if approval["plan_hash"] != p["hash"]:
        raise ApprovalRefused("plan changed after approval")
    lam, iam = _c("client", "lambda"), _c("client", "iam")

    def one(s):
        n = s["n"]
        if not s["implemented"]:
            return {"n": n, "status": "not set up for this agent"}
        try:
            detail = None
            if n == 1:
                detail = cedar_forbid(p["role"], p["policy_engine_id"], p["gateway_arn"], p.get("tool_actions"), p.get("cedar_pattern", "lenient"))
            elif n == 2:
                for sec in p["secrets"]:
                    secret_deny(sec, p["role"])
            elif n == 3:
                cut_calls(p["role"])
            elif n == 4:
                detail = stop_sessions(p["runtime_arn"], p.get("runtime_sessions", []))
            elif n == 5 and p.get("tool_lambda"):
                lam.put_function_concurrency(FunctionName=p["tool_lambda"], ReservedConcurrentExecutions=0)
            elif n == 6:
                iam.put_role_policy(RoleName=p["role"], PolicyName="TourniquetQuarantine",
                                    PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
                                        {"Effect": "Deny", "Action": "*", "Resource": "*"}]}))
            elif n == 7:
                for k in p["keys_to_deactivate"]:
                    iam.update_access_key(UserName=k["user"], AccessKeyId=k["id"], Status="Inactive")
            elif n == 8:
                for sec in p.get("exclusive_secrets", []):   # never a secret the helpers also use
                    secret_rotate(sec)
            out = {"n": n, "status": "done"}
            if detail is not None:
                out["detail"] = detail
            audit(f"step_{n}", {"plan": p["plan_id"], "name": STEP_NAMES[n]})
            return out
        except Exception as e:
            audit(f"step_{n}_failed", {"plan": p["plan_id"], "error": str(e)[:1800]})
            return {"n": n, "status": "failed", "error": str(e)[:1800]}

    by_n = {s["n"]: s for s in p["steps"]}

    def chain(ns):                             # steps in a chain run in order; chains run side by side
        return [one(by_n[n]) for n in ns if n in by_n]

    # Step 8 (rotate) only after step 2 (deny): the contained agent must not be able to read the new value.
    chains = [[1], [4], [3], [5], [6], [7], [2, 8]]
    with ThreadPoolExecutor(max_workers=7) as ex:
        results = sorted((r for rs in ex.map(chain, chains) for r in rs), key=lambda r: r["n"])
    failed = [r for r in results if r["status"] == "failed"]
    state = "contained_with_errors" if failed else "contained"
    _ddb().Table(T_ALERTS).update_item(Key={"alert_id": p["alert_id"]}, UpdateExpression="SET #s=:s ADD version :one",
                                       ExpressionAttributeNames={"#s": "state"}, ExpressionAttributeValues={":s": state, ":one": 1})
    if failed:
        audit("contained_with_errors", {"agent": p["agent"], "failed": [r["n"] for r in failed]})
        raise RuntimeError(f"steps done except {[r['n'] for r in failed]}: {failed}")   # shows red in Step Functions
    audit("contained", {"agent": p["agent"]})
    return results


# ---------------------------------------------------------------- undo (lift the cut)
class LiftRefused(Exception):
    pass


def lift(agent, approver, approver_arn=None):
    """Lifts a cut: removes the Cedar forbid, the Lambda concurrency limit and the role lock. A key the agent created
    stays Inactive on purpose (it was never the agent's to have). Same approval rules as the cut."""
    d = _ddb()
    reach = [r for r in d.Table(T_REACH).scan()["Items"] if r["agent"] == agent]
    alerts = [a for a in d.Table(T_ALERTS).scan()["Items"] if a["agent"] == agent and a["state"] in ("contained", "contained_with_errors")]
    if not reach or not alerts:
        raise LiftRefused("that agent is not contained")
    reach = reach[0]
    if approver == reach["owner"] or approver in REFUSED_APPROVERS:
        audit("lift_refused", {"agent": agent, "approver": approver})
        raise LiftRefused("the owner and the Orchestrator cannot lift a cut")
    if not is_approver(approver, approver_arn):
        audit("lift_refused", {"agent": agent, "approver": approver, "why": "not an approver"})
        raise LiftRefused("not on the approver list")
    claimed = []                               # claim first: two lifts at once cannot both run
    for a in alerts:
        try:
            d.Table(T_ALERTS).update_item(Key={"alert_id": a["alert_id"]}, UpdateExpression="SET #s=:l ADD version :one",
                                          ConditionExpression="#s IN (:c, :e)", ExpressionAttributeNames={"#s": "state"},
                                          ExpressionAttributeValues={":l": "lifting", ":c": "contained", ":e": "contained_with_errors", ":one": 1})
            claimed.append((a["alert_id"], a["state"]))
        except d.meta.client.exceptions.ConditionalCheckFailedException:
            pass
    if not claimed:
        raise LiftRefused("a lift is already running or the agent is not contained")
    try:                                       # any error after the claim puts the alerts back, so the cut can be lifted again
        lam, iam = _c("client", "lambda"), _c("client", "iam")
        results = []

        def run(n, label, fn):
            try:
                fn(); results.append({"n": n, "step": label, "status": "lifted"})
            except Exception as e:
                code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
                if code in ("NoSuchEntity", "ResourceNotFoundException"):
                    results.append({"n": n, "step": label, "status": "was not set"})
                else:
                    results.append({"n": n, "step": label, "status": "failed", "error": str(e)[:400]})

        if reach.get("policy_engine_id"):
            run(1, "Cedar forbid", lambda: delete_forbids(reach["role_name"], reach["policy_engine_id"]))
        if reach.get("tool_lambda"):
            run(5, "Tool Lambda concurrency", lambda: lam.delete_function_concurrency(FunctionName=reach["tool_lambda"]))
        for sec in reach.get("secrets", []):
            run(2, "Vault deny", lambda sec=sec: secret_allow_again(sec, reach["role_name"]))
        run(3, "Agent calls", lambda: restore_calls(reach["role_name"]))
        run(6, "Role lock", lambda: iam.delete_role_policy(RoleName=reach["role_name"], PolicyName="TourniquetQuarantine"))
        results.append({"n": 7, "step": "Keys it created", "status": "left Inactive on purpose"})
        if reach.get("runtime_arn"):
            results.append({"n": 4, "step": "Runtime sessions", "status": "left ended on purpose"})
        if _exclusive(reach):                  # step 8 only ever touches secrets no helper uses
            results.append({"n": 8, "step": "Rotated secrets", "status": "left rotated on purpose"})
        failed = [r for r in results if r["status"] == "failed"]
        for aid, before in claimed:
            d.Table(T_ALERTS).update_item(Key={"alert_id": aid}, UpdateExpression="SET #s=:s ADD version :one", ExpressionAttributeNames={"#s": "state"},
                                          ExpressionAttributeValues={":s": "lifted" if not failed else before, ":one": 1})
        audit("cut_lifted" if not failed else "lift_failed", {"agent": agent, "approver": approver, "approver_arn": approver_arn, "results": results})
        return results
    except BaseException:
        for aid, before in claimed:
            try:
                d.Table(T_ALERTS).update_item(Key={"alert_id": aid}, UpdateExpression="SET #s=:s ADD version :one",
                                              ExpressionAttributeNames={"#s": "state"}, ExpressionAttributeValues={":s": before, ":one": 1})
            except Exception:
                pass
        raise


# ---------------------------------------------------------------- trigger (scheduled CloudTrail poll)
def cloudtrail_records(minutes=15):
    """All CreateAccessKey and GetSecretValue records in the last few minutes, from the regions where IAM events are recorded."""
    start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=minutes)
    seen = set()
    for region in CT_REGIONS:
        ct = boto3.client("cloudtrail", region_name=region)
        for name in ("CreateAccessKey", "GetSecretValue"):
            for page in ct.get_paginator("lookup_events").paginate(
                    LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": name}], StartTime=start):
                for ev in page["Events"]:
                    rec = json.loads(ev["CloudTrailEvent"])
                    if rec.get("eventID") not in seen:
                        seen.add(rec.get("eventID")); yield rec


def poll(start_execution, minutes=15, mark_only=False):
    """Each event is acted on once. An event is marked in tq-seen only AFTER its pipeline started, so a failed start is
    retried on the next run; the execution name is the eventID, so a second start of the same event is a no-op.
    Only events made by an assumed role start the pipeline; everything else is marked and ignored."""
    seen = _ddb().Table(T_SEEN)
    out = {"new": 0, "started": 0, "marked_only": 0, "failed": 0}

    def mark(rec):
        seen.put_item(Item={"event_id": rec["eventID"], "time": rec.get("eventTime", ""), "seen_at": now()})

    for rec in cloudtrail_records(minutes):
        if seen.get_item(Key={"event_id": rec["eventID"]}).get("Item"):
            continue
        out["new"] += 1
        if mark_only:
            mark(rec); out["marked_only"] += 1
            continue
        issuer = rec.get("userIdentity", {}).get("sessionContext", {}).get("sessionIssuer", {})
        if rec.get("eventName") == "GetSecretValue":      # type 3: counted here, a pipeline only when it is a spike
            spike = secret_spike(rec)
            if spike:
                try:
                    start_execution(spike)
                except Exception as e:
                    out["failed"] += 1
                    audit("pipeline_start_failed", {"eventID": rec["eventID"], "error": str(e)[:300]})
                    continue
                secret_spike_fired(spike)
                audit("pipeline_started_by_poll", {"eventID": rec["eventID"], "role": spike["role_name"], "type": 3})
                out["started"] += 1
            mark(rec)
            continue
        if issuer.get("type") == "Role":
            try:
                start_execution(rec)
            except Exception as e:
                out["failed"] += 1             # not marked: the next run tries again
                audit("pipeline_start_failed", {"eventID": rec["eventID"], "error": str(e)[:300]})
                continue
            audit("pipeline_started_by_poll", {"eventID": rec["eventID"], "role": issuer.get("userName")})
            out["started"] += 1
        mark(rec)
    return out
