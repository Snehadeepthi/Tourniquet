import json, os, pytest, boto3
from moto import mock_aws
from tourniquet_slice import core

os.environ.update(TQ_APPROVERS="sec-lead,tq-demo-sec-lead", AWS_ACCESS_KEY_ID="x", AWS_SECRET_ACCESS_KEY="x", AWS_DEFAULT_REGION=core.REGION)
TRUST = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]})


@pytest.fixture
def shop():
    with mock_aws():
        iam, lam, s3 = (boto3.client(x, region_name=core.REGION) for x in ("iam", "lambda", "s3"))
        s3.create_bucket(Bucket=core.AUDIT_BUCKET, CreateBucketConfiguration={"LocationConstraint": core.REGION})
        core.create_tables()
        roles = {}
        for r in ("supervisor-role", "subagents-role"):
            roles[r] = iam.create_role(RoleName=r, AssumeRolePolicyDocument=TRUST)["Role"]["Arn"]
        iam.create_user(UserName="backdoor-user")
        key = iam.create_access_key(UserName="backdoor-user")["AccessKey"]
        lam.create_function(FunctionName="order-tools", Runtime="python3.12", Role=roles["supervisor-role"],
                            Handler="x.y", Code={"ZipFile": b"x"})
        d = boto3.resource("dynamodb", region_name=core.REGION)
        d.Table(core.T_REACH).put_item(Item={"role_name": "supervisor-role", "agent": "supervisor-agent",
            "owner": "alice", "tool_lambda": "order-tools",
            "shared": ["subagents-role", "orders-db-password", "customer-notes"]})
        d.Table(core.T_SESSIONS).put_item(Item={"access_key_id": "AKIASUPERVISOR", "agent": "supervisor-agent"})
        yield iam, lam, key


def guardrail(role="supervisor-role", key="AKIASUPERVISOR"):
    return {"source": "guardrails", "prompt_attack": True, "role_name": role, "access_key_id": key}


def create_key_event(key):
    return {"eventName": "CreateAccessKey",
            "userIdentity": {"accessKeyId": "AKIASUPERVISOR",
                             "sessionContext": {"sessionIssuer": {"type": "Role", "userName": "supervisor-role"}}},
            "responseElements": {"accessKey": {"accessKeyId": key["AccessKeyId"], "userName": "backdoor-user"}}}


def url_event(arn, body):
    return {"requestContext": {"authorizer": {"iam": {"userArn": arn}}}, "body": json.dumps(body)}


def test_poisoned_order_end_to_end(shop):
    iam, lam, key = shop
    a = core.match(core.detect(guardrail()))                       # type 6, Low
    assert a["level"] == "Low" and a["severity"] == 2
    a = core.match(core.detect(create_key_event(key)))             # type 2 added as evidence, High
    assert a["level"] == "High" and a["severity"] == 8 and len(a["evidence"]) == 2
    p = core.plan(a["alert_id"])
    assert p["role"] == "supervisor-role" and "subagents-role" in p["left_alone"]
    with pytest.raises(core.ApprovalRefused):
        core.approve(p, "alice")                                   # owner refused
    with pytest.raises(core.ApprovalRefused):
        core.approve(p, "orchestrator")                            # cannot approve its own plan
    res = core.act(p, core.approve(p, "sec-lead"))
    assert [r["status"] for r in res if r["n"] in (5, 6, 7)] == ["done"] * 3
    assert [r["status"] for r in res if r["n"] in (1, 2, 4, 8)] == ["not set up for this agent"] * 4
    assert [r["status"] for r in res if r["n"] == 3] == ["done"]
    assert sorted(iam.list_role_policies(RoleName="supervisor-role")["PolicyNames"]) == ["TourniquetCutCalls", "TourniquetQuarantine"]
    assert iam.list_role_policies(RoleName="subagents-role")["PolicyNames"] == []      # helpers untouched
    assert iam.list_access_keys(UserName="backdoor-user")["AccessKeyMetadata"][0]["Status"] == "Inactive"
    assert lam.get_function_concurrency(FunctionName="order-tools")["ReservedConcurrentExecutions"] == 0
    assert core.verify_audit()


def test_no_match_cuts_nothing(shop):
    iam, lam, key = shop
    sig = core.detect(guardrail(role="some-other-role", key="AKIAUNKNOWN"))
    assert core.match(sig) is None
    assert iam.list_role_policies(RoleName="supervisor-role")["PolicyNames"] == []


def test_non_agent_create_key_is_ignored(shop):
    assert core.detect({"eventName": "CreateAccessKey", "userIdentity": {"type": "IAMUser"}}) is None


def test_plan_change_after_approval_is_refused(shop):
    iam, lam, key = shop
    a = core.match(core.detect(guardrail()))
    p = core.plan(a["alert_id"])
    ap = core.approve(p, "sec-lead")
    p["steps"][0]["name"] = "tampered"; p["hash"] = "different"
    with pytest.raises(core.ApprovalRefused):
        core.act(p, ap)


def test_audit_tamper_detected(shop):
    core.audit("x", {}); core.audit("y", {})
    s3 = boto3.client("s3", region_name=core.REGION)
    s3.put_object(Bucket=core.AUDIT_BUCKET, Key="audit/000001.json",
                  Body=json.dumps({"seq": 1, "time": "t", "action": "z", "detail": {}, "prev": "0" * 64, "hash": "bad"}).encode())
    assert not core.verify_audit()


def test_handlers_pipeline_with_approval_wait(shop, monkeypatch):
    from tourniquet_slice import handlers
    iam, lam, key = shop
    released = {}

    class FakeSfn:
        def send_task_success(self, taskToken, output):
            released["token"], released["out"] = taskToken, output
    real = boto3.client
    monkeypatch.setattr(handlers.boto3, "client", lambda svc, **k: FakeSfn() if svc == "stepfunctions" else real(svc, **k))
    d = boto3.client("dynamodb", region_name=core.REGION)
    d.create_table(TableName="tq-approvals", KeySchema=[{"AttributeName": "plan_id", "KeyType": "HASH"}],
                   AttributeDefinitions=[{"AttributeName": "plan_id", "AttributeType": "S"}], BillingMode="PAY_PER_REQUEST") \
        if "tq-approvals" not in d.list_tables()["TableNames"] else None
    # signal 1 stays Low; signal 2 goes High and plans
    m1 = handlers.match(handlers.detect({"record": guardrail()}))
    assert m1["alert"]["level"] == "Low"
    m2 = handlers.match(handlers.detect({"record": create_key_event(key)}))
    assert m2["alert"]["level"] == "High"
    p = handlers.plan({"alert": m2["alert"]})["plan"]
    handlers.request_approval({"plan": p, "token": "TOKEN123"})
    typed = handlers.approve({"plan_id": p["plan_id"], "approver": "sec-lead"})              # a typed name is worthless
    assert typed["ok"] is False and "no verified identity" in typed["why"]
    assert handlers.approve(url_event("arn:aws:sts::111122223333:assumed-role/alice/s1", {"plan_id": p["plan_id"]}))["ok"] is False
    assert handlers.approve(url_event("arn:aws:sts::111122223333:assumed-role/tq-orchestrator-role/x", {"plan_id": p["plan_id"]}))["ok"] is False
    assert "token" not in released                                   # refusal does not release the workflow
    r = handlers.approve(url_event("arn:aws:sts::111122223333:assumed-role/sec-lead/s9", {"plan_id": p["plan_id"]}))
    assert r["ok"] is True and r["approver"] == "sec-lead"
    assert released["token"] == "TOKEN123"
    out = handlers.act({"plan": p, "approval": json.loads(released["out"])["approval"]})
    assert [r["status"] for r in out["results"] if r["n"] in (5, 6, 7)] == ["done"] * 3


def test_cloudtrail_readback_feeds_detect(shop, monkeypatch):
    iam, lam, key = shop
    rec = create_key_event(key); rec["eventTime"] = "2026-11-18T10:00:00Z"; rec["eventID"] = "e1"
    class FakeCT:
        def get_paginator(self, n):
            class P:
                def paginate(self, **kw):
                    assert kw["LookupAttributes"][0]["AttributeValue"] == "CreateAccessKey"
                    return [{"Events": [{"CloudTrailEvent": json.dumps(rec)}]}]
            return P()
    real = boto3.client
    monkeypatch.setattr(core.boto3, "client", lambda svc, **kw: FakeCT() if svc == "cloudtrail" else real(svc, **kw))
    got = core.read_cloudtrail(key["AccessKeyId"])
    assert got["eventID"] == "e1"
    assert core.read_cloudtrail("AKIAOTHER") is None            # a different key id is not picked up
    sig = core.detect(got)
    assert sig["type"] == 2 and sig["role_name"] == "supervisor-role"


class FakeAC:
    """Stands in for bedrock-agentcore-control: refuses the first forbid form, accepts the second."""
    class exceptions:
        class ConflictException(Exception): pass
    def __init__(self): self.made, self.deleted = [], []
    def create_policy(self, **kw):
        assert kw["validationMode"] == "FAIL_ON_ANY_FINDINGS" and "forbid(" in kw["definition"]["cedar"]["statement"]
        self.made.append(kw["definition"]["cedar"]["statement"])
        return {"policyId": f"p{len(self.made)}"}
    def get_policy(self, policyEngineId, policyId):
        return {"status": "CREATE_FAILED" if policyId == "p1" else "ACTIVE", "statusReasons": ["no match"]}
    def delete_policy(self, policyEngineId, policyId): self.deleted.append(policyId)


def test_cedar_forbid_falls_back_and_names_only_the_agent_role(shop, monkeypatch):
    fake = FakeAC()
    real_c = core._c
    monkeypatch.setattr(core, "_c", lambda kind, svc: fake if svc == "bedrock-agentcore-control" else real_c(kind, svc))
    gw = "arn:aws:bedrock-agentcore:ap-southeast-2:111122223333:gateway/tq-gateway-x"
    r = core.cedar_forbid("supervisor-role", "eng1", gw)
    assert r["policy_id"] == "p2" and r["form"] == "one gateway" and fake.deleted == ["p1"]
    for stmt in fake.made:
        assert "assumed-role/supervisor-role" in stmt and "subagents-role" not in stmt   # helpers are never named
    assert 'resource == AgentCore::Gateway::"' + gw + '"' in fake.made[1]


def test_plan_marks_step_1_implemented_only_when_gateway_is_configured(shop):
    a = core.match(core.detect(guardrail())); a = core.match(core.detect(create_key_event(shop[2])))
    assert core.plan(a["alert_id"])["steps"][0]["implemented"] is False
    boto3.resource("dynamodb", region_name=core.REGION).Table(core.T_REACH).update_item(Key={"role_name": "supervisor-role"},
        UpdateExpression="SET policy_engine_id = :e, gateway_arn = :g", ExpressionAttributeValues={":e": "eng1", ":g": "arn:x:y:z:111122223333:gateway/g"})
    boto3.resource("dynamodb", region_name=core.REGION).Table(core.T_ALERTS).update_item(Key={"alert_id": a["alert_id"]},
        UpdateExpression="SET #s=:o", ExpressionAttributeNames={"#s": "state"}, ExpressionAttributeValues={":o": "open"})
    p = core.plan(a["alert_id"])
    assert p["steps"][0]["implemented"] is True and p["policy_engine_id"] == "eng1"


def test_a_failed_step_does_not_stop_the_other_steps(shop, monkeypatch):
    iam, lam, key = shop
    a = core.match(core.detect(guardrail())); a = core.match(core.detect(create_key_event(key)))
    boto3.resource("dynamodb", region_name=core.REGION).Table(core.T_REACH).update_item(Key={"role_name": "supervisor-role"},
        UpdateExpression="SET policy_engine_id = :e, gateway_arn = :g", ExpressionAttributeValues={":e": "eng1", ":g": "arn:x:y:z:111122223333:gateway/g"})
    boto3.resource("dynamodb", region_name=core.REGION).Table(core.T_ALERTS).update_item(Key={"alert_id": a["alert_id"]},
        UpdateExpression="SET #s=:o", ExpressionAttributeNames={"#s": "state"}, ExpressionAttributeValues={":o": "open"})
    p = core.plan(a["alert_id"])
    monkeypatch.setattr(core, "cedar_forbid", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("AccessDenied")))
    with pytest.raises(RuntimeError, match="steps done except"):
        core.act(p, core.approve(p, "sec-lead"))
    assert "TourniquetQuarantine" in iam.list_role_policies(RoleName="supervisor-role")["PolicyNames"]      # step 6 still ran
    assert lam.get_function_concurrency(FunctionName="order-tools")["ReservedConcurrentExecutions"] == 0       # step 5 too


def test_principal_name_from_arns():
    assert core.principal_name("arn:aws:sts::1:assumed-role/sec-lead/sess") == "sec-lead"
    assert core.principal_name("arn:aws:iam::1:user/team/bob") == "bob"
    assert core.principal_name("arn:aws:iam::1:root") == "root"


def contain(shop):
    iam, lam, key = shop
    a = core.match(core.detect(guardrail())); a = core.match(core.detect(create_key_event(key)))
    p = core.plan(a["alert_id"])
    core.act(p, core.approve(p, "sec-lead"))
    return p


def test_lift_undoes_the_cut_but_keeps_the_backdoor_key_off(shop):
    iam, lam, key = shop
    contain(shop)
    assert "TourniquetQuarantine" in iam.list_role_policies(RoleName="supervisor-role")["PolicyNames"]
    with pytest.raises(core.LiftRefused):
        core.lift("supervisor-agent", "alice")                      # owner refused
    with pytest.raises(core.LiftRefused):
        core.lift("supervisor-agent", "tq-orchestrator-role")       # Orchestrator refused
    res = core.lift("supervisor-agent", "sec-lead")
    assert not [r for r in res if r["status"] == "failed"]
    assert iam.list_role_policies(RoleName="supervisor-role")["PolicyNames"] == []
    assert "ReservedConcurrentExecutions" not in lam.get_function_concurrency(FunctionName="order-tools")
    assert iam.list_access_keys(UserName="backdoor-user")["AccessKeyMetadata"][0]["Status"] == "Inactive"
    with pytest.raises(core.LiftRefused):
        core.lift("supervisor-agent", "sec-lead")                   # nothing left to lift
    assert core.verify_audit() is True


def test_lift_needs_a_signed_identity(shop):
    from tourniquet_slice import handlers
    assert "no verified identity" in handlers.lift({"body": json.dumps({"agent": "supervisor-agent"})})["why"]


def test_poll_starts_each_event_once_and_ignores_other_callers(shop, monkeypatch):
    iam, lam, key = shop
    by_role = create_key_event(key); by_role.update(eventID="e1", eventTime="2026-11-18T10:00:00Z")
    by_user = {"eventName": "CreateAccessKey", "eventID": "e2", "eventTime": "2026-11-18T10:00:01Z",
               "userIdentity": {"type": "IAMUser", "accessKeyId": "AKIAX"}}
    class FakeCT:
        def get_paginator(self, n):
            class P:
                def paginate(self, **kw): return [{"Events": [{"CloudTrailEvent": json.dumps(by_role)}, {"CloudTrailEvent": json.dumps(by_user)}]}]
            return P()
    real = boto3.client
    monkeypatch.setattr(core.boto3, "client", lambda svc, **kw: FakeCT() if svc == "cloudtrail" else real(svc, **kw))
    started = []
    assert core.poll(started.append) == {"new": 2, "started": 1, "marked_only": 0, "failed": 0}      # role event starts, user event does not
    assert core.poll(started.append) == {"new": 0, "started": 0, "marked_only": 0, "failed": 0}      # second poll: nothing is repeated
    assert [r["eventID"] for r in started] == ["e1"]


def test_poll_mark_seen_starts_nothing(shop, monkeypatch):
    iam, lam, key = shop
    ev = create_key_event(key); ev.update(eventID="old1", eventTime="2026-11-18T09:00:00Z")
    class FakeCT:
        def get_paginator(self, n):
            class P:
                def paginate(self, **kw): return [{"Events": [{"CloudTrailEvent": json.dumps(ev)}]}]
            return P()
    real = boto3.client
    monkeypatch.setattr(core.boto3, "client", lambda svc, **kw: FakeCT() if svc == "cloudtrail" else real(svc, **kw))
    started = []
    assert core.poll(started.append, mark_only=True)["marked_only"] == 1
    assert core.poll(started.append)["started"] == 0 and started == []


def test_strict_cedar_pattern_matches_only_the_role_sessions():
    gw = "arn:aws:bedrock-agentcore:ap-southeast-2:111122223333:gateway/g"
    strict = core.forbid_statements("supervisor-role", gw, ["T___t"], "strict")
    lenient = core.forbid_statements("supervisor-role", gw, ["T___t"], "lenient")
    assert all('assumed-role/supervisor-role/*"' in st for _, st in strict)
    assert all('assumed-role/supervisor-role*"' in st for _, st in lenient)


def test_exact_cedar_pattern_has_no_wildcard():
    gw = "arn:aws:bedrock-agentcore:ap-southeast-2:111122223333:gateway/g"
    for _, st in core.forbid_statements("supervisor-role", gw, ["T___t"], "exact"):
        assert 'principal.id == "arn:aws:sts::111122223333:assumed-role/supervisor-role"' in st and "like" not in st


def test_delete_forbids_matches_the_exact_name_only(shop, monkeypatch):
    deleted = []
    names = ["tq_forbid_supervisor_role_1795003897_0",        # ours
             "tq_forbid_supervisor_role_1795003897_1",        # ours, second form
             "tq_forbid_supervisor_role_2_1795003897_0",      # supervisor-role-2: must survive
             "tq_forbid_supervisor_role_old_1795003897_0",    # supervisor-role-old: must survive
             "tq_forbid_supervisor_role_17950038_0",          # wrong time width: must survive
             "tq_permit_agents"]

    class AC:
        def list_policies(self, policyEngineId, nextToken=None):
            items = [{"name": n, "policyId": n, "description": "Tourniquet step 1: cut " + ("supervisor-role-2" if "role_2" in n else "supervisor-role")} for n in names]
            return {"policies": items}
        def delete_policy(self, policyEngineId, policyId):
            deleted.append(policyId)
    real = boto3.client
    monkeypatch.setattr(core.boto3, "client", lambda svc, **kw: AC() if svc == "bedrock-agentcore-control" else real(svc, **kw))
    assert core.delete_forbids("supervisor-role", "eng") == 2
    assert deleted == ["tq_forbid_supervisor_role_1795003897_0", "tq_forbid_supervisor_role_1795003897_1"]
    deleted.clear()
    assert core.delete_forbids("supervisor-role-2", "eng") == 1 and deleted == ["tq_forbid_supervisor_role_2_1795003897_0"]


def test_delete_forbids_uses_the_description_when_two_roles_share_an_underscored_name(shop, monkeypatch):
    deleted = []

    class AC:
        def list_policies(self, policyEngineId, nextToken=None):
            return {"policies": [{"name": "tq_forbid_a_b_1795003897_0", "policyId": "p1", "description": "Tourniquet step 1: cut a_b"},
                                 {"name": "tq_forbid_a_b_1795003897_1", "policyId": "p2", "description": "Tourniquet step 1: cut a-b"}]}
        def delete_policy(self, policyEngineId, policyId):
            deleted.append(policyId)
    real = boto3.client
    monkeypatch.setattr(core.boto3, "client", lambda svc, **kw: AC() if svc == "bedrock-agentcore-control" else real(svc, **kw))
    core.delete_forbids("a-b", "eng")
    assert deleted == ["p2"]


def test_poll_failed_start_is_retried_not_lost(shop, monkeypatch):
    iam, lam, key = shop
    ev = create_key_event(key); ev.update(eventID="e9", eventTime="2026-11-18T10:00:00Z")

    class FakeCT:
        def get_paginator(self, n):
            class P:
                def paginate(self, **kw): return [{"Events": [{"CloudTrailEvent": json.dumps(ev)}]}]
            return P()
    real = boto3.client
    monkeypatch.setattr(core.boto3, "client", lambda svc, **kw: FakeCT() if svc == "cloudtrail" else real(svc, **kw))
    calls = []

    def flaky(rec):
        calls.append(rec["eventID"])
        if len(calls) == 1:
            raise RuntimeError("throttled")
    assert core.poll(flaky)["failed"] == 1                      # first start fails: NOT marked seen
    assert core.poll(flaky)["started"] == 1                     # next run starts it
    assert core.poll(flaky)["new"] == 0 and calls == ["e9", "e9"]


def test_a_second_plan_for_the_same_alert_is_skipped(shop):
    from tourniquet_slice import handlers
    a = core.match(core.detect(guardrail())); a = core.match(core.detect(create_key_event(shop[2])))
    assert handlers.plan({"alert": a})["plan"] is not None
    assert handlers.plan({"alert": a})["plan"] is None


def test_approver_allowlist_and_one_approval_only(shop, monkeypatch):
    from tourniquet_slice import handlers
    iam, lam, key = shop
    sent = []

    class FakeSfn:
        def send_task_success(self, taskToken, output): sent.append(taskToken)
    real = boto3.client
    monkeypatch.setattr(handlers.boto3, "client", lambda svc, **k: FakeSfn() if svc == "stepfunctions" else real(svc, **k))
    a = core.match(core.detect(guardrail())); a = core.match(core.detect(create_key_event(key)))
    p = handlers.plan({"alert": a})["plan"]
    handlers.request_approval({"plan": p, "token": "T1"})
    body = {"plan_id": p["plan_id"]}
    stranger = handlers.approve(url_event("arn:aws:sts::111122223333:assumed-role/bob/s", body))
    assert stranger["ok"] is False and "approver list" in stranger["why"]
    assert handlers.approve(url_event("arn:aws:sts::111122223333:assumed-role/sec-lead/s", body))["ok"] is True
    again = handlers.approve(url_event("arn:aws:sts::111122223333:assumed-role/sec-lead/s2", body))
    assert again["ok"] is False and again["why"] == "no waiting plan" and sent == ["T1"]


def test_lift_refuses_a_stranger_and_an_empty_allowlist_refuses_everyone(shop, monkeypatch):
    contain(shop)
    with pytest.raises(core.LiftRefused, match="approver list"):
        core.lift("supervisor-agent", "bob")
    monkeypatch.setenv("TQ_APPROVERS", "")
    with pytest.raises(core.LiftRefused, match="approver list"):
        core.lift("supervisor-agent", "sec-lead")
    monkeypatch.setenv("TQ_APPROVERS", "arn:aws:sts::111122223333:assumed-role/AWSReservedSSO_Sec_ab12/alice")
    assert core.is_approver("AWSReservedSSO_Sec_ab12", "arn:aws:sts::111122223333:assumed-role/AWSReservedSSO_Sec_ab12/alice")
    assert not core.is_approver("AWSReservedSSO_Sec_ab12", "arn:aws:sts::111122223333:assumed-role/AWSReservedSSO_Sec_ab12/mallory")


def test_parallel_audit_writes_keep_one_chain(shop):
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=6) as ex:
        list(ex.map(lambda i: core.audit("t", {"i": i}), range(12)))
    assert core.verify_audit() is True


def test_approval_timeout_expires_the_alert(shop):
    from tourniquet_slice import handlers
    a = core.match(core.detect(guardrail())); a = core.match(core.detect(create_key_event(shop[2])))
    p = handlers.plan({"alert": a})["plan"]
    handlers.request_approval({"plan": p, "token": "T"})
    handlers.expire({"p": {"plan": p}})
    d = boto3.resource("dynamodb", region_name=core.REGION)
    assert d.Table(core.T_ALERTS).get_item(Key={"alert_id": p["alert_id"]})["Item"]["state"] == "expired"
    assert d.Table(core.T_APPROVALS).get_item(Key={"plan_id": p["plan_id"]})["Item"]["state"] == "expired"


def test_a_stale_match_cannot_put_an_old_state_back(shop):
    """match() read the Alert, then plan() moved it on: match's write must fail its version check and retry."""
    from tourniquet_slice import handlers
    a = core.match(core.detect(guardrail())); a = core.match(core.detect(create_key_event(shop[2])))
    stale = dict(a)                                   # what a slow match() read: state open, version N
    p = handlers.plan({"alert": a})["plan"]
    t = boto3.resource("dynamodb", region_name=core.REGION).Table(core.T_ALERTS)
    after = t.get_item(Key={"alert_id": a["alert_id"]})["Item"]
    assert after["state"] == "planned" and int(after["version"]) > int(stale["version"])
    import botocore
    with pytest.raises(botocore.exceptions.ClientError):                # the stale write is refused
        t.put_item(Item=json.loads(json.dumps(stale, default=core._dec), parse_float=str),
                   ConditionExpression="version = :v", ExpressionAttributeValues={":v": stale["version"]})
    assert handlers.plan({"alert": a})["plan"] is None                  # and no second plan
    p2 = core.match(core.detect(create_key_event(shop[2])))              # new evidence joins the planned alert
    assert p2["alert_id"] == a["alert_id"]
    assert t.get_item(Key={"alert_id": a["alert_id"]})["Item"]["state"] == "planned"


def test_act_and_lift_and_expire_bump_the_version(shop):
    t = boto3.resource("dynamodb", region_name=core.REGION).Table(core.T_ALERTS)
    p = contain(shop)
    v1 = int(t.get_item(Key={"alert_id": p["alert_id"]})["Item"]["version"])
    core.lift("supervisor-agent", "sec-lead")
    item = t.get_item(Key={"alert_id": p["alert_id"]})["Item"]
    assert item["state"] == "lifted" and int(item["version"]) > v1


def test_approve_error_after_the_claim_puts_the_row_back(shop, monkeypatch):
    from tourniquet_slice import handlers
    a = core.match(core.detect(guardrail())); a = core.match(core.detect(create_key_event(shop[2])))
    p = handlers.plan({"alert": a})["plan"]
    handlers.request_approval({"plan": p, "token": "T"})
    monkeypatch.setattr(handlers.core, "approve", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("audit down")))
    with pytest.raises(RuntimeError):
        handlers.approve(url_event("arn:aws:sts::111122223333:assumed-role/sec-lead/s", {"plan_id": p["plan_id"]}))
    row = boto3.resource("dynamodb", region_name=core.REGION).Table(core.T_APPROVALS).get_item(Key={"plan_id": p["plan_id"]})["Item"]
    assert row["state"] == "waiting"                                     # not stuck at deciding


def test_lift_error_after_the_claim_puts_the_alert_back(shop, monkeypatch):
    p = contain(shop)
    monkeypatch.setattr(core, "audit", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("audit down")))
    with pytest.raises(RuntimeError):
        core.lift("supervisor-agent", "sec-lead")
    t = boto3.resource("dynamodb", region_name=core.REGION).Table(core.T_ALERTS)
    assert t.get_item(Key={"alert_id": p["alert_id"]})["Item"]["state"] == "contained"
    monkeypatch.undo()
    core.lift("supervisor-agent", "sec-lead")                            # can be lifted again


# ---- cuts 2, 3, 4, 8
def _secret(name="tq-demo/orders-db-password", value="old-secret"):
    sm = boto3.client("secretsmanager", region_name=core.REGION)
    sm.create_secret(Name=name, SecretString=value)
    return sm, name


def test_step_2_vault_deny_adds_and_removes_only_its_own_statement(shop):
    sm, name = _secret()
    other = {"Sid": "KeepMe", "Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:role/other"}, "Action": "secretsmanager:GetSecretValue", "Resource": "*"}
    sm.put_resource_policy(SecretId=name, ResourcePolicy=json.dumps({"Version": "2012-10-17", "Statement": [other]}))
    core.secret_deny(name, "supervisor-role")
    sids = [x["Sid"] for x in json.loads(sm.get_resource_policy(SecretId=name)["ResourcePolicy"])["Statement"]]
    assert sids == ["KeepMe", "TourniquetDenysupervisorrole"]
    core.secret_deny(name, "supervisor-role")                          # twice is still one statement
    assert len(json.loads(sm.get_resource_policy(SecretId=name)["ResourcePolicy"])["Statement"]) == 2
    core.secret_allow_again(name, "supervisor-role")
    assert [x["Sid"] for x in json.loads(sm.get_resource_policy(SecretId=name)["ResourcePolicy"])["Statement"]] == ["KeepMe"]
    with pytest.raises(Exception) as e:
        core.secret_allow_again(name, "supervisor-role")
    assert e.value.response["Error"]["Code"] == "ResourceNotFoundException"


def test_step_8_rotate_changes_the_value_and_drops_the_old_one_from_previous(shop):
    sm, name = _secret()
    old = sm.get_secret_value(SecretId=name)["SecretString"]
    core.secret_rotate(name)
    assert sm.get_secret_value(SecretId=name)["SecretString"] != old
    stages = sm.describe_secret(SecretId=name)["VersionIdsToStages"]
    assert not any("AWSPREVIOUS" in v for v in stages.values())         # the leaked value is not the previous version either
    assert sum("AWSCURRENT" in v for v in stages.values()) == 1


def test_step_3_cut_calls_adds_and_removes_the_policy(shop):
    iam = shop[0]
    core.cut_calls("supervisor-role")
    doc = iam.get_role_policy(RoleName="supervisor-role", PolicyName="TourniquetCutCalls")["PolicyDocument"]
    assert doc["Statement"][0]["Effect"] == "Deny" and "lambda:InvokeFunction" in doc["Statement"][0]["Action"]
    core.restore_calls("supervisor-role")
    assert "TourniquetCutCalls" not in iam.list_role_policies(RoleName="supervisor-role")["PolicyNames"]


def test_step_4_stop_sessions_stops_each_and_tolerates_gone_sessions(shop, monkeypatch):
    stopped = []

    class AC:
        def stop_runtime_session(self, agentRuntimeArn, runtimeSessionId):
            if runtimeSessionId == "gone":
                e = Exception("nf"); e.response = {"Error": {"Code": "ResourceNotFoundException"}}; raise e
            stopped.append((agentRuntimeArn, runtimeSessionId))
    real = boto3.client
    monkeypatch.setattr(core.boto3, "client", lambda svc, **kw: AC() if svc == "bedrock-agentcore" else real(svc, **kw))
    out = core.stop_sessions("arn:rt", ["s1", "gone"])
    assert stopped == [("arn:rt", "s1")] and out[1]["stopped"] == "already gone"


def test_full_plan_runs_all_eight_steps_when_the_agent_is_set_up_for_them(shop, monkeypatch):
    iam, lam, key = shop
    sm, name = _secret()
    old = sm.get_secret_value(SecretId=name)["SecretString"]
    d = boto3.resource("dynamodb", region_name=core.REGION)
    d.Table(core.T_REACH).update_item(Key={"role_name": "supervisor-role"},
        UpdateExpression="SET secrets=:s, exclusive_secrets=:s, runtime_arn=:r, policy_engine_id=:e, gateway_arn=:g",
        ExpressionAttributeValues={":s": [name], ":r": "arn:rt", ":e": "eng", ":g": "arn:x:y:z:111122223333:gateway/g"})
    d.Table(core.T_SESSIONS).put_item(Item={"access_key_id": "AKIARUNTIME", "agent": "supervisor-agent", "runtime_session_id": "sess-1"})
    seen = {}
    monkeypatch.setattr(core, "cedar_forbid", lambda *a, **k: {"ok": True})
    monkeypatch.setattr(core, "stop_sessions", lambda arn, ids: seen.update(arn=arn, ids=ids) or [{"session": i, "stopped": True} for i in ids])
    monkeypatch.setattr(core, "delete_forbids", lambda *a, **k: 1)
    a = core.match(core.detect(guardrail())); a = core.match(core.detect(create_key_event(key)))
    p = core.plan(a["alert_id"])
    assert [s["implemented"] for s in p["steps"]] == [True] * 8
    res = core.act(p, core.approve(p, "sec-lead"))
    assert [r["status"] for r in res] == ["done"] * 8 and seen == {"arn": "arn:rt", "ids": ["sess-1"]}
    assert sm.get_secret_value(SecretId=name)["SecretString"] != old
    assert "TourniquetDenysupervisorrole" in sm.get_resource_policy(SecretId=name)["ResourcePolicy"]
    lifted = core.lift("supervisor-agent", "sec-lead")
    assert {r["n"]: r["status"] for r in lifted} == {1: "lifted", 2: "lifted", 3: "lifted", 4: "left ended on purpose", 5: "lifted",
                                                     6: "lifted", 7: "left Inactive on purpose", 8: "left rotated on purpose"}
    assert core.verify_audit() is True


def test_step_8_never_rotates_a_secret_the_helpers_also_use(shop, monkeypatch):
    iam, lam, key = shop
    sm, name = _secret()
    old = sm.get_secret_value(SecretId=name)["SecretString"]
    d = boto3.resource("dynamodb", region_name=core.REGION)
    # the discovered row says: one secret, and a helper reads it too, so nothing is exclusive
    d.Table(core.T_REACH).update_item(Key={"role_name": "supervisor-role"},
        UpdateExpression="SET secrets=:s, exclusive_secrets=:x", ExpressionAttributeValues={":s": [name], ":x": []})
    a = core.match(core.detect(guardrail())); a = core.match(core.detect(create_key_event(key)))
    p = core.plan(a["alert_id"])
    s8 = [s for s in p["steps"] if s["n"] == 8][0]
    assert s8["implemented"] is False and p["exclusive_secrets"] == []
    core.act(p, core.approve(p, "sec-lead"))
    assert sm.get_secret_value(SecretId=name)["SecretString"] == old      # untouched
    assert "TourniquetDenysupervisorrole" in sm.get_resource_policy(SecretId=name)["ResourcePolicy"]   # step 2 still blocks the agent


def test_old_reach_rows_without_the_field_are_treated_safely():
    assert core._exclusive({"secrets": ["a"], "shared": ["helper-role"]}) == []
    assert core._exclusive({"secrets": ["a"], "shared": []}) == ["a"]


def test_concurrent_first_signals_make_one_alert(shop):
    from concurrent.futures import ThreadPoolExecutor
    key = shop[2]
    sigs = [core.detect(guardrail()) for _ in range(3)] + [core.detect(create_key_event(key)) for _ in range(3)]
    with ThreadPoolExecutor(max_workers=6) as ex:
        list(ex.map(core.match, sigs))
    items = boto3.resource("dynamodb", region_name=core.REGION).Table(core.T_ALERTS).scan()["Items"]
    mine = [a for a in items if a["agent"] == "supervisor-agent"]
    assert len(mine) == 1 and len(mine[0]["evidence"]) == 6 and mine[0]["alert_id"] == "supervisor-agent-0001"
    assert core.verify_audit() is True


def test_collector_discovers_the_reach_map(shop):
    from tourniquet_slice import collector
    iam, lam, key = shop
    sm = boto3.client("secretsmanager", region_name=core.REGION)
    sm.create_secret(Name="tq-demo/orders-db-password", SecretString="x")
    sm.create_secret(Name="unrelated/secret", SecretString="y")
    arn = "arn:aws:secretsmanager:" + core.REGION + ":123456789012:secret:tq-demo/*"
    pol = lambda st: json.dumps({"Version": "2012-10-17", "Statement": st})
    iam.put_role_policy(RoleName="supervisor-role", PolicyName="p", PolicyDocument=pol([
        {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": arn},
        {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": "arn:aws:lambda:x:1:function:tq-helper-agent"},
        {"Effect": "Deny", "Action": "secretsmanager:*", "Resource": "*"}]))
    iam.put_role_policy(RoleName="subagents-role", PolicyName="p", PolicyDocument=pol([{"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": arn}]))
    iam.tag_role(RoleName="supervisor-role", Tags=[{"Key": "tq-owner", "Value": "alice"}])
    lam.tag_resource(Resource=lam.get_function(FunctionName="order-tools")["Configuration"]["FunctionArn"], Tags={"tq-tool-of": "supervisor-agent"})
    row = collector.discover("supervisor-role", "supervisor-agent")
    assert row["secrets"] == ["tq-demo/orders-db-password"] and row["shared"] == ["subagents-role"]
    assert row["exclusive_secrets"] == []     # the helper reads the same secret, so step 8 must leave it alone
    assert row["calls"] == ["tq-helper-agent"] and row["tool_lambda"] == "order-tools" and row["owner"] == "alice"
    d = boto3.resource("dynamodb", region_name=core.REGION).Table(core.T_REACH)
    d.update_item(Key={"role_name": "supervisor-role"}, UpdateExpression="SET policy_engine_id=:e", ExpressionAttributeValues={":e": "eng9"})
    merged = collector.write_reach(row)
    assert merged["policy_engine_id"] == "eng9" and merged["discovered"] is True        # undiscovered fields survive


def test_collector_refuses_an_agent_without_an_owner(shop):
    from tourniquet_slice import collector
    with pytest.raises(ValueError, match="tq-owner"):
        collector.discover("subagents-role", "helper-agent")


def test_orchestrator_chooses_from_available_steps_and_is_checked(shop, monkeypatch):
    iam, lam, key = shop
    monkeypatch.setenv("TQ_MODEL", "fake-model")
    answers = iter(['Sure: {"steps": [3, 5, 6, 7], "rationale": "Cut calls and the role; leave the helpers."}',
                    '{"steps": [5], "rationale": "only the lambda"}',            # too little: the safety floor adds the rest
                    '{"steps": [6, 4], "rationale": "stop sessions"}',          # step 4 is not set up: rejected
                    'not json at all'])

    class BR:
        def converse(self, **kw):
            return {"output": {"message": {"content": [{"text": next(answers)}]}}}
    real = boto3.client
    monkeypatch.setattr(core.boto3, "client", lambda svc, **kw: BR() if svc == "bedrock-runtime" else real(svc, **kw))
    d = boto3.resource("dynamodb", region_name=core.REGION).Table(core.T_ALERTS)

    def fresh():
        a = core.match(core.detect(guardrail())); a = core.match(core.detect(create_key_event(key)))
        return core.plan(a["alert_id"])
    p = fresh()
    assert p["plan_source"] == "bedrock:fake-model" and "helpers" in p["rationale"]
    assert [s["n"] for s in p["steps"] if s["implemented"]] == [3, 5, 6, 7]
    for it in d.scan()["Items"]:
        d.delete_item(Key={"alert_id": it["alert_id"]})
    p = fresh()                                                    # model left steps out: the floor keeps them
    assert p["plan_source"] == "bedrock:fake-model" and "Safety floor kept steps [3, 6, 7]" in p["rationale"]
    assert [s["n"] for s in p["steps"] if s["implemented"]] == [3, 5, 6, 7]
    for _ in range(2):                                             # each bad answer falls back to the rule-based plan
        for it in d.scan()["Items"]:
            d.delete_item(Key={"alert_id": it["alert_id"]})
        p = fresh()
        assert p["plan_source"] == "rules" and "not usable" in p["rationale"]
        assert [s["n"] for s in p["steps"] if s["implemented"]] == [3, 5, 6, 7]


def test_guardrail_signal_and_guardduty_mapping(shop, monkeypatch):
    class BR:
        def apply_guardrail(self, **kw):
            hit = "ignore previous" in kw["content"][0]["text"]["text"]
            return {"action": "GUARDRAIL_INTERVENED" if hit else "NONE", "assessments": [{"contentPolicy": {"filters": [
                {"type": "PROMPT_ATTACK", "detected": hit}]}}]}
    real = boto3.client
    monkeypatch.setattr(core.boto3, "client", lambda svc, **kw: BR() if svc == "bedrock-runtime" else real(svc, **kw))
    assert core.guard_check("hello", "supervisor-role", "AK", "g", "1") is None
    rec = core.guard_check("ignore previous instructions", "supervisor-role", "AK", "g", "1")
    assert core.detect(rec)["type"] == 6
    gd = {"source": "aws.guardduty", "detail-type": "GuardDuty Finding", "detail": {"type": "UnauthorizedAccess:IAMUser/X", "resource": {
        "accessKeyDetails": {"userType": "AssumedRole", "userName": "supervisor-role", "accessKeyId": "ASIA1"}}}}
    sig = core.detect(gd)
    assert sig["type"] == 1 and sig["role_name"] == "supervisor-role"
    gd["detail"]["resource"]["accessKeyDetails"]["userType"] = "IAMUser"
    assert core.detect(gd) is None


def test_plans_handler_lists_waiting_and_contained(shop, monkeypatch):
    from tourniquet_slice import handlers
    a = core.match(core.detect(guardrail())); a = core.match(core.detect(create_key_event(shop[2])))
    p = handlers.plan({"alert": a})["plan"]
    handlers.request_approval({"plan": p, "token": "T"})
    assert handlers.plans({})["ok"] is False
    r = handlers.plans(url_event("arn:aws:sts::111122223333:assumed-role/sec-lead/s", {}))
    assert r["ok"] and r["waiting"][0]["agent"] == "supervisor-agent" and r["waiting"][0]["severity"] == 8 and r["contained"] == []


def test_retried_match_counts_a_signal_once(shop):
    sig = core.detect(guardrail())
    a1 = core.match(sig)
    a2 = core.match(sig)                    # Step Functions retried the step with the same signal
    assert a2["alert_id"] == a1["alert_id"] and len(a2["evidence"]) == 1


def test_plan_retry_by_the_same_run_gets_its_plan_back(shop):
    a = core.match(core.detect(guardrail())); a = core.match(core.detect(create_key_event(shop[2])))
    p1 = core.plan(a["alert_id"], "run-A")
    again = core.plan(a["alert_id"], "run-A")        # Step Functions retried the step after a failure
    other = core.plan(a["alert_id"], "run-B")        # a different run must still get nothing
    assert again["plan_id"] == p1["plan_id"] and other is None


def test_dashboard_chain_check_agrees_with_the_real_audit_chain(shop, monkeypatch):
    import importlib.util, sys, json as _j
    monkeypatch.setattr(sys, "argv", ["approver_ui.py", "--sample"])
    spec = importlib.util.spec_from_file_location("approver_ui", "deploy/approver_ui.py")
    ui = importlib.util.module_from_spec(spec); spec.loader.exec_module(ui)
    core.audit("plan_created", {"plan": "p"}); core.audit("plan_approved", {"plan": "p"}); core.audit("contained", {"agent": "a"})
    s3 = boto3.client("s3", region_name=core.REGION)
    recs = [_j.loads(s3.get_object(Bucket=core.AUDIT_BUCKET, Key=o["Key"])["Body"].read()) for o in sorted(s3.list_objects_v2(Bucket=core.AUDIT_BUCKET)["Contents"], key=lambda o: o["Key"])]
    assert ui.chain_check(recs) is True and core.verify_audit() is True
    recs[1]["detail"] = {"plan": "tampered"}
    assert ui.chain_check(recs) is False                       # one changed record breaks the chain
    live_, plans = ui.sample()
    assert live_["chain_ok"] is True and live_["audit_count"] == 18 and plans["ok"]
    assert [t["seconds"] for t in live_["times"]][:3] == [12.0, 14.0, 82.0]


# ---------------------------------------------------------------- alert types 3, 4, 5, 7 (Q3 baselines and manual)
def secret_read(role="supervisor-role"):
    return {"eventName": "GetSecretValue", "userIdentity": {"accessKeyId": "AKIASUPERVISOR",
            "sessionContext": {"sessionIssuer": {"type": "Role", "userName": role}}}}


def test_type_3_spike_needs_the_threshold_and_is_raised_once_per_minute(shop):
    spikes = [core.secret_spike(dict(secret_read(), eventID=f"e{i}", eventTime=core.now())) for i in range(core.SECRET_MIN + 6)]
    first = [x for x in spikes if x]
    assert spikes.index(first[0]) == core.SECRET_MIN - 1 and first[0]["role_name"] == "supervisor-role"
    core.secret_spike_fired(first[0])
    assert not core.secret_spike(dict(secret_read(), eventID="late", eventTime=core.now()))     # same minute, already raised


def test_type_3_detect_turns_the_spike_into_a_signal_and_it_reaches_a_plan(shop):
    sp = None
    for i in range(core.SECRET_MIN):
        sp = core.secret_spike(dict(secret_read(), eventID=f"e{i}", eventTime=core.now())) or sp
    sig = core.detect(sp)
    assert sig["type"] == 3 and sig["role_name"] == "supervisor-role" and "secret reads" in sig["txt"]
    assert core.match(sig)["agent"] == "supervisor-agent"


def test_type_3_ignores_a_few_reads_non_agent_callers_and_tourniquets_own_roles(shop):
    assert not any(core.secret_spike(dict(secret_read(), eventID=f"a{i}", eventTime=core.now())) for i in range(core.SECRET_MIN - 1))
    user = secret_read(); user["userIdentity"]["sessionContext"]["sessionIssuer"]["type"] = "User"
    assert not any(core.secret_spike(dict(user, eventID=f"u{i}", eventTime=core.now())) for i in range(30))
    own = secret_read("tq-act-role")
    assert not any(core.secret_spike(dict(own, eventID=f"o{i}", eventTime=core.now())) for i in range(30))


def test_type_3_counts_by_the_minute_the_event_happened_not_when_it_was_read(shop):
    old = lambda i: dict(secret_read(), eventID=f"o{i}", eventTime="2026-11-24T05:00:%02dZ" % i)
    assert any(core.secret_spike(old(i)) for i in range(core.SECRET_MIN))
    assert core.secret_spike(dict(secret_read(), eventID="n", eventTime="2026-11-24T05:03:00Z")) is None


def test_poll_starts_one_pipeline_for_a_burst_of_secret_reads(shop, monkeypatch):
    recs = [dict(secret_read(), eventID=f"b{i}", eventTime=core.now()) for i in range(core.SECRET_MIN + 8)]
    monkeypatch.setattr(core, "cloudtrail_records", lambda minutes=15: iter(recs))
    started = []
    out = core.poll(started.append)
    assert out["started"] == 1 and started[0]["kind"] == "secret_read_spike" and started[0]["count"] == core.SECRET_MIN
    out2 = core.poll(started.append)                       # everything already seen
    assert out2["new"] == 0 and len(started) == 1


def test_type_4_learns_first_then_flags_a_tool_never_used_before(shop):
    d = lambda tool: core.detect({"source": "agentcore.gateway", "tool": tool, "role_name": "supervisor-role"})
    assert d("order-tools___lookup_order") is None              # first sight with nothing known: only learned
    assert d("order-tools___lookup_order") is None              # same tool again: normal
    sig = d("admin-tools___export_customers")
    assert sig and sig["type"] == 4 and "export_customers" in sig["txt"]
    assert d("admin-tools___export_customers") is None          # now known, no second alert for it


def test_type_5_fires_at_the_deny_threshold_once_per_minute(shop):
    deny = {"source": "agentcore.policy", "decision": "DENY", "role_name": "supervisor-role"}
    allow = dict(deny, decision="ALLOW")
    assert not any(core.detect(allow) for _ in range(20))
    hits = [h for h in (core.detect(deny) for _ in range(core.DENY_MIN + 4)) if h]
    assert len(hits) == 1 and hits[0]["type"] == 5


def test_type_7_manual_names_an_agent_and_unknown_agents_are_ignored(shop):
    sig = core.detect({"source": "manual", "agent": "supervisor-agent", "raised_by": "sec-lead", "reason": "odd refunds"})
    assert sig["type"] == 7 and sig["role_name"] == "supervisor-role" and "odd refunds" in sig["txt"]
    assert core.detect({"source": "manual", "agent": "no-such-agent"}) is None


def test_every_type_reaches_a_plan_when_strong_enough(shop):
    sig = core.detect({"source": "manual", "agent": "supervisor-agent", "raised_by": "sec-lead", "reason": "x"})
    a = core.match(sig)
    assert a and a["agent"] == "supervisor-agent"
    assert set(core.STRENGTH) == {1, 2, 3, 4, 5, 6, 7}
