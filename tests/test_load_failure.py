"""Load (many things at once) and failure (things break) tests. Offline with moto: they show the logic holds, they are not
a measurement of AWS. deploy/load_aws.py does a small real-AWS version."""
import json, boto3, pytest
from concurrent.futures import ThreadPoolExecutor
from test_slice import shop, guardrail, create_key_event, url_event, contain  # noqa: F401  (fixtures and helpers)
from tourniquet_slice import core, handlers


def test_forty_signals_at_once_make_one_alert_and_the_chain_stays_intact(shop):
    with ThreadPoolExecutor(max_workers=16) as ex:
        list(ex.map(lambda i: core.match(core.detect(guardrail())), range(40)))
    mine = [a for a in boto3.resource("dynamodb", region_name=core.REGION).Table(core.T_ALERTS).scan()["Items"] if a["agent"] == "supervisor-agent"]
    assert len(mine) == 1 and len(mine[0]["evidence"]) == 40
    assert core.verify_audit() is True


def test_many_simultaneous_approvals_release_the_plan_exactly_once(shop, monkeypatch):
    sent = []

    class FakeSfn:
        def send_task_success(self, taskToken, output): sent.append(taskToken)
    real = boto3.client
    monkeypatch.setattr(handlers.boto3, "client", lambda svc, **k: FakeSfn() if svc == "stepfunctions" else real(svc, **k))
    a = core.match(core.detect(guardrail())); a = core.match(core.detect(create_key_event(shop[2])))
    p = handlers.plan({"alert": a})["plan"]
    handlers.request_approval({"plan": p, "token": "T"})
    ev = url_event("arn:aws:sts::111122223333:assumed-role/sec-lead/s", {"plan_id": p["plan_id"]})
    with ThreadPoolExecutor(max_workers=10) as ex:
        res = list(ex.map(lambda _: handlers.approve(ev), range(10)))
    assert sum(1 for r in res if r["ok"]) == 1 and sent == ["T"]
    assert core.verify_audit() is True


def test_many_simultaneous_lifts_run_exactly_once(shop):
    contain(shop)
    out = []

    def lift(_):
        try:
            return core.lift("supervisor-agent", "sec-lead")
        except core.LiftRefused as e:
            return str(e)
    with ThreadPoolExecutor(max_workers=6) as ex:
        out = list(ex.map(lift, range(6)))
    done = [o for o in out if isinstance(o, list)]
    assert len(done) == 1 and not [r for r in done[0] if r["status"] == "failed"]
    assert core.verify_audit() is True


def test_a_step_that_fails_midway_is_reported_and_the_rest_still_run(shop, monkeypatch):
    iam, lam, key = shop
    monkeypatch.setattr(core, "cut_calls", lambda r: (_ for _ in ()).throw(RuntimeError("IAM throttled")))
    a = core.match(core.detect(guardrail())); a = core.match(core.detect(create_key_event(key)))
    p = core.plan(a["alert_id"])
    with pytest.raises(RuntimeError, match=r"steps done except \[3\]"):
        core.act(p, core.approve(p, "sec-lead"))
    assert "TourniquetQuarantine" in iam.list_role_policies(RoleName="supervisor-role")["PolicyNames"]
    state = boto3.resource("dynamodb", region_name=core.REGION).Table(core.T_ALERTS).get_item(Key={"alert_id": a["alert_id"]})["Item"]["state"]
    assert state == "contained_with_errors"
    res = core.lift("supervisor-agent", "sec-lead")               # a half-done cut can still be lifted
    assert not [r for r in res if r["status"] == "failed"]


def test_an_act_with_a_changed_plan_cuts_nothing(shop):
    iam, lam, key = shop
    a = core.match(core.detect(guardrail())); a = core.match(core.detect(create_key_event(key)))
    p = core.plan(a["alert_id"])
    ap = core.approve(p, "sec-lead")
    p["role"] = "subagents-role"                                   # someone edits the plan after approval
    p["hash"] = "x"
    with pytest.raises(core.ApprovalRefused):
        core.act(p, ap)
    assert iam.list_role_policies(RoleName="subagents-role")["PolicyNames"] == []


def test_a_tampered_audit_record_is_detected(shop):
    core.audit("one", {}); core.audit("two", {}); core.audit("three", {})
    assert core.verify_audit() is True
    s3 = boto3.client("s3", region_name=core.REGION)
    keys = sorted(o["Key"] for o in s3.list_objects_v2(Bucket=core.AUDIT_BUCKET)["Contents"])
    rec = json.loads(s3.get_object(Bucket=core.AUDIT_BUCKET, Key=keys[1])["Body"].read())
    rec["detail"] = {"changed": True}
    s3.put_object(Bucket=core.AUDIT_BUCKET, Key=keys[1], Body=json.dumps(rec).encode())
    assert core.verify_audit() is False


def test_approval_after_the_wait_expired_is_refused_cleanly(shop, monkeypatch):
    class FakeSfn:
        def send_task_success(self, taskToken, output): raise RuntimeError("TaskTimedOut")
    real = boto3.client
    monkeypatch.setattr(handlers.boto3, "client", lambda svc, **k: FakeSfn() if svc == "stepfunctions" else real(svc, **k))
    a = core.match(core.detect(guardrail())); a = core.match(core.detect(create_key_event(shop[2])))
    p = handlers.plan({"alert": a})["plan"]
    handlers.request_approval({"plan": p, "token": "T"})
    r = handlers.approve(url_event("arn:aws:sts::111122223333:assumed-role/sec-lead/s", {"plan_id": p["plan_id"]}))
    assert r["ok"] is False and "wait is over" in r["why"]
