"""Tourniquet live dashboard and approver buttons. Runs on YOUR machine or in CloudShell (Actions > Preview port 8080).
Reads the control plane's own tables and the S3 audit bucket with your credentials, verifies the audit hash chain, and
signs Approve and Lift clicks as the approver role through the same API Gateway as everything else (owner, Orchestrator
and non-approvers are refused there). There is no login: whoever can reach this port is acting as the approver role,
so it listens on 127.0.0.1 only.
Usage:
  python deploy/approver_ui.py [role-name]          live, default role tq-demo-sec-lead
  python deploy/approver_ui.py --sample             no AWS: the numbers of the 19 Nov run, buttons off
  python deploy/approver_ui.py --export file.html   write a self-contained sample page (no server, no AWS)
  python deploy/approver_ui.py --snapshot file.html  read LIVE data once and write it into a page you download and open
                                                      (for AWS CloudShell, which has no port preview); run again to refresh"""
import json, os, sys, hashlib, time, datetime, urllib.request, urllib.error, http.server

REGION = os.environ.get("TQ_REGION", "ap-southeast-2")
ARGS = [a for a in sys.argv[1:]]
SAMPLE = "--sample" in ARGS or "--export" in ARGS
EXPORT = ARGS[ARGS.index("--export") + 1] if "--export" in ARGS else None
SNAP = ARGS[ARGS.index("--snapshot") + 1] if "--snapshot" in ARGS else None
POS = [a for a in ARGS if not a.startswith("--") and a not in (EXPORT, SNAP)]
ROLE = POS[0] if POS else "tq-demo-sec-lead"
PORT = int(os.environ.get("PORT", "8080"))
_cache = {}


def _dec(o):
    return int(o) if o == int(o) else float(o)


def chain_check(recs):
    """recs: audit records in order. True when every record links to the one before and its own hash matches."""
    prev = "0" * 64
    for r in recs:
        r = dict(r)
        h = r.pop("hash", None)
        if r.get("prev") != prev or hashlib.sha256(json.dumps(r, sort_keys=True, default=_dec).encode()).hexdigest() != h:
            return False
        prev = h
    return True


def times_from(recs):
    """Durations between the milestones in the audit trail (latest occurrence of each)."""
    def last(*names):
        t = None
        for r in recs:
            if r.get("action") in names:
                t = r.get("time")
        return t
    def secs(a, b):
        try:
            return round((datetime.datetime.fromisoformat(b) - datetime.datetime.fromisoformat(a)).total_seconds(), 1)
        except Exception:
            return None
    m = [("Pipeline started", last("pipeline_started_by_poll")), ("Plan waiting", last("plan_created", "approval_requested")),
         ("Approved", last("plan_approved")), ("Cuts done", last("contained", "contained_with_errors")), ("Lifted", last("cut_lifted"))]
    out, prev = [], None
    for name, t in m:
        if t and prev:
            out.append({"step": prev[0] + " to " + name.lower(), "seconds": secs(prev[1], t)})
        if t:
            prev = (name, t)
    if m[0][1] and m[3][1]:
        out.append({"step": "Pipeline start to cuts done (includes the approval wait)", "seconds": secs(m[0][1], m[3][1])})
    return out


# ---------------------------------------------------------------- sample data (19 Nov run, built the same way the audit does)
def sample():
    base = datetime.datetime(2026, 11, 19, 22, 3, 0)
    ev = [(0, "reach_discovered", {"role": "supervisor-role", "secrets": ["tq-demo/orders-db-password"], "shared": ["subagents-role"]}),
          (4, "alert_updated", {"alert": "supervisor-agent-0001", "evidence": 1}), (6, "alert_updated", {"alert": "supervisor-agent-0001", "evidence": 2}),
          (96, "cloudtrail_record_read", {"event": "CreateAccessKey", "role": "supervisor-role"}), (97, "pipeline_started_by_poll", {"event": "CreateAccessKey"}),
          (98, "alert_updated", {"alert": "supervisor-agent-0001", "evidence": 3, "level": "High"}),
          (108, "plan_created", {"plan": "p-0001", "source": "bedrock", "steps": [1, 2, 3, 4, 5, 6, 7]}), (109, "approval_requested", {"plan": "p-0001"}),
          (123, "plan_approved", {"plan": "p-0001", "approver": "arn:aws:sts::123456789012:assumed-role/tq-demo-sec-lead/tq-demo-sec-lead"}),
          (135, "step_1_cedar_forbid", {"plan": "p-0001", "name": "Cedar forbid"}), (140, "step_4", {"plan": "p-0001", "name": "Stop sessions"}),
          (146, "step_3", {"plan": "p-0001", "name": "Cut agent calls"}), (158, "step_5", {"plan": "p-0001", "name": "Tool Lambda concurrency 0"}),
          (170, "step_6", {"plan": "p-0001", "name": "Role lock"}), (182, "step_7", {"plan": "p-0001", "name": "Deactivate keys"}),
          (193, "step_2", {"plan": "p-0001", "name": "Vault deny"}), (205, "contained", {"agent": "supervisor-agent", "plan": "p-0001"}),
          (260, "cut_lifted", {"agent": "supervisor-agent", "by": "tq-demo-sec-lead"})]
    recs, prev = [], "0" * 64
    for i, (dt, act, det) in enumerate(ev, 1):
        r = {"seq": i, "time": (base + datetime.timedelta(seconds=dt)).isoformat(timespec="seconds"), "action": act, "detail": det, "prev": prev}
        r["hash"] = hashlib.sha256(json.dumps(r, sort_keys=True).encode()).hexdigest()
        prev = r["hash"]; recs.append(r)
    ev3 = [{"type": 6, "txt": "Prompt attack flagged"}, {"type": 1, "txt": "GuardDuty: UnauthorizedAccess:IAMUser (shape)"},
           {"type": 2, "txt": "CreateAccessKey by an agent role", "created_key": "AKIA..."}]
    live_ = {"reach": [{"agent": "supervisor-agent", "role_name": "supervisor-role", "owner": "tq-demo-owner", "tool_actions": ["order-tools"], "secrets": ["tq-demo/orders-db-password"], "runtime_arn": "arn:rt", "shared": ["subagents-role"]},
                       {"agent": "tq-helper-agent", "role_name": "subagents-role", "owner": "tq-demo-owner", "tool_actions": [], "secrets": ["tq-demo/orders-db-password"]}],
             "alerts": [{"alert_id": "supervisor-agent-0001", "agent": "supervisor-agent", "level": "High", "severity": 10, "state": "lifted", "evidence": ev3}],
             "sessions": [{"access_key_id": "AKIASUPERVISOR", "role_name": "supervisor-role", "agent": "supervisor-agent", "runtime_session_id": "sess-1"}],
             "approvals": [{"plan_id": "p-0001", "agent": "supervisor-agent", "status": "approved", "approver_arn": "arn:aws:sts::123456789012:assumed-role/tq-demo-sec-lead/tq-demo-sec-lead"}],
             "signals": [{"signal_id": "s1", "type": 6, "rule": "pass-through (Guardrails)", "role_name": "supervisor-role", "txt": "Prompt attack flagged"},
                         {"signal_id": "s2", "type": 1, "rule": "pass-through (GuardDuty)", "role_name": "supervisor-role", "txt": "GuardDuty finding (shape, sent in)"},
                         {"signal_id": "s3", "type": 2, "rule": "fixed rule (always suspicious)", "role_name": "supervisor-role", "txt": "CreateAccessKey by an agent role"}],
             "audit": list(reversed(recs[-25:])), "audit_count": len(recs), "chain_ok": chain_check(recs), "times": times_from(recs), "sample": True}
    plans = {"ok": True, "you": "tq-demo-sec-lead (sample)", "waiting": [], "contained": []}
    return live_, plans


# ---------------------------------------------------------------- live data
if not SAMPLE:
    import boto3
    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest
    from botocore.credentials import Credentials
    s = boto3.Session(region_name=REGION, profile_name=os.environ.get("AWS_PROFILE"))
    acct = s.client("sts").get_caller_identity()["Account"]
    API = {o["OutputKey"]: o["OutputValue"] for o in s.client("cloudformation").describe_stacks(StackName="tourniquet-slice")["Stacks"][0]["Outputs"]}["ApiUrl"].rstrip("/")
    AUDIT = os.environ.get("TQ_AUDIT_BUCKET") or f"tq-audit-{acct}"


def live():
    """Read-only snapshot (your CloudShell credentials, not the approver role)."""
    d = s.resource("dynamodb")
    def scan(t):
        try:
            items, kw = [], {}
            while True:
                r = d.Table(t).scan(**kw)
                items += r["Items"]
                if "LastEvaluatedKey" not in r: return items
                kw = {"ExclusiveStartKey": r["LastEvaluatedKey"]}
        except Exception:
            return []
    def clean(x):
        return json.loads(json.dumps(x, default=_dec))
    out = {"reach": clean(scan("tq-reach")), "alerts": clean(scan("tq-alerts")), "sessions": clean(scan("tq-sessions")),
           "approvals": [{k: v for k, v in clean(r).items() if k != "task_token"} for r in scan("tq-approvals")],
           "signals": clean(scan("tq-signals"))[-30:], "audit": [], "audit_count": 0, "chain_ok": None, "times": [], "sample": False}
    try:
        s3 = s.client("s3")
        keys, tok = [], None
        while True:
            r = s3.list_objects_v2(Bucket=AUDIT, Prefix="audit/", **({"ContinuationToken": tok} if tok else {}))
            keys += [o["Key"] for o in r.get("Contents", [])]
            tok = r.get("NextContinuationToken")
            if not tok: break
        keys.sort()
        key = tuple(keys[-1:])
        if _cache.get("audit_key") != (len(keys), key):                      # records never change: only read new ones
            have = _cache.setdefault("recs", {})
            for k in keys:
                if k not in have:
                    have[k] = json.loads(s3.get_object(Bucket=AUDIT, Key=k)["Body"].read())
            _cache["audit_key"] = (len(keys), key)
        recs = [_cache["recs"][k] for k in keys]
        out["audit_count"], out["chain_ok"] = len(recs), chain_check(recs)
        out["audit"] = list(reversed(recs[-25:]))
        out["times"] = times_from(recs)
    except Exception as e:
        out["audit_error"] = str(e)[:160]
    return out


def creds():
    c = _cache.get("c")
    if not c or c["Expiration"].timestamp() < time.time() + 120:
        c = s.client("sts").assume_role(RoleArn=f"arn:aws:iam::{acct}:role/{ROLE}", RoleSessionName=ROLE)["Credentials"]
        _cache["c"] = c
    return c


def call(method, path, body=None):
    c = creds()
    url, data = API + path, (json.dumps(body) if body is not None else "")
    req = AWSRequest(method=method, url=url, data=data, headers={"Content-Type": "application/json"})
    SigV4Auth(Credentials(c["AccessKeyId"], c["SecretAccessKey"], c["SessionToken"]), "execute-api", REGION).add_auth(req)
    r = urllib.request.Request(url, data=data.encode() if method == "POST" else None, headers=dict(req.headers), method=method)
    try:
        with urllib.request.urlopen(r, timeout=60) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return {"ok": False, "why": f"HTTP {e.code} {e.read().decode()[:200]}"}


PAGE = """<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Tourniquet dashboard</title>
<style>:root{--bg:#10151d;--card:#171e29;--tile:#1c2533;--line:#2a3445;--fg:#eef1f6;--mu:#9aa6b8;--ok:#3ddc97;--bad:#ff5c5c;--warn:#f5a54a;--blue:#4aa3ff;color-scheme:dark}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif;padding:18px 16px}
.wrap{max-width:1400px;margin:0 auto}header{display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:space-between;margin-bottom:14px}
h1{font-size:22px;margin:0;font-weight:700}h2{font-size:13px;margin:0 0 8px;text-transform:uppercase;letter-spacing:.06em;color:var(--mu);font-weight:600}
.mu{color:var(--mu);font-size:12px}.badge{border-radius:999px;padding:2px 12px;font-size:12px;font-weight:600;border:1px solid var(--line)}.live{color:var(--ok);border-color:var(--ok)}.samp{color:var(--warn);border-color:var(--warn)}
.tiles{display:grid;gap:10px;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));margin-bottom:14px}.tile{background:var(--tile);border:1px solid var(--line);border-radius:10px;padding:12px}.tile b{display:block;font-size:28px;font-weight:600;font-variant-numeric:tabular-nums}
.grid{display:grid;gap:14px;grid-template-columns:repeat(auto-fit,minmax(min(100%,520px),1fr));margin-bottom:14px}.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px;min-width:0}
.sc{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:12.5px;min-width:420px}th{text-align:left;color:var(--mu);font-weight:500}td,th{padding:5px 7px;border-bottom:1px solid var(--line);vertical-align:top}
.pill{border:1px solid var(--line);border-radius:999px;padding:0 8px;font-size:11px;white-space:nowrap;display:inline-block;margin:1px 2px 1px 0}.good{color:var(--ok);border-color:var(--ok)}.warn{color:var(--warn);border-color:var(--warn)}.bad{color:var(--bad);border-color:var(--bad)}
button{font:inherit;font-weight:600;padding:7px 14px;border-radius:8px;border:0;cursor:pointer;margin:6px 6px 0 0;color:#fff}button:disabled{opacity:.4;cursor:not-allowed}.ok{background:#15803d}.lift{background:#8a5a22}
#msg{padding:8px 10px;border-radius:8px;border:1px solid var(--line);background:var(--card);margin-bottom:14px}code{font:12px ui-monospace,Menlo,Consolas,monospace;color:var(--mu)}</style>
<div class=wrap><header><div><h1>Tourniquet dashboard</h1><div class=mu>Signed as <b id=you>-</b> · updated <span id=at>-</span> · <span id=refr>refreshes every 5 s</span></div></div><span id=mode class=badge>-</span></header>
<div id=msg>loading...</div><div class=tiles id=tiles></div>
<div class=card style="margin-bottom:14px"><h2>Approvals</h2><div id=appr></div></div>
<div class=grid><div class=card><h2>Agents</h2><div class=sc id=agents></div></div><div class=card><h2>Alerts, with evidence</h2><div class=sc id=alerts></div></div></div>
<div class=grid><div class=card><h2>Recent signals</h2><div class=sc id=signals></div></div><div class=card><h2>Times from the audit trail</h2><div class=sc id=times></div></div></div>
<div class=card><h2>Audit log <span id=chain class=badge style="margin-left:8px;text-transform:none;letter-spacing:0"></span></h2><div class=sc id=audit></div></div></div>
<script>
const SAMPLE=__SAMPLE__;
const E=t=>String(t==null?'':t).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
async function j(p,b){if(SAMPLE){return p==='/api/live'?SAMPLE.live:p==='/api/plans'?SAMPLE.plans:{ok:false,why:'sample mode: buttons are off'}}
 const r=await fetch(p,b?{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)}:{});return r.json()}
const say=t=>document.getElementById('msg').textContent=t;
const tbl=(h,rows)=>rows.length?'<table><tr>'+h.map(x=>'<th>'+x+'</th>').join('')+'</tr>'+rows.map(r=>'<tr>'+r.map(c=>'<td>'+c+'</td>').join('')+'</tr>').join('')+'</table>':'<span class=mu>Nothing yet.</span>';
const pill=(t,c)=>'<span class="pill '+(c||'')+'">'+E(t)+'</span>';
const ST={contained:'warn',contained_with_errors:'bad',lifted:'good',open:'warn',planned:'warn',approved:'good',expired:'',rejected:'bad'};
const dt=t=>E(String(t||'').replace('T',' ').slice(0,19));
async function load(){
 const [l,d]=await Promise.all([j('/api/live'),j('/api/plans')]);
 document.getElementById('at').textContent=new Date().toLocaleTimeString();if(l.snapshot)document.getElementById('refr').textContent='snapshot, buttons off; run the command again to refresh';
 const m=document.getElementById('mode');m.textContent=l.sample?'sample data':l.snapshot?'live snapshot '+l.snapshot:'live';m.className='badge '+(l.sample?'samp':'live');
 if(d.ok){document.getElementById('you').textContent=d.you;say(d.waiting.length+' plan(s) waiting, '+d.contained.length+' agent(s) contained'+(l.sample?' (sample: the incident is over, the cut was lifted)':''))}else say('Approval API: '+(d.why||l.error||'error'));
 const al=l.alerts||[],se=l.sessions||[],sg=l.signals||[];
 const T=[['agents watched',(l.reach||[]).length],['alerts open',al.filter(a=>!/^(lifted|expired)/.test(a.state)).length],['agents contained',al.filter(a=>/^contained/.test(a.state)).length],['sessions tracked',se.length],['signals seen',sg.length],['audit records',l.audit_count||0]];
 document.getElementById('tiles').innerHTML=T.map(t=>'<div class=tile><b>'+E(t[1])+'</b><span class=mu>'+t[0]+'</span></div>').join('');
 const dis=(l.sample||l.snapshot)?' disabled':'';
 document.getElementById('appr').innerHTML=((d.ok?d.waiting:[]).map(p=>'<div style="margin-bottom:10px"><b>'+E(p.agent)+'</b> (role '+E(p.role)+', owner '+E(p.owner)+') severity '+E(p.severity)+' '+E(p.level||'')+'<br>'+(p.evidence||[]).map(e=>pill('type '+e.type+': '+e.txt)).join(' ')+'<br><span class=mu>Plan by '+E(p.source)+(p.why?': '+E(p.why):'')+'</span><br>'+(p.steps||[]).map(s=>pill(s.n+' '+s.name+(s.implemented?'':' (not run)'),s.implemented?'good':'')).join(' ')+'<br><button class=ok data-a=approve data-id="'+E(p.plan_id)+'"'+dis+'>Approve and cut</button></div>').join('')
  +(d.ok?d.contained:[]).map(a=>'<div style="margin-bottom:10px"><b>'+E(a)+'</b> is contained <button class=lift data-a=lift data-id="'+E(a)+'"'+dis+'>Lift the cut</button></div>').join(''))||'<span class=mu>No plan waiting and nothing contained.</span>';
 document.getElementById('appr').innerHTML+=(l.approvals||[]).length?'<div class=sc style="margin-top:8px">'+tbl(['Plan','Agent','Status','Approver'],(l.approvals||[]).map(r=>[E(r.plan_id),E(r.agent),pill(r.status||r.state||'',ST[r.status||r.state]),E(r.approver_arn||r.approver||'')]))+'</div>':'';
 document.getElementById('agents').innerHTML=tbl(['Agent','Role','Owner','Tools','Secrets','Runtime','Shared with'],(l.reach||[]).map(r=>[E(r.agent),E(r.role_name),E(r.owner),E((r.tool_actions||[]).length||(r.tools||[]).length||''),E((r.secrets||[]).length||''),E(r.runtime_arn?'yes':''),E((r.shared||[]).join(', '))]));
 document.getElementById('alerts').innerHTML=tbl(['Alert','Agent','Level','Sev','State','Evidence'],al.map(a=>[E(a.alert_id),E(a.agent),pill(a.level,a.level==='High'?'bad':''),E(a.severity),pill(a.state,ST[a.state]),(a.evidence||[]).map(e=>pill('type '+e.type+': '+e.txt)).join(' ')]));
 document.getElementById('signals').innerHTML=tbl(['Type','Rule','Role','Detail'],sg.map(x=>[E(x.type),E(x.rule),E(x.role_name),E(x.txt)]));
 document.getElementById('times').innerHTML=tbl(['Interval','Seconds'],(l.times||[]).map(x=>[E(x.step),E(x.seconds)]))+'<div class=mu style="margin-top:6px">From the audit timestamps. A scripted approval makes the approval wait short; a person adds their own time.</div>';
 const c=document.getElementById('chain');if(l.chain_ok===true){c.textContent='chain intact';c.className='badge good'}else if(l.chain_ok===false){c.textContent='CHAIN BROKEN';c.className='badge bad'}else{c.textContent='unchecked';c.className='badge'}
 document.getElementById('audit').innerHTML=l.audit_error?'<span class=bad>'+E(l.audit_error)+'</span>':tbl(['#','Time','Event','Detail','Hash'],(l.audit||[]).map(a=>[E(a.seq),dt(a.time),E(a.action),'<code>'+E(JSON.stringify(a.detail||'').slice(0,150))+'</code>','<code>'+E((a.hash||'').slice(0,10))+'</code>']));
}
document.addEventListener('click',async e=>{const b=e.target.closest('button[data-a]');if(!b||b.disabled)return;say('working...');
 const r=await j('/api/'+b.dataset.a,b.dataset.a==='approve'?{plan_id:b.dataset.id}:{agent:b.dataset.id});
 say(r.ok?('Done: '+JSON.stringify(r).slice(0,300)):('Refused: '+(r.why||JSON.stringify(r))));load()});
load();setInterval(load,5000);
</script>"""


def page():
    if SNAP:
        lv = live()
        lv["snapshot"] = datetime.datetime.now().strftime("%H:%M:%S")
        return PAGE.replace("__SAMPLE__", json.dumps({"live": lv, "plans": call("GET", "/plans")}))
    if SAMPLE:
        lv, pl = sample()
        return PAGE.replace("__SAMPLE__", json.dumps({"live": lv, "plans": pl}))
    return PAGE.replace("__SAMPLE__", "null")


class H(http.server.BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    def do_GET(self):
        if SAMPLE:
            return self._send(200, page(), "text/html")
        if self.path == "/api/live":
            try:
                return self._send(200, json.dumps(live()))
            except Exception as e:
                return self._send(200, json.dumps({"error": str(e)[:200]}))
        if self.path == "/api/plans":
            return self._send(200, json.dumps(call("GET", "/plans")))
        self._send(200, page(), "text/html")

    def do_POST(self):
        host = self.headers.get("Host", "")
        origin = self.headers.get("Origin", "")
        if origin and not origin.split("//")[-1] == host:          # a page on another site cannot press the buttons
            return self._send(403, json.dumps({"ok": False, "why": "bad origin"}))
        n = int(self.headers.get("Content-Length", 0)); body = json.loads(self.rfile.read(n) or b"{}")
        if self.path == "/api/approve":
            return self._send(200, json.dumps(call("POST", "/approve", {"plan_id": body.get("plan_id")})))
        if self.path == "/api/lift":
            return self._send(200, json.dumps(call("POST", "/lift", {"agent": body.get("agent")})))
        self._send(404, "{}")

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    if EXPORT or SNAP:
        open(EXPORT or SNAP, "w").write(page())
        print("wrote", EXPORT or SNAP, "(live snapshot: download it and open it in your browser; run again to refresh)" if SNAP else "")
    else:
        print(f"Dashboard ({'sample data' if SAMPLE else 'live, approver role ' + ROLE}): http://127.0.0.1:{PORT}  (CloudShell: Actions > Preview port {PORT}). Ctrl+C to stop.")
        http.server.ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
