"""Collector: builds an agent's reach row from what is really in the account, instead of typing it by hand.
Reads the agent role's own policies (inline and attached), the secrets they allow, the functions they may call, the
other roles that can read the same secrets (the helpers that must keep running), the tool Lambda tagged for the agent,
and the Runtime agent named in a role tag. Tags used:  role: tq-owner, tq-runtime   Lambda: tq-tool-of=<agent>."""
import fnmatch
import json
from . import core

SKIP_SHARED = ("tq-", "AWSServiceRole", "aws-service-role")


def _statements(iam, role_name):
    docs = []
    for pn in iam.list_role_policies(RoleName=role_name)["PolicyNames"]:
        docs.append(iam.get_role_policy(RoleName=role_name, PolicyName=pn)["PolicyDocument"])
    for ap in iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]:
        pol = iam.get_policy(PolicyArn=ap["PolicyArn"])["Policy"]
        docs.append(iam.get_policy_version(PolicyArn=ap["PolicyArn"], VersionId=pol["DefaultVersionId"])["PolicyVersion"]["Document"])
    for d in docs:
        st = d.get("Statement", [])
        for x in (st if isinstance(st, list) else [st]):
            if x.get("Effect") == "Allow":
                yield x


def _list(v):
    return v if isinstance(v, list) else [v] if v else []


def _allows(stmt, prefix):
    return any(a == "*" or a.lower().startswith(prefix) for a in _list(stmt.get("Action")))


def _secret_names(sm, patterns):
    """Secret names whose ARN matches any allowed resource pattern."""
    names = []
    for page in sm.get_paginator("list_secrets").paginate():
        for sec in page["SecretList"]:
            if any(fnmatch.fnmatch(sec["ARN"], p) or fnmatch.fnmatch(sec["ARN"], p + "-??????") or p == "*" for p in patterns):
                names.append(sec["Name"])
    return sorted(set(names))


def discover(role_name, agent):
    iam, sm, lam = core._c("client", "iam"), core._c("client", "secretsmanager"), core._c("client", "lambda")
    tags = {t["Key"]: t["Value"] for t in iam.list_role_tags(RoleName=role_name).get("Tags", [])}
    stmts = list(_statements(iam, role_name))
    sec_patterns = [r for x in stmts if _allows(x, "secretsmanager:") for r in _list(x.get("Resource"))]
    secrets = _secret_names(sm, sec_patterns) if sec_patterns else []
    calls = sorted({r.split(":function:")[-1] for x in stmts if _allows(x, "lambda:invoke") for r in _list(x.get("Resource")) if ":function:" in r})
    # helpers: other roles that can read one of the same secrets
    shared, shared_secrets = [], set()
    if secrets:
        for page in iam.get_paginator("list_roles").paginate():
            for r in page["Roles"]:
                n = r["RoleName"]
                if n == role_name or n.startswith(SKIP_SHARED):
                    continue
                pats = [x for st in _statements(iam, n) if _allows(st, "secretsmanager:") for x in _list(st.get("Resource"))]
                both = set(_secret_names(sm, pats)) & set(secrets) if pats else set()
                if both:
                    shared.append(n)
                    shared_secrets |= both
    tool = None
    for page in lam.get_paginator("list_functions").paginate():
        for f in page["Functions"]:
            if lam.list_tags(Resource=f["FunctionArn"]).get("Tags", {}).get("tq-tool-of") == agent:
                tool = f["FunctionName"]
    runtime_arn = None
    if tags.get("tq-runtime"):
        for rt in core._c("client", "bedrock-agentcore-control").list_agent_runtimes().get("agentRuntimes", []):
            if rt["agentRuntimeName"] == tags["tq-runtime"]:
                runtime_arn = rt["agentRuntimeArn"]
    row = {"role_name": role_name, "agent": agent, "owner": tags.get("tq-owner"), "secrets": secrets, "calls": calls,
           "shared": sorted(shared), "discovered": True,
           "exclusive_secrets": sorted(set(secrets) - shared_secrets)}
    if tool:
        row["tool_lambda"] = tool
    if runtime_arn:
        row["runtime_arn"] = runtime_arn
    if not row["owner"]:
        raise ValueError(f"role {role_name} has no tq-owner tag: an agent without a named owner cannot be put under Tourniquet")
    return row


def write_reach(row):
    """Writes the discovered row. Fields the Collector does not discover (gateway, engine, Cedar pattern) are kept."""
    t = core._ddb().Table(core.T_REACH)
    old = t.get_item(Key={"role_name": row["role_name"]}).get("Item") or {}
    keep = {k: v for k, v in old.items() if k in ("policy_engine_id", "gateway_arn", "tool_actions", "cedar_pattern")}
    merged = {**keep, **row}
    t.put_item(Item=json.loads(json.dumps(merged), parse_float=str))
    core.audit("reach_discovered", {"role": row["role_name"], "agent": row["agent"], "secrets": row["secrets"], "shared": row["shared"]})
    return merged
