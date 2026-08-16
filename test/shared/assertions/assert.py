#!/usr/bin/env python3
"""读 expected.yaml，对 sysarmorctl --json 输出逐条断言。

当前为骨架：sysarmorctl 尚未构建时以 DRY-RUN 跑通断言逻辑（打印将要校验的契约），
binary 就绪后把 _query() 接到真实 CLI 即可。
断言类型见 test/README.md 和 test/DETAILS.md：正向存在 / 结构 / 契约完整性 / 负向缺失 / 对照。
"""
import argparse, json, os, shlex, shutil, subprocess, sys

try:
    import yaml
except ImportError:
    sys.exit("need pyyaml: pip install pyyaml")

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
TEST_ROOT = os.path.join(ROOT, "test")
VM_ENV = os.path.join(TEST_ROOT, "env", "vm")
LOCAL_CTL = os.path.join(ROOT, "bin", "sysarmorctl")
CTL = LOCAL_CTL if os.path.exists(LOCAL_CTL) else shutil.which("sysarmorctl")
DOCKER = shutil.which("docker")
DRY = CTL is None


def _query(mgr, topology, *args):
    """调 sysarmorctl 取 JSON；DRY-RUN 下返回 None。"""
    if DRY:
        print(f"  [dry-run] sysarmorctl --manager-url {mgr} --json {' '.join(args)}")
        return None
    if topology == "vm":
        cmd = " ".join(shlex.quote(x) for x in ["/tmp/sysarmorctl", "--manager-url", "127.0.0.1:9443", "--json", *args])
        out = subprocess.check_output([
            "vagrant", "ssh", "mgr", "-c", cmd,
        ], cwd=VM_ENV)
    elif DOCKER and _container_running("mgr"):
        out = subprocess.check_output([
            DOCKER, "exec", "mgr", "/opt/sysarmor/bin/sysarmorctl",
            "--manager-url", "127.0.0.1:9443", "--json", *args,
        ])
    else:
        out = subprocess.check_output([CTL, "--manager-url", mgr, "--json", *args])
    return json.loads(out)


def _container_running(name):
    try:
        out = subprocess.check_output([DOCKER, "ps", "--filter", f"name={name}", "--format", "{{.Names}}"])
    except Exception:
        return False
    return name in out.decode().splitlines()


class Result:
    def __init__(self): self.passed, self.failed, self.skipped = 0, 0, 0
    def check(self, name, cond):
        if cond is None:
            self.skipped += 1; print(f"  ~ SKIP {name} (dry-run)")
        elif cond:
            self.passed += 1; print(f"  ✓ PASS {name}")
        else:
            self.failed += 1; print(f"  ✗ FAIL {name}")


def assert_incident(exp, mgr, topology, scenario, r):
    inc = exp.get("incident")
    if not inc:
        return
    data = _query(mgr, topology, "manager", "incidents", "list", "--label", f"scenario={scenario}")
    if "count" in inc:
        r.check(f"incident.count=={inc['count']}",
                None if data is None else len(data.get("incidents", [])) == inc["count"])
    if data and inc.get("lineage_ids_min"):
        ok = any(len(i.get("lineage_ids", [])) >= inc["lineage_ids_min"]
                 for i in data.get("incidents", []))
        r.check(f"incident.lineage_ids>={inc['lineage_ids_min']}", ok)
    if "converge_method" in inc:
        r.check("incident.converge_method", None if data is None else any(
            i.get("converge", {}).get("method") == inc["converge_method"]
            for i in data.get("incidents", [])))


def assert_signals(exp, mgr, topology, scenario, r):
    for layer in ("endpoint_signals", "cloud_signals"):
        spec = exp.get(layer)
        if not spec:
            continue
        data = _query(mgr, topology, "manager", "signals", "list", "--label", f"scenario={scenario}", "--layer", layer.split("_")[0])
        names = [] if data is None else [s.get("name") for s in data]
        for want in spec.get("must_contain", []):
            nm = want["name"] if isinstance(want, dict) else want
            r.check(f"{layer}.must_contain[{nm}]", None if data is None else nm in names)
        for want in spec.get("must_absent", []):
            nm = want["name"] if isinstance(want, dict) else want
            r.check(f"{layer}.must_absent[{nm}]", None if data is None else nm not in names)
        if spec.get("must_have_entities"):
            r.check(f"{layer}.must_have_entities(D4)",
                    None if data is None else all(s.get("entities") for s in data))


def assert_negative(exp, mgr, topology, scenario, r):
    neg = exp.get("negative", {})
    if "endpoint_conclusion_count" in neg:
        data = _query(mgr, topology, "manager", "signals", "list", "--label", f"scenario={scenario}", "--stage", "conclusion")
        r.check(f"negative.endpoint_conclusion_count=={neg['endpoint_conclusion_count']}",
                None if data is None else len(data) == neg["endpoint_conclusion_count"])
    if neg.get("endpoint_conclusion_required"):
        data = _query(mgr, topology, "manager", "signals", "list", "--label", f"scenario={scenario}", "--stage", "conclusion")
        r.check("negative.endpoint_conclusion_required",
                None if data is None else len(data) >= 1)


def assert_controls(exp, mgr, topology, scenario, r):
    for ctl in exp.get("control_assertions", []):
        args = ["manager", "recompute", "--label", f"scenario={scenario}"]
        label = ctl.get("disable") or ctl.get("switch")
        if ctl.get("disable"):
            args.extend(["--disable", ctl["disable"]])
        if ctl.get("switch"):
            key, _, value = ctl["switch"].partition("=")
            if key == "converge.mode" and value:
                args.extend(["--mode", value])
        data = _query(mgr, topology, *args)
        incidents = [] if data is None else data.get("incidents", [])
        if "then_incident_count" in ctl:
            r.check(f"control[{label}].incident_count=={ctl['then_incident_count']}",
                    None if data is None else len(incidents) == ctl["then_incident_count"])
        if "then_incident_count_min" in ctl:
            r.check(f"control[{label}].incident_count>={ctl['then_incident_count_min']}",
                    None if data is None else len(incidents) >= ctl["then_incident_count_min"])


def assert_lifecycle(exp, mgr, topology, scenario, r):
    spec = exp.get("lifecycle")
    if not spec:
        return
    if spec.get("agent_registered"):
        agents = _query(mgr, topology, "manager", "agents", "list")
        r.check("lifecycle.agent_registered",
                None if agents is None else any(a.get("agent_id") for a in agents))
    visible = spec.get("events_visible")
    if visible:
        events = _query(mgr, topology, "manager", "events", "list", "--label", f"scenario={scenario}", "--behavior", visible.get("behavior", ""))
        r.check("lifecycle.events_visible", None if events is None else len(events) >= 1)
        if visible.get("require_stable_id"):
            r.check("lifecycle.events_visible.stable_id",
                    None if events is None else all(e.get("subject_proc", {}).get("stable_id") for e in events))
        if visible.get("require_lineage_id"):
            r.check("lifecycle.events_visible.lineage_id",
                    None if events is None else all(e.get("lineage_id") for e in events))
    if spec.get("policy_applied"):
        status = _query(mgr, topology, "manager", "status")
        r.check("lifecycle.policy_applied", None if status is None else status.get("ok") is True)
    resource = spec.get("resource", {})
    if resource.get("no_panic") and DOCKER and _container_running("mgr"):
        logs = subprocess.check_output([DOCKER, "logs", "--tail", "200", "mgr"], stderr=subprocess.STDOUT).decode(errors="replace").lower()
        r.check("lifecycle.resource.no_panic", "panic:" not in logs)
    if resource.get("no_oom") and DOCKER and _container_running("mgr"):
        inspect = subprocess.check_output([DOCKER, "inspect", "mgr", "--format", "{{.State.OOMKilled}}"]).decode().strip()
        r.check("lifecycle.resource.no_oom", inspect == "false")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", required=True)
    ap.add_argument("--expected", required=True)
    ap.add_argument("--topology", default="unknown")
    ap.add_argument("--manager-url", default="127.0.0.1:19443")
    a = ap.parse_args()
    exp = yaml.safe_load(open(a.expected))
    print(f"[assert] topology={a.topology} scenario={a.scenario} dry_run={DRY}")
    r = Result()
    assert_signals(exp, a.manager_url, a.topology, a.scenario, r)
    assert_incident(exp, a.manager_url, a.topology, a.scenario, r)
    assert_negative(exp, a.manager_url, a.topology, a.scenario, r)
    assert_controls(exp, a.manager_url, a.topology, a.scenario, r)
    assert_lifecycle(exp, a.manager_url, a.topology, a.scenario, r)
    print(f"[assert] {a.topology}/{a.scenario}: pass={r.passed} fail={r.failed} skip={r.skipped}")
    # 把结果落到 .results 供 report.py 汇总
    os.makedirs(".results", exist_ok=True)
    result = {"topology": a.topology, "scenario": a.scenario, "pass": r.passed, "fail": r.failed, "skip": r.skipped}
    json.dump(result, open(f".results/{a.topology}.{a.scenario}.json", "w"))
    if a.topology == "unknown":
        json.dump(result, open(f".results/{a.scenario}.json", "w"))
    sys.exit(1 if r.failed else 0)


if __name__ == "__main__":
    main()
