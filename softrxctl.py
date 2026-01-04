#!/usr/bin/env python3
import argparse
import json
import os
import re
import stat
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DEFAULT_RUNS_DIR = ROOT / "softrx_runs"
DEFAULT_LAUNCHER = ROOT / "bin" / "softrx_launcher"

RUN_ID_RE = re.compile(r"(run_\d{8}_\d{6})")

def expand_path(s: str) -> str:
    # Handle literal "$PWD/..." coming from UI/JSON
    s = s.replace("$PWD", str(ROOT))
    s = os.path.expandvars(os.path.expanduser(s))
    return str(Path(s).resolve())

def ensure_executable(p: Path) -> None:
    try:
        st = p.stat()
        if not (st.st_mode & stat.S_IXUSR):
            p.chmod(st.st_mode | stat.S_IXUSR)
    except Exception:
        pass

def parse_events_ndjson(events_path: Path):
    events = []
    if not events_path.exists():
        return events
    with events_path.open("r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                obj = {"event": "parse_error", "raw": line}
            obj["idx"] = i
            events.append(obj)
    return events

def write_report(run_dir: Path, meta: dict, events: list) -> Path:
    report = {
        "run_id": run_dir.name,
        "outdir": str(run_dir),
        "meta": meta,
        "events": events,  # ordered
        "event_count": len(events),
    }
    rp = run_dir / "report.json"
    rp.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return rp

def run_cmd(args) -> int:
    p = subprocess.run(args)
    return p.returncode

def cmd_run(ns) -> int:
    runs_dir = Path(ns.runs_dir).resolve()
    runs_dir.mkdir(parents=True, exist_ok=True)

    # Create run dir if not provided
    outdir = Path(expand_path(ns.outdir)) if ns.outdir else None
    if outdir is None:
        run_id = time.strftime("run_%Y%m%d_%H%M%S")
        outdir = runs_dir / run_id
    outdir.mkdir(parents=True, exist_ok=True)

    launcher = Path(expand_path(ns.launcher))
    sample = Path(expand_path(ns.sample))
    ensure_executable(sample)

    # Default write jail:
    # - dev mode: C backend will default to outdir/fs (and chdir there)
    # - malware/re: default to outdir/fs so we can capture "drops" while still denying outside-jail writes
    # - reveal-net: C backend ignores write_jail and never allows writes
    write_jail = expand_path(ns.write_jail) if ns.write_jail else ""
    if not write_jail and ns.mode in ("malware", "re"):
        write_jail = str((outdir / "fs").resolve())

    # Build launcher argv
    argv = [
        str(launcher),
        "--outdir", str(outdir),
        "--timeout-ms", str(ns.timeout_ms),
        "--max-events", str(ns.max_events),
        "--mode", ns.mode,
    ]

    # Filesystem policy
    if write_jail:
        argv += ["--write-jail", write_jail]
    if ns.interactive_fs:
        argv += ["--interactive-fs"]
    if ns.quarantine_drops:
        argv += ["--quarantine-drops"]

    # Network policy (best-effort; options are enforced by the C backend)
    if ns.allow_dns:
        argv += ["--allow-dns"]
    if ns.allow_dot:
        argv += ["--allow-dot"]
    if ns.deny_unlisted:
        argv += ["--deny-unlisted"]
    if ns.net_cap_bytes is not None:
        argv += ["--net-cap-bytes", str(ns.net_cap_bytes)]
    if ns.net_cap_ms is not None:
        argv += ["--net-cap-ms", str(ns.net_cap_ms)]
    if ns.net_cap_sends is not None:
        argv += ["--net-cap-sends", str(ns.net_cap_sends)]
    for a in (ns.allow or []):
        argv += ["--allow", a]

    argv += ["--", str(sample)]
    if ns.sample_args:
        argv += ns.sample_args

    meta = {
        "launcher": str(launcher),
        "argv": argv,
        "sample": str(sample),
        "mode": ns.mode,
        "timeout_ms": ns.timeout_ms,
        "max_events": ns.max_events,
        "write_jail": write_jail or None,
        "quarantine_drops": bool(ns.quarantine_drops),
        "interactive_fs": bool(ns.interactive_fs),
        "allow_dns": bool(ns.allow_dns),
        "allow_dot": bool(ns.allow_dot),
        "deny_unlisted": bool(ns.deny_unlisted),
        "allow": list(ns.allow or []),
        "net_cap_bytes": ns.net_cap_bytes,
        "net_cap_ms": ns.net_cap_ms,
        "net_cap_sends": ns.net_cap_sends,
        "ts_start": time.time(),
    }

    rc = None
    try:
        rc = run_cmd(argv)
        return rc
    finally:
        meta["ts_end"] = time.time()
        meta["rc"] = rc
        events_path = outdir / "events.ndjson"
        events = parse_events_ndjson(events_path)
        report_path = write_report(outdir, meta, events)

        # Machine-readable summary for Flask
        if ns.json_out:
            print(json.dumps({
                "ok": (rc == 0),
                "rc": rc,
                "run_id": outdir.name,
                "outdir": str(outdir),
                "events_path": str(events_path),
                "report_path": str(report_path),
                "event_count": len(events),
            }))

def cmd_list(ns) -> int:
    runs_dir = Path(expand_path(ns.runs_dir))
    if not runs_dir.exists():
        print("[]")
        return 0

    items = []
    for p in runs_dir.iterdir():
        if not p.is_dir():
            continue
        if not p.name.startswith("run_"):
            continue
        rp = p / "report.json"
        ev = p / "events.ndjson"
        mtime = p.stat().st_mtime
        if rp.exists():
            try:
                data = json.loads(rp.read_text(encoding="utf-8"))
                items.append({
                    "run_id": p.name,
                    "mtime": mtime,
                    "event_count": data.get("event_count", 0),
                    "rc": data.get("meta", {}).get("rc", None),
                })
                continue
            except Exception:
                pass
        # fallback
        items.append({
            "run_id": p.name,
            "mtime": mtime,
            "event_count": sum(1 for _ in ev.open()) if ev.exists() else 0,
            "rc": None,
        })

    items.sort(key=lambda x: x["mtime"], reverse=True)
    print(json.dumps(items, indent=2))
    return 0

def cmd_show(ns) -> int:
    runs_dir = Path(expand_path(ns.runs_dir))
    run_dir = runs_dir / ns.run_id
    rp = run_dir / "report.json"
    if not rp.exists():
        print(json.dumps({"error": "missing report.json", "run_id": ns.run_id}))
        return 1
    data = json.loads(rp.read_text(encoding="utf-8"))
    if ns.timeline:
        # emit ordered events only
        print(json.dumps(data.get("events", []), indent=2))
    else:
        print(json.dumps(data, indent=2))
    return 0

def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    runp = sub.add_parser("run")
    runp.add_argument("--launcher", default=str(DEFAULT_LAUNCHER))
    runp.add_argument("--runs-dir", default=str(DEFAULT_RUNS_DIR))
    runp.add_argument("--outdir", default="")
    runp.add_argument("--timeout-ms", type=int, default=4000)
    runp.add_argument("--max-events", type=int, default=2000)
    runp.add_argument("--mode", default="dev", choices=["dev", "malware", "re", "reveal-net"])
    runp.add_argument("--write-jail", default="")
    runp.add_argument("--interactive-fs", action="store_true")
    runp.add_argument("--quarantine-drops", action="store_true")
    runp.add_argument("--allow-dns", action="store_true")
    runp.add_argument("--allow-dot", action="store_true")
    runp.add_argument("--deny-unlisted", action="store_true")
    runp.add_argument("--allow", action="append", default=[], help="Allow dst in form A.B.C.D:PORT (repeatable)")
    runp.add_argument("--net-cap-bytes", type=int, default=None)
    runp.add_argument("--net-cap-ms", type=int, default=None)
    runp.add_argument("--net-cap-sends", type=int, default=None)
    runp.add_argument("--json-out", action="store_true")
    runp.add_argument("sample")
    runp.add_argument("sample_args", nargs=argparse.REMAINDER)

    listp = sub.add_parser("list")
    listp.add_argument("--runs-dir", default=str(DEFAULT_RUNS_DIR))

    showp = sub.add_parser("show")
    showp.add_argument("--runs-dir", default=str(DEFAULT_RUNS_DIR))
    showp.add_argument("--timeline", action="store_true")
    showp.add_argument("run_id")

    ns = ap.parse_args()

    if ns.cmd == "run":
        # normalize empty strings
        ns.outdir = ns.outdir.strip() or ""
        ns.write_jail = ns.write_jail.strip() or ""
        return cmd_run(ns)
    if ns.cmd == "list":
        return cmd_list(ns)
    if ns.cmd == "show":
        return cmd_show(ns)
    return 1

if __name__ == "__main__":
    raise SystemExit(main())
