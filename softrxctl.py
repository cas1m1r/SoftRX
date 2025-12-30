#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_RUNS = HERE / "softrx_runs"

def utc_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

def latest_run_dir(base: Path) -> Path | None:
    if not base.exists():
        return None
    runs = sorted([p for p in base.glob("run_*") if p.is_dir()], reverse=True)
    return runs[0] if runs else None

def parse_events_ndjson(path: Path):
    events = []
    if not path.exists():
        return events
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except Exception:
            events.append({"event":"parse_error","raw":line})
    return events

def write_report(outdir: Path, sample: str, rc: int, t0: float, t1: float, stdout: str, stderr: str):
    events_path = outdir / "events.ndjson"
    events = parse_events_ndjson(events_path)

    report = {
        "sample": sample,
        "outdir": str(outdir),
        "ts_start": utc_iso(t0),
        "ts_end": utc_iso(t1),
        "duration_s": round(t1 - t0, 3),
        "returncode": rc,
        "events": events,
        "dumps": [],
        "artifacts": [],
        "raw_stdout": stdout,
        "raw_stderr": stderr,
    }
    (outdir / "report.json").write_text(json.dumps(report, indent=2) + "\n")

    md = []
    md.append(f"# SoftRX report\n")
    md.append(f"- Sample: `{sample}`")
    md.append(f"- Start: `{report['ts_start']}`")
    md.append(f"- End: `{report['ts_end']}`")
    md.append(f"- Duration: `{report['duration_s']}s`")
    md.append(f"- Return code: `{rc}`\n")
    md.append(f"## Events ({len(events)})\n")
    for e in events[:50]:
        md.append(f"- `{e.get('event','?')}`: {json.dumps(e, ensure_ascii=False)}")
    if len(events) > 50:
        md.append(f"- ... ({len(events)-50} more)\n")
    (outdir / "report.md").write_text("\n".join(md) + "\n")

def build_cmd(args, outdir: Path, write_jail: Path):
    launcher = HERE / "bin" / "softrx_launcher"
    if not launcher.exists():
        print("[SoftRX] ERROR: bin/softrx_launcher not found. Run `make` first.", file=sys.stderr)
        sys.exit(2)

    timeout_ms = args.timeout_ms
    if timeout_ms is None:
        timeout_ms = int(args.timeout * 1000)

    cmd = [
        str(launcher),
        "--outdir", str(outdir),
        "--timeout-ms", str(timeout_ms),
        "--max-events", str(args.max_events),
        "--mode", args.mode,
        "--write-jail", str(write_jail),
        "--",
        str(Path(args.sample).resolve()),
    ]
    if args.sample_args:
        cmd.extend(args.sample_args)
    return cmd

def parse_args(argv):
    p = argparse.ArgumentParser(
        prog="softrxctl.py",
        description="SoftRX wrapper: create run dir, invoke softrx_launcher, and generate report.json/report.md",
        add_help=True,
        allow_abbrev=False,
    )
    p.add_argument("sample", help="Path to sample/binary to run under SoftRX")
    p.add_argument("sample_args", nargs=argparse.REMAINDER, help="Arguments passed to the sample. Use `--` before sample args if needed.")
    p.add_argument("--runs-dir", default=str(DEFAULT_RUNS), help="Directory to store run outputs (default: ./softrx_runs)")
    p.add_argument("--timeout", type=float, default=4.0, help="Timeout in seconds (default: 4.0)")
    p.add_argument("--timeout-ms", type=int, default=None, help="Timeout in ms (overrides --timeout)")
    p.add_argument("--max-events", type=int, default=200, help="Max seccomp events before kill (default: 200)")
    p.add_argument("--mode", default="malware", choices=["malware", "re", "dev"], help="Policy mode label (default: malware)")
    return p.parse_args(argv)

def main():
    args = parse_args(sys.argv[1:])
    runs_dir = Path(args.runs_dir).expanduser().resolve()
    ensure_dir(runs_dir)

    run_dir = runs_dir / ("run_" + datetime.now().strftime("%Y%m%d_%H%M%S"))
    write_jail = run_dir / "fs"
    ensure_dir(write_jail)

    print(f"[SoftRX] run_dir={run_dir}")
    print(f"[SoftRX] write_jail={write_jail}")
    print(f"[SoftRX] mode={args.mode} interactive_fs=False")

    cmd = build_cmd(args, run_dir, write_jail)
    print(f"[SoftRX] cmd={' '.join(map(str, cmd))}")

    t0 = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
        rc = proc.returncode
        out = proc.stdout or ""
        err = proc.stderr or ""
    except Exception as e:
        rc = -1
        out = ""
        err = f"launcher_error: {e!r}\n"
    t1 = time.time()

    write_report(run_dir, str(Path(args.sample).resolve()), rc, t0, t1, out, err)

    print(f"[SoftRX] Wrote {run_dir/'report.json'}")
    print(f"[SoftRX] Wrote {run_dir/'report.md'}")

if __name__ == "__main__":
    main()

