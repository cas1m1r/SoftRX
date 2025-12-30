#!/usr/bin/env python3
"""SoftRX batch orchestrator.

Offline-first batch runner for SoftRX.

- Runs softrxctl for each sample.
- Keeps per-run artifacts in softrxctl's per-run output folders.
- Writes an NDJSON index (one line per run) for fast grepping / ingestion.

Inspired by Project Bubble's orchestrator organization patterns, but intentionally
no Flask, no network, no background services.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import os
import time
from hashlib import sha256
from pathlib import Path
from subprocess import run


def sha256_hex(p: Path) -> str:
    h = sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def iter_samples(inp: list[str]) -> list[Path]:
    out: list[Path] = []
    for s in inp:
        p = Path(s)
        if p.is_dir():
            for child in sorted(p.iterdir()):
                if child.is_file() and os.access(child, os.R_OK):
                    out.append(child.resolve())
        else:
            out.append(p.resolve())
    # de-dupe preserving order
    seen: set[str] = set()
    uniq: list[Path] = []
    for p in out:
        k = str(p)
        if k in seen:
            continue
        seen.add(k)
        uniq.append(p)
    return uniq


def run_one(root: Path, softrxctl: Path, sample: Path, outdir: Path, timeout_ms: int, max_events: int) -> dict:
    start = time.time()
    cmd = [
        str(softrxctl),
        str(sample),
        "--outdir",
        str(outdir),
        "--timeout-ms",
        str(timeout_ms),
        "--max-events",
        str(max_events),
        "--",
    ]
    # softrxctl passes args after -- to the sample; for batch runs we keep it empty.
    proc = run(cmd, cwd=str(root), capture_output=True, text=True)
    end = time.time()

    # Try to find the newest run folder created by softrxctl.
    run_dir = None
    if outdir.exists():
        run_dir = max((p for p in outdir.glob("run_*") if p.is_dir()), key=lambda p: p.stat().st_mtime, default=None)

    report_path = run_dir / "report.json" if run_dir else None
    report = None
    if report_path and report_path.exists():
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except Exception:
            report = None

    first_event = None
    if report and isinstance(report.get("events"), list) and report["events"]:
        first_event = report["events"][0].get("event")

    return {
        "ts": now_iso(),
        "sample": str(sample),
        "sample_sha256": sha256_hex(sample) if sample.exists() else None,
        "run_dir": str(run_dir) if run_dir else None,
        "returncode": proc.returncode,
        "duration_s": round(end - start, 3),
        "first_event": first_event,
        "stdout": proc.stdout[-4000:],
        "stderr": proc.stderr[-4000:],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Batch-run SoftRX across many samples")
    ap.add_argument("inputs", nargs="+", help="Sample files and/or directories")
    ap.add_argument("--outdir", default="softrx_runs", help="Same meaning as softrxctl --outdir")
    ap.add_argument("--timeout-ms", type=int, default=4000)
    ap.add_argument("--max-events", type=int, default=4)
    ap.add_argument("--jobs", type=int, default=1, help="Parallel jobs")
    ap.add_argument("--index", default="batch_index.ndjson", help="NDJSON index filename")
    args = ap.parse_args()

    root = Path(__file__).resolve().parents[1]
    softrxctl = root / "softrxctl.py"
    outdir = (Path(args.outdir).resolve())
    outdir.mkdir(parents=True, exist_ok=True)

    samples = [p for p in iter_samples(args.inputs) if p.exists() and p.is_file()]
    if not samples:
        raise SystemExit("No readable samples found")

    idx_path = outdir / args.index
    with idx_path.open("a", encoding="utf-8") as f:
        if args.jobs <= 1:
            for s in samples:
                row = run_one(root, softrxctl, s, outdir, args.timeout_ms, args.max_events)
                f.write(json.dumps(row) + "\n")
                f.flush()
        else:
            with cf.ThreadPoolExecutor(max_workers=args.jobs) as ex:
                futs = [ex.submit(run_one, root, softrxctl, s, outdir, args.timeout_ms, args.max_events) for s in samples]
                for fut in cf.as_completed(futs):
                    row = fut.result()
                    f.write(json.dumps(row) + "\n")
                    f.flush()

    print(f"[SoftRX] batch index: {idx_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
