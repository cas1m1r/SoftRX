#!/usr/bin/env python3
"""SoftRX Web Interface - Flask Backend

This server intentionally stays thin:
- The authoritative run/metadata format is produced by softrxctl.py (report.json + events.ndjson).
- The UI is a single-page app (index.html) that talks to /api/* endpoints.
"""

from flask import Flask, request, jsonify, send_file
from pathlib import Path
import json
import re
import subprocess
import time
import sys
from datetime import datetime
from werkzeug.utils import secure_filename
import os, re, signal

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size
app.config['UPLOAD_FOLDER'] = Path(__file__).parent / 'uploads'
app.config['UPLOAD_FOLDER'].mkdir(exist_ok=True)

def _find_repo_root(start: Path) -> Path:
    """Find the directory that contains softrxctl.py (repo root-ish).

    This makes the Flask app resilient if you move it into e.g. a /web folder.
    """
    start = start.resolve()
    for p in [start] + list(start.parents):
        if (p / "softrxctl.py").exists():
            return p
    return start

ROOT = _find_repo_root(Path(__file__).resolve().parent)

SOFTRXCTL = ROOT / "softrxctl.py"
RUNS_DIR = ROOT / "softrx_runs"
UPLOADS_DIR = ROOT / "uploads"
SAMPLES_DIR = UPLOADS_DIR / "ex"   # adjust to your actual layout

# Ensure runs directory exists
RUNS_DIR.mkdir(exist_ok=True)


def _safe_read_json(path: Path, default=None):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


# ---------- Event loading + light UI joins (pid tree / stages / friendly labels) ----------

def _iter_events_ndjson(path: Path, max_events: int | None = None):
    """Stream NDJSON events; tolerates partial/corrupt lines."""
    n = 0
    with open(path, "r", errors="replace") as f:
        for line in f:
            if max_events is not None and n >= max_events:
                break
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
                n += 1
            except Exception:
                continue


def load_run_events(run_dir: Path, max_events: int | None = None):
    """Prefer events.ndjson (newer, streaming-friendly). Fall back to report.json events."""
    nd = run_dir / "events.ndjson"
    if nd.exists():
        return list(_iter_events_ndjson(nd, max_events=max_events))
    rp = run_dir / "report.json"
    if rp.exists():
        rj = _safe_read_json(rp, default={}) or {}
        evs = rj.get("events", []) or []
        if max_events is not None:
            evs = evs[:max_events]
        return evs
    return []


_LOADER_PATH_RE = re.compile(
    r"(^|/)(ld-linux|ld-[^/]*\.so|ld\.so\.cache|libc\.so|libpthread\.so|libm\.so|libdl\.so|libstdc\+\+\.so)",
    re.IGNORECASE,
)

def _is_loaderish_path(p: str) -> bool:
    if not p:
        return False
    # Cheap heuristic: libc/ld + any /lib or /usr/lib are usually loader noise.
    if _LOADER_PATH_RE.search(p):
        return True
    if "/lib/" in p or p.startswith("/lib") or "/usr/lib/" in p:
        return True
    if p.startswith("/etc/ld.so"):
        return True
    return False


def _decode_open_flags(flags: int | None) -> str:
    if flags is None:
        return ""
    try:
        flags = int(flags)
    except Exception:
        return ""
    # POSIX: access mode is low 2 bits (0=RDONLY, 1=WRONLY, 2=RDWR)
    acc = flags & 0x3
    mode = {0: "r", 1: "w", 2: "rw"}.get(acc, "?")
    tags = []
    # Common Linux bits (not exhaustive)
    if flags & 0x40:      # O_CREAT
        tags.append("creat")
    if flags & 0x200:     # O_TRUNC
        tags.append("trunc")
    if flags & 0x400:     # O_APPEND
        tags.append("append")
    if flags & 0x80000:   # O_CLOEXEC
        tags.append("cloexec")
    return mode + (("+" + "+".join(tags)) if tags else "")


def add_stage_ids(events: list[dict]) -> tuple[list[dict], list[dict]]:
    """Derive stage_id from exec boundaries (cheap + deterministic).

    stage_id format: "<pid>:<exec_seq>" where exec_seq increments after an exec boundary.

    Semantics:
    - The stage_id groups events between exec boundaries for the *same pid*.
    - We attach the "image" (what is now running) to the stage *after* the exec boundary.

    Boundary selection:
    - If the trace contains exec_commit (newer schema), we treat *only* exec_commit as the
      boundary (so we don't double-increment when exec_allow_* is also present).
    - If exec_commit is absent, we fall back to exec_allow_* as the boundary.
    """
    stage_seq: dict[int, int] = {}
    stages: dict[str, dict] = {}

    # For each pid, the most recently committed exec target (applied to the *next* stage).
    pending_image: dict[int, dict] = {}

    # Ensure deterministic order
    events_sorted = sorted(events, key=lambda e: int(e.get("idx", 0)))

    has_exec_commit = any(str(e.get("event", "")) == "exec_commit" for e in events_sorted)

    def _is_boundary(et: str) -> bool:
        if has_exec_commit:
            return et == "exec_commit"
        return et.startswith("exec_allow")

    for ev in events_sorted:
        pid = int(ev.get("pid", -1))
        if pid < 0:
            continue

        seq = stage_seq.get(pid, 0)
        sid = f"{pid}:{seq}"
        ev["stage_id"] = sid

        # Stage record (created on first touch)
        if sid not in stages:
            img = pending_image.pop(pid, None)
            img_abs = (img or {}).get("abs")
            img_path = (img or {}).get("path")
            stages[sid] = {
                "stage_id": sid,
                "pid": pid,
                "ppid": ev.get("ppid"),
                "comm": ev.get("comm"),
                "start_idx": ev.get("idx"),
                "start_ts_ms": ev.get("ts_ms"),
                # What is now running in this stage (best-effort)
                "image_abs": img_abs,
                "image_path": img_path,
                # Back-compat aliases used by the current UI
                "exec_abs": img_abs,
                "exec_path": img_path,
                # The boundary event that ended this stage (filled when we hit it)
                "boundary_abs": None,
                "boundary_path": None,
            }

        et = str(ev.get("event", ""))
        if _is_boundary(et):
            # Record the exec target that ended *this* stage
            stages[sid]["boundary_abs"] = ev.get("abs")
            stages[sid]["boundary_path"] = ev.get("path")

            # And apply it to the *next* stage as the running image
            pending_image[pid] = {"abs": ev.get("abs"), "path": ev.get("path")}

            stage_seq[pid] = seq + 1

    # Fixup: propagate comm updates (comm can change after exec)
    for ev in events_sorted:
        sid = ev.get("stage_id")
        if sid in stages and ev.get("comm"):
            stages[sid]["comm"] = ev.get("comm")

    return events_sorted, list(stages.values())


def build_process_index(events: list[dict], stages: list[dict]):
    """Build a minimal process table + parent/child edges for UI."""
    procs: dict[int, dict] = {}
    for ev in events:
        pid = int(ev.get("pid", -1))
        if pid < 0:
            continue
        p = procs.setdefault(pid, {
            "pid": pid,
            "ppid": ev.get("ppid"),
            "comm": ev.get("comm"),
            "first_idx": ev.get("idx"),
            "last_idx": ev.get("idx"),
            "first_ts_ms": ev.get("ts_ms"),
            "last_ts_ms": ev.get("ts_ms"),
            "exec_chain": [],
            "children": [],
        })
        # Update rolling facts
        p["ppid"] = ev.get("ppid", p["ppid"])
        if ev.get("comm"):
            p["comm"] = ev.get("comm")
        p["last_idx"] = ev.get("idx", p["last_idx"])
        p["last_ts_ms"] = ev.get("ts_ms", p["last_ts_ms"])

        et = str(ev.get("event", ""))
        if et.startswith("exec_allow") and ev.get("abs"):
            p["exec_chain"].append(ev.get("abs"))

    # Edges
    for pid, p in procs.items():
        ppid = p.get("ppid")
        if isinstance(ppid, int) and ppid in procs and ppid != pid:
            procs[ppid]["children"].append(pid)

    # Roots (ppid not in table)
    roots = [pid for pid, p in procs.items() if not (isinstance(p.get("ppid"), int) and p["ppid"] in procs and p["ppid"] != pid)]
    roots.sort()

    def _to_tree(pid: int):
        node = dict(procs[pid])
        node["children"] = [ _to_tree(c) for c in sorted(node.get("children", [])) ]
        return node

    tree = [ _to_tree(r) for r in roots ]
    return list(procs.values()), tree

def build_stage_summaries(events: list[dict], stages: list[dict], *, top_n: int = 10, include_loader: bool = False):
    """Compute deterministic per-stage digests.

    This is an 'analysis/enrichment' layer that stays non-speculative:
    - uses existing event fields (pid/ppid/comm/stage_id/abs/dst/adds_exec)
    - aggregates counts and top file/destination touches
    - filters loader noise by default
    """
    # Index stage metadata
    stage_meta: dict[str, dict] = {s.get("stage_id"): dict(s) for s in stages if s.get("stage_id")}
    stage_stats: dict[str, dict] = {}

    def _get(sid: str) -> dict:
        if sid not in stage_stats:
            sm = stage_meta.get(sid, {})
            stage_stats[sid] = {
                "stage_id": sid,
                "pid": sm.get("pid"),
                "ppid": sm.get("ppid"),
                "comm": sm.get("comm"),
                "image_abs": sm.get("image_abs") or sm.get("exec_abs"),
                "image_path": sm.get("image_path") or sm.get("exec_path"),
                "boundary_abs": sm.get("boundary_abs"),
                "boundary_path": sm.get("boundary_path"),
                "start_idx": sm.get("start_idx"),
                "end_idx": sm.get("start_idx"),
                "start_ts_ms": sm.get("start_ts_ms"),
                "end_ts_ms": sm.get("start_ts_ms"),
                "duration_ms": 0,
                "counts": {
                    "exec": 0,
                    "fs_open": 0,
                    "fd_open": 0,
                    "fd_read": 0,
                    "fd_write": 0,
                    "fd_close": 0,
                    "net": 0,
                    "mprotect_exec": 0,
                    "policy": 0,
                },
                "top_files": [],     # filled later
                "top_net_dsts": [],  # filled later
                "notes": [],
            }
            stage_stats[sid]["_files"] = {}  # abs -> counters
            stage_stats[sid]["_dsts"] = {}   # dst -> counters
        return stage_stats[sid]

    for ev in events:
        sid = ev.get("stage_id")
        if not sid:
            continue
        st = _get(sid)

        idx = ev.get("idx")
        ts = ev.get("ts_ms")

        # Update end markers
        if isinstance(idx, int) and (st["end_idx"] is None or idx > st["end_idx"]):
            st["end_idx"] = idx
        elif st["end_idx"] is None:
            st["end_idx"] = idx

        if isinstance(ts, (int, float)) and (st["end_ts_ms"] is None or ts > st["end_ts_ms"]):
            st["end_ts_ms"] = ts
        elif st["end_ts_ms"] is None:
            st["end_ts_ms"] = ts

        et = str(ev.get("event", ""))

        # Counts
        if et.startswith("exec_"):
            st["counts"]["exec"] += 1
        elif et == "fs_open_attempt" or et.startswith("fs_open_"):
            st["counts"]["fs_open"] += 1
        elif et == "fd_open_result":
            st["counts"]["fd_open"] += 1
        elif et in ("fd_read", "fd_readv"):
            st["counts"]["fd_read"] += 1
        elif et in ("fd_write", "fd_writev"):
            st["counts"]["fd_write"] += 1
        elif et == "fd_close":
            st["counts"]["fd_close"] += 1
        elif et.startswith("net_"):
            st["counts"]["net"] += 1
        elif et == "mprotect" and bool(ev.get("adds_exec", False)):
            st["counts"]["mprotect_exec"] += 1
        elif et in ("hard_kill","snapshot","timeout_halt","max_events_halt"):
            st["counts"]["policy"] += 1

        # File touches (prefer resolved abs)
        abs_p = ev.get("abs") or ev.get("target") or ev.get("path")
        if isinstance(abs_p, str) and abs_p:
            if include_loader or not _is_loaderish_path(abs_p):
                f = st["_files"].setdefault(abs_p, {"opens": 0, "reads": 0, "writes": 0, "closes": 0})
                if et.startswith("fs_open") or et == "fd_open_result":
                    f["opens"] += 1
                if et in ("fd_read", "fd_readv"):
                    f["reads"] += 1
                if et in ("fd_write", "fd_writev"):
                    f["writes"] += 1
                if et == "fd_close":
                    f["closes"] += 1

        # Net destinations
        dst = ev.get("dst")
        if isinstance(dst, str) and dst:
            d = st["_dsts"].setdefault(dst, {"count": 0})
            d["count"] += 1

    # Finalize: duration + top lists + notes
    summaries = []
    for sid, st in stage_stats.items():
        try:
            if isinstance(st["start_ts_ms"], (int, float)) and isinstance(st["end_ts_ms"], (int, float)):
                st["duration_ms"] = int(st["end_ts_ms"] - st["start_ts_ms"])
        except Exception:
            st["duration_ms"] = 0

        files = []
        for p, c in st["_files"].items():
            score = (c["opens"] * 3) + (c["reads"] * 2) + (c["writes"] * 4)
            files.append({"abs": p, **c, "_score": score})
        files.sort(key=lambda x: (x["_score"], x["writes"], x["reads"], x["opens"]), reverse=True)
        st["top_files"] = [{k: v for k, v in f.items() if k != "_score"} for f in files[:top_n]]

        dsts = [{"dst": d, "count": c["count"]} for d, c in st["_dsts"].items()]
        dsts.sort(key=lambda x: x["count"], reverse=True)
        st["top_net_dsts"] = dsts[:top_n]

        # Notes
        if st["counts"]["mprotect_exec"] > 0:
            st["notes"].append("memory protections added EXEC")
        if st["counts"]["net"] > 0:
            st["notes"].append(f"network activity ({st['counts']['net']} events)")
        if st["top_files"]:
            st["notes"].append(f"file activity ({len(st['top_files'])} top paths)")

        # Drop private scratch
        st.pop("_files", None)
        st.pop("_dsts", None)

        summaries.append(st)

    # Sort by (pid, start_idx)
    summaries.sort(key=lambda s: (int(s.get("pid") or -1), int(s.get("start_idx") or 0)))
    return summaries


def _friendly_label(ev: dict) -> str:
    et = str(ev.get("event", ""))
    pid = ev.get("pid")
    # Synthetic rows
    if et == "fs_loader_group":
        return f"loader: {ev.get('count', 0)} library/ld opens (collapsed)"
    if et == "fs_loader_io":
        abs_p = ev.get("abs") or ev.get("path") or ""
        tail = abs_p.split("/")[-1] if abs_p else "(unknown)"
        reads = int(ev.get("reads", 0) or 0)
        b = int(ev.get("bytes", 0) or 0)
        return f"loader io: {tail} ({reads} reads, {b} bytes)"
    if et == "fd_read_group":
        return f"read: fd={ev.get('fd')} x{ev.get('count', 0)} ({ev.get('bytes', 0)} bytes)"

    if et == "fs_open_attempt":
        abs_p = ev.get("abs") or ev.get("path") or ""
        flags = _decode_open_flags(ev.get("flags"))
        tail = abs_p.split("/")[-1] if abs_p else ""
        return f"open({flags}) {tail or abs_p}"
    if et.startswith("fs_open_write_allowed"):
        abs_p = ev.get("abs") or ""
        tail = abs_p.split("/")[-1] if abs_p else abs_p
        return f"open(write allowed) {tail}"
    if et.startswith("fs_unlink"):
        abs_p = ev.get("abs") or ev.get("path") or ""
        return f"unlink {abs_p}"
    if et.startswith("exec_attempt"):
        abs_p = ev.get("abs") or ev.get("path") or ""
        return f"exec? {abs_p}"
    if et.startswith("exec_allow"):
        abs_p = ev.get("abs") or ""
        return f"exec ✓ {abs_p}"
    if et == "exec_commit":
        abs_p = ev.get("abs") or ev.get("path") or ""
        return f"exec ↳ {abs_p}"
    if et == "proc_fork_attempt":
        return f"fork/clone?"
    if et == "net_connect_attempt":
        return f"connect {ev.get('dst', '')} (fd={ev.get('fd')})"
    if et == "net_sendto_attempt":
        return f"sendto {ev.get('dst', '')} len={ev.get('len')}"
    if et == "net_attempt":
        return f"net syscall {ev.get('sys')}"
    if et == "mprotect":
        return f"mprotect prot={ev.get('prot')} adds_exec={bool(ev.get('adds_exec'))}"
    if et.startswith("fd_"):
        fd = ev.get("fd")
        abs_p = ev.get("abs")
        tgt = ev.get("target")
        name = ""
        if isinstance(abs_p, str) and abs_p:
            name = abs_p.split("/")[-1]
        elif isinstance(tgt, str) and tgt:
            name = tgt

        if et == "fd_open_result":
            # from C lazy resolver
            kind = ev.get("kind") or ""
            if name:
                return f"fd={fd} → {name} ({kind})"
            return f"fd_open_result fd={fd} ({kind})"

        if et == "fd_read":
            if name:
                return f"read {name} (fd={fd}, {ev.get('count')} bytes)"
            return f"read fd={fd} ({ev.get('count')} bytes)"
        if et == "fd_readv":
            if name:
                return f"readv {name} (fd={fd}, iov={ev.get('iovcnt')})"
            return f"readv fd={fd} (iov={ev.get('iovcnt')})"
        if et == "fd_write":
            if name:
                return f"write {name} (fd={fd}, {ev.get('count')} bytes)"
            return f"write fd={fd} ({ev.get('count')} bytes)"
        if et == "fd_writev":
            if name:
                return f"writev {name} (fd={fd}, iov={ev.get('iovcnt')})"
            return f"writev fd={fd} (iov={ev.get('iovcnt')})"
        if et == "fd_close":
            if name:
                return f"close {name} (fd={fd})"
            return f"close fd={fd}"
        return f"{et} fd={fd}"
    return et


def build_compact_timeline(events: list[dict], *, hide_mem_noise: bool = True, collapse_loader: bool = True, group_fd_reads: bool = True):
    """Return a UI-friendly timeline with basic noise controls and friendly labels.

    This is still 'thin': no guessing, only grouping consecutive identical-ish rows.
    """
    out = []
    i = 0
    n = len(events)

    while i < n:
        ev = events[i]
        et = str(ev.get("event", ""))

        # 1) Hide mprotect unless adds_exec=true
        if hide_mem_noise and et == "mprotect" and not bool(ev.get("adds_exec", False)):
            i += 1
            continue

        # 2) Collapse loader I/O into a single row per file.
        #
        # In your trace, loader-ish work is usually:
        #   fs_open_attempt(abs=/usr/lib/.../libc.so.6)
        #   fd_open_result(fd=..., abs=/usr/lib/.../libc.so.6)
        #   (maybe fd_fcntl...)
        #   fd_read...
        #   fd_close
        #
        # Collapsing only fs_open_attempt still left tons of fd_open_result/fd_close noise.
        if collapse_loader and et == "fs_open_attempt" and _is_loaderish_path(str(ev.get("abs", ""))):
            pid = ev.get("pid")
            sid = ev.get("stage_id")

            j = i + 1
            fd = None
            abs_p = ev.get("abs") or ev.get("path")
            kind = None

            # Optional: capture fd+abs from the immediate fd_open_result
            if j < n:
                ev2 = events[j]
                if (str(ev2.get("event", "")) == "fd_open_result" and ev2.get("pid") == pid and ev2.get("stage_id") == sid):
                    fd = ev2.get("fd")
                    abs_p = ev2.get("abs") or abs_p
                    kind = ev2.get("kind")
                    j += 1

            reads = 0
            bytes_read = 0
            consumed = 1 + (1 if fd is not None else 0)
            closed = False

            # Consume fd_* noise until we see the close for this fd.
            while j < n:
                ev3 = events[j]
                if ev3.get("pid") != pid or ev3.get("stage_id") != sid:
                    break

                et3 = str(ev3.get("event", ""))
                fd3 = ev3.get("fd")

                if et3 in ("fd_fcntl", "fd_fstat", "fd_lseek", "fd_mmap", "fd_munmap") and (fd is None or fd3 == fd):
                    j += 1
                    consumed += 1
                    continue

                if et3 in ("fd_read", "fd_readv") and (fd is None or fd3 == fd):
                    reads += 1
                    try:
                        bytes_read += int(ev3.get("count", 0) or 0)
                    except Exception:
                        pass
                    j += 1
                    consumed += 1
                    continue

                if et3 == "fd_close" and (fd is None or fd3 == fd):
                    j += 1
                    consumed += 1
                    closed = True
                    break

                # Stop if the pattern breaks.
                break

            # Only collapse if we actually saw a full-ish open->close pattern.
            if closed and consumed >= 4:
                synthetic = {
                    "ts_ms": ev.get("ts_ms"),
                    "idx": ev.get("idx"),
                    "event": "fs_loader_io",
                    "pid": pid,
                    "tid": ev.get("tid"),
                    "ppid": ev.get("ppid"),
                    "comm": ev.get("comm"),
                    "stage_id": sid,
                    "fd": fd,
                    "abs": abs_p,
                    "kind": kind,
                    "reads": reads,
                    "bytes": bytes_read,
                    "consumed": consumed,
                }
                synthetic["label"] = _friendly_label(synthetic)
                out.append(synthetic)
                i = j
                continue

            # If we couldn't collapse into loader_io, fall back to the older "group of opens" behavior.
            # This catches odd cases where the fd_open_result/close isn't adjacent or is missing.
            if collapse_loader:
                j2 = i
                sample_paths = []
                while j2 < n:
                    ev2 = events[j2]
                    if str(ev2.get("event", "")) != "fs_open_attempt":
                        break
                    if not _is_loaderish_path(str(ev2.get("abs", ""))):
                        break
                    if ev2.get("pid") != ev.get("pid") or ev2.get("stage_id") != ev.get("stage_id"):
                        break
                    if len(sample_paths) < 3 and ev2.get("abs"):
                        sample_paths.append(ev2.get("abs"))
                    j2 += 1
                count = j2 - i
                if count >= 4:
                    synthetic = {
                        "ts_ms": ev.get("ts_ms"),
                        "idx": ev.get("idx"),
                        "event": "fs_loader_group",
                        "pid": ev.get("pid"),
                        "tid": ev.get("tid"),
                        "ppid": ev.get("ppid"),
                        "comm": ev.get("comm"),
                        "stage_id": ev.get("stage_id"),
                        "count": count,
                        "samples": sample_paths,
                    }
                    synthetic["label"] = _friendly_label(synthetic)
                    out.append(synthetic)
                    i = j2
                    continue

        # 3) Group consecutive fd_read on same fd
        if group_fd_reads and et == "fd_read":
            fd = ev.get("fd")
            j = i
            total = 0
            while j < n:
                ev2 = events[j]
                if str(ev2.get("event","")) != "fd_read":
                    break
                if ev2.get("pid") != ev.get("pid") or ev2.get("stage_id") != ev.get("stage_id"):
                    break
                if ev2.get("fd") != fd:
                    break
                try:
                    total += int(ev2.get("count", 0))
                except Exception:
                    pass
                j += 1
            count = j - i
            if count >= 4:
                synthetic = {
                    "ts_ms": ev.get("ts_ms"),
                    "idx": ev.get("idx"),
                    "event": "fd_read_group",
                    "pid": ev.get("pid"),
                    "tid": ev.get("tid"),
                    "ppid": ev.get("ppid"),
                    "comm": ev.get("comm"),
                    "stage_id": ev.get("stage_id"),
                    "fd": fd,
                    "count": count,
                    "bytes": total,
                }
                synthetic["label"] = _friendly_label(synthetic)
                out.append(synthetic)
                i = j
                continue

        ev = dict(ev)
        ev["label"] = _friendly_label(ev)
        out.append(ev)
        i += 1

    return out

def get_all_runs():
    runs = []
    if not RUNS_DIR.exists():
        print(f"[runs] RUNS_DIR missing: {RUNS_DIR}")
        return runs

    for run_dir in RUNS_DIR.glob("run_*"):
        if not run_dir.is_dir():
            continue

        report_json = run_dir / "report.json"
        if report_json.exists():
            report = _safe_read_json(report_json, default={}) or {}
            meta = report.get("meta", {}) or {}
            ts_start = meta.get("ts_start")
            ts_end = meta.get("ts_end")
            duration_s = 0.0
            if isinstance(ts_start, (int, float)) and isinstance(ts_end, (int, float)) and ts_end >= ts_start:
                duration_s = round(ts_end - ts_start, 3)

            runs.append({
                "id": run_dir.name,
                "path": str(run_dir),
                "sample": meta.get("sample", "unknown"),
                "timestamp": datetime.fromtimestamp(run_dir.stat().st_mtime).isoformat(),
                "duration_s": duration_s,
                "returncode": meta.get("rc"),
                "mode": meta.get("mode"),
                "event_count": int(report.get("event_count", 0) or 0),
            })
            continue

        # Fallback: legacy or partial runs
        events_ndjson = run_dir / "events.ndjson"
        if events_ndjson.exists():
            try:
                with open(events_ndjson, "r", errors="replace") as f:
                    event_count = sum(1 for _ in f)
                runs.append({
                    "id": run_dir.name,
                    "path": str(run_dir),
                    "sample": "unknown",
                    "timestamp": datetime.fromtimestamp(run_dir.stat().st_mtime).isoformat(),
                    "duration_s": 0,
                    "returncode": None,
                    "mode": None,
                    "event_count": event_count,
                })
            except Exception as e:
                print(f"[runs] failed to read {events_ndjson}: {e}")

    runs.sort(key=lambda x: x["timestamp"], reverse=True)
    return runs


def parse_events(events):
    """Best-effort event categorization (purely for UI grouping)."""
    categories = {
        "timeline": events or [],  # ordered
        "filesystem": [],
        "network": [],
        "process": [],
        "memory": [],
        "fd": [],
        "policy": [],
        "other": [],
    }

    for ev in events or []:
        et = (ev.get("event") or "").lower()
        if et.startswith("fs_") or "_fs_" in et:
            categories["filesystem"].append(ev)
        elif et.startswith("net_") or "_net_" in et:
            categories["network"].append(ev)
        elif et.startswith("proc_") or et.startswith("exec") or "fork" in et or "clone" in et:
            categories["process"].append(ev)
        elif et.startswith("mprotect") or "mprotect" in et:
            categories["memory"].append(ev)
        elif et.startswith("fd_"):
            categories["fd"].append(ev)
        elif et in ("hard_kill", "snapshot", "timeout_halt", "max_events_halt") or et.startswith("tripwire"):
            categories["policy"].append(ev)
        else:
            categories["other"].append(ev)

    return categories


@app.route('/')
def index():
    """Serve the single-page UI."""
    return send_file(ROOT / "index.html")


@app.route('/api/config')
def api_config():
    """Expose server-side defaults/capabilities for the UI."""
    return jsonify({
        "root": str(ROOT),
        "softrxctl": str(SOFTRXCTL),
        "runs_dir": str(RUNS_DIR),
        "upload_dir": str(app.config['UPLOAD_FOLDER']),
        "modes": ["malware", "re", "reveal-net", "dev"],
        "defaults": {
            "timeout_ms": 4000,
            "max_events": 2000,
            "mode": "malware",
            "quarantine_drops": True,
            "interactive_fs": False,
            "allow_dns": True,
            "allow_dot": True,
            "deny_unlisted": False,
            "net_cap_bytes": 10240,
            "net_cap_ms": 2000,
            "net_cap_sends": 32,
        }
    })


@app.route('/api/runs')
def api_runs():
    """Get list of all runs"""
    runs = get_all_runs()
    return jsonify(runs)


@app.route('/api/run/<run_id>')
def api_run_detail(run_id):
    """Get detailed information for a specific run.

    Notes:
    - We prefer events.ndjson because it contains pid/tid/ppid/comm envelopes and is streaming-friendly.
    - report.json is still used for meta (cmdline, mode, write_dir, etc.) when available.
    """
    run_dir = RUNS_DIR / run_id
    if not run_dir.exists():
        return jsonify({'error': 'Run not found'}), 404

    # Optional UI controls
    try:
        max_events = int(request.args.get("max_events")) if request.args.get("max_events") else None
    except Exception:
        max_events = None

    include_raw = request.args.get("raw", "0") == "1"
    hide_mem_noise = request.args.get("hide_mem", "1") == "1"
    collapse_loader = request.args.get("collapse_loader", "1") == "1"
    group_fd_reads = request.args.get("group_fd", "1") == "1"
    include_stage_summaries = request.args.get("stage_summaries", "1") == "1"
    try:
        stage_top_n = int(request.args.get("stage_top_n", "10"))
    except Exception:
        stage_top_n = 10
    include_loader_stage = request.args.get("stage_include_loader", "0") == "1"

    report_path = run_dir / "report.json"
    report = _safe_read_json(report_path, default={}) if report_path.exists() else {}
    meta = (report.get("meta", {}) or {}) if isinstance(report, dict) else {}

    # Load events (ndjson preferred)
    raw_events = load_run_events(run_dir, max_events=max_events)

    # Derive stage_id + process tree
    events, stages = add_stage_ids(raw_events)
    processes, proc_tree = build_process_index(events, stages)
    # Stage digests (analysis/enrichment layer)
    stage_summaries = []
    if include_stage_summaries:
        stage_summaries = build_stage_summaries(events, stages, top_n=stage_top_n, include_loader=include_loader_stage)


    # Build a compact timeline for the UI
    timeline = build_compact_timeline(
        events,
        hide_mem_noise=hide_mem_noise,
        collapse_loader=collapse_loader,
        group_fd_reads=group_fd_reads,
    )

    # Re-use existing categorizer for convenience
    categorized = parse_events(timeline)

    # Files created inside the write jail typically live at outdir/fs
    fs_dir = run_dir / "fs"
    artifacts = []
    if fs_dir.exists():
        for item in fs_dir.rglob('*'):
            if item.is_file():
                artifacts.append({
                    'name': item.name,
                    'path': str(item.relative_to(fs_dir)),
                    'size': item.stat().st_size,
                })

    # Snapshot files written to outdir on hard_kill/snapshot
    snapshots = []
    for p in run_dir.glob("dump_*"):
        if p.is_file():
            snapshots.append({
                "name": p.name,
                "size": p.stat().st_size,
            })

    # sockmap is optional; leave as-is if present
    sockmap_path = run_dir / "sockmap.json"
    sockmap = _safe_read_json(sockmap_path, default=None) if sockmap_path.exists() else None

    def _count(prefix: str) -> int:
        return sum(1 for ev in events if str(ev.get("event", "")).startswith(prefix))

    summary = {
        "event_count": len(events),
        "timeline_count": len(timeline),
        "fs": _count("fs_"),
        "net": _count("net_"),
        "proc": _count("proc_") + sum(1 for ev in events if str(ev.get("event", "")).startswith("exec")),
        "mprotect": sum(1 for ev in events if str(ev.get("event", "")) == "mprotect"),
        "policy": sum(1 for ev in events if str(ev.get("event", "")) in ("hard_kill","snapshot","timeout_halt","max_events_halt")),
        "drops": sum(1 for ev in events if str(ev.get("event", "")) in ("drop_mark", "exec_denied_drop")),
    }

    resp = {
        'report': report,
        'meta': meta,
        'summary': summary,
        'categorized_events': categorized,
        'timeline': timeline,
        'stages': stages,
        'stage_summaries': stage_summaries,
        'processes': processes,
        'process_tree': proc_tree,
        'artifacts': artifacts,
        'snapshots': snapshots,
        'sockmap': sockmap,
        'run_id': run_id,
    }

    if include_raw:
        resp["events_raw"] = events

    return jsonify(resp)


@app.route('/api/run/<run_id>/events')
def api_run_events(run_id):
    """Stream raw events.ndjson if available (fallback: report.json events as JSON)."""
    run_dir = RUNS_DIR / run_id
    nd = run_dir / "events.ndjson"
    if nd.exists():
        # Send as a file to keep it cheap (client can parse NDJSON progressively)
        return send_file(str(nd), mimetype="application/x-ndjson")
    rp = run_dir / "report.json"
    if rp.exists():
        report = _safe_read_json(rp, default={}) or {}
        return jsonify(report.get("events", []) or [])
    return jsonify({'error': 'Run not found'}), 404

@app.route('/api/run/<run_id>/artifact/<path:artifact_path>')
def api_download_artifact(run_id, artifact_path):
    """Download an artifact from a run"""
    run_dir = RUNS_DIR / run_id
    artifact_full_path = (run_dir / "fs" / artifact_path).resolve()

    # Path traversal guard
    fs_root = (run_dir / "fs").resolve()
    if not str(artifact_full_path).startswith(str(fs_root)):
        return jsonify({'error': 'Invalid path'}), 400
    
    if not artifact_full_path.exists() or not artifact_full_path.is_file():
        return jsonify({'error': 'Artifact not found'}), 404
    
    return send_file(artifact_full_path, as_attachment=True)


@app.route('/api/run/<run_id>/snapshot/<path:filename>')
def api_download_snapshot(run_id, filename):
    """Download snapshot/diagnostic files (dump_*) from a run."""
    run_dir = RUNS_DIR / run_id
    p = (run_dir / filename).resolve()
    if not str(p).startswith(str(run_dir.resolve())):
        return jsonify({'error': 'Invalid path'}), 400
    if not p.exists() or not p.is_file() or not p.name.startswith("dump_"):
        return jsonify({'error': 'Snapshot not found'}), 404
    return send_file(p, as_attachment=True)


@app.route('/api/upload', methods=['POST'])
def api_upload():
    """Upload a sample file"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Empty filename'}), 400
    
    filename = secure_filename(file.filename)
    filepath = app.config['UPLOAD_FOLDER'] / filename
    file.save(filepath)
    
    # Make executable
    os.chmod(filepath, 0o755)
    
    return jsonify({
        'success': True,
        'filename': filename,
        'path': str(filepath)
    })


@app.route('/api/execute', methods=['POST'])
def api_execute():
    """Execute a sample through softrxctl (preferred entrypoint).

    Expects JSON like:
      {
        sample_path, args:[], mode, timeout_ms, max_events,
        write_jail, quarantine_drops, interactive_fs,
        allow_dns, allow_dot, deny_unlisted,
        allowlist:["1.2.3.4:80"], net_cap_bytes, net_cap_ms, net_cap_sends,
        launcher, runs_dir
      }
    """
    data = request.json or {}
    sample_path = data.get('sample_path')
    timeout_ms = int(data.get('timeout_ms', data.get('timeout', 4.0) * 1000))
    max_events = int(data.get('max_events', 2000))
    mode = data.get('mode', 'malware')
    sample_args = data.get('args', []) or []

    write_jail = (data.get('write_jail') or '').strip()
    quarantine_drops = bool(data.get('quarantine_drops', True))
    interactive_fs = bool(data.get('interactive_fs', False))

    # Network knobs (optional)
    allow_dns = bool(data.get('allow_dns', True))
    allow_dot = bool(data.get('allow_dot', True))
    deny_unlisted = bool(data.get('deny_unlisted', False))
    allowlist = data.get('allowlist', []) or []
    net_cap_bytes = data.get('net_cap_bytes', None)
    net_cap_ms = data.get('net_cap_ms', None)
    net_cap_sends = data.get('net_cap_sends', None)

    launcher = (data.get('launcher') or str(ROOT / 'bin' / 'softrx_launcher')).strip()
    runs_dir = (data.get('runs_dir') or str(RUNS_DIR)).strip()

    if not sample_path:
        return jsonify({'success': False, 'error': 'No sample path provided'}), 400

    sample = Path(sample_path)
    if not sample.exists():
        return jsonify({'success': False, 'error': f'Sample not found: {sample_path}'}), 404

    cmd = [
        'python3', str(SOFTRXCTL),
        'run',
        '--json-out',
        '--launcher', launcher,
        '--runs-dir', runs_dir,
        '--timeout-ms', str(timeout_ms),
        '--max-events', str(max_events),
        '--mode', str(mode),
    ]

    if write_jail:
        cmd += ['--write-jail', write_jail]
    if quarantine_drops:
        cmd += ['--quarantine-drops']
    if interactive_fs:
        cmd += ['--interactive-fs']

    if allow_dns:
        cmd += ['--allow-dns']
    if allow_dot:
        cmd += ['--allow-dot']
    if deny_unlisted:
        cmd += ['--deny-unlisted']
    for a in (allowlist if isinstance(allowlist, list) else []):
        a = str(a).strip()
        if a:
            cmd += ['--allow', a]
    if net_cap_bytes not in (None, "", 0):
        cmd += ['--net-cap-bytes', str(int(net_cap_bytes))]
    if net_cap_ms not in (None, "", 0):
        cmd += ['--net-cap-ms', str(int(net_cap_ms))]
    if net_cap_sends not in (None, "", 0):
        cmd += ['--net-cap-sends', str(int(net_cap_sends))]

    cmd.append(str(sample))
    if sample_args:
        if isinstance(sample_args, str):
            cmd.extend([x for x in sample_args.split(" ") if x.strip()])
        else:
            cmd.extend([str(x) for x in sample_args])

    # Capture an initial snapshot so we can detect the new run deterministically.
    before = {p.name for p in Path(runs_dir).glob('run_*') if p.is_dir()}

    # Use Popen so we can kill the whole process group on timeout.
    stdout = ""
    stderr = ""
    rc = -1
    start_ts = time.time()

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True  # new process group
    )

    try:
        hard_timeout_s = max(2.0, (timeout_ms / 1000.0) + 2.0)
        stdout, stderr = proc.communicate(timeout=hard_timeout_s)
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        # Kill the whole group (proc is leader because start_new_session=True)
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

        try:
            stdout2, stderr2 = proc.communicate(timeout=1.0)
            stdout = (stdout or "") + (stdout2 or "")
            stderr = (stderr or "") + (stderr2 or "") + "\nlauncher_timeout: killed process group\n"
        except Exception:
            stderr = (stderr or "") + "\nlauncher_timeout: killed process group\n"
        rc = -9

    # Preferred: parse the final JSON line (from --json-out)
    combined = (stdout or "") + "\n" + (stderr or "")
    latest_run = None
    run_meta = None
    for line in (stdout or "").splitlines()[::-1]:
        line = line.strip()
        if not line:
            continue
        if line.startswith("{") and "run_id" in line and "outdir" in line:
            try:
                run_meta = json.loads(line)
                break
            except Exception:
                pass

    if run_meta and isinstance(run_meta, dict):
        candidate = Path(run_meta.get("outdir", ""))
        if candidate.exists() and candidate.is_dir():
            latest_run = candidate

    # Otherwise, detect the new run by comparing directory listings pre/post.
    runs_dir_p = Path(runs_dir)
    after = {p.name for p in runs_dir_p.glob('run_*') if p.is_dir()}
    new_runs = sorted(list(after - before))
    if latest_run is None and new_runs:
        latest_run = runs_dir_p / new_runs[-1]

    # Fallback: pick newest by mtime
    if latest_run is None:
        candidates = [p for p in runs_dir_p.glob('run_*') if p.is_dir()]
        if candidates:
            latest_run = max(candidates, key=lambda p: p.stat().st_mtime)

    elapsed = time.time() - start_ts

    payload = {
        'success': (latest_run is not None),
        'run_id': latest_run.name if latest_run is not None else None,
        'stdout': stdout or "",
        'stderr': stderr or "",
        'returncode': rc,
        'cmd': cmd,
        'elapsed_s': round(elapsed, 3),
    }

    if latest_run is None:
        payload['error'] = 'Run completed but no run directory was detected'
        payload['runs_dir'] = str(runs_dir)
        payload['runs_dir_listing'] = [p.name for p in sorted(Path(runs_dir).glob("run_*"))]

        # If softrxctl itself failed, signal that too
        if rc not in (0, None):
            payload['note'] = 'Non-zero return code from softrxctl; see stdout/stderr.'

        return jsonify(payload), 500

    return jsonify(payload)


@app.route('/api/samples')

def api_samples():
    """List available samples in uploads folder"""
    samples = []
    upload_dir = app.config['UPLOAD_FOLDER']
    
    if upload_dir.exists():
        for item in upload_dir.iterdir():
            if item.is_file():
                samples.append({
                    'name': item.name,
                    'path': str(item),
                    'size': item.stat().st_size,
                    'modified': datetime.fromtimestamp(item.stat().st_mtime).isoformat()
                })
    
    return jsonify(samples)


@app.route('/api/debug')
def api_debug():
    """Debug endpoint to check configuration"""
    return jsonify({
        'root': str(ROOT),
        'softrxctl': str(SOFTRXCTL),
        'softrxctl_exists': SOFTRXCTL.exists(),
        'runs_dir': str(RUNS_DIR),
        'runs_dir_exists': RUNS_DIR.exists(),
        'upload_folder': str(app.config['UPLOAD_FOLDER']),
        'run_count': len(list(RUNS_DIR.glob('run_*'))) if RUNS_DIR.exists() else 0
    })


@app.route('/api/run/<run_id>/delete', methods=['DELETE'])
def api_delete_run(run_id):
    """Delete a run"""
    run_dir = RUNS_DIR / run_id
    
    if not run_dir.exists():
        return jsonify({'error': 'Run not found'}), 404
    
    try:
        import shutil
        shutil.rmtree(run_dir)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':

    print(f"[SoftRX Web] ROOT: {ROOT}", file=sys.stderr)
    print(f"[SoftRX Web] SOFTRXCTL: {SOFTRXCTL}", file=sys.stderr)
    print(f"[SoftRX Web] RUNS_DIR: {RUNS_DIR}", file=sys.stderr)
    print(f"[SoftRX Web] SOFTRXCTL exists: {SOFTRXCTL.exists()}", file=sys.stderr)

    app.run(debug=True, host='0.0.0.0', port=5000)
