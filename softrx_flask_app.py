#!/usr/bin/env python3
"""SoftRX Web Interface - Flask Backend

This server intentionally stays thin:
- The authoritative run/metadata format is produced by softrxctl.py (report.json + events.ndjson).
- The UI is a single-page app (index.html) that talks to /api/* endpoints.
"""

from flask import Flask, request, jsonify, send_file
from pathlib import Path
import json
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
    """Get detailed information for a specific run"""
    run_dir = RUNS_DIR / run_id
    report_path = run_dir / "report.json"

    if not report_path.exists():
        return jsonify({'error': 'Run not found'}), 404

    report = _safe_read_json(report_path, default=None)
    if report is None:
        return jsonify({'error': 'Failed to parse report.json'}), 500

    meta = report.get("meta", {}) or {}
    events = report.get("events", []) or []
    categorized = parse_events(events)

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

    sockmap = None
    sockmap_path = run_dir / "dump_sockmap.json"
    if sockmap_path.exists():
        sockmap = _safe_read_json(sockmap_path, default=None)

    # Derived summary for quick UI badges
    def _count(prefix: str) -> int:
        return sum(1 for ev in events if str(ev.get("event", "")).startswith(prefix))

    summary = {
        "event_count": len(events),
        "fs": _count("fs_"),
        "net": _count("net_"),
        "proc": _count("proc_") + sum(1 for ev in events if str(ev.get("event","" )).startswith("exec")),
        "mprotect": sum(1 for ev in events if "mprotect" in str(ev.get("event", ""))),
        "policy": sum(1 for ev in events if str(ev.get("event", "")).startswith("tripwire") or str(ev.get("event", "")) in ("hard_kill","snapshot","timeout_halt","max_events_halt")),
        "drops": sum(1 for ev in events if str(ev.get("event", "")) in ("drop_mark", "exec_denied_drop")),
    }

    return jsonify({
        'report': report,
        'meta': meta,
        'categorized_events': categorized,
        'artifacts': artifacts,
        'snapshots': snapshots,
        'sockmap': sockmap,
        'summary': summary,
        'run_id': run_id,
    })


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

