#!/usr/bin/env python3
"""SoftRX Web Interface - Flask Backend"""

from flask import Flask, render_template, request, jsonify, send_file
from pathlib import Path
import json
import subprocess
import time
import sys
from datetime import datetime
from werkzeug.utils import secure_filename
import os, re

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size
app.config['UPLOAD_FOLDER'] = Path(__file__).parent / 'uploads'
app.config['UPLOAD_FOLDER'].mkdir(exist_ok=True)

# ROOT = Path(os.path.split(Path(__file__).resolve())[0])
ROOT = Path(__file__).resolve().parent   # if softrx_flask_app.py is in repo root

SOFTRXCTL = ROOT / "softrxctl.py"
RUNS_DIR = ROOT / "softrx_runs"
UPLOADS_DIR = ROOT / "uploads"
SAMPLES_DIR = UPLOADS_DIR / "ex"   # adjust to your actual layout

# Ensure runs directory exists
RUNS_DIR.mkdir(exist_ok=True)


def get_all_runs():
    runs = []
    if not RUNS_DIR.exists():
        print(f"[runs] RUNS_DIR missing: {RUNS_DIR}")
        return runs

    for run_dir in RUNS_DIR.glob("run_*"):
        if not run_dir.is_dir():
            continue

        report_json = run_dir / "report.json"
        events_ndjson = run_dir / "events.ndjson"

        # Accept either format
        if report_json.exists():
            try:
                report = json.loads(report_json.read_text())
                runs.append({
                    "id": run_dir.name,
                    "path": str(run_dir),
                    "sample": report.get("sample", "unknown"),
                    "timestamp": report.get("ts_start", ""),
                    "duration": report.get("duration_s", 0),
                    "returncode": report.get("returncode", -1),
                    "event_count": len(report.get("events", [])),
                })
            except Exception as e:
                print(f"[runs] failed to read {report_json}: {e}")
            continue

        if events_ndjson.exists():
            # Minimal metadata if report.json wasn't created
            try:
                with open(events_ndjson, "r", errors="replace") as f:
                    event_count = sum(1 for _ in f)

                runs.append({
                    "id": run_dir.name,
                    "path": str(run_dir),
                    "sample": "unknown",
                    "timestamp": run_dir.name.replace("run_", ""),
                    "duration": 0,
                    "returncode": 0,
                    "event_count": event_count,
                })
            except Exception as e:
                print(f"[runs] failed to read {events_ndjson}: {e}")

    runs.sort(key=lambda x: x["timestamp"], reverse=True)
    return runs


def parse_events(events):
    """Parse and categorize events for frontend display"""
    categories = {
        'filesystem': [],
        'network': [],
        'process': [],
        'memory': [],
        'other': []
    }
    
    for event in events:
        event_type = event.get('event', '')
        
        if 'fs_' in event_type or 'open' in event_type or 'unlink' in event_type:
            categories['filesystem'].append(event)
        elif 'net_' in event_type or 'socket' in event_type or 'connect' in event_type:
            categories['network'].append(event)
        elif 'exec' in event_type or 'fork' in event_type or 'proc_' in event_type:
            categories['process'].append(event)
        elif 'mprotect' in event_type:
            categories['memory'].append(event)
        else:
            categories['other'].append(event)
    
    return categories


@app.route('/')
def index():
    """Main dashboard"""
    return render_template('index.html')


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
    
    try:
        with open(report_path) as f:
            report = json.load(f)
        
        # Parse events by category
        events = report.get('events', [])
        categorized = parse_events(events)
        
        # Check for artifacts in fs folder
        fs_dir = run_dir / "fs"
        artifacts = []
        if fs_dir.exists():
            for item in fs_dir.rglob('*'):
                if item.is_file():
                    artifacts.append({
                        'name': item.name,
                        'path': str(item.relative_to(fs_dir)),
                        'size': item.stat().st_size
                    })
        
        return jsonify({
            'report': report,
            'categorized_events': categorized,
            'artifacts': artifacts,
            'run_id': run_id
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/run/<run_id>/artifact/<path:artifact_path>')
def api_download_artifact(run_id, artifact_path):
    """Download an artifact from a run"""
    run_dir = RUNS_DIR / run_id
    artifact_full_path = run_dir / "fs" / artifact_path
    
    if not artifact_full_path.exists() or not artifact_full_path.is_file():
        return jsonify({'error': 'Artifact not found'}), 404
    
    return send_file(artifact_full_path, as_attachment=True)


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
    # Execute a sample through softrxctl and return the newest run id + logs.
    data = request.json or {}
    sample_path = data.get('sample_path')
    timeout = float(data.get('timeout', 4.0))
    max_events = int(data.get('max_events', 200))
    mode = data.get('mode', 'malware')
    sample_args = data.get('args', []) or []

    if not sample_path:
        return jsonify({'success': False, 'error': 'No sample path provided'}), 400

    sample = Path(sample_path)
    if not sample.exists():
        return jsonify({'success': False, 'error': f'Sample not found: {sample_path}'}), 404

    cmd = [
        'python3', str(SOFTRXCTL),
        str(sample),
        '--runs-dir', str(RUNS_DIR),
        '--timeout', str(timeout),
        '--max-events', str(max_events),
        '--mode', str(mode),
    ]

    # IMPORTANT: only append args if softrxctl expects them as passthrough
    if sample_args:
        # Allow either a list of strings or a single string
        if isinstance(sample_args, str):
            cmd.extend([sample_args])
        else:
            cmd.extend([str(x) for x in sample_args])

    # Capture an initial snapshot so we can detect the new run deterministically.
    before = {p.name for p in RUNS_DIR.glob('run_*') if p.is_dir()}

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
        stdout, stderr = proc.communicate(timeout=timeout + 1.0)  # slight cushion
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

    combined = (stdout or "") + "\n" + (stderr or "")

    # Best-effort: try to parse a printed run_dir marker from softrxctl output.
    latest_run = None
    m = re.search(r"\[SoftRX\]\s*run_dir\s*=\s*(.+)", combined)
    if m:
        candidate = Path(m.group(1).strip())
        if candidate.exists() and candidate.is_dir():
            latest_run = candidate

    # Otherwise, detect the new run by comparing directory listings pre/post.
    after = {p.name for p in RUNS_DIR.glob('run_*') if p.is_dir()}
    new_runs = sorted(list(after - before))
    if latest_run is None and new_runs:
        latest_run = RUNS_DIR / new_runs[-1]

    # Fallback: pick newest by mtime
    if latest_run is None:
        candidates = [p for p in RUNS_DIR.glob('run_*') if p.is_dir()]
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
        payload['runs_dir'] = str(RUNS_DIR)
        payload['runs_dir_listing'] = [p.name for p in sorted(RUNS_DIR.glob("run_*"))]

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

