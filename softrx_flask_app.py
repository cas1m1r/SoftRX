#!/usr/bin/env python3
"""SoftRX Web Interface - Flask Backend"""

from flask import Flask, render_template, request, jsonify, send_file
from pathlib import Path
import json
import subprocess
import time
from datetime import datetime
from werkzeug.utils import secure_filename
import os

# The UI template is a single HTML file checked into the repo. To avoid forcing a
# separate `templates/` directory layout, point Flask's template folder at this
# script's directory.
app = Flask(__name__, template_folder=str(Path(__file__).resolve().parent))
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size
app.config['UPLOAD_FOLDER'] = Path(__file__).parent / 'uploads'
app.config['UPLOAD_FOLDER'].mkdir(exist_ok=True)

ROOT =Path(__file__).resolve().parent
SOFTRXCTL = Path(os.path.join(os.getcwd(),"softrxctl.py"))
RUNS_DIR = Path(os.path.join(os.getcwd(),"softrx_runs"))


def get_all_runs():
    """Get all run directories sorted by timestamp (newest first)"""
    if not RUNS_DIR.exists():
        return []
    
    runs = []
    for run_dir in RUNS_DIR.glob("run_*"):
        if not run_dir.is_dir():
            continue
        
        report_path = run_dir / "report.json"
        if not report_path.exists():
            continue
        
        try:
            with open(report_path) as f:
                report = json.load(f)
            
            runs.append({
                'id': run_dir.name,
                'path': str(run_dir),
                'sample': report.get('sample', 'unknown'),
                'timestamp': report.get('ts_start', ''),
                'duration': report.get('duration_s', 0),
                'returncode': report.get('returncode', -1),
                'event_count': len(report.get('events', []))
            })
        except Exception:
            continue
    
    runs.sort(key=lambda x: x['timestamp'], reverse=True)
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
    """Execute a sample with SoftRX"""
    data = request.json
    sample_path = data.get('sample_path')
    timeout = data.get('timeout', 4.0)
    max_events = data.get('max_events', 200)
    mode = data.get('mode', 'malware')
    sample_args = data.get('args', [])
    allow_dns = bool(data.get('allow_dns', False))
    
    if not sample_path:
        return jsonify({'error': 'No sample path provided'}), 400
    
    sample = Path(sample_path)
    if not sample.exists():
        return jsonify({'error': 'Sample not found'}), 404
    
    # Build command
    cmd = [
        str(SOFTRXCTL),
        str(sample),
        '--timeout', str(timeout),
        '--max-events', str(max_events),
        '--mode', mode
    ]
    
    if sample_args:
        cmd.extend(['--'] + sample_args)
    
    try:
        env = os.environ.copy()
        if allow_dns:
            env['SOFTRX_ALLOW_DNS'] = '1'

        # Run the sandbox
        result = subprocess.run(
            cmd,
            cwd=str(ROOT),
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout + 5  # Add buffer to prevent timeout race
        )
        
        # Find the latest run
        runs = get_all_runs()
        if runs:
            latest_run = runs[0]
            return jsonify({
                'success': True,
                'run_id': latest_run['id'],
                'stdout': result.stdout,
                'stderr': result.stderr
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Run completed but no output found',
                'stdout': result.stdout,
                'stderr': result.stderr
            })
    
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Execution timeout'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


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
    app.run(debug=True, host='0.0.0.0', port=5000)
