import json
from pathlib import Path
from typing import Any, Dict, List


def write_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=False), encoding="utf-8")


def write_markdown(path: Path, report: Dict[str, Any]) -> None:
    lines: List[str] = []
    lines.append("# SoftRX Report")
    lines.append("")
    lines.append(f"**Sample:** `{report.get('sample','')}`")
    lines.append(f"**Outdir:** `{report.get('outdir','')}`")
    lines.append(f"**Timestamp:** `{report.get('ts_start','')}` → `{report.get('ts_end','')}`")
    lines.append("")

    events = report.get("events", [])
    lines.append(f"## Events ({len(events)})")
    lines.append("")
    for ev in events:
        lines.append(f"- `{ev.get('ts','')}` **{ev.get('event','')}** (pid={ev.get('pid')}, sysnr={ev.get('sysnr', 'n/a')})")
        if "addr" in ev:
            lines.append(f"  - addr: `{ev.get('addr')}`")
        if "len" in ev:
            lines.append(f"  - len: `{ev.get('len')}`")
        if "prot" in ev:
            lines.append(f"  - prot: `{ev.get('prot')}`")
        if ev.get("dump"):
            lines.append(f"  - dump: `{ev.get('dump')}`")
    lines.append("")

    dumps = report.get("dumps", [])
    lines.append(f"## Dumps ({len(dumps)})")
    lines.append("")
    for d in dumps:
        lines.append(f"- `{d.get('path')}` (sha256={d.get('sha256')})")
    lines.append("")

    artifacts = report.get("artifacts", [])
    lines.append(f"## Extracted Strings ({len(artifacts)})")
    lines.append("")
    for a in artifacts:
        lines.append(f"### {a.get('file')}")
        lines.append(f"Count: {a.get('count')} (min_len={a.get('min_len')})")
        lines.append("")
        for s in a.get("strings", [])[:200]:
            lines.append(f"- {s}")
        if a.get("count", 0) > 200:
            lines.append(f"- ... ({a.get('count')-200} more)")
        lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")
