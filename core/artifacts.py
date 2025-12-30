import re
from pathlib import Path
from typing import List, Dict

ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")


def extract_ascii_strings(blob: bytes, min_len: int = 4) -> List[str]:
    """Extract printable ASCII strings from a binary blob."""
    out: List[str] = []
    for m in ASCII_RE.finditer(blob):
        s = m.group(0)
        if len(s) >= min_len:
            out.append(s.decode("utf-8", errors="ignore"))
    return out


def extract_strings_from_file(path: Path, min_len: int = 4, max_strings: int = 2000) -> Dict[str, List[str]]:
    """Extract strings from a dumped region file. Returns a dict for reporting."""
    blob = path.read_bytes()
    s = extract_ascii_strings(blob, min_len=min_len)
    if len(s) > max_strings:
        s = s[:max_strings]
    return {
        "file": str(path),
        "min_len": min_len,
        "count": len(s),
        "strings": s,
    }
