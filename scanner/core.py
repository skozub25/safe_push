import re
from dataclasses import dataclass
from .patterns import PATTERNS
from .entropy import shannon_entropy

SENSITIVE_HINTS = ["key", "secret", "token", "password", "jwt"]

@dataclass
class Finding:
    file: str
    line_no: int
    snippet: str
    reason: str

def _is_sensitive_context(line: str) -> bool:
    lower = line.lower()
    return any(h in lower for h in SENSITIVE_HINTS)

def _looks_like_secret(token: str) -> bool:
    return len(token) >= 24 and shannon_entropy(token) >= 4.0

def scan_line(file_path: str, line_no: int, line: str):
    """Scan a single added line and return any findings."""
    findings = []

    # 1) Known patterns
    for pat in PATTERNS:
        if pat.search(line):
            findings.append(Finding(
                file=file_path,
                line_no=line_no,
                snippet=line.strip(),
                reason="Matches known secret pattern",
            ))

    # 2) High-entropy candidates inside quotes (possible unknown secrets)
    for token in re.findall(r'["\']([A-Za-z0-9/+_=.-]{16,})["\']', line):
        if _is_sensitive_context(line) and _looks_like_secret(token):
            findings.append(Finding(
                file=file_path,
                line_no=line_no,
                snippet=line.strip(),
                reason="High-entropy value in sensitive context",
            ))

    return findings
