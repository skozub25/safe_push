# tests/test_config_integration.py
"""
Tests for Stage 1 config behavior:
- ignore_paths
- ignore_lines_with
- ignore_patterns
- allowlist_hashes (literal + sha256)
 
These are *integration-style* tests:
they verify how scan_line + scanner.config interact,
without touching provider-specific regex tests or entropy math.
"""

import hashlib
import pytest

from scanner import config as cfg
from scanner.config import SafePushConfig
from scanner.core import scan_line


@pytest.fixture(autouse=True)
def reset_config():
    """
    Automatically run before & after each test.

    We temporarily replace cfg._CONFIG with a custom SafePushConfig
    and then restore the original after each test.

    This avoids depending on whatever .safepush.yml the repo may have,
    and keeps tests isolated + deterministic.
    """
    original = cfg._CONFIG
    yield
    cfg._CONFIG = original


def make_findings(file_path: str, line: str):
    """
    Helper to call scan_line with a fake file/line number.
    We only care about whether findings are produced or suppressed.
    """
    return scan_line(file_path, 10, line)


def test_ignore_paths_skips_entire_file():
    """
    If a file path matches ignore_paths, scan_line should return no findings
    even if the content looks like a real secret.
    """
    cfg._CONFIG = SafePushConfig(
        ignore_paths=["ignored_dir/**"]
    )

    line = 'API_KEY = "AKIA_TEST_NOT_REAL"'
    findings = make_findings("ignored_dir/secrets.py", line)

    assert findings == []  # file-level ignore wins


def test_ignore_lines_with_marker_skips_line():
    """
    Lines containing any of ignore_lines_with markers should be skipped.
    This is our inline 'escape hatch', e.g. '# safepush: ignore'.
    """
    cfg._CONFIG = SafePushConfig(
        ignore_lines_with=["# safepush: ignore"]
    )

    line = 'API_KEY = "AKIA_TEST_NOT_REAL"  # safepush: ignore'
    findings = make_findings("app/config.py", line)

    assert findings == []  # inline marker suppresses finding


def test_ignore_patterns_suppresses_matching_lines():
    """
    ignore_patterns entries are treated as regexes.
    If a line matches any of them, findings should be suppressed.
    """
    cfg._CONFIG = SafePushConfig(
        ignore_patterns=[r"AKIA_TEST_NOT_REAL"]
    )

    # This would normally match the AWS pattern, but is ignored by config.
    line = 'API_KEY = "AKIA_TEST_NOT_REAL"'
    findings = make_findings("app/config.py", line)

    assert findings == []


def test_allowlist_literal_token_suppresses_specific_secret():
    """
    allowlist_hashes supports literal token entries (no 'sha256:' prefix).
    If the matched token exactly equals an allowlisted value,
    it should NOT be reported, even if it matches a known pattern.
    """
    allowlisted = "AKIA_TEST_NOT_REAL"

    cfg._CONFIG = SafePushConfig(
        allowlist_hashes=[allowlisted]
    )

    line = f'API_KEY = "{allowlisted}"'
    findings = make_findings("app/config.py", line)

    assert findings == []  # this exact token is globally allowlisted


def test_allowlist_sha256_suppresses_specific_secret_anywhere():
    """
    allowlist_hashes also supports entries of the form 'sha256:<hex>'.

    This lets us allowlist a specific secret value by hash, regardless of
    where it appears, without storing the raw value in config.
    """
    token = "sk_live_TEST_NOT_REAL"
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()

    cfg._CONFIG = SafePushConfig(
        allowlist_hashes=[f"sha256:{token_hash}"]
    )

    line = f'STRIPE_SECRET = "{token}"'
    findings = make_findings("payments/keys.py", line)

    assert findings == []  # hashed allowlist prevents this from being flagged
