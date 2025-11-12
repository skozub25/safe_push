# tests/test_patterns_provider_tokens.py

import re
from scanner.patterns import PATTERNS

def _has_match(regex: str, text: str) -> bool:
    pattern = re.compile(regex)
    return bool(pattern.search(text))

def test_aws_access_key_pattern_matches_valid_and_rejects_invalid():
    aws_re = r'AKIA[0-9A-Z]{16}'
    assert _has_match(aws_re, 'AKIA_TEST_NOT_REAL')
    assert not _has_match(aws_re, 'AKIA123')                 # too short
    assert not _has_match(aws_re, 'akia1234567890ABCDE1')    # lowercase

def test_rsa_private_key_header_pattern_matches_only_rsa_ec():
    pem_re = r'-----BEGIN (RSA|EC) PRIVATE KEY-----'
    assert _has_match(pem_re, '-----BEGIN RSA PRIVATE KEY-----')
    assert _has_match(pem_re, '-----BEGIN EC PRIVATE KEY-----')
    assert not _has_match(pem_re, '-----BEGIN PRIVATE KEY-----')

def test_stripe_live_key_pattern_matches_valid():
    stripe_re = r'sk_live_[0-9a-zA-Z]{24,}'
    assert _has_match(stripe_re, 'sk_live_TEST_NOT_REAL')
    assert not _has_match(stripe_re, 'sk_live_short')

def test_core_patterns_are_present_in_PATTERNS():
    sources = {p.pattern for p in PATTERNS}

    assert r'AKIA[0-9A-Z]{16}' in sources
    assert r'-----BEGIN (RSA|EC) PRIVATE KEY-----' in sources
    assert r'sk_live_[0-9a-zA-Z]{24,}' in sources
