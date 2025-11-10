import re

PATTERNS = [
    re.compile(r'AKIA[0-9A-Z]{16}'),                 # AWS access key ID
    re.compile(r'-----BEGIN (RSA|EC) PRIVATE KEY-----'),
    re.compile(r'sk_live_[0-9a-zA-Z]{24,}'),         # Stripe secret-style
]
