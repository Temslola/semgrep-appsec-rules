"""
Test fixture for rules/python/jwt-insecure-verification.yaml

Lines annotated "ruleid" must produce the named finding.
Lines annotated "ok" must NOT produce it.

Run with:  semgrep --test --config rules/ tests/
"""

import jwt

SECRET = "load-me-from-the-environment"
PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----..."


# ---------------------------------------------------------------- vulnerable

def read_token_verification_off(token):
    # ruleid: jwt-verification-disabled
    return jwt.decode(token, SECRET, verify=False)


def read_token_options_off(token):
    # ruleid: jwt-verification-disabled
    return jwt.decode(token, SECRET, options={"verify_signature": False})


def read_token_skip_expiry(token):
    # ruleid: jwt-verification-disabled
    return jwt.decode(token, SECRET, algorithms=["HS256"], options={"verify_exp": False})


def read_token_none_allowed(token):
    # ruleid: jwt-none-algorithm-accepted
    return jwt.decode(token, SECRET, algorithms=["HS256", "none"])


def read_token_no_key(token):
    # ruleid: jwt-decoded-without-key
    return jwt.decode(token)


# --------------------------------------------------------------------- safe

def read_token_hmac(token):
    # ok: jwt-verification-disabled
    return jwt.decode(token, SECRET, algorithms=["HS256"])


def read_token_rsa(token):
    # ok: jwt-none-algorithm-accepted
    return jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])


def read_token_with_audience(token):
    # ok: jwt-verification-disabled
    return jwt.decode(
        token,
        PUBLIC_KEY,
        algorithms=["RS256"],
        audience="api://orders",
        options={"verify_signature": True, "verify_exp": True},
    )


def documentation_string():
    """A docstring mentioning verify=False must not trigger the rule."""
    # ok: jwt-verification-disabled
    note = "never call jwt.decode with verify=False in production"
    return note
