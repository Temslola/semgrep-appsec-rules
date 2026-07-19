"""
Test fixture for rules/python/mass-assignment-and-injection.yaml

Lines annotated "ruleid" must produce the named finding.
Lines annotated "ok" must NOT produce it.
"""

import os
import subprocess

from flask import request

ALLOWED_FIELDS = {"name", "email", "phone"}


class User:
    objects = None

    def __init__(self, **kwargs):
        pass


def get_db():
    ...


# ---------------------------------------------------------------- vulnerable

def create_user_splat():
    # ruleid: mass-assignment-from-request-body
    user = User(**request.get_json())
    return user


def create_user_form():
    # ruleid: mass-assignment-from-request-body
    return User(**request.form)


def update_user_setattr(user):
    # ruleid: setattr-loop-over-request-data
    for key, value in request.get_json().items():
        setattr(user, key, value)
    return user


def find_user_fstring(user_id):
    cursor = get_db().cursor()
    # ruleid: sql-query-string-interpolation
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()


def find_user_concat(name):
    cursor = get_db().cursor()
    # ruleid: sql-query-string-interpolation
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return cursor.fetchone()


def ping_host():
    host = request.args.get("host")
    # ruleid: os-command-from-request-input
    os.system(f"ping -c 1 {host}")


def run_report():
    name = request.args.get("name")
    # ruleid: os-command-from-request-input
    subprocess.run(f"generate-report {name}", shell=True)


# --------------------------------------------------------------------- safe

def create_user_allowlist():
    body = request.get_json()
    fields = {k: v for k, v in body.items() if k in ALLOWED_FIELDS}
    # ok: mass-assignment-from-request-body
    return User(**fields)


def update_user_allowlist(user):
    body = request.get_json()
    # ok: setattr-loop-over-request-data
    for key in ALLOWED_FIELDS:
        if key in body:
            setattr(user, key, body[key])
    return user


def find_user_parameterised(user_id):
    cursor = get_db().cursor()
    # ok: sql-query-string-interpolation
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    return cursor.fetchone()


def ping_host_safe():
    host = request.args.get("host")
    if host not in {"db1.internal", "db2.internal"}:
        raise ValueError("host not allowed")
    # ok: os-command-from-request-input
    subprocess.run(["ping", "-c", "1", host], check=True)
