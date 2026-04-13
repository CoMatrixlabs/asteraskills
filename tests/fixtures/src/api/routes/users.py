"""
Scenario 2 fixture: Python API route with intentional CWE-89 SQL injection taint chain.

Source: request.args.get("user_id")  — HTTP parameter (untrusted)
Sink:   cursor.execute(...)           — raw SQL query (CWE-89)
"""

from flask import request
import sqlite3


def get_user():
    # Source: untrusted HTTP parameter flows into user_id
    user_id = request.args.get("user_id")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # Sink: tainted user_id concatenated directly into SQL — CWE-89
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    return cursor.fetchone()


def list_users_by_role():
    # Second taint chain: role param passed to database query
    role = request.args.get("role")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, name FROM users WHERE role = '" + role + "'")
    return cursor.fetchall()
