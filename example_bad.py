"""
Example: AI-generated code with common hallucination and security issues.

This file intentionally contains problems that the review pipeline catches.
Run: python -m src.pipeline.review_pipeline examples/example_bad.py
"""

# Issue 1: Hardcoded secret
api_key = "sk-1234567890abcdef"  # noqa: S106

# Issue 2: Nonexistent stdlib function
import os
result = os.makedirs_recursive("/tmp/test")  # os.makedirs_recursive doesn't exist

# Issue 3: SQL injection via % formatting
def get_user(cursor, username):
    cursor.execute("SELECT * FROM users WHERE username = '%s'" % username)
    return cursor.fetchone()

# Issue 4: Bare except swallowing errors
def parse_number(s):
    try:
        return int(s)
    except:
        pass  # silently returns None

# Issue 5: N+1 query pattern
def get_all_user_orders(user_ids, db):
    orders = []
    for uid in user_ids:
        # Separate DB call per user — should use WHERE user_id IN (...)
        user_orders = db.query("SELECT * FROM orders WHERE user_id = ?", uid)
        orders.extend(user_orders)
    return orders

# Issue 6: Missing return annotation with no return statement
def compute_total(items: list) -> float:
    total = sum(item["price"] for item in items)
    # oops, forgot to return

# Issue 7: subprocess with shell=True
import subprocess
def list_files(directory):
    subprocess.run(f"ls {directory}", shell=True)

# Issue 8: pickle.loads on user data
import pickle
def deserialize(data):
    return pickle.loads(data)  # arbitrary code execution
