# app/auth.py
import os, yaml, bcrypt

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_PATH = os.path.join(SCRIPT_DIR, "users.yaml")

def load_users():
    if not os.path.exists(USERS_PATH):
        return []
    with open(USERS_PATH, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return data.get("users", [])

def find_user(username: str):
    for u in load_users():
        if u.get("username") == username:
            return u
    return None

def verify_password(plain: str, hashed_bcrypt: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed_bcrypt.encode("utf-8"))
    except Exception:
        return False
