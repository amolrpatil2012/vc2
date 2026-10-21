"""
DELIBERATELY VULNERABLE DEMO APP - FOR GITHUB ADVANCED SECURITY DEMOS ONLY.
Never deploy this. Every issue below is intentional.
"""
import hashlib
import os
import pickle
import random
import sqlite3
import subprocess
import sys
import base64
import yaml
import jwt
from flask import Flask, request, jsonify, make_response, send_file
from Crypto.Cipher import DES

app = Flask(__name__)

# Vulnerability 2 / 20: Hardcoded credentials (CWE-798)
ADMIN_USER = "admin"
ADMIN_PASSWORD = "SuperSecret123!"
DB_PASSWORD = "P@ssw0rd_prod_db"

# Vulnerability 14: Hardcoded encryption key (CWE-321)
ENCRYPTION_KEY = b"8bytekey"

# Vulnerability 17: Weak JWT secret (CWE-798 / CWE-347)
JWT_SECRET = "secret"

DB_PATH = "demo.db"


def get_db():
    return sqlite3.connect(DB_PATH)


def init_db():
    db = get_db()
    db.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)")
    db.execute("CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY, owner TEXT, item TEXT, card TEXT)")
    db.commit()


# ---------------------------------------------------------------------------
# Vulnerability 16: Weak password hashing - unsalted MD5 (CWE-327 / CWE-328)
# ---------------------------------------------------------------------------
def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"]
    password = request.form["password"]
    db = get_db()
    # Vulnerability 7 / 21: SQL injection - string formatting (CWE-89)
    db.execute(
        "INSERT INTO users (username, password, role) VALUES ('%s', '%s', 'user')"
        % (username, hash_password(password))
    )
    db.commit()
    return jsonify(status="registered")


# ---------------------------------------------------------------------------
# Vulnerability 19: No rate limiting on login (CWE-307)
# Vulnerability 7 / 21: SQL injection (CWE-89)
# Vulnerability 17: Insecure JWT (CWE-347)
# ---------------------------------------------------------------------------
@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    db = get_db()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{hash_password(password)}'"
    user = db.execute(query).fetchone()
    if user:
        token = jwt.encode({"user": username, "role": user[3]}, JWT_SECRET, algorithm="HS256")
        return jsonify(token=token)
    return jsonify(error="invalid credentials"), 401


def current_user():
    token = request.headers.get("Authorization", "")
    # Insecure JWT: signature verification disabled
    return jwt.decode(token, options={"verify_signature": False}, algorithms=["HS256", "none"])


# ---------------------------------------------------------------------------
# Vulnerability 3: Insecure Direct Object Reference (CWE-639)
# ---------------------------------------------------------------------------
@app.route("/api/orders/<int:order_id>")
def get_order(order_id):
    db = get_db()
    # No check that the order belongs to the logged-in user
    row = db.execute("SELECT * FROM orders WHERE id = %d" % order_id).fetchone()
    return jsonify(order=row)


# ---------------------------------------------------------------------------
# Vulnerability 21: No input sanitization for DB queries (CWE-89)
# ---------------------------------------------------------------------------
@app.route("/search")
def search():
    term = request.args.get("q", "")
    db = get_db()
    rows = db.execute("SELECT * FROM orders WHERE item LIKE '%" + term + "%'").fetchall()
    return jsonify(results=rows)


# ---------------------------------------------------------------------------
# Vulnerability 9: Reflected XSS (CWE-79)
# ---------------------------------------------------------------------------
@app.route("/hello")
def hello():
    name = request.args.get("name", "guest")
    return f"<html><body><h1>Welcome, {name}!</h1></body></html>"


@app.route("/comment", methods=["POST"])
def comment():
    text = request.form["text"]
    resp = make_response("<div class='comment'>" + text + "</div>")
    return resp


# ---------------------------------------------------------------------------
# Vulnerability 5: Insecure deserialization (CWE-502)
# ---------------------------------------------------------------------------
@app.route("/load-session", methods=["POST"])
def load_session():
    data = base64.b64decode(request.form["session"])
    session = pickle.loads(data)  # arbitrary object deserialization
    return jsonify(session=str(session))


@app.route("/load-config", methods=["POST"])
def load_config():
    cfg = yaml.load(request.data)  # unsafe YAML load
    return jsonify(config=str(cfg))


# ---------------------------------------------------------------------------
# Vulnerability 6 / 14: Weak cryptography + hardcoded key (CWE-327 / CWE-321)
# ---------------------------------------------------------------------------
def encrypt_card(card_number: str) -> bytes:
    cipher = DES.new(ENCRYPTION_KEY, DES.MODE_ECB)  # DES + ECB
    padded = card_number.ljust(16)
    return cipher.encrypt(padded.encode())


# ---------------------------------------------------------------------------
# Vulnerability 11: Insecure random number generation (CWE-338)
# ---------------------------------------------------------------------------
def generate_reset_token() -> str:
    return str(random.randint(100000, 999999))


@app.route("/reset-password", methods=["POST"])
def reset_password():
    return jsonify(token=generate_reset_token())


# ---------------------------------------------------------------------------
# Vulnerability 13: Insecure file operations (CWE-22 / CWE-377 / CWE-732)
# ---------------------------------------------------------------------------
@app.route("/download")
def download():
    filename = request.args.get("file")
    return send_file(os.path.join("/var/app/uploads", filename))  # path traversal


@app.route("/upload", methods=["POST"])
def upload():
    f = request.files["file"]
    path = "/tmp/" + f.filename  # untrusted filename
    f.save(path)
    os.chmod(path, 0o777)  # world-writable
    return jsonify(saved=path)


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # Command injection (CWE-78)
    return subprocess.check_output("ping -c 1 " + host, shell=True)


# ---------------------------------------------------------------------------
# Vulnerability 10: Insecure parsing of command line arguments (CWE-78)
# ---------------------------------------------------------------------------
def run_cli():
    if len(sys.argv) > 1 and sys.argv[1] == "backup":
        target = sys.argv[2]
        os.system("tar -czf /backups/backup.tar.gz " + target)  # unsanitised argv -> shell


# ---------------------------------------------------------------------------
# Vulnerability 20: No TLS, debug mode, bound to all interfaces (CWE-319 / CWE-489)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    run_cli()
    app.run(host="0.0.0.0", port=5000, debug=True)
