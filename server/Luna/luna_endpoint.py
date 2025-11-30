import os
import json
import time
import base64
import uuid
from functools import wraps
from flask import Flask, request, jsonify, abort, send_file
import jwt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


import helper


JWT_SECRET = os.environ.get("JWT_SECRET", "dev-jwt-secret-change-me")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXP_SECONDS = int(os.environ.get("ACCESS_TOKEN_EXP_SECONDS", 15 * 60))
REFRESH_TOKEN_EXP_SECONDS = int(os.environ.get("REFRESH_TOKEN_EXP_SECONDS", 7 * 24 * 3600))

MASTER_CODE = os.environ.get("MASTER_CODE", "change-me")

AES_KEY_B64 = os.environ.get("AES_KEY_B64") 
DATA_FILE = os.environ.get("DATA_FILE", "data.json.aes")

if AES_KEY_B64 is None:
    print("WARNING: AES_KEY_B64 not set. Generating a temporary key (save this for persistent storage).")
    generated = base64.urlsafe_b64encode(os.urandom(32)).decode()
    print("Generated AES_KEY_B64 (save this to AES_KEY_B64 env var):", generated)
    AES_KEY_B64 = generated

try:
    AES_KEY = base64.urlsafe_b64decode(AES_KEY_B64)
except Exception as e:
    raise RuntimeError("AES_KEY_B64 must be a urlsafe-base64 encoded 32-byte key") from e

if len(AES_KEY) != 32:
    raise RuntimeError("Decoded AES key length must be 32 bytes (AES-256)")

aesgcm = AESGCM(AES_KEY)

def save_data(data: dict):
    """
    Encrypts JSON-serialized 'data' and writes to DATA_FILE as: nonce(12) || ciphertext+tag
    """
    plaintext = json.dumps(data).encode()
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    with open(DATA_FILE, "wb") as f:
        f.write(nonce + ciphertext)


def load_data() -> dict:
    """
    Reads DATA_FILE, decrypts and returns dict; returns {} if file missing or on decryption error.
    """
    if not os.path.exists(DATA_FILE):
        return {}
    with open(DATA_FILE, "rb") as f:
        raw = f.read()
    if len(raw) < 12:
        return {}
    nonce = raw[:12]
    ciphertext = raw[12:]
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
        return json.loads(plaintext.decode())
    except Exception:
        return {}

def create_token(subject: str, expiry_seconds: int, extra_claims: dict = None):
    now = int(time.time())
    jti = str(uuid.uuid4())
    payload = {
        "sub": subject,
        "iat": now,
        "exp": now + expiry_seconds,
        "jti": jti,
    }
    if extra_claims:
        payload.update(extra_claims)
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    if isinstance(token, bytes):
        token = token.decode()
    return token, payload


def decode_token(token: str, verify_exp: bool = True):
    options = {"verify_exp": verify_exp}
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM], options=options)
        return payload
    except jwt.ExpiredSignatureError:
        abort(401, description="Token expired")
    except jwt.InvalidTokenError:
        abort(401, description="Invalid token")


app = Flask(__name__)

def token_required(fn):
    """
    Decorator that requires a valid access token (Bearer).
    Verifies token signature and 'verified' claim.
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Missing Authorization Bearer token"}), 401
        token = auth.split(" ", 1)[1].strip()
        payload = decode_token(token)  # checks signature and expiry
        # require 'verified' claim in token
        if not payload.get("verified"):
            return jsonify({"error": "Not verified"}), 403
        request.user = payload.get("sub")
        request.token_jti = payload.get("jti")
        return fn(*args, **kwargs)
    return wrapper


@app.route("/auth", methods=["POST"])
def auth():
    """
    Exchange master code for access + refresh tokens.
    Request body: JSON { "code": "..." } (also supports form-data)
    Response: { access_token, refresh_token, access_expires_in, refresh_expires_in }
    """
    if request.is_json:
        code = request.json.get("code")
    else:
        code = request.form.get("code")

    if code is None:
        return jsonify({"error": "Missing code"}), 400

    if code != MASTER_CODE:
        return jsonify({"error": "Invalid code"}), 403

    subject = request.remote_addr or "unknown"  # replace with username/ID if you have one

    # Create access token (short-lived)
    access_token, access_payload = create_token(subject, ACCESS_TOKEN_EXP_SECONDS, extra_claims={"verified": True})

    # Create refresh token (longer lived). We'll store the refresh token jti server-side for revocation.
    refresh_token, refresh_payload = create_token(subject, REFRESH_TOKEN_EXP_SECONDS, extra_claims={"type": "refresh"})

    # Persist refresh token jti in encrypted storage (simple revocation/rotation store)
    data = load_data()
    # structure: data["refresh_tokens"] = { subject: { jti: {issued_at, expires_at}}}
    refresh_store = data.get("refresh_tokens", {})
    subj_store = refresh_store.get(subject, {})
    subj_store[refresh_payload["jti"]] = {
        "issued_at": refresh_payload["iat"],
        "expires_at": refresh_payload["exp"]
    }
    refresh_store[subject] = subj_store
    data["refresh_tokens"] = refresh_store
    save_data(data)

    return jsonify({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "access_expires_in": ACCESS_TOKEN_EXP_SECONDS,
        "refresh_expires_in": REFRESH_TOKEN_EXP_SECONDS
    }), 200

@app.route("/refresh", methods=["POST"])
def refresh():
    """
    Exchange a valid refresh token for a new access token.
    Send JSON { "refresh_token": "..." } or form-data.
    """
    if request.is_json:
        refresh_token = request.json.get("refresh_token")
    else:
        refresh_token = request.form.get("refresh_token")

    if not refresh_token:
        return jsonify({"error": "Missing refresh_token"}), 400

    payload = decode_token(refresh_token)

    if payload.get("type") != "refresh":
        return jsonify({"error": "Not a refresh token"}), 400

    subject = payload.get("sub")
    jti = payload.get("jti")

    data = load_data()
    refresh_store = data.get("refresh_tokens", {})
    subj_store = refresh_store.get(subject, {})

    entry = subj_store.get(jti)
    if not entry:
        return jsonify({"error": "Refresh token revoked or unknown"}), 401

    access_token, access_payload = create_token(subject, ACCESS_TOKEN_EXP_SECONDS, extra_claims={"verified": True})

    return jsonify({
        "access_token": access_token,
        "access_expires_in": ACCESS_TOKEN_EXP_SECONDS
    }), 200


@app.route("/logout", methods=["POST"])
def logout():
    """
    Revoke a refresh token. Client sends { refresh_token: "..." }.
    This deletes the refresh token jti from the server store so it cannot be used again.
    """
    if request.is_json:
        refresh_token = request.json.get("refresh_token")
    else:
        refresh_token = request.form.get("refresh_token")

    if not refresh_token:
        return jsonify({"error": "Missing refresh_token"}), 400

    payload = decode_token(refresh_token)
    if payload.get("type") != "refresh":
        return jsonify({"error": "Not a refresh token"}), 400

    subject = payload.get("sub")
    jti = payload.get("jti")

    data = load_data()
    refresh_store = data.get("refresh_tokens", {})
    subj_store = refresh_store.get(subject, {})

    if jti in subj_store:
        del subj_store[jti]
        refresh_store[subject] = subj_store
        data["refresh_tokens"] = refresh_store
        save_data(data)
        return jsonify({"message": "Refresh token revoked"}), 200

    return jsonify({"error": "Refresh token not found"}), 400

@app.route('/luna/clients')
@token_required
def luna_endpoint():
    with open("clients.json", 'r') as f:
        dat = json.dump(f)
    return jsonify(dat)

@app.route('/luna/icarus')
@token_required
def luna_endpoint2():
    client = request.json.get('client_num')
    path = fr"C\clients\icarus\{client}"
    retur_val = helper.tree_to_dict(path)
    return jsonify(retur_val)

@app.route('/luna/icarus/get')
@token_required
def luna_endpoint3():
    client = request.json.get('client_num')
    file = request.json.get('file_path')
    name = request.json.get('file_name')
    send_file(file, as_attachment=True, attachment_filename=name)

@app.route('/luna/icarus/control')
@token_required
def luna_endpoint3():
    pass


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
