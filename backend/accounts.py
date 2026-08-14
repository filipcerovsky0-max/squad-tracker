"""
Account system for Squad Tracker: guest or registered users, manual
email+password registration with Resend verification codes, Google OAuth
login, persistent cookie sessions ("remember me"), profile picture upload,
and the admin panel.

Admin rights are bound to a single, hardcoded email address (ADMIN_EMAIL)
rather than a database flag. This is deliberate: a database row can be
edited by a bug, a migration, or an attacker with DB access, but this
constant can only change by editing and redeploying the source code.
"""
import contextlib
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
import urllib.parse
from pathlib import Path

from aiohttp import web, ClientSession

ADMIN_EMAIL = "squad.tracker.support@gmail.com"

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "https://squad-tracker.site")
GOOGLE_REDIRECT_URI = f"{PUBLIC_BASE_URL}/auth/google/callback"

RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
RESEND_FROM = os.environ.get("RESEND_FROM", "Squad Tracker <onboarding@resend.dev>")

SESSION_COOKIE_NAME = "sq_session"
SESSION_TTL_SECONDS = 60 * 60 * 24 * 90  # 90 days - "remember me" auto-login
VERIFICATION_CODE_TTL_SECONDS = 15 * 60
VERIFICATION_MAX_ATTEMPTS = 6
PBKDF2_ITERATIONS = 100_000
MAX_AVATAR_BYTES = 900_000  # ~ generous cap for a compressed JPEG profile picture

DB_PATH: Path | None = None
AVATAR_DIR: Path | None = None


def init(db_path: Path, avatar_dir: Path):
    global DB_PATH, AVATAR_DIR
    DB_PATH = db_path
    AVATAR_DIR = avatar_dir
    AVATAR_DIR.mkdir(parents=True, exist_ok=True)
    with _db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            username TEXT NOT NULL,
            password_salt TEXT,
            password_hash TEXT,
            google_sub TEXT UNIQUE,
            avatar_path TEXT,
            email_verified INTEGER DEFAULT 0,
            created_ts REAL
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS email_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            code TEXT NOT NULL,
            attempts INTEGER DEFAULT 0,
            expires_ts REAL NOT NULL
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_ts REAL,
            expires_ts REAL
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS oauth_states (
            state TEXT PRIMARY KEY,
            created_ts REAL
        )""")


@contextlib.contextmanager
def _db():
    """Always closes the connection, even if the caller's code raises
    (e.g. a UNIQUE constraint violation) - a bare conn.close() at the end of
    a function is skipped on exception, which was leaving connections open
    and locking the database for everyone else."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


# ---------- passwords ----------

def hash_password(password: str, salt: bytes | None = None) -> dict:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return {"salt": salt.hex(), "hash": digest.hex()}


def verify_password(password: str, salt_hex: str, hash_hex: str) -> bool:
    if not salt_hex or not hash_hex:
        return False
    candidate = hash_password(password, bytes.fromhex(salt_hex))
    return hmac.compare_digest(candidate["hash"], hash_hex)


# ---------- users ----------

def get_user_by_email(email: str):
    with _db() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email.lower().strip(),)).fetchone()
        return dict(row) if row else None


def get_user_by_id(user_id: int):
    with _db() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None


def get_user_by_google_sub(sub: str):
    with _db() as conn:
        row = conn.execute("SELECT * FROM users WHERE google_sub = ?", (sub,)).fetchone()
        return dict(row) if row else None


def create_user_manual(email: str, username: str, password: str) -> int:
    hashed = hash_password(password)
    with _db() as conn:
        cur = conn.execute(
            "INSERT INTO users (email, username, password_salt, password_hash, email_verified, created_ts) "
            "VALUES (?, ?, ?, ?, 0, ?)",
            (email.lower().strip(), username[:32], hashed["salt"], hashed["hash"], time.time()),
        )
        return cur.lastrowid


def create_user_google(email: str, username: str, google_sub: str, avatar_path: str | None) -> int:
    with _db() as conn:
        cur = conn.execute(
            "INSERT INTO users (email, username, google_sub, avatar_path, email_verified, created_ts) "
            "VALUES (?, ?, ?, ?, 1, ?)",
            (email.lower().strip(), username[:32], google_sub, avatar_path, time.time()),
        )
        return cur.lastrowid


def set_email_verified(user_id: int):
    with _db() as conn:
        conn.execute("UPDATE users SET email_verified = 1 WHERE id = ?", (user_id,))


def update_avatar(user_id: int, avatar_path: str):
    with _db() as conn:
        conn.execute("UPDATE users SET avatar_path = ? WHERE id = ?", (avatar_path, user_id))


def update_username(user_id: int, new_username: str):
    with _db() as conn:
        conn.execute("UPDATE users SET username = ? WHERE id = ?", (new_username[:32], user_id))


def update_password(user_id: int, new_password: str):
    hashed = hash_password(new_password)
    with _db() as conn:
        conn.execute(
            "UPDATE users SET password_salt = ?, password_hash = ? WHERE id = ?",
            (hashed["salt"], hashed["hash"], user_id),
        )


def delete_user_account(user_id: int):
    with _db() as conn:
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM email_codes WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))


def is_admin_email(email: str) -> bool:
    return bool(email) and email.lower().strip() == ADMIN_EMAIL


# ---------- email verification codes (sent via Resend) ----------

def create_verification_code(user_id: int) -> str:
    code = f"{secrets.randbelow(1_000_000):06d}"
    with _db() as conn:
        conn.execute("DELETE FROM email_codes WHERE user_id = ?", (user_id,))  # only one active code at a time
        conn.execute(
            "INSERT INTO email_codes (user_id, code, attempts, expires_ts) VALUES (?, ?, 0, ?)",
            (user_id, code, time.time() + VERIFICATION_CODE_TTL_SECONDS),
        )
    return code


def check_verification_code(user_id: int, submitted_code: str) -> str:
    """Returns 'ok', 'expired', 'too_many_attempts', or 'wrong'."""
    with _db() as conn:
        row = conn.execute("SELECT * FROM email_codes WHERE user_id = ?", (user_id,)).fetchone()
        if not row:
            return "expired"
        if time.time() > row["expires_ts"]:
            conn.execute("DELETE FROM email_codes WHERE user_id = ?", (user_id,))
            return "expired"
        if row["attempts"] >= VERIFICATION_MAX_ATTEMPTS:
            return "too_many_attempts"
        if hmac.compare_digest(row["code"], submitted_code.strip()):
            conn.execute("DELETE FROM email_codes WHERE user_id = ?", (user_id,))
            return "ok"
        conn.execute("UPDATE email_codes SET attempts = attempts + 1 WHERE user_id = ?", (user_id,))
        return "wrong"


async def send_verification_email(email: str, code: str) -> bool:
    if not RESEND_API_KEY:
        return False
    try:
        async with ClientSession() as session:
            async with session.post(
                "https://api.resend.com/emails",
                headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"},
                json={
                    "from": RESEND_FROM,
                    "to": [email],
                    "subject": f"Squad Tracker - overovaci kod {code}",
                    "html": (
                        f"<p>Tvuj overovaci kod pro Squad Tracker:</p>"
                        f"<p style='font-size:28px;font-weight:bold;letter-spacing:4px'>{code}</p>"
                        f"<p>Kod plati 15 minut.</p>"
                    ),
                },
            ) as resp:
                return resp.status < 300
    except Exception:
        return False


# ---------- sessions (cookie-based "remember me") ----------

def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    now = time.time()
    with _db() as conn:
        conn.execute(
            "INSERT INTO sessions (token, user_id, created_ts, expires_ts) VALUES (?, ?, ?, ?)",
            (token, user_id, now, now + SESSION_TTL_SECONDS),
        )
    return token


def get_user_from_session(token: str):
    if not token:
        return None
    with _db() as conn:
        row = conn.execute(
            "SELECT sessions.user_id, sessions.expires_ts, users.* FROM sessions "
            "JOIN users ON users.id = sessions.user_id WHERE sessions.token = ?",
            (token,),
        ).fetchone()
        if not row or time.time() > row["expires_ts"]:
            return None
        return dict(row)


def destroy_session(token: str):
    with _db() as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))


def set_session_cookie(response: web.StreamResponse, token: str):
    response.set_cookie(
        SESSION_COOKIE_NAME, token, max_age=SESSION_TTL_SECONDS,
        httponly=True, secure=True, samesite="Lax", path="/",
    )


def clear_session_cookie(response: web.StreamResponse):
    response.del_cookie(SESSION_COOKIE_NAME, path="/")


# ---------- Google OAuth (authorization code flow) ----------

def google_login_url() -> tuple[str, str]:
    """Returns (redirect_url, state) - the state must be stored (e.g. in a
    short-lived cookie) and checked again on callback to prevent CSRF."""
    state = secrets.token_urlsafe(24)
    with _db() as conn:
        conn.execute("DELETE FROM oauth_states WHERE created_ts < ?", (time.time() - 600,))  # prune old
        conn.execute("INSERT INTO oauth_states (state, created_ts) VALUES (?, ?)", (state, time.time()))
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "prompt": "select_account",
    }
    return "https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode(params), state


def consume_oauth_state(state: str) -> bool:
    with _db() as conn:
        row = conn.execute("SELECT state FROM oauth_states WHERE state = ?", (state,)).fetchone()
        if row:
            conn.execute("DELETE FROM oauth_states WHERE state = ?", (state,))
        return bool(row)


async def exchange_google_code(code: str) -> dict | None:
    """Exchanges an OAuth code for tokens, then fetches the user's profile.
    Returns {"email","sub","name","picture"} or None on any failure."""
    try:
        async with ClientSession() as session:
            async with session.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "code": code,
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "redirect_uri": GOOGLE_REDIRECT_URI,
                    "grant_type": "authorization_code",
                },
            ) as resp:
                if resp.status >= 300:
                    return None
                token_data = await resp.json()
            access_token = token_data.get("access_token")
            if not access_token:
                return None
            async with session.get(
                "https://www.googleapis.com/oauth2/v3/userinfo",
                headers={"Authorization": f"Bearer {access_token}"},
            ) as resp:
                if resp.status >= 300:
                    return None
                info = await resp.json()
                return {
                    "email": info.get("email"),
                    "sub": info.get("sub"),
                    "name": info.get("name") or (info.get("email", "").split("@")[0]),
                    "picture": info.get("picture"),
                }
    except Exception:
        return None


# ---------- avatar upload ----------

def save_avatar(user_id: int, image_bytes: bytes) -> str:
    """Stores a profile picture on disk and returns its public URL path."""
    filename = f"{user_id}-{secrets.token_hex(6)}.jpg"
    (AVATAR_DIR / filename).write_bytes(image_bytes)
    return f"/avatars/{filename}"


# ---------- HTTP route handlers ----------
# `srv` is the server.py module, passed in to give admin routes access to the
# live in-memory room state without a circular import.

def _get_session_token(request) -> str:
    return request.cookies.get(SESSION_COOKIE_NAME, "")


def current_user(request):
    return get_user_from_session(_get_session_token(request))


async def handle_register(request):
    data = await request.json()
    email = str(data.get("email", "")).strip().lower()[:120]
    username = str(data.get("username", "")).strip()[:32]
    password = str(data.get("password", ""))
    if not email or "@" not in email or not username or len(password) < 8:
        return web.json_response({"error": "invalid_input"}, status=400)
    if get_user_by_email(email):
        return web.json_response({"error": "email_taken"}, status=409)
    user_id = create_user_manual(email, username, password)
    code = create_verification_code(user_id)
    sent = await send_verification_email(email, code)
    return web.json_response({"ok": True, "user_id": user_id, "email_sent": sent})


async def handle_verify_email(request):
    data = await request.json()
    user_id = data.get("user_id")
    code = str(data.get("code", ""))
    if not isinstance(user_id, int):
        return web.json_response({"error": "invalid_input"}, status=400)
    result = check_verification_code(user_id, code)
    if result != "ok":
        return web.json_response({"error": result}, status=400)
    set_email_verified(user_id)
    user = get_user_by_id(user_id)
    token = create_session(user_id)
    resp = web.json_response({"ok": True, "username": user["username"], "avatar": user["avatar_path"]})
    set_session_cookie(resp, token)
    return resp


async def handle_resend_code(request):
    data = await request.json()
    user_id = data.get("user_id")
    user = get_user_by_id(user_id) if isinstance(user_id, int) else None
    if not user:
        return web.json_response({"error": "not_found"}, status=404)
    code = create_verification_code(user_id)
    sent = await send_verification_email(user["email"], code)
    return web.json_response({"ok": True, "email_sent": sent})


async def handle_login(request):
    data = await request.json()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    user = get_user_by_email(email)
    if not user or not user["password_hash"]:
        return web.json_response({"error": "invalid_credentials"}, status=401)
    if not verify_password(password, user["password_salt"], user["password_hash"]):
        return web.json_response({"error": "invalid_credentials"}, status=401)
    if not user["email_verified"]:
        return web.json_response({"error": "not_verified", "user_id": user["id"]}, status=403)
    token = create_session(user["id"])
    resp = web.json_response({
        "ok": True, "username": user["username"], "avatar": user["avatar_path"],
        "is_admin": is_admin_email(user["email"]),
    })
    set_session_cookie(resp, token)
    return resp


async def handle_logout(request):
    token = _get_session_token(request)
    if token:
        destroy_session(token)
    resp = web.json_response({"ok": True})
    clear_session_cookie(resp)
    return resp


async def handle_me(request):
    user = current_user(request)
    if not user:
        return web.json_response({"logged_in": False})
    return web.json_response({
        "logged_in": True, "username": user["username"], "email": user["email"],
        "avatar": user["avatar_path"], "is_admin": is_admin_email(user["email"]),
    })


async def handle_google_login(request):
    url, _state = google_login_url()
    raise web.HTTPFound(url)


async def handle_google_callback(request):
    code = request.query.get("code")
    state = request.query.get("state")
    if not code or not state or not consume_oauth_state(state):
        return web.Response(text="Invalid or expired login attempt. Please try again.", status=400)
    profile = await exchange_google_code(code)
    if not profile or not profile.get("email"):
        return web.Response(text="Google login failed. Please try again.", status=400)

    user = get_user_by_google_sub(profile["sub"]) or get_user_by_email(profile["email"])
    if not user:
        avatar_path = None
        user_id = create_user_google(profile["email"], profile["name"], profile["sub"], avatar_path)
        user = get_user_by_id(user_id)
    token = create_session(user["id"])
    resp = web.HTTPFound("/")
    set_session_cookie(resp, token)
    return resp


async def handle_avatar_upload(request):
    user = current_user(request)
    if not user:
        return web.json_response({"error": "not_logged_in"}, status=401)
    reader = await request.multipart()
    field = await reader.next()
    if field is None or field.name != "avatar":
        return web.json_response({"error": "missing_file"}, status=400)
    image_bytes = await field.read(decode=True)
    if len(image_bytes) > MAX_AVATAR_BYTES:
        return web.json_response({"error": "too_large"}, status=413)
    avatar_url = save_avatar(user["id"], image_bytes)
    update_avatar(user["id"], avatar_url)
    return web.json_response({"ok": True, "avatar": avatar_url})


async def handle_change_username(request):
    user = current_user(request)
    if not user:
        return web.json_response({"error": "not_logged_in"}, status=401)
    data = await request.json()
    new_username = str(data.get("username", "")).strip()
    if not (1 <= len(new_username) <= 32):
        return web.json_response({"error": "invalid_username"}, status=400)
    update_username(user["id"], new_username)
    return web.json_response({"ok": True, "username": new_username})


async def handle_change_password(request):
    user = current_user(request)
    if not user:
        return web.json_response({"error": "not_logged_in"}, status=401)
    data = await request.json()
    new_password = str(data.get("new_password", ""))
    if len(new_password) < 8:
        return web.json_response({"error": "password_too_short"}, status=400)
    # If the account already has a password set (manual signup, or a Google
    # account that later added one), the current password must be confirmed
    # before it can be changed. Pure Google-only accounts (no password yet)
    # can set an initial one without this check - there is nothing to confirm.
    if user["password_hash"]:
        current_password = str(data.get("current_password", ""))
        if not verify_password(current_password, user["password_salt"], user["password_hash"]):
            return web.json_response({"error": "wrong_current_password"}, status=403)
    update_password(user["id"], new_password)
    return web.json_response({"ok": True})


async def handle_delete_account(request):
    user = current_user(request)
    if not user:
        return web.json_response({"error": "not_logged_in"}, status=401)
    data = await request.json()
    if user["password_hash"]:
        password = str(data.get("password", ""))
        if not verify_password(password, user["password_salt"], user["password_hash"]):
            return web.json_response({"error": "wrong_password"}, status=403)
    delete_user_account(user["id"])
    resp = web.json_response({"ok": True})
    clear_session_cookie(resp)
    return resp


# ---------- admin panel ----------

def require_admin(request):
    user = current_user(request)
    if not user or not is_admin_email(user["email"]):
        return None
    return user


async def handle_admin_rooms(request, srv):
    if not require_admin(request):
        return web.json_response({"error": "forbidden"}, status=403)
    rooms_payload = []
    for room_id, members in srv.rooms.items():
        rooms_payload.append({
            "room_id": room_id,
            "member_count": len(members),
            "usernames": [m["username"] for m in members.values()],
            "has_password": bool(srv.room_passwords.get(room_id)),
            "message_count": srv.room_msg_count.get(room_id, 0),
            "has_active_poll": bool(srv.room_polls.get(room_id)),
            "waypoint_count": len(srv.room_waypoints.get(room_id, [])),
        })
    return web.json_response({"rooms": rooms_payload})


async def handle_admin_close_room(request, srv):
    if not require_admin(request):
        return web.json_response({"error": "forbidden"}, status=403)
    room_id = request.match_info["room_id"]
    room = srv.rooms.get(room_id, {})
    for entry in list(room.values()):
        try:
            await entry["ws"].send_str(json.dumps({"type": "kicked"}))
            await entry["ws"].close()
        except Exception:
            pass
    srv.rooms.pop(room_id, None)
    srv._clear_room_state(room_id)
    return web.json_response({"ok": True})


async def handle_admin_kick_user(request, srv):
    if not require_admin(request):
        return web.json_response({"error": "forbidden"}, status=403)
    room_id = request.match_info["room_id"]
    target_username = request.match_info["username"]
    room = srv.rooms.get(room_id, {})
    targets = [mid for mid, e in room.items() if e["username"] == target_username]
    for target_id in targets:
        entry = room[target_id]
        try:
            await entry["ws"].send_str(json.dumps({"type": "kicked"}))
            await entry["ws"].close()
        except Exception:
            pass
        room.pop(target_id, None)
    return web.json_response({"ok": True, "kicked": len(targets)})


def register_routes(app: web.Application, srv):
    app.router.add_post("/auth/register", handle_register)
    app.router.add_post("/auth/verify", handle_verify_email)
    app.router.add_post("/auth/resend-code", handle_resend_code)
    app.router.add_post("/auth/login", handle_login)
    app.router.add_post("/auth/logout", handle_logout)
    app.router.add_get("/auth/me", handle_me)
    app.router.add_get("/auth/google/login", handle_google_login)
    app.router.add_get("/auth/google/callback", handle_google_callback)
    app.router.add_post("/auth/avatar", handle_avatar_upload)
    app.router.add_post("/auth/change-username", handle_change_username)
    app.router.add_post("/auth/change-password", handle_change_password)
    app.router.add_post("/auth/delete-account", handle_delete_account)
    app.router.add_static("/avatars", AVATAR_DIR, show_index=False)
    app.router.add_get("/admin/api/rooms", lambda r: handle_admin_rooms(r, srv))
    app.router.add_post("/admin/api/rooms/{room_id}/close", lambda r: handle_admin_close_room(r, srv))
    app.router.add_post("/admin/api/rooms/{room_id}/kick/{username}", lambda r: handle_admin_kick_user(r, srv))