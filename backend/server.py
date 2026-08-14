"""
Squad Tracker - backend server
aiohttp app: servi static frontend + WebSocket na jedne portu.
Room management, presence broadcast, Haversine geofencing, SQLite history, heartbeat.

Members are keyed by a unique per-connection id (not username), so two people
picking the same display name can never overwrite each other's connection.
"""
import asyncio
import hashlib
import hmac
import itertools
import json
import math
import os
import secrets
import sqlite3
import sys
import time
from pathlib import Path

from aiohttp import web, WSMsgType
from pywebpush import webpush, WebPushException
import accounts

BASE_DIR = Path(__file__).parent
FRONTEND_DIR = BASE_DIR.parent / "frontend"
DATA_DIR = Path(os.environ.get("DATA_DIR", str(BASE_DIR)))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "history.db"

RATE_LIMIT_SECONDS = 3
GEOFENCE_METERS = 50
HEARTBEAT_INTERVAL = 15
HEARTBEAT_TIMEOUT = 40
MAX_CHAT_CHARS = 500
MAX_VOICE_B64_CHARS = 2_000_000   # ~1.5MB raw audio, generous for a short PTT clip
MAX_IMAGE_B64_CHARS = 1_000_000   # ~750KB raw image, enough for a compressed photo
MAX_REPLY_CHARS = 120
TYPING_THROTTLE_SECONDS = 2
MAX_SPEED_MPS = 15  # ~54 km/h; faster deltas are treated as GPS noise, not real movement
ADMIN_KEY = os.environ.get("ADMIN_KEY", "")

# ---- Web Push (VAPID) ----
# Generate a keypair once (see deployment notes) and set these as Railway env vars.
# Without them, push notifications are silently disabled (no crash).
VAPID_PRIVATE_KEY = os.environ.get("VAPID_PRIVATE_KEY", "")
VAPID_PUBLIC_KEY = os.environ.get("VAPID_PUBLIC_KEY", "")
VAPID_CLAIMS_SUB = os.environ.get("VAPID_CLAIMS_SUB", "mailto:admin@squad-tracker.site")
PUSH_ENABLED = bool(VAPID_PRIVATE_KEY and VAPID_PUBLIC_KEY)

# ---- abuse / DoS protections ----
MAX_ROOM_ID_LEN = 64
MAX_ROOMS = 500
MAX_MEMBERS_PER_ROOM = 60
CHAT_MIN_INTERVAL = 0.4          # per-member: max ~2-3 chat/voice/pin actions per second
VOICE_MIN_INTERVAL = 1.0
PIN_MIN_INTERVAL = 1.0
KICK_MIN_INTERVAL = 1.0
WS_MAX_MSG_BYTES = 3_000_000      # hard cap on a single raw WS frame, before any JSON parsing
MAX_FAILED_JOINS = 8              # per IP, within the window below
FAILED_JOIN_WINDOW_S = 60
PASSWORD_SALT_BYTES = 16
PBKDF2_ITERATIONS = 100_000

_id_counter = itertools.count(1)

# rooms[room_id] = { member_id: { "ws", "username", "lat", "lng", "battery", "color",
#                                  "last_location_ts", "last_seen", "prev_lat", "prev_lng",
#                                  "prev_ts", "speed_mps", "distance_m", "last_typing_ts" } }
rooms: dict[str, dict[int, dict]] = {}

# room_passwords[room_id] = sha256 hex digest, or None if the room has no password.
room_passwords: dict[str, str | None] = {}

# room_chat_history[room_id] = list of the last MAX_CHAT_HISTORY chat messages.
room_chat_history: dict[str, list[dict]] = {}
MAX_CHAT_HISTORY = 50

# room_pins[room_id] = {"lat","lng","by","ts"} or None.
room_pins: dict[str, dict | None] = {}

# room_polls[room_id] = {"question","options":[...],"votes":{member_id:idx},"by","ts"} or None.
# One active poll per room at a time (same simple pattern as the meet-here pin).
room_polls: dict[str, dict | None] = {}
MAX_POLL_OPTIONS = 5
MAX_POLL_QUESTION_CHARS = 120
MAX_POLL_OPTION_CHARS = 40

# room_waypoints[room_id] = ordered list of {"id","lat","lng","label","by","ts"}.
# A multi-stop route the whole group can see, distinct from the single "meet here" pin.
room_waypoints: dict[str, list[dict]] = {}
MAX_WAYPOINTS = 10
MAX_WAYPOINT_LABEL_CHARS = 40
_waypoint_id_counter = itertools.count(1)

# room_owners[room_id] = member_id of whoever created the room (or the longest-present
# remaining member if the original creator left). Owners can kick and change the password.
room_owners: dict[str, int] = {}

# room_msg_count[room_id] = total chat messages sent in this room's lifetime (session-scoped).
room_msg_count: dict[str, int] = {}

SERVER_START_TS = time.time()


def _clear_room_state(room_id: str):
    room_passwords.pop(room_id, None)
    room_chat_history.pop(room_id, None)
    room_pins.pop(room_id, None)
    room_polls.pop(room_id, None)
    room_waypoints.pop(room_id, None)
    room_owners.pop(room_id, None)
    room_msg_count.pop(room_id, None)


def _hash_password(password: str, salt: bytes | None = None) -> dict:
    salt = salt or secrets.token_bytes(PASSWORD_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return {"salt": salt.hex(), "hash": digest.hex()}


def _verify_password(password: str, stored: dict) -> bool:
    if not stored:
        return False
    salt = bytes.fromhex(stored["salt"])
    candidate = _hash_password(password, salt)
    return hmac.compare_digest(candidate["hash"], stored["hash"])


# failed_joins[(ip, room_id)] = list of failure timestamps within the last
# FAILED_JOIN_WINDOW_S, used to throttle password brute-forcing of one specific
# room without penalizing that IP for joining other, unrelated rooms.
failed_joins: dict[tuple, list[float]] = {}


def _too_many_failed_joins(key: tuple) -> bool:
    now = time.time()
    attempts = [t for t in failed_joins.get(key, []) if now - t < FAILED_JOIN_WINDOW_S]
    failed_joins[key] = attempts
    return len(attempts) >= MAX_FAILED_JOINS


def _record_failed_join(key: tuple):
    failed_joins.setdefault(key, []).append(time.time())


async def broadcast_to_room(room_id, msg: dict, exclude: int | None = None):
    room = rooms.get(room_id)
    if not room:
        return
    data = json.dumps(msg)
    dead = []
    for member_id, entry in room.items():
        if member_id == exclude:
            continue
        try:
            await entry["ws"].send_str(data)
        except ConnectionResetError:
            dead.append(member_id)
    for member_id in dead:
        room.pop(member_id, None)


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            room TEXT,
            user TEXT,
            lat REAL,
            lng REAL
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS push_subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            p256dh TEXT NOT NULL,
            auth TEXT NOT NULL,
            created_ts REAL,
            UNIQUE(room_id, device_id)
        )"""
    )
    conn.commit()
    conn.close()


def save_history(room, user, lat, lng):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO history (timestamp, room, user, lat, lng) VALUES (?, ?, ?, ?, ?)",
        (time.time(), room, user, lat, lng),
    )
    conn.commit()
    conn.close()


def save_push_subscription(room_id, device_id, endpoint, p256dh, auth):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """INSERT INTO push_subscriptions (room_id, device_id, endpoint, p256dh, auth, created_ts)
           VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT(room_id, device_id) DO UPDATE SET endpoint=excluded.endpoint,
               p256dh=excluded.p256dh, auth=excluded.auth, created_ts=excluded.created_ts""",
        (room_id, device_id, endpoint, p256dh, auth, time.time()),
    )
    conn.commit()
    conn.close()


def delete_push_subscription(room_id, device_id):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM push_subscriptions WHERE room_id=? AND device_id=?", (room_id, device_id))
    conn.commit()
    conn.close()


def delete_push_subscription_by_endpoint(endpoint):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM push_subscriptions WHERE endpoint=?", (endpoint,))
    conn.commit()
    conn.close()


def get_push_subscriptions(room_id, exclude_device_id=None):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT device_id, endpoint, p256dh, auth FROM push_subscriptions WHERE room_id=?", (room_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows if r["device_id"] != exclude_device_id]


def _send_single_push(sub, title, body):
    try:
        webpush(
            subscription_info={
                "endpoint": sub["endpoint"],
                "keys": {"p256dh": sub["p256dh"], "auth": sub["auth"]},
            },
            data=json.dumps({"title": title, "body": body}),
            vapid_private_key=VAPID_PRIVATE_KEY,
            vapid_claims={"sub": VAPID_CLAIMS_SUB},
        )
    except WebPushException as e:
        status = getattr(e.response, "status_code", None)
        if status in (404, 410):
            delete_push_subscription_by_endpoint(sub["endpoint"])
    except Exception:
        pass  # never let a push delivery failure affect the live WS session


async def send_push_to_room(room_id, title, body, exclude_device_id=None):
    if not PUSH_ENABLED:
        return
    subs = get_push_subscriptions(room_id, exclude_device_id)
    if not subs:
        return
    loop = asyncio.get_event_loop()
    for sub in subs:
        loop.run_in_executor(None, _send_single_push, sub, title, body)


async def send_push_to_device(room_id, device_id, title, body):
    if not PUSH_ENABLED or not device_id:
        return
    subs = [s for s in get_push_subscriptions(room_id) if s["device_id"] == device_id]
    if not subs:
        return
    loop = asyncio.get_event_loop()
    for sub in subs:
        loop.run_in_executor(None, _send_single_push, sub, title, body)


def haversine(lat1, lng1, lat2, lng2):
    R = 6371000  # metres
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lng2 - lng1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return 2 * R * math.asin(math.sqrt(a))


async def broadcast_presence(room_id):
    room = rooms.get(room_id)
    if not room:
        return
    now = time.time()
    owner_id = room_owners.get(room_id)
    users_payload = [
        {
            "username": data["username"],
            "lat": data["lat"],
            "lng": data["lng"],
            "battery": data.get("battery"),
            "color": data.get("color"),
            "avatar": data.get("avatar"),
            "vehicle": data.get("vehicle"),
            "age_s": round(now - data["last_location_ts"]) if data["last_location_ts"] else None,
            "speed_mps": data.get("speed_mps"),
            "distance_m": round(data.get("distance_m", 0)),
            "is_owner": member_id == owner_id,
        }
        for member_id, data in room.items()
        if data["lat"] is not None
    ]
    msg = json.dumps({"type": "presence", "users": users_payload})
    dead = []
    for member_id, data in room.items():
        try:
            await data["ws"].send_str(msg)
        except ConnectionResetError:
            dead.append(member_id)
    for member_id in dead:
        room.pop(member_id, None)


async def check_geofence(room_id, moved_id):
    room = rooms.get(room_id)
    if not room:
        return
    moved = room.get(moved_id)
    if not moved or moved["lat"] is None:
        return
    for member_id, data in room.items():
        if member_id == moved_id or data["lat"] is None:
            continue
        dist = haversine(moved["lat"], moved["lng"], data["lat"], data["lng"])
        if dist < GEOFENCE_METERS:
            alert = json.dumps(
                {"type": "proximity_alert", "with": data["username"], "distance_m": round(dist, 1)}
            )
            other_alert = json.dumps(
                {"type": "proximity_alert", "with": moved["username"], "distance_m": round(dist, 1)}
            )
            try:
                await moved["ws"].send_str(alert)
                await data["ws"].send_str(other_alert)
            except ConnectionResetError:
                pass
            asyncio.create_task(send_push_to_device(
                room_id, moved.get("device_id"), "Squad Tracker",
                f"{data['username']} is nearby ({round(dist)}m)"
            ))
            asyncio.create_task(send_push_to_device(
                room_id, data.get("device_id"), "Squad Tracker",
                f"{moved['username']} is nearby ({round(dist)}m)"
            ))


def _promote_new_owner(room_id):
    """If the room has no owner (creator left), hand ownership to whoever has
    been present the longest among the remaining members."""
    room = rooms.get(room_id)
    if not room:
        return
    if room_owners.get(room_id) not in room:
        first_member_id = next(iter(room))
        room_owners[room_id] = first_member_id


def _poll_payload(room_id: str) -> dict:
    """Builds the public poll broadcast: question/options plus a live vote
    tally per option, without exposing who voted for what."""
    poll = room_polls.get(room_id)
    if not poll:
        return {}
    counts = [0] * len(poll["options"])
    for option_idx in poll["votes"].values():
        if 0 <= option_idx < len(counts):
            counts[option_idx] += 1
    return {
        "question": poll["question"],
        "options": poll["options"],
        "counts": counts,
        "total_votes": len(poll["votes"]),
        "by": poll["by"],
    }


async def websocket_handler(request):
    ws = web.WebSocketResponse(heartbeat=HEARTBEAT_INTERVAL, max_msg_size=WS_MAX_MSG_BYTES)
    await ws.prepare(request)
    client_ip = request.remote or "unknown"

    room_id = None
    member_id = None

    try:
        async for msg in ws:
            if msg.type != WSMsgType.TEXT:
                continue
            try:
                data = json.loads(msg.data)
            except json.JSONDecodeError:
                continue

            mtype = data.get("type")

            if mtype == "join":
                candidate_room_id = str(data.get("room", "default"))[:MAX_ROOM_ID_LEN].strip()
                if not candidate_room_id:
                    candidate_room_id = "default"
                candidate_username = str(data.get("username", "anon"))[:32].strip() or "anon"
                provided_password = str(data.get("password") or "")
                color = data.get("color")
                if not isinstance(color, str) or not color.startswith("#") or len(color) not in (4, 7):
                    color = None
                avatar = data.get("avatar")
                if not isinstance(avatar, str) or not avatar.startswith("/avatars/") or len(avatar) > 128:
                    avatar = None
                device_id = data.get("device_id")
                device_id = str(device_id)[:64] if device_id else None

                room_is_new = candidate_room_id not in rooms
                if room_is_new:
                    if len(rooms) >= MAX_ROOMS:
                        await ws.send_str(json.dumps({"type": "join_error", "reason": "server_full"}))
                        continue
                    room_passwords[candidate_room_id] = (
                        _hash_password(provided_password) if provided_password else None
                    )
                else:
                    if len(rooms[candidate_room_id]) >= MAX_MEMBERS_PER_ROOM:
                        await ws.send_str(json.dumps({"type": "join_error", "reason": "room_full"}))
                        continue
                    required = room_passwords.get(candidate_room_id)
                    if required:
                        throttle_key = (client_ip, candidate_room_id)
                        if _too_many_failed_joins(throttle_key):
                            await ws.send_str(json.dumps({"type": "join_error", "reason": "rate_limited"}))
                            continue
                        if not _verify_password(provided_password, required):
                            _record_failed_join(throttle_key)
                            await ws.send_str(json.dumps({"type": "join_error", "reason": "password"}))
                            continue

                room_id = candidate_room_id
                username = candidate_username
                member_id = next(_id_counter)
                rooms.setdefault(room_id, {})
                rooms[room_id][member_id] = {
                    "ws": ws,
                    "username": username,
                    "lat": None,
                    "lng": None,
                    "color": color,
                    "avatar": avatar,
                    "vehicle": None,
                    "last_location_ts": 0,
                    "last_seen": time.time(),
                    "prev_lat": None,
                    "prev_lng": None,
                    "prev_ts": None,
                    "speed_mps": None,
                    "distance_m": 0.0,
                    "last_typing_ts": 0,
                    "last_chat_ts": 0,
                    "last_voice_ts": 0,
                    "last_pin_ts": 0,
                    "last_kick_ts": 0,
                    "device_id": device_id,
                }
                if room_is_new:
                    room_owners[room_id] = member_id
                    room_msg_count[room_id] = 0
                else:
                    _promote_new_owner(room_id)

                await ws.send_str(json.dumps({
                    "type": "joined", "room": room_id, "username": username,
                    "is_owner": room_owners.get(room_id) == member_id,
                }))
                if room_chat_history.get(room_id):
                    await ws.send_str(json.dumps({"type": "chat_history", "messages": room_chat_history[room_id]}))
                if room_pins.get(room_id):
                    await ws.send_str(json.dumps({"type": "pin", **room_pins[room_id]}))
                if room_polls.get(room_id):
                    await ws.send_str(json.dumps({"type": "poll", **_poll_payload(room_id)}))
                if room_waypoints.get(room_id):
                    await ws.send_str(json.dumps({"type": "waypoints", "waypoints": room_waypoints[room_id]}))
                await broadcast_presence(room_id)

            elif mtype == "location" and room_id and member_id:
                now = time.time()
                entry = rooms.get(room_id, {}).get(member_id)
                if not entry:
                    continue
                if now - entry["last_location_ts"] < RATE_LIMIT_SECONDS:
                    continue
                lat, lng = data.get("lat"), data.get("lng")
                if lat is None or lng is None:
                    continue

                # speed (for ETA) + cumulative distance walked this session
                if entry["prev_lat"] is not None and entry["prev_ts"]:
                    dt = now - entry["prev_ts"]
                    dist_delta = haversine(entry["prev_lat"], entry["prev_lng"], lat, lng)
                    if dt >= 2:
                        speed = dist_delta / dt
                        entry["speed_mps"] = speed if speed <= MAX_SPEED_MPS else entry["speed_mps"]
                    if dist_delta <= MAX_SPEED_MPS * max(dt, 1):  # discard GPS-jump noise
                        entry["distance_m"] += dist_delta
                entry["prev_lat"], entry["prev_lng"], entry["prev_ts"] = lat, lng, now

                entry["lat"], entry["lng"] = lat, lng
                battery = data.get("battery")
                if isinstance(battery, (int, float)):
                    entry["battery"] = max(0, min(100, round(battery)))
                vehicle = data.get("vehicle")
                if vehicle in ("car", "train", "bus"):
                    entry["vehicle"] = vehicle
                elif vehicle is None:
                    pass  # keep whatever was set before (client only sends it when relevant)
                entry["last_location_ts"] = now
                entry["last_seen"] = now
                save_history(room_id, entry["username"], lat, lng)
                await broadcast_presence(room_id)
                await check_geofence(room_id, member_id)

            elif mtype == "ping":
                await ws.send_str(json.dumps({"type": "pong"}))

            elif mtype == "profile_update" and room_id and member_id:
                # Lets a member push a fresh avatar/color/username mid-session (e.g. right
                # after uploading a photo or renaming their account) without waiting for
                # the next rate-limited location tick - other clients' maps update at once.
                entry = rooms.get(room_id, {}).get(member_id)
                if not entry:
                    continue
                avatar = data.get("avatar")
                if isinstance(avatar, str) and avatar.startswith("/avatars/") and len(avatar) <= 128:
                    entry["avatar"] = avatar
                color = data.get("color")
                if isinstance(color, str) and color.startswith("#") and len(color) in (4, 7):
                    entry["color"] = color
                new_username = data.get("username")
                if isinstance(new_username, str) and 1 <= len(new_username.strip()) <= 24:
                    entry["username"] = new_username.strip()
                await broadcast_presence(room_id)

            elif mtype == "typing" and room_id and member_id:
                entry = rooms.get(room_id, {}).get(member_id)
                if not entry:
                    continue
                now = time.time()
                if now - entry["last_typing_ts"] < TYPING_THROTTLE_SECONDS:
                    continue
                entry["last_typing_ts"] = now
                await broadcast_to_room(room_id, {"type": "typing", "username": entry["username"]}, exclude=member_id)

            elif mtype == "chat" and room_id and member_id:
                entry = rooms.get(room_id, {}).get(member_id)
                if not entry:
                    continue
                now = time.time()
                if now - entry["last_chat_ts"] < CHAT_MIN_INTERVAL:
                    continue
                entry["last_chat_ts"] = now
                text = str(data.get("text", "")).strip()[:MAX_CHAT_CHARS]
                image_b64 = data.get("image")
                if image_b64 and len(image_b64) > MAX_IMAGE_B64_CHARS:
                    image_b64 = None
                if not text and not image_b64:
                    continue

                chat_msg = {
                    "type": "chat", "username": entry["username"], "text": text, "ts": time.time(),
                }
                if image_b64:
                    chat_msg["image"] = image_b64
                reply_to = data.get("reply_to")
                if isinstance(reply_to, dict) and reply_to.get("username") and reply_to.get("text"):
                    chat_msg["reply_to"] = {
                        "username": str(reply_to["username"])[:32],
                        "text": str(reply_to["text"])[:MAX_REPLY_CHARS],
                    }

                history = room_chat_history.setdefault(room_id, [])
                history.append(chat_msg)
                if len(history) > MAX_CHAT_HISTORY:
                    del history[: len(history) - MAX_CHAT_HISTORY]
                room_msg_count[room_id] = room_msg_count.get(room_id, 0) + 1
                await broadcast_to_room(room_id, chat_msg, exclude=member_id)
                push_body = text if text else "Photo"
                asyncio.create_task(send_push_to_room(
                    room_id, entry["username"], push_body, exclude_device_id=entry.get("device_id")
                ))

            elif mtype == "pin" and room_id and member_id:
                entry = rooms.get(room_id, {}).get(member_id)
                if not entry:
                    continue
                now = time.time()
                if now - entry["last_pin_ts"] < PIN_MIN_INTERVAL:
                    continue
                entry["last_pin_ts"] = now
                lat, lng = data.get("lat"), data.get("lng")
                if lat is None or lng is None:
                    continue
                pin = {"lat": lat, "lng": lng, "by": entry["username"], "ts": time.time()}
                room_pins[room_id] = pin
                await broadcast_to_room(room_id, {"type": "pin", **pin})

            elif mtype == "pin_clear" and room_id and member_id:
                room_pins[room_id] = None
                await broadcast_to_room(room_id, {"type": "pin_clear"})

            elif mtype == "poll_create" and room_id and member_id:
                entry = rooms.get(room_id, {}).get(member_id)
                if not entry:
                    continue
                question = str(data.get("question", "")).strip()[:MAX_POLL_QUESTION_CHARS]
                raw_options = data.get("options")
                if not question or not isinstance(raw_options, list):
                    continue
                options = [str(o).strip()[:MAX_POLL_OPTION_CHARS] for o in raw_options if str(o).strip()]
                options = options[:MAX_POLL_OPTIONS]
                if len(options) < 2:
                    continue
                room_polls[room_id] = {
                    "question": question, "options": options, "votes": {}, "by": entry["username"], "ts": time.time(),
                }
                await broadcast_to_room(room_id, {"type": "poll", **_poll_payload(room_id)})

            elif mtype == "poll_vote" and room_id and member_id:
                poll = room_polls.get(room_id)
                if not poll:
                    continue
                option_idx = data.get("option")
                if not isinstance(option_idx, int) or not (0 <= option_idx < len(poll["options"])):
                    continue
                poll["votes"][member_id] = option_idx
                await broadcast_to_room(room_id, {"type": "poll", **_poll_payload(room_id)})

            elif mtype == "poll_clear" and room_id and member_id:
                poll = room_polls.get(room_id)
                if not poll:
                    continue
                entry = rooms.get(room_id, {}).get(member_id)
                is_creator = entry and entry["username"] == poll["by"]
                if not (is_creator or room_owners.get(room_id) == member_id):
                    continue
                room_polls[room_id] = None
                await broadcast_to_room(room_id, {"type": "poll_clear"})

            elif mtype == "waypoint_add" and room_id and member_id:
                entry = rooms.get(room_id, {}).get(member_id)
                if not entry:
                    continue
                lat, lng = data.get("lat"), data.get("lng")
                if lat is None or lng is None:
                    continue
                waypoints = room_waypoints.setdefault(room_id, [])
                if len(waypoints) >= MAX_WAYPOINTS:
                    continue
                label = str(data.get("label", "")).strip()[:MAX_WAYPOINT_LABEL_CHARS]
                waypoints.append({
                    "id": next(_waypoint_id_counter), "lat": lat, "lng": lng,
                    "label": label, "by": entry["username"], "ts": time.time(),
                })
                await broadcast_to_room(room_id, {"type": "waypoints", "waypoints": waypoints})

            elif mtype == "waypoint_remove" and room_id and member_id:
                waypoints = room_waypoints.get(room_id)
                if not waypoints:
                    continue
                wp_id = data.get("id")
                new_list = [w for w in waypoints if w["id"] != wp_id]
                if len(new_list) == len(waypoints):
                    continue
                room_waypoints[room_id] = new_list
                await broadcast_to_room(room_id, {"type": "waypoints", "waypoints": new_list})

            elif mtype == "waypoint_clear_all" and room_id and member_id:
                room_waypoints[room_id] = []
                await broadcast_to_room(room_id, {"type": "waypoints", "waypoints": []})

            elif mtype == "push_subscribe" and room_id and member_id:
                entry = rooms.get(room_id, {}).get(member_id)
                if not entry or not PUSH_ENABLED:
                    continue
                dev_id = str(data.get("device_id", ""))[:64]
                sub = data.get("subscription") or {}
                endpoint = sub.get("endpoint")
                keys = sub.get("keys") or {}
                p256dh, auth = keys.get("p256dh"), keys.get("auth")
                if not (dev_id and endpoint and p256dh and auth):
                    continue
                entry["device_id"] = dev_id
                save_push_subscription(room_id, dev_id, endpoint, p256dh, auth)
                await ws.send_str(json.dumps({"type": "push_subscribed"}))

            elif mtype == "push_unsubscribe" and room_id and member_id:
                dev_id = str(data.get("device_id", ""))[:64]
                if dev_id:
                    delete_push_subscription(room_id, dev_id)

            elif mtype == "voice" and room_id and member_id:
                entry = rooms.get(room_id, {}).get(member_id)
                if not entry:
                    continue
                now = time.time()
                if now - entry["last_voice_ts"] < VOICE_MIN_INTERVAL:
                    continue
                entry["last_voice_ts"] = now
                audio_b64 = data.get("audio")
                mime = data.get("mime", "audio/webm")
                if not audio_b64 or len(audio_b64) > MAX_VOICE_B64_CHARS:
                    continue
                await broadcast_to_room(
                    room_id,
                    {"type": "voice", "username": entry["username"], "audio": audio_b64, "mime": mime},
                    exclude=member_id,
                )
                asyncio.create_task(send_push_to_room(
                    room_id, entry["username"], "Voice message", exclude_device_id=entry.get("device_id")
                ))

            elif mtype == "kick" and room_id and member_id:
                if room_owners.get(room_id) != member_id:
                    continue
                entry = rooms.get(room_id, {}).get(member_id)
                if not entry:
                    continue
                now = time.time()
                if now - entry["last_kick_ts"] < KICK_MIN_INTERVAL:
                    continue
                entry["last_kick_ts"] = now
                target_username = str(data.get("username", ""))
                room = rooms.get(room_id, {})
                targets = [mid for mid, e in room.items() if e["username"] == target_username and mid != member_id]
                for target_id in targets:
                    target_entry = room[target_id]
                    try:
                        await target_entry["ws"].send_str(json.dumps({"type": "kicked"}))
                        await target_entry["ws"].close()
                    except Exception:
                        pass
                    room.pop(target_id, None)
                if targets:
                    await broadcast_presence(room_id)

            elif mtype == "change_password" and room_id and member_id:
                if room_owners.get(room_id) != member_id:
                    continue
                new_password = str(data.get("password") or "")[:128]
                room_passwords[room_id] = _hash_password(new_password) if new_password else None
                await ws.send_str(json.dumps({"type": "password_changed"}))

            elif mtype == "get_stats" and room_id and member_id:
                await ws.send_str(json.dumps({
                    "type": "room_stats",
                    "message_count": room_msg_count.get(room_id, 0),
                    "member_count": len(rooms.get(room_id, {})),
                }))

    finally:
        if room_id and member_id and room_id in rooms:
            rooms[room_id].pop(member_id, None)
            if not rooms[room_id]:
                rooms.pop(room_id, None)
                _clear_room_state(room_id)
            else:
                _promote_new_owner(room_id)
                await broadcast_presence(room_id)

    return ws


async def stale_connection_reaper(app):
    """Removes ghost users that stopped sending heartbeats (WS heartbeat already
    handles TCP-level dead peers; this is a belt-and-suspenders app-level check)."""
    while True:
        await asyncio.sleep(HEARTBEAT_INTERVAL)
        now = time.time()
        for key in list(failed_joins.keys()):
            recent = [t for t in failed_joins[key] if now - t < FAILED_JOIN_WINDOW_S]
            if recent:
                failed_joins[key] = recent
            else:
                failed_joins.pop(key, None)
        for room_id in list(rooms.keys()):
            for member_id in list(rooms[room_id].keys()):
                if now - rooms[room_id][member_id]["last_seen"] > HEARTBEAT_TIMEOUT:
                    rooms[room_id].pop(member_id, None)
            if not rooms[room_id]:
                rooms.pop(room_id, None)
                _clear_room_state(room_id)
            else:
                _promote_new_owner(room_id)
                await broadcast_presence(room_id)


LOCATION_HISTORY_RETENTION_DAYS = 30


async def history_retention_sweeper(app):
    """Deletes location-history rows older than LOCATION_HISTORY_RETENTION_DAYS.
    Without this, GPS coordinates tied to a username would accumulate in the
    database forever - keeping precise historical location data indefinitely
    with no purpose isn't compliant with GDPR's storage-limitation principle
    (Art. 5(1)(e)), so this runs once a day to keep only recent history."""
    while True:
        try:
            cutoff = time.time() - LOCATION_HISTORY_RETENTION_DAYS * 86400
            conn = sqlite3.connect(DB_PATH)
            conn.execute("DELETE FROM history WHERE timestamp < ?", (cutoff,))
            conn.commit()
            conn.close()
        except Exception:
            pass
        await asyncio.sleep(86400)


async def health(request):
    return web.json_response({"status": "ok", "rooms": len(rooms)})


async def vapid_public_key(request):
    if not PUSH_ENABLED:
        return web.json_response({"enabled": False})
    return web.json_response({"enabled": True, "key": VAPID_PUBLIC_KEY})


async def admin_stats(request):
    key = request.query.get("key", "")
    if not ADMIN_KEY or not hmac.compare_digest(key, ADMIN_KEY):
        return web.json_response({"error": "forbidden"}, status=403)
    total_members = sum(len(members) for members in rooms.values())
    return web.json_response({
        "rooms": len(rooms),
        "members": total_members,
        "uptime_s": round(time.time() - SERVER_START_TS),
    })


@web.middleware
async def security_headers_middleware(request, handler):
    response = await handler(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "interest-cohort=()"
    return response


@web.middleware
async def custom_404_middleware(request, handler):
    try:
        response = await handler(request)
        if response.status == 404:
            return web.FileResponse(FRONTEND_DIR / "404.html", status=404)
        return response
    except web.HTTPNotFound:
        return web.FileResponse(FRONTEND_DIR / "404.html", status=404)


async def start_background_tasks(app):
    app["reaper"] = asyncio.create_task(stale_connection_reaper(app))
    app["history_sweeper"] = asyncio.create_task(history_retention_sweeper(app))


async def cleanup_background_tasks(app):
    app["reaper"].cancel()
    app["history_sweeper"].cancel()


async def index(request):
    return web.FileResponse(FRONTEND_DIR / "index.html")


async def admin_page(request):
    return web.FileResponse(FRONTEND_DIR / "admin.html")


async def legal_page(request):
    name = request.match_info["page"]
    return web.FileResponse(FRONTEND_DIR / f"{name}.html")


async def static_or_404(request):
    """Serves any real file under FRONTEND_DIR, or the custom 404 page for
    anything else. Replaces app.router.add_static(), whose own internal
    404 handling conflicts with custom_404_middleware and silently returns
    an empty body instead of our page."""
    rel_path = request.match_info.get("tail", "")
    root = FRONTEND_DIR.resolve()
    candidate = (root / rel_path).resolve()
    if root != candidate and root not in candidate.parents:
        return web.FileResponse(FRONTEND_DIR / "404.html", status=404)
    if candidate.is_file():
        return web.FileResponse(candidate)
    return web.FileResponse(FRONTEND_DIR / "404.html", status=404)


def create_app():
    init_db()
    accounts.init(DATA_DIR / "accounts.db", DATA_DIR / "avatars")
    app = web.Application(middlewares=[security_headers_middleware, custom_404_middleware])
    app.router.add_get("/health", health)
    app.router.add_get("/vapid-public-key", vapid_public_key)
    app.router.add_get("/admin/stats", admin_stats)
    app.router.add_get("/ws", websocket_handler)
    app.router.add_get("/", index)
    accounts.register_routes(app, sys.modules[__name__])
    app.router.add_get("/admin", admin_page)
    app.router.add_get("/{page:privacy|terms|eula|cookies|imprint}", legal_page)
    app.router.add_get("/{tail:.*}", static_or_404)
    app.on_startup.append(start_background_tasks)
    app.on_cleanup.append(cleanup_background_tasks)
    return app


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8765))
    web.run_app(create_app(), port=port)
