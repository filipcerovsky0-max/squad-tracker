"""
Squad Tracker - backend server
aiohttp app: serví static frontend + WebSocket na jedné portu.
Room management, presence broadcast, Haversine geofencing, SQLite history, heartbeat.
"""
import asyncio
import json
import math
import os
import sqlite3
import time
from pathlib import Path

from aiohttp import web, WSMsgType

BASE_DIR = Path(__file__).parent
FRONTEND_DIR = BASE_DIR.parent / "frontend"
DB_PATH = BASE_DIR / "history.db"

RATE_LIMIT_SECONDS = 3
GEOFENCE_METERS = 50
HEARTBEAT_INTERVAL = 15
HEARTBEAT_TIMEOUT = 40
MAX_CHAT_CHARS = 500
MAX_VOICE_B64_CHARS = 2_000_000  # ~1.5MB raw audio, generous for a short PTT clip

# rooms[room_id] = { username: { "ws": WebSocketResponse, "lat": float, "lng": float,
#                                 "last_location_ts": float, "last_seen": float } }
rooms: dict[str, dict[str, dict]] = {}


async def broadcast_to_room(room_id, msg: dict, exclude: str | None = None):
    room = rooms.get(room_id)
    if not room:
        return
    data = json.dumps(msg)
    dead = []
    for uname, entry in room.items():
        if uname == exclude:
            continue
        try:
            await entry["ws"].send_str(data)
        except ConnectionResetError:
            dead.append(uname)
    for uname in dead:
        room.pop(uname, None)


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
    users_payload = [
        {"username": u, "lat": data["lat"], "lng": data["lng"]}
        for u, data in room.items()
        if data["lat"] is not None
    ]
    msg = json.dumps({"type": "presence", "users": users_payload})
    dead = []
    for username, data in room.items():
        try:
            await data["ws"].send_str(msg)
        except ConnectionResetError:
            dead.append(username)
    for username in dead:
        room.pop(username, None)


async def check_geofence(room_id, moved_user):
    room = rooms.get(room_id)
    if not room:
        return
    moved = room.get(moved_user)
    if not moved or moved["lat"] is None:
        return
    for username, data in room.items():
        if username == moved_user or data["lat"] is None:
            continue
        dist = haversine(moved["lat"], moved["lng"], data["lat"], data["lng"])
        if dist < GEOFENCE_METERS:
            alert = json.dumps(
                {"type": "proximity_alert", "with": username, "distance_m": round(dist, 1)}
            )
            other_alert = json.dumps(
                {"type": "proximity_alert", "with": moved_user, "distance_m": round(dist, 1)}
            )
            try:
                await moved["ws"].send_str(alert)
                await data["ws"].send_str(other_alert)
            except ConnectionResetError:
                pass


async def websocket_handler(request):
    ws = web.WebSocketResponse(heartbeat=HEARTBEAT_INTERVAL)
    await ws.prepare(request)

    room_id = None
    username = None

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
                room_id = str(data.get("room", "default"))
                username = str(data.get("username", "anon"))[:32]
                rooms.setdefault(room_id, {})
                rooms[room_id][username] = {
                    "ws": ws,
                    "lat": None,
                    "lng": None,
                    "last_location_ts": 0,
                    "last_seen": time.time(),
                }
                await ws.send_str(json.dumps({"type": "joined", "room": room_id, "username": username}))
                await broadcast_presence(room_id)

            elif mtype == "location" and room_id and username:
                now = time.time()
                entry = rooms.get(room_id, {}).get(username)
                if not entry:
                    continue
                # rate limiting - ignore packets sent faster than the allowed interval
                if now - entry["last_location_ts"] < RATE_LIMIT_SECONDS:
                    continue
                lat, lng = data.get("lat"), data.get("lng")
                if lat is None or lng is None:
                    continue
                entry["lat"], entry["lng"] = lat, lng
                entry["last_location_ts"] = now
                entry["last_seen"] = now
                save_history(room_id, username, lat, lng)
                await broadcast_presence(room_id)
                await check_geofence(room_id, username)

            elif mtype == "ping":
                await ws.send_str(json.dumps({"type": "pong"}))

            elif mtype == "chat" and room_id and username:
                text = str(data.get("text", "")).strip()[:MAX_CHAT_CHARS]
                if not text:
                    continue
                await broadcast_to_room(
                    room_id,
                    {"type": "chat", "username": username, "text": text, "ts": time.time()},
                    exclude=username,
                )

            elif mtype == "voice" and room_id and username:
                audio_b64 = data.get("audio")
                mime = data.get("mime", "audio/webm")
                if not audio_b64 or len(audio_b64) > MAX_VOICE_B64_CHARS:
                    continue
                await broadcast_to_room(
                    room_id,
                    {"type": "voice", "username": username, "audio": audio_b64, "mime": mime},
                    exclude=username,
                )

    finally:
        if room_id and username and room_id in rooms:
            rooms[room_id].pop(username, None)
            if not rooms[room_id]:
                rooms.pop(room_id, None)
            else:
                await broadcast_presence(room_id)

    return ws


async def stale_connection_reaper(app):
    """Removes ghost users that stopped sending heartbeats (WS heartbeat already
    handles TCP-level dead peers; this is a belt-and-suspenders app-level check)."""
    while True:
        await asyncio.sleep(HEARTBEAT_INTERVAL)
        now = time.time()
        for room_id in list(rooms.keys()):
            for username in list(rooms[room_id].keys()):
                if now - rooms[room_id][username]["last_seen"] > HEARTBEAT_TIMEOUT:
                    rooms[room_id].pop(username, None)
            if not rooms[room_id]:
                rooms.pop(room_id, None)
            else:
                await broadcast_presence(room_id)


async def health(request):
    return web.json_response({"status": "ok", "rooms": len(rooms)})


async def start_background_tasks(app):
    app["reaper"] = asyncio.create_task(stale_connection_reaper(app))


async def cleanup_background_tasks(app):
    app["reaper"].cancel()


async def index(request):
    return web.FileResponse(FRONTEND_DIR / "index.html")


def create_app():
    init_db()
    app = web.Application()
    app.router.add_get("/health", health)
    app.router.add_get("/ws", websocket_handler)
    app.router.add_get("/", index)
    app.router.add_static("/", FRONTEND_DIR, show_index=False)
    app.on_startup.append(start_background_tasks)
    app.on_cleanup.append(cleanup_background_tasks)
    return app


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8765))
    web.run_app(create_app(), port=port)
