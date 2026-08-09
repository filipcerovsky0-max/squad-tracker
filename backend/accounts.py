import os
import sqlite3
import hashlib
import secrets
from pathlib import Path
from aiohttp import web

DB_PATH = None
AVATARS_DIR = None

def init(db_path, avatars_dir):
    global DB_PATH, AVATARS_DIR
    DB_PATH = Path(db_path)
    AVATARS_DIR = Path(avatars_dir)
    AVATARS_DIR.mkdir(parents=True, exist_ok=True)
    
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                avatar TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        conn.commit()

def hash_password(password):
    salt = secrets.token_hex(16)
    pwd_hash = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}:{pwd_hash}"

def verify_password(stored, provided):
    try:
        salt, pwd_hash = stored.split(":")
        return pwd_hash == hashlib.sha256((salt + provided).encode()).hexdigest()
    except Exception:
        return False

async def handle_register(request):
    try:
        data = await request.json()
        username = data.get("username", "").strip()
        password = data.get("password", "").strip()
        
        if not username or len(username) < 3:
            return web.json_response({"error": "Uživatelské jméno musí mít alespoň 3 znaky"}, status=400)
        if not password or len(password) < 4:
            return web.json_response({"error": "Heslo musí mít alespoň 4 znaky"}, status=400)
        
        pwd_hash = hash_password(password)
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            if cursor.fetchone():
                return web.json_response({"error": "Uživatel již existuje"}, status=400)
            
            cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, pwd_hash))
            conn.commit()
            
        return web.json_response({"success": True, "message": "Registrace proběhla úspěšně"})
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)

async def handle_login(request):
    try:
        data = await request.json()
        username = data.get("username", "").strip()
        password = data.get("password", "").strip()
        
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, password_hash, avatar FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            
            if not row or not verify_password(row[1], password):
                return web.json_response({"error": "Nesprávné uživatelské jméno nebo heslo"}, status=401)
            
            user_id, _, avatar = row
            token = secrets.token_hex(32)
            
            cursor.execute("INSERT INTO sessions (token, user_id) VALUES (?, ?)", (token, user_id))
            conn.commit()
            
        return web.json_response({
            "success": True,
            "token": token,
            "username": username,
            "user_id": user_id,
            "avatar": avatar
        })
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)

async def handle_verify_token(request):
    try:
        auth_header = request.headers.get("Authorization", "")
        token = auth_header.replace("Bearer ", "").strip()
        if not token:
            return web.json_response({"valid": False}, status=401)
            
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT u.id, u.username, u.avatar 
                FROM sessions s 
                JOIN users u ON s.user_id = u.id 
                WHERE s.token = ?
            """, (token,))
            row = cursor.fetchone()
            if not row:
                return web.json_response({"valid": False}, status=401)
                
            return web.json_response({
                "valid": True,
                "user_id": row[0],
                "username": row[1],
                "avatar": row[2]
            })
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)

def register_routes(app, root_module):
    app.router.add_post('/api/register', handle_register)
    app.router.add_post('/api/login', handle_login)
    app.router.add_post('/api/verify-token', handle_verify_token)
