import os
import sqlite3
import secrets
from pathlib import Path
from datetime import datetime, timezone
from contextlib import contextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect, Depends, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel, Field
from pwdlib import PasswordHash

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = os.getenv("DATABASE_PATH", str(BASE_DIR / "ssb.sqlite3"))
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)
MAX_AVATAR_BYTES = 3 * 1024 * 1024
MAX_MESSAGE_FILE_BYTES = 10 * 1024 * 1024
ADMIN_EMAIL = os.getenv("SSB_ADMIN_EMAIL", "").strip().lower()
ADMIN_PANEL_CODE = os.getenv("SSB_ADMIN_PANEL_CODE", "sm135792468.1391")
SECRET_KEY = os.getenv("SECRET_KEY", "")
if len(SECRET_KEY) < 32 or SECRET_KEY.startswith("replace-with-"):
    if os.getenv("ENVIRONMENT") == "production":
        raise RuntimeError("Set a strong SECRET_KEY environment variable in production.")
    SECRET_KEY = "local-development-only-" + secrets.token_urlsafe(32)

COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
password_hash = PasswordHash.recommended()
app = FastAPI(title="SSB Messenger")
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    session_cookie="ssb_session",
    same_site="lax",
    https_only=COOKIE_SECURE,
    max_age=60 * 60 * 24 * 7,
)
# For production, configure trusted hosts through the deployment platform and add
# TrustedHostMiddleware with the exact domains you own.

@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()

def init_db():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            display_name TEXT NOT NULL DEFAULT '',
            email TEXT UNIQUE COLLATE NOCASE,
            is_admin INTEGER NOT NULL DEFAULT 0,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS rooms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            kind TEXT NOT NULL CHECK(kind IN ('private','group','channel')),
            owner_id INTEGER NOT NULL REFERENCES users(id),
            created_at TEXT NOT NULL,
            suspended INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS memberships (
            room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            role TEXT NOT NULL DEFAULT 'member',
            PRIMARY KEY(room_id, user_id)
        );
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
            sender_id INTEGER NOT NULL REFERENCES users(id),
            body TEXT NOT NULL,
            created_at TEXT NOT NULL,
            media_url TEXT,
            media_type TEXT,
            original_name TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_messages_room_id ON messages(room_id, id);
        """)
        room_columns = {row[1] for row in c.execute("PRAGMA table_info(rooms)").fetchall()}
        if "suspended" not in room_columns:
            c.execute("ALTER TABLE rooms ADD COLUMN suspended INTEGER NOT NULL DEFAULT 0")
        columns = {row[1] for row in c.execute("PRAGMA table_info(users)").fetchall()}
        if "email" not in columns:
            c.execute("ALTER TABLE users ADD COLUMN email TEXT")
        if "display_name" not in columns:
            c.execute("ALTER TABLE users ADD COLUMN display_name TEXT NOT NULL DEFAULT ''")
        c.execute("UPDATE users SET display_name=username WHERE display_name='' OR display_name IS NULL")
        if "is_admin" not in columns:
            c.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")
        if "avatar_url" not in columns:
            c.execute("ALTER TABLE users ADD COLUMN avatar_url TEXT")
        message_columns = {row[1] for row in c.execute("PRAGMA table_info(messages)").fetchall()}
        if "media_url" not in message_columns:
            c.execute("ALTER TABLE messages ADD COLUMN media_url TEXT")
        if "media_type" not in message_columns:
            c.execute("ALTER TABLE messages ADD COLUMN media_type TEXT")
        if "original_name" not in message_columns:
            c.execute("ALTER TABLE messages ADD COLUMN original_name TEXT")
init_db()

def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def current_user(request: Request):
    uid = request.session.get("uid")
    if not uid:
        return None
    with db() as c:
        row = c.execute("SELECT id, username, display_name, email, avatar_url, is_admin FROM users WHERE id=?", (uid,)).fetchone()
    return dict(row) if row else None

def require_user(request: Request):
    user = current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="ابتدا وارد حساب شوید.")
    return user

def require_admin_access(request: Request, user):
    if not user.get("is_admin") and not request.session.get("admin_panel_unlocked"):
        raise HTTPException(status_code=403, detail="ابتدا کد پنل ادمین را در تنظیمات وارد کنید.")

class Credentials(BaseModel):
    username: str = Field(min_length=6, max_length=254, pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
    password: str = Field(min_length=10, max_length=128)
    display_name: str = Field(default="", max_length=40)

class RoomCreate(BaseModel):
    name: str = Field(min_length=2, max_length=60)
    kind: str = Field(pattern=r"^(group|channel)$")

class RoomRename(BaseModel):
    name: str = Field(min_length=2, max_length=60)

class PrivateChat(BaseModel):
    username: str = Field(min_length=2, max_length=254)

class SendMessage(BaseModel):
    body: str = Field(min_length=1, max_length=2000)

@app.get("/", response_class=HTMLResponse)
def index():
    return (BASE_DIR / "static" / "index.html").read_text(encoding="utf-8")

@app.get("/api/me")
def me(request: Request):
    return {"user": current_user(request)}

@app.post("/api/register")
def register(data: Credentials, request: Request):
    username = data.username.strip().lower()
    display_name = data.display_name.strip()
    if not display_name:
        raise HTTPException(status_code=422, detail="لطفاً یک نام نمایشی برای خودتان انتخاب کنید.")
    if len(display_name) < 2:
        raise HTTPException(status_code=422, detail="نام نمایشی باید حداقل ۲ نویسه باشد.")
    hashed = password_hash.hash(data.password)
    try:
        with db() as c:
            cur = c.execute(
                "INSERT INTO users(username,display_name,email,is_admin,password_hash,created_at) VALUES(?,?,?,?,?,?)",
                (username, display_name, username, 1 if ADMIN_EMAIL and username == ADMIN_EMAIL else 0, hashed, now_iso()),
            )
            uid = cur.lastrowid
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="این نام کاربری قبلاً ثبت شده است.")
    request.session.clear()
    request.session["uid"] = uid
    return {"ok": True, "username": username, "display_name": display_name, "email": username}

@app.post("/api/login")
def login(data: Credentials, request: Request):
    with db() as c:
        row = c.execute("SELECT * FROM users WHERE (email=? COLLATE NOCASE OR username=? COLLATE NOCASE)", (data.username.strip().lower(), data.username.strip().lower())).fetchone()
    if not row or not password_hash.verify(data.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="نام کاربری یا رمز عبور نادرست است.")
    request.session.clear()
    request.session["uid"] = row["id"]
    return {"ok": True, "username": row["username"], "display_name": row["display_name"]}

@app.post("/api/me/avatar")
async def upload_avatar(file: UploadFile = File(...), user=Depends(require_user)):
    allowed = {
        "image/jpeg": (".jpg", b"\xff\xd8\xff"),
        "image/png": (".png", b"\x89PNG\r\n\x1a\n"),
        "image/webp": (".webp", b"RIFF"),
        "image/gif": (".gif", b"GIF8"),
    }
    if file.content_type not in allowed:
        raise HTTPException(status_code=415, detail="فقط تصویر JPG، PNG، WEBP یا GIF مجاز است.")
    data = await file.read(MAX_AVATAR_BYTES + 1)
    if not data or len(data) > MAX_AVATAR_BYTES:
        raise HTTPException(status_code=413, detail="حجم عکس باید کمتر از ۳ مگابایت باشد.")
    ext, signature = allowed[file.content_type]
    if not data.startswith(signature) or (file.content_type == "image/webp" and data[8:12] != b"WEBP"):
        raise HTTPException(status_code=400, detail="محتوای فایل با نوع تصویر مطابقت ندارد.")
    filename = f"user_{user['id']}_{secrets.token_hex(8)}{ext}"
    (UPLOAD_DIR / filename).write_bytes(data)
    avatar_url = f"/uploads/{filename}"
    with db() as c:
        old = c.execute("SELECT avatar_url FROM users WHERE id=?", (user["id"],)).fetchone()
        c.execute("UPDATE users SET avatar_url=? WHERE id=?", (avatar_url, user["id"]))
    if old and old["avatar_url"]:
        old_name = Path(old["avatar_url"]).name
        old_path = UPLOAD_DIR / old_name
        if old_path.parent == UPLOAD_DIR and old_path.exists():
            try: old_path.unlink()
            except OSError: pass
    return {"avatar_url": avatar_url}

@app.post("/api/logout")
def logout(request: Request):
    request.session.clear()
    return {"ok": True}

def room_member(c, room_id, user_id):
    return c.execute(
        "SELECT role FROM memberships WHERE room_id=? AND user_id=?", (room_id, user_id)
    ).fetchone()

@app.get("/api/rooms")
def list_rooms(user=Depends(require_user)):
    with db() as c:
        rows = c.execute("""
            SELECT r.id,r.name,r.kind,r.owner_id,m.role,
                   (SELECT body FROM messages WHERE room_id=r.id ORDER BY id DESC LIMIT 1) last_message
            FROM rooms r JOIN memberships m ON m.room_id=r.id
            WHERE m.user_id=? ORDER BY r.id DESC
        """, (user["id"],)).fetchall()
    return [dict(r) for r in rows]

@app.post("/api/private")
def create_private(data: PrivateChat, user=Depends(require_user)):
    with db() as c:
        target = c.execute("SELECT id,username,display_name FROM users WHERE username=? COLLATE NOCASE OR display_name=? COLLATE NOCASE ORDER BY CASE WHEN username=? COLLATE NOCASE THEN 0 ELSE 1 END LIMIT 1", (data.username.strip(), data.username.strip(), data.username.strip())).fetchone()
        if not target:
            raise HTTPException(status_code=404, detail="کاربر پیدا نشد.")
        if target["id"] == user["id"]:
            raise HTTPException(status_code=400, detail="نمی‌توانید با خودتان گفت‌وگو بسازید.")
        existing = c.execute("""
            SELECT r.id FROM rooms r
            JOIN memberships a ON a.room_id=r.id
            JOIN memberships b ON b.room_id=r.id
            WHERE r.kind='private' AND a.user_id=? AND b.user_id=?
            AND (SELECT COUNT(*) FROM memberships x WHERE x.room_id=r.id)=2
            LIMIT 1
        """, (user["id"], target["id"])).fetchone()
        if existing:
            return {"id": existing["id"]}
        cur = c.execute(
            "INSERT INTO rooms(name,kind,owner_id,created_at) VALUES(?,?,?,?)",
            (f'{user["display_name"]} و {target["display_name"]}', "private", user["id"], now_iso())
        )
        rid = cur.lastrowid
        c.executemany("INSERT INTO memberships(room_id,user_id,role) VALUES(?,?,?)", [
            (rid, user["id"], "member"), (rid, target["id"], "member")
        ])
    return {"id": rid}

@app.post("/api/rooms")
def create_room(data: RoomCreate, user=Depends(require_user)):
    with db() as c:
        cur = c.execute(
            "INSERT INTO rooms(name,kind,owner_id,created_at) VALUES(?,?,?,?)",
            (data.name.strip(), data.kind, user["id"], now_iso())
        )
        rid = cur.lastrowid
        c.execute("INSERT INTO memberships(room_id,user_id,role) VALUES(?,?,?)", (rid, user["id"], "owner"))
    return {"id": rid}

@app.patch("/api/rooms/{room_id}")
def rename_room(room_id: int, data: RoomRename, user=Depends(require_user)):
    with db() as c:
        room = c.execute("SELECT id, kind, owner_id FROM rooms WHERE id=?", (room_id,)).fetchone()
        if not room or room["kind"] == "private":
            raise HTTPException(status_code=404, detail="گروه یا کانال پیدا نشد.")
        membership = c.execute("SELECT role FROM memberships WHERE room_id=? AND user_id=?", (room_id, user["id"])).fetchone()
        if room["owner_id"] != user["id"] and not user.get("is_admin") and (not membership or membership["role"] not in ("owner", "admin")):
            raise HTTPException(status_code=403, detail="فقط مالک، مدیر یا ادمین برنامه می‌تواند نام گروه یا کانال را ویرایش کند.")
        c.execute("UPDATE rooms SET name=? WHERE id=?", (data.name.strip(), room_id))
    return {"ok": True, "name": data.name.strip()}

@app.post("/api/rooms/{room_id}/join")
def join_room(room_id: int, user=Depends(require_user)):
    with db() as c:
        room = c.execute("SELECT id,kind FROM rooms WHERE id=?", (room_id,)).fetchone()
        if not room or room["kind"] == "private":
            raise HTTPException(status_code=404, detail="گروه یا کانال پیدا نشد.")
        c.execute("INSERT OR IGNORE INTO memberships(room_id,user_id,role) VALUES(?,?,?)",
                  (room_id, user["id"], "member"))
    return {"ok": True}

@app.get("/api/rooms/{room_id}/members")
def list_room_members(room_id: int, user=Depends(require_user)):
    with db() as c:
        room = c.execute("SELECT owner_id,kind FROM rooms WHERE id=?", (room_id,)).fetchone()
        membership = room_member(c, room_id, user["id"])
        if not room or room["kind"] == "private": raise HTTPException(status_code=404, detail="گروه یا کانال پیدا نشد.")
        if not membership: raise HTTPException(status_code=403, detail="اجازه دسترسی ندارید.")
        rows = c.execute("SELECT u.id,u.username,u.display_name,m.role FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.room_id=? ORDER BY CASE m.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END,u.display_name", (room_id,)).fetchall()
    return [dict(r) for r in rows]

class MemberChange(BaseModel):
    username: str = Field(min_length=2, max_length=254)
    role: str = Field(default="member", pattern=r"^(member|admin)$")

def can_manage_room(c, room_id, user):
    room = c.execute("SELECT owner_id,kind FROM rooms WHERE id=?", (room_id,)).fetchone()
    membership = room_member(c, room_id, user["id"])
    if not room or room["kind"] == "private": raise HTTPException(status_code=404, detail="گروه یا کانال پیدا نشد.")
    if room["owner_id"] != user["id"] and not user.get("is_admin") and (not membership or membership["role"] not in ("owner", "admin")):
        raise HTTPException(status_code=403, detail="فقط مالک یا مدیر می‌تواند اعضا را مدیریت کند.")
    return room

@app.post("/api/rooms/{room_id}/members")
def add_room_member(room_id: int, data: MemberChange, user=Depends(require_user)):
    with db() as c:
        room = can_manage_room(c, room_id, user)
        target = c.execute("SELECT id FROM users WHERE username=? COLLATE NOCASE OR display_name=? COLLATE NOCASE LIMIT 1", (data.username.strip(), data.username.strip())).fetchone()
        if not target: raise HTTPException(status_code=404, detail="کاربر پیدا نشد.")
        role = data.role if (room["owner_id"] == user["id"] or user.get("is_admin")) else "member"
        c.execute("INSERT INTO memberships(room_id,user_id,role) VALUES(?,?,?) ON CONFLICT(room_id,user_id) DO UPDATE SET role=excluded.role", (room_id,target["id"],role))
    return {"ok":True}

@app.delete("/api/rooms/{room_id}/members/{member_id}")
def remove_room_member(room_id: int, member_id: int, user=Depends(require_user)):
    with db() as c:
        room = can_manage_room(c, room_id, user)
        if member_id == room["owner_id"]: raise HTTPException(status_code=400, detail="مالک گروه یا کانال قابل حذف نیست.")
        c.execute("DELETE FROM memberships WHERE room_id=? AND user_id=?", (room_id,member_id))
    return {"ok":True}

@app.get("/api/discover")
def discover(user=Depends(require_user)):
    with db() as c:
        rows = c.execute("""
            SELECT r.id,r.name,r.kind,r.owner_id
            FROM rooms r WHERE r.kind IN ('group','channel')
            AND NOT EXISTS (SELECT 1 FROM memberships m WHERE m.room_id=r.id AND m.user_id=?)
            ORDER BY r.id DESC
        """, (user["id"],)).fetchall()
    return [dict(r) for r in rows]

@app.get("/api/rooms/{room_id}/messages")
def get_messages(room_id: int, user=Depends(require_user)):
    with db() as c:
        if not room_member(c, room_id, user["id"]):
            raise HTTPException(status_code=403, detail="اجازه دسترسی ندارید.")
        rows = c.execute("""
            SELECT messages.id, messages.sender_id, users.display_name AS username, messages.body, messages.created_at,
                   messages.media_url, messages.media_type, messages.original_name
            FROM messages JOIN users ON users.id=messages.sender_id
            WHERE room_id=? ORDER BY messages.id DESC LIMIT 100
        """, (room_id,)).fetchall()
    return [dict(r) for r in reversed(rows)]

@app.post("/api/rooms/{room_id}/messages")
def send_message(room_id: int, data: SendMessage, user=Depends(require_user)):
    body = data.body.strip()
    if not body:
        raise HTTPException(status_code=400, detail="پیام خالی است.")
    with db() as c:
        membership = room_member(c, room_id, user["id"])
        if not membership:
            raise HTTPException(status_code=403, detail="اجازه ارسال پیام ندارید.")
        room = c.execute("SELECT kind,owner_id,suspended FROM rooms WHERE id=?", (room_id,)).fetchone()
        if not room:
            raise HTTPException(status_code=404, detail="گروه یا کانال پیدا نشد.")
        if room["suspended"]:
            raise HTTPException(status_code=403, detail="ارسال پیام در این گروه یا کانال موقتاً توسط ادمین برنامه متوقف شده است.")
        if room["kind"] == "channel" and room["owner_id"] != user["id"] and membership["role"] not in ("owner", "admin") and not user.get("is_admin"):
            raise HTTPException(status_code=403, detail="فقط مدیر کانال می‌تواند پیام بفرستد.")
        cur = c.execute(
            "INSERT INTO messages(room_id,sender_id,body,created_at) VALUES(?,?,?,?)",
            (room_id, user["id"], body, now_iso())
        )
        msg = c.execute("""
            SELECT messages.id, messages.sender_id, users.display_name AS username, messages.body, messages.created_at,
                   messages.media_url, messages.media_type, messages.original_name
            FROM messages JOIN users ON users.id=messages.sender_id WHERE messages.id=?
        """, (cur.lastrowid,)).fetchone()
    return dict(msg)

@app.post("/api/rooms/{room_id}/media")
async def send_media(room_id: int, file: UploadFile = File(...), user=Depends(require_user)):
    data = await file.read(MAX_MESSAGE_FILE_BYTES + 1)
    if not data or len(data) > MAX_MESSAGE_FILE_BYTES:
        raise HTTPException(status_code=413, detail="حجم فایل باید حداکثر ۱۰ مگابایت باشد.")
    name = Path(file.filename or "file").name
    suffix = Path(name).suffix.lower()[:12]
    ct = (file.content_type or "application/octet-stream").lower().split(";")[0]
    image_types = {"image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp", "image/gif": ".gif"}
    video_types = {"video/mp4": ".mp4", "video/webm": ".webm", "video/ogg": ".ogv"}
    audio_types = {"audio/webm": ".webm", "audio/ogg": ".ogg", "audio/wav": ".wav", "audio/x-wav": ".wav", "audio/mpeg": ".mp3", "audio/mp4": ".m4a", "audio/aac": ".aac", "audio/3gpp": ".3gp"}
    if ct in image_types:
        media_type, ext, body = "image", image_types[ct], "📷 " + name
    elif ct in video_types:
        media_type, ext, body = "video", video_types[ct], "🎬 " + name
    elif ct in audio_types:
        media_type, ext, body = "audio", audio_types[ct], "🎤 " + name
    else:
        allowed_ext = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".psd", ".txt", ".csv", ".zip", ".rar", ".7z", ".odt", ".ods", ".odp"}
        if suffix not in allowed_ext:
            raise HTTPException(status_code=415, detail="این نوع فایل مجاز نیست. فایل‌های اداری، PDF، PSD، ZIP، عکس، صدا و ویدیو پشتیبانی می‌شوند.")
        media_type, ext, body = "file", suffix, "📎 " + name
    with db() as c:
        membership = room_member(c, room_id, user["id"])
        if not membership:
            raise HTTPException(status_code=403, detail="اجازه ارسال فایل ندارید.")
        room = c.execute("SELECT kind,owner_id,suspended FROM rooms WHERE id=?", (room_id,)).fetchone()
        if not room:
            raise HTTPException(status_code=404, detail="گروه یا کانال پیدا نشد.")
        if room["suspended"]:
            raise HTTPException(status_code=403, detail="ارسال فایل در این گروه یا کانال موقتاً توسط ادمین برنامه متوقف شده است.")
        if room["kind"] == "channel" and room["owner_id"] != user["id"] and membership["role"] not in ("owner", "admin") and not user.get("is_admin"):
            raise HTTPException(status_code=403, detail="فقط مدیر کانال یا ادمین برنامه می‌تواند پیام بفرستد.")
        filename = f"message_{user['id']}_{secrets.token_hex(12)}{ext}"
        (UPLOAD_DIR / filename).write_bytes(data)
        media_url = f"/uploads/{filename}"
        cur = c.execute("INSERT INTO messages(room_id,sender_id,body,created_at,media_url,media_type,original_name) VALUES(?,?,?,?,?,?,?)", (room_id,user["id"],body,now_iso(),media_url,media_type,name[:200]))
        msg = c.execute("SELECT messages.id, messages.sender_id, users.display_name AS username, messages.body, messages.created_at, messages.media_url, messages.media_type, messages.original_name FROM messages JOIN users ON users.id=messages.sender_id WHERE messages.id=?", (cur.lastrowid,)).fetchone()
    return dict(msg)

class AdminUnlock(BaseModel):
    code: str = Field(min_length=1, max_length=128)

@app.post("/api/admin/unlock")
def admin_unlock(data: AdminUnlock, request: Request, user=Depends(require_user)):
    if not secrets.compare_digest(data.code, ADMIN_PANEL_CODE):
        raise HTTPException(status_code=403, detail="کد پنل ادمین نادرست است.")
    request.session["admin_panel_unlocked"] = True
    return {"ok": True}

@app.get("/api/admin/overview")
def admin_overview(request: Request, user=Depends(require_user)):
    require_admin_access(request, user)
    with db() as c:
        rooms = [dict(x) for x in c.execute("SELECT id,name,kind,owner_id,created_at,suspended FROM rooms WHERE kind IN ('group','channel') ORDER BY id DESC").fetchall()]
    return {"rooms":rooms}

class RoomSuspension(BaseModel):
    suspended: bool

@app.post("/api/admin/rooms/{room_id}/suspension")
def admin_set_room_suspension(room_id: int, data: "RoomSuspension", request: Request, user=Depends(require_user)):
    require_admin_access(request, user)
    with db() as c:
        room = c.execute("SELECT id,kind FROM rooms WHERE id=?", (room_id,)).fetchone()
        if not room or room["kind"] not in ("group", "channel"):
            raise HTTPException(status_code=404, detail="گروه یا کانال پیدا نشد.")
        c.execute("UPDATE rooms SET suspended=? WHERE id=?", (1 if data.suspended else 0, room_id))
    return {"ok": True, "suspended": data.suspended}

@app.post("/api/admin/rooms/{room_id}/delete")
def admin_delete_room(room_id: int, request: Request, user=Depends(require_user)):
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="فقط ادمین واقعی برنامه اجازه حذف دارد.")
    with db() as c: c.execute("DELETE FROM rooms WHERE id=?", (room_id,))
    return {"ok":True}

@app.post("/api/admin/rooms/{room_id}/rename")
def admin_rename_room(room_id: int, data: RoomRename, request: Request, user=Depends(require_user)):
    require_admin_access(request, user)
    with db() as c:
        cur=c.execute("UPDATE rooms SET name=? WHERE id=?", (data.name.strip(),room_id))
        if not cur.rowcount: raise HTTPException(status_code=404, detail="مورد پیدا نشد.")
    return {"ok":True}

@app.post("/api/rooms/{room_id}/messages/{message_id}/delete")
def delete_message(room_id: int, message_id: int, user=Depends(require_user)):
    with db() as c:
        if not room_member(c,room_id,user["id"]): raise HTTPException(status_code=403, detail="اجازه دسترسی ندارید.")
        msg=c.execute("SELECT sender_id FROM messages WHERE id=? AND room_id=?",(message_id,room_id)).fetchone()
        room=c.execute("SELECT owner_id FROM rooms WHERE id=?",(room_id,)).fetchone()
        if not msg: raise HTTPException(status_code=404, detail="پیام پیدا نشد.")
        if msg["sender_id"]!=user["id"] and room["owner_id"]!=user["id"] and not user.get("is_admin"): raise HTTPException(status_code=403, detail="فقط فرستنده، مدیر یا ادمین می‌تواند پیام را حذف کند.")
        c.execute("DELETE FROM messages WHERE id=?",(message_id,))
    return {"ok":True}

@app.websocket("/ws/{room_id}")
async def websocket_room(websocket: WebSocket, room_id: int):
    # The signed session cookie is used for authentication.
    await websocket.accept()
    uid = websocket.session.get("uid") if hasattr(websocket, "session") else None
    if not uid:
        await websocket.close(code=4401)
        return
    with db() as c:
        membership = room_member(c, room_id, uid)
        room = c.execute("SELECT kind,owner_id FROM rooms WHERE id=?", (room_id,)).fetchone()
        user = c.execute("SELECT username FROM users WHERE id=?", (uid,)).fetchone()
    if not membership or not room or not user:
        await websocket.close(code=4403)
        return
    # This demo socket is intentionally receive-only for notifications: message
    # creation still uses the authenticated HTTP endpoint. Multi-worker production
    # deployments should use Redis Pub/Sub for cross-process fan-out.
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        return

app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")
