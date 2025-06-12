import base64
import json
import time
import asyncio
from aiohttp import web
import socketio
from tinydb import TinyDB, Query
import pysqlcipher3.dbapi2 as sqlcipher
from pathlib import Path

# SQLCipher DB for message buffering (relay)
DB_PATH = "relay_messages_encrypted.db"
DB_PASSWORD = "798laůdaf5668alfáaojdlad5458ad.@msldmsf5"

def sqlcipher_connect(path=DB_PATH, password=DB_PASSWORD):
    exists = Path(path).exists()
    conn = sqlcipher.connect(path)
    c = conn.cursor()
    c.execute(f"PRAGMA key='{password}';")
    if not exists:
        c.execute("""
        CREATE TABLE IF NOT EXISTS relay_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient_id TEXT NOT NULL,
            payload BLOB NOT NULL,
            delivered INTEGER DEFAULT 0,
            timestamp INTEGER
        );
        """)
        conn.commit()
    return conn

def store_relay_message(recipient_id, payload):
    conn = sqlcipher_connect()
    c = conn.cursor()
    c.execute("INSERT INTO relay_messages (recipient_id, payload, timestamp) VALUES (?, ?, ?)",
              (recipient_id, payload, int(time.time())))
    conn.commit()
    conn.close()

def fetch_undelivered_messages(recipient_id):
    conn = sqlcipher_connect()
    c = conn.cursor()
    c.execute("SELECT id, payload FROM relay_messages WHERE recipient_id=? AND delivered=0", (recipient_id,))
    msgs = c.fetchall()
    msg_list = []
    for msg in msgs:
        msg_list.append({"id": msg[0], "payload": msg[1]})
    conn.close()
    return msg_list

def mark_message_delivered(msg_id):
    conn = sqlcipher_connect()
    c = conn.cursor()
    c.execute("UPDATE relay_messages SET delivered=1 WHERE id=?", (msg_id,))
    conn.commit()
    conn.close()

# Key registry (TinyDB)
db = TinyDB('user_keys.json')
user_map = {}
sid_map = {}

def create_user_schema(username, ik, sik, spk, spk_sign):
    return {"username": username, "ik": ik, "sik": sik, "spk": spk, "spk_sign": spk_sign}

def find_user(username):
    query = Query()
    res = db.search(query.username == username)
    if len(res):
        return (True, res[0])
    else:
        return (False, None)

def update_user(username, user):
    query = Query()
    db.update(user, query.username == username)

def add_user(username, ik, sik, spk, spk_sign):
    user_json = create_user_schema(username, ik, sik, spk, spk_sign)
    if (find_user(username)[0]):
        update_user(username, user_json)
    else:
        db.insert(user_json)

def update_user_spk(username, spk, spk_sign):
    res = find_user(username)
    if (not res[0]):
        raise Exception(f"User {username} not found!")
    user = res[1]
    user['spk'] = spk
    user['spk_sign'] = spk_sign
    update_user(username, user)

def request_prekey(username):
    res = find_user(username)
    if (not res[0]):
        raise Exception(f"User {username} not found!")
    user = res[1]
    return {"ik": user['ik'], "sik": user['sik'], "spk": user['spk'], "spk_sign": user['spk_sign']}

# Socket.IO/Aiohttp server
sio = socketio.AsyncServer(logger=False, engineio_logger=False, async_mode='aiohttp')
app = web.Application()
sio.attach(app)

@sio.event
def connect(sid, environ):
    print('connect ', sid)

@sio.on('register_user')
async def on_register_user(sid, data):
    user_map[data["username"]] = sid
    sid_map[sid] = data["username"]
    add_user(data["username"], data["ik"],  data["sik"], data["spk"], data["spk_sig"])
    return True

@sio.on('request_users')
async def on_request_users(sid):
    return list(user_map.keys())

@sio.on('request_prekey')
async def on_request_prekey(sid, data):
    try:
        prekey_bundle = request_prekey(data["username"])
    except:
        return (False, {})
    return (True, prekey_bundle)

@sio.on('relay')
async def relay_event(sid, data):
    """
    Sealed Sender relay.
    data = {
      'recipient_id': str,
      'sealed_sender': True,
      'payload': base64-encoded bytes (JSON inside),
    }
    """
    recipient_id = data.get("recipient_id")
    payload = data.get("payload")
    if not recipient_id or not payload:
        return {"success": False, "error": "Malformed relay request"}

    # Store to SQLCipher DB for offline recipient
    store_relay_message(recipient_id, payload)

    # Relay in real-time if online
    if recipient_id in user_map:
        await sio.emit("sealed_message", data, room=user_map[recipient_id])
    return {"success": True}

@sio.on('fetch_msgs')
async def fetch_msgs(sid, data):
    """
    Client fetches undelivered sealed messages.
    data = { 'recipient_id': ... }
    """
    recipient_id = data.get("recipient_id")
    if not recipient_id:
        return {"success": False, "error": "Missing recipient_id"}
    msgs = fetch_undelivered_messages(recipient_id)
    for msg in msgs:
        await sio.emit("sealed_message", {
            "recipient_id": recipient_id,
            "payload": msg["payload"],
            "sealed_sender": True,
        }, room=sid)
        mark_message_delivered(msg["id"])
    return {"success": True, "count": len(msgs)}

@sio.event
async def disconnect(sid):
    print('disconnect')
    if sid in sid_map and sid_map[sid] in user_map:
        del user_map[sid_map[sid]]
        del sid_map[sid]

if __name__ == '__main__':
    web.run_app(app, port=5000)
