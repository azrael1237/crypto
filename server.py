import os
import time
import hashlib
import secrets
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

DH_P = int(
    "C71CAEB9C6B1C9048E6C522F70F13F73980D40238E3E21C14934D037563D930F"
    "48198A0AA7C14058229493D22530F4DBFA336F6E0AC925139543AED44CCE7C3720"
    "FD51F6B7E1FA22F07F7E8E1764B8C72B6A1E5D6E22C5F6F6C7A70F21F2B3A278A4"
    "D3A9E1C04D5E3A651E436FFD2B4F6F0B1C3E3A7E8E01D1F6E93E2B2F7D1E6A31B5"
    "3B5C43A0C70E0F2B5E03C5D1E8A9F7C7B950B1E3F2D7C1E8D0A1B2C3D4E5F6A7B8"
    "B9C8D7E6F5A4B3C2D1E0F9E8D7C6B5A4F3E2D1C0B9A8F7E6D5C4B3A2F1E0D9C8B7"
    "A6F5E4D3C2B1A0F9E8D7C6B5A4F3E2D1C0B9A8F7E6D5C4B3A2F1E0D9C8B7A6F5E4"
    "D3C2B1A0F9E8D7C6B5A4F3E2D1C0B9A8F7E6D5C4B3A2F1E0D9C8B7A6F5E4D3C2B1",
    16
)
DH_G = 7

USERS = {}           # username: {"identifier":..., "accepted_chats": set()}
CHAT_REQUESTS = {}   # username: [{"from":..., "identifier":...}]
MESSAGES = {}        # chat_id: [ {from, msg, ts}, ... ]
ACCEPTED_CHATS = set() # tuple (user, peer) if chat is accepted
DH_SESSIONS = {}     # (user, peer): { "a": ..., "g_a": ..., "auth_key": ... }

UPDATE_VERSION = "1.0.0"
UPDATE_URL = "https://example.com/latest-chat.py"

def get_random_int(bits):
    return int.from_bytes(secrets.token_bytes((bits+7)//8), "big") | (1<<(bits-1))

def server_time():
    return int(time.time())

def get_chat_id(user1, user2):
    u1, u2 = sorted([user1, user2])
    return hashlib.sha256((u1 + u2).encode()).hexdigest()

class Handler(BaseHTTPRequestHandler):
    def _set_headers(self, code=200):
        self.send_response(code)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

    def do_POST(self):
        length = int(self.headers['Content-Length'])
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw)
        except Exception:
            self._set_headers(400)
            self.wfile.write(b'{"error":"bad json"}')
            return
        path = urlparse(self.path).path

        if path == '/api/register':
            username = data.get("username")
            identifier = data.get("identifier")
            if not username or not identifier:
                self._set_headers()
                self.wfile.write(json.dumps({"error": "missing username or identifier"}).encode())
                return
            USERS[username] = {"identifier": identifier, "accepted_chats": set()}
            CHAT_REQUESTS.setdefault(username, [])
            self._set_headers()
            self.wfile.write(json.dumps({"ok": True}).encode())

        elif path == '/api/chat_request':
            fromuser = data.get("fromuser")
            identifier = data.get("identifier")
            touser = data.get("touser")
            if not all([fromuser, identifier, touser]):
                self._set_headers()
                self.wfile.write(json.dumps({"error":"missing fields"}).encode())
                return
            if touser not in CHAT_REQUESTS:
                CHAT_REQUESTS[touser] = []
            already = any(r["from"] == fromuser for r in CHAT_REQUESTS[touser])
            if not already:
                CHAT_REQUESTS[touser].append({"from": fromuser, "identifier": identifier})
            self._set_headers()
            self.wfile.write(json.dumps({"ok": True}).encode())

        elif path == '/api/accept_chat':
            user = data.get("user")
            peer = data.get("peer")
            if not user or not peer:
                self._set_headers()
                self.wfile.write(json.dumps({"error": "missing params"}).encode())
                return
            ACCEPTED_CHATS.add((user, peer))
            ACCEPTED_CHATS.add((peer, user))
            if user in CHAT_REQUESTS:
                CHAT_REQUESTS[user] = [r for r in CHAT_REQUESTS[user] if r["from"] != peer]
            self._set_headers()
            self.wfile.write(json.dumps({"ok": True}).encode())

        elif path == '/api/reject_chat':
            user = data.get("user")
            peer = data.get("peer")
            if not user or not peer:
                self._set_headers()
                self.wfile.write(json.dumps({"error": "missing params"}).encode())
                return
            if user in CHAT_REQUESTS:
                CHAT_REQUESTS[user] = [r for r in CHAT_REQUESTS[user] if r["from"] != peer]
            self._set_headers()
            self.wfile.write(json.dumps({"ok": True}).encode())

        elif path == '/api/check_accepted':
            user = data.get("user")
            peer = data.get("peer")
            accepted = ((user, peer) in ACCEPTED_CHATS)
            self._set_headers()
            self.wfile.write(json.dumps({"accepted": accepted}).encode())

        elif path == '/api/send_message':
            chat_id = get_chat_id(data["from"], data["peer"])
            if chat_id not in MESSAGES:
                MESSAGES[chat_id] = []
            MESSAGES[chat_id].append({
                "from": data["from"],
                "msg": data["msg"],
                "ts": server_time()
            })
            self._set_headers()
            self.wfile.write(json.dumps({"ok": True}).encode())

        elif path == '/api/get_messages':
            peer = data.get("peer")
            user = data.get("chat_id")
            chat_id = get_chat_id(user, peer) if peer and user else data.get("chat_id")
            if chat_id in MESSAGES:
                resp = {"messages": MESSAGES[chat_id]}
            else:
                resp = {"messages": []}
            self._set_headers()
            self.wfile.write(json.dumps(resp).encode())

        elif path == '/api/get_requests':
            user = data.get("user")
            reqs = CHAT_REQUESTS.get(user, [])
            self._set_headers()
            self.wfile.write(json.dumps({"requests": reqs}).encode())

        elif path == '/api/get_dh_params':
            user = data.get("user")
            peer = data.get("peer")
            g = DH_G
            dh_prime = DH_P
            a = get_random_int(2048)
            g_a = pow(g, a, dh_prime)
            DH_SESSIONS[(user, peer)] = {"a": a, "g_a": g_a}
            self._set_headers()
            self.wfile.write(json.dumps({
                "g": g,
                "dh_prime": hex(dh_prime),
                "g_a": hex(g_a)
            }).encode())

        elif path == '/api/set_dh_gb':
            user = data.get("user")
            peer = data.get("peer")
            g_b = int(data.get("g_b"), 16)
            session = DH_SESSIONS.get((user, peer))
            if not session:
                self._set_headers(400)
                self.wfile.write(json.dumps({"error": "no session"}).encode())
                return
            a = session["a"]
            dh_prime = DH_P
            auth_key = pow(g_b, a, dh_prime)
            session["auth_key"] = auth_key
            self._set_headers()
            self.wfile.write(json.dumps({"ok": True}).encode())

        elif path == '/api/add_contact_for_peer':
            user = data.get("user")
            peer = data.get("peer")
            identifier = data.get("identifier")
            if user not in USERS:
                USERS[user] = {"identifier": identifier, "accepted_chats": set()}
            self._set_headers()
            self.wfile.write(json.dumps({"ok": True}).encode())

        elif path == '/api/check_update':
            self._set_headers()
            self.wfile.write(json.dumps({"version": UPDATE_VERSION, "url": UPDATE_URL}).encode())

        else:
            self._set_headers()
            self.wfile.write(json.dumps({"error": "bad endpoint"}).encode())

def main():
    server = HTTPServer(("0.0.0.0", 8080), Handler)
    print("Server running on 0.0.0.0:8080")
    server.serve_forever()

if __name__ == "__main__":
    main()
