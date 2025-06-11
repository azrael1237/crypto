import sys
import os
import json
import hashlib
import secrets
import time

from PySide6 import QtCore, QtWidgets, QtGui
import requests

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from rsa import rsa_encrypt_oaep, rsa_decrypt_oaep, generate_rsa_keypair, sha256
from aes import encrypt_aes, decrypt_aes, pad, bytes_to_long, long_to_bytes

SERVER_URL = "http://127.0.0.1:8080/api"
APP_VERSION = "1.0.0"

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

def get_random_bytes(n):
    return secrets.token_bytes(n)
def get_random_int(bits):
    return int.from_bytes(get_random_bytes((bits+7)//8), "big") | (1<<(bits-1))
def sha256_(x): return hashlib.sha256(x).digest()
def long_to_bytes(val):
    width = (val.bit_length() + 7) // 8
    return val.to_bytes(width, 'big')

def open_db(username, passcode):
    import pysqlcipher3.dbapi2 as sqlcipher
    dbfile = f"db_{username}.db"
    conn = sqlcipher.connect(dbfile)
    conn.execute(f"PRAGMA key='{passcode}'")
    conn.execute(f"CREATE TABLE IF NOT EXISTS contacts (id INTEGER PRIMARY KEY, username TEXT, identifier TEXT, lastmsg TEXT, lastts INTEGER)")
    conn.execute(f"CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY, contact TEXT, direction TEXT, msg TEXT, ts INTEGER)")
    conn.commit()
    return conn

def mtproto_kdf(auth_key, msg_key, direction):
    if direction == 0:
        x = 0
    else:
        x = 8
    sha256_a = sha256_(msg_key + auth_key[x:x+36])
    sha256_b = sha256_(auth_key[40+x:40+x+36] + msg_key)
    aes_key = sha256_a[:8] + sha256_b[8:24] + sha256_a[24:32]
    aes_iv = sha256_b[:8] + sha256_a[8:24] + sha256_b[24:32]
    return aes_key, aes_iv

class SecretChat:
    def __init__(self, myname, peer, peer_identifier, dbconn):
        self.myname = myname
        self.peer = peer
        self.peer_identifier = peer_identifier
        self.db = dbconn
        self.auth_key = b'authkey'
        self.msg_count = 0
        self.session = requests.Session()
        self.accepted = False
        self.waiting = False

    def start_handshake(self):
        # Real DH handshake, Telegram style!
        # 1. Get DH params from server
        resp = self.session.post(SERVER_URL + "/get_dh_params", json={
            "user": self.myname,
            "peer": self.peer
        }).json()
        g = resp["g"]
        dh_prime = int(resp["dh_prime"], 16)
        g_a = int(resp["g_a"], 16)

        # 2. Generate own secret b and public value g_b
        b = get_random_int(2048)
        g_b = pow(g, b, dh_prime)

        # 3. Compute auth_key
        auth_key = pow(g_a, b, dh_prime)
        self.auth_key = long_to_bytes(auth_key)

        # 4. Send g_b to server
        self.session.post(SERVER_URL + "/set_dh_gb", json={
            "user": self.myname,
            "peer": self.peer,
            "g_b": hex(g_b)
        })

    def send_msg(self):
        msg = self.msg_bar.text()
        if not msg: return
        msg_bytes = msg.encode()
        msg_key = sha256_(msg_bytes)[:16]
        aes_key, aes_iv = mtproto_kdf(self.auth_key, msg_key, 0)
        ciphered = encrypt_aes(msg_bytes, aes_key)
        payload = {
            "chat_id": self._chat_id(),
            "from": self.myname,
            "msg": ciphered.hex(),
            "peer": self.peer
        }
        self.session.post(SERVER_URL + "/send_message", json=payload)
        self.db.execute("INSERT INTO messages (contact, direction, msg, ts) VALUES (?, ?, ?, ?)", (self.peer, "out", ciphered.hex(), int(time.time())))
        self.db.commit()
        self.msg_count += 1
        self.msg_bar.clear()
        self.chat_area.append(f'<div align="right"><b style="color:#25D366;">You:</b> {msg}</div>')

    def fetch_messages(self):
        r = self.session.post(SERVER_URL + "/get_messages", json={
            "chat_id":self._chat_id(),
            "peer":self.peer
        })
        messages = r.json().get("messages", [])
        out = []
        for m in messages:
            ciphered = bytes.fromhex(m["msg"])
            msg_key = ciphered[:16]
            aes_key, aes_iv = mtproto_kdf(self.auth_key, msg_key, 1)
            try:
                plain = decrypt_aes(ciphered, aes_key)
                out.append((m["from"], plain.decode(errors="replace")))
            except Exception:
                out.append((m["from"], "<DECRYPT ERROR>"))
        return out

    def _chat_id(self):
        h = hashlib.sha256((self.myname + self.peer).encode()).hexdigest()
        return h

class ChatWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SecretChatX")
        self.setGeometry(200, 100, 1024, 700)
        self.username = None
        self.identifier = None
        self.passcode = None
        self.db = None
        self.chats = {}
        self.active_peer = None
        self.requests_tab = None
        self.contacts_tab = None
        self.setup_ui()
        self.show_login()

    def setup_ui(self):
        self.tabs = QtWidgets.QTabWidget()
        self.contacts_tab = QtWidgets.QWidget()
        self.requests_tab = QtWidgets.QWidget()

        # --- CONTACTS TAB ---
        nav_widget = QtWidgets.QWidget()
        nav_layout = QtWidgets.QVBoxLayout(nav_widget)
        self.add_btn = QtWidgets.QPushButton("+ Add Contact")
        self.add_btn.clicked.connect(self.add_contact)
        self.nav = QtWidgets.QListWidget()
        self.nav.setMaximumWidth(250)
        self.nav.itemClicked.connect(self.switch_chat)
        nav_layout.addWidget(self.add_btn)
        nav_layout.addWidget(self.nav)
        nav_layout.setContentsMargins(0, 0, 0, 0)
        nav_widget.setMaximumWidth(250)

        # Chat area
        self.chat_area = QtWidgets.QTextEdit()
        self.chat_area.setReadOnly(True)
        self.msg_bar = QtWidgets.QLineEdit()
        self.send_btn = QtWidgets.QPushButton("Send")
        self.send_btn.clicked.connect(self.send_msg)
        self.update_btn = QtWidgets.QPushButton("Update")
        self.update_btn.clicked.connect(self.check_update)
        self.status_label = QtWidgets.QLabel("")
        right = QtWidgets.QWidget()
        right_layout = QtWidgets.QVBoxLayout(right)
        right_layout.addWidget(self.chat_area)
        msgrow = QtWidgets.QHBoxLayout()
        msgrow.addWidget(self.msg_bar)
        msgrow.addWidget(self.send_btn)
        right_layout.addLayout(msgrow)
        right_layout.addWidget(self.status_label)
        right_layout.addWidget(self.update_btn)
        main = QtWidgets.QWidget()
        main_layout = QtWidgets.QHBoxLayout(main)
        main_layout.addWidget(nav_widget)
        main_layout.addWidget(right)
        self.contacts_tab.setLayout(main_layout)

        # --- REQUESTS TAB ---
        self.req_list = QtWidgets.QListWidget()
        self.req_accept_btn = QtWidgets.QPushButton("Accept")
        self.req_reject_btn = QtWidgets.QPushButton("Reject")
        req_vbox = QtWidgets.QVBoxLayout()
        req_vbox.addWidget(self.req_list)
        req_hbox = QtWidgets.QHBoxLayout()
        req_hbox.addWidget(self.req_accept_btn)
        req_hbox.addWidget(self.req_reject_btn)
        req_vbox.addLayout(req_hbox)
        self.requests_tab.setLayout(req_vbox)
        self.req_accept_btn.clicked.connect(self.accept_request)
        self.req_reject_btn.clicked.connect(self.reject_request)

        self.tabs.addTab(self.contacts_tab, "Chats")
        self.tabs.addTab(self.requests_tab, "Requests")
        self.tabs.currentChanged.connect(self.tab_changed)
        self.setCentralWidget(self.tabs)

    def show_login(self):
        dlg = QtWidgets.QDialog(self)
        dlg.setWindowTitle("Login / Register")
        lay = QtWidgets.QFormLayout(dlg)
        username = QtWidgets.QLineEdit()
        identifier = QtWidgets.QLineEdit()
        passcode = QtWidgets.QLineEdit()
        passcode.setEchoMode(QtWidgets.QLineEdit.Password)
        btn = QtWidgets.QPushButton("Login/Register")
        lay.addRow("Username:", username)
        lay.addRow("Identifier (Secret):", identifier)
        lay.addRow("Passcode:", passcode)
        lay.addWidget(btn)
        def go():
            self.username = username.text()
            self.identifier = identifier.text()
            self.passcode = passcode.text()
            self.db = open_db(self.username, self.passcode)
            # Register with server
            requests.post(SERVER_URL + "/register", json={
                "username": self.username,
                "identifier": self.identifier
            })
            self.load_contacts()
            self.load_requests()
            dlg.accept()
        btn.clicked.connect(go)
        dlg.exec()

    def add_contact(self):
        dlg = QtWidgets.QDialog(self)
        dlg.setWindowTitle("Add Contact")
        lay = QtWidgets.QFormLayout(dlg)
        peername = QtWidgets.QLineEdit()
        identifier = QtWidgets.QLineEdit()
        btn = QtWidgets.QPushButton("Add")
        status = QtWidgets.QLabel()
        lay.addRow("Peer username:", peername)
        lay.addRow("Peer identifier:", identifier)
        lay.addWidget(btn)
        lay.addWidget(status)
        def add():
            uname = peername.text().strip()
            ident = identifier.text().strip()
            if not uname or not ident:
                status.setText("Please fill both fields.")
                return
            cur = self.db.execute("SELECT 1 FROM contacts WHERE username=?", (uname,))
            if cur.fetchone():
                status.setText("Contact already exists.")
                return
            req = {
                "fromuser": self.username,
                "identifier": self.identifier,
                "touser": uname
            }
            requests.post(SERVER_URL + "/chat_request", json=req)
            self.db.execute("INSERT INTO contacts (username, identifier, lastmsg, lastts) VALUES (?, ?, ?, ?)", (uname, ident, '', 0))
            self.db.commit()
            self.load_contacts()
            dlg.accept()
        btn.clicked.connect(add)
        dlg.exec()

    def load_contacts(self):
        self.nav.clear()
        cur = self.db.execute("SELECT username FROM contacts")
        for row in cur.fetchall():
            self.nav.addItem(row[0])

    def load_requests(self):
        self.req_list.clear()
        try:
            r = requests.post(SERVER_URL + "/get_requests", json={"user": self.username})
            d = r.json()
            for req in d.get("requests", []):
                fromuser = req.get("from", "")
                identifier = req.get("identifier", "")
                self.req_list.addItem(f"{fromuser} (ID: {identifier[:8]})")
        except Exception as e:
            self.req_list.addItem("Failed to load requests from server.")

    def tab_changed(self, idx):
        if idx == 1:
            self.load_requests()

    def switch_chat(self, item):
        peer = item.text()
        self.active_peer = peer
        self.chat_area.clear()
        accepted = True
        waiting = False
        resp = requests.post(SERVER_URL + "/check_accepted", json={
            "user": self.username,
            "peer": peer
        }).json()
        if not resp.get("accepted", False):
            accepted = False
            waiting = True
        if peer not in self.chats:
            contact = self.db.execute("SELECT identifier FROM contacts WHERE username=?", (peer,)).fetchone()
            if not contact:
                return
            ident = contact[0]
            self.chats[peer] = SecretChat(self.username, peer, ident, self.db)
            self.chats[peer].accepted = accepted
            self.chats[peer].waiting = waiting
            self.chats[peer].msg_bar = self.msg_bar
            self.chats[peer].chat_area = self.chat_area
            self.chats[peer].start_handshake()
        else:
            self.chats[peer].accepted = accepted
            self.chats[peer].waiting = waiting
            self.chats[peer].msg_bar = self.msg_bar
            self.chats[peer].chat_area = self.chat_area
        if not self.chats[peer].accepted:
            self.msg_bar.setDisabled(True)
            self.send_btn.setDisabled(True)
            self.status_label.setText(f"Waiting for {peer} to accept chat request")
        else:
            self.msg_bar.setDisabled(False)
            self.send_btn.setDisabled(False)
            self.status_label.setText("Key Exchange initialized, now you can chat.")
        msgs = self.db.execute("SELECT direction, msg, ts FROM messages WHERE contact=?", (peer,))
        for d, m, ts in msgs.fetchall():
            if d == "out":
                self.chat_area.append(f'<div align="right"><b style="color:#25D366;">You:</b> {m}</div>')
            else:
                self.chat_area.append(f'<div align="left"><b style="color:#075E54;">{peer}:</b> {m}</div>')

    def accept_request(self):
        row = self.req_list.currentRow()
        if row < 0: return
        item = self.req_list.item(row)
        fromuser = item.text().split(" ")[0]
        requests.post(SERVER_URL + "/accept_chat", json={
            "user": self.username,
            "peer": fromuser
        })
        cur = self.db.execute("SELECT 1 FROM contacts WHERE username=?", (fromuser,))
        if not cur.fetchone():
            r = requests.post(SERVER_URL + "/get_requests", json={"user": self.username}).json()
            ident = ""
            for req in r.get("requests", []):
                if req.get("from") == fromuser:
                    ident = req.get("identifier", "")
                    break
            self.db.execute("INSERT INTO contacts (username, identifier, lastmsg, lastts) VALUES (?, ?, ?, ?)",
                            (fromuser, ident, '', 0))
            self.db.commit()
        requests.post(SERVER_URL + "/add_contact_for_peer", json={
            "user": fromuser,
            "peer": self.username,
            "identifier": self.identifier
        })
        self.load_contacts()
        self.load_requests()
        items = self.nav.findItems(fromuser, QtCore.Qt.MatchExactly)
        if items:
            self.nav.setCurrentItem(items[0])
            self.switch_chat(items[0])
            self.status_label.setText("Key Exchange initialized, now you can chat.")
            self.msg_bar.setDisabled(False)
            self.send_btn.setDisabled(False)

    def reject_request(self):
        row = self.req_list.currentRow()
        if row < 0: return
        item = self.req_list.item(row)
        fromuser = item.text().split(" ")[0]
        requests.post(SERVER_URL + "/reject_chat", json={
            "user": self.username,
            "peer": fromuser
        })
        self.load_requests()

    def check_update(self):
        r = requests.post(SERVER_URL + "/check_update", json={"version":APP_VERSION})
        d = r.json()
        if d.get("version") != APP_VERSION:
            QtWidgets.QMessageBox.information(self, "Update", "Downloading update...")
            url = d["url"]
            newfile = "chat_new.py"
            with open(newfile, "wb") as f:
                f.write(requests.get(url).content)
            os.replace(newfile, sys.argv[0])
            QtWidgets.QMessageBox.information(self, "Update", "Restarting...")
            QtCore.QCoreApplication.quit()
            os.execv(sys.executable, [sys.executable] + sys.argv)

def main():
    app = QtWidgets.QApplication(sys.argv)
    win = ChatWindow()
    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
