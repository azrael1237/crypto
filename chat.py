import sys
import base64
import time
import json
from PySide6.QtWidgets import (
    QApplication, QPushButton, QVBoxLayout, QHBoxLayout, QTextEdit, QLineEdit,
    QWidget, QLabel, QMainWindow, QListWidget, QSplitter, QFrame, QStackedWidget, QInputDialog
)
from PySide6.QtCore import Qt, QTimer, Signal, QObject, QThread
from PySide6.QtGui import QFont, QTextCursor, QPixmap, QImage
import pydenticon
import pysqlcipher3.dbapi2 as sqlcipher
from pathlib import Path

from msgdr import DRSession, DHPublicKey, DHKeyPair, Message
from ecdsa import sign_message, verify_signature, make_keypair
import socketio

DB_PATH = "client_encrypted.db"
DB_PASSWORD = "798laůdaf5668alfáaojdlad5458ad.@msldmsf5"

# SQLCipher local DB
def sqlcipher_connect(path=DB_PATH, password=DB_PASSWORD):
    exists = Path(path).exists()
    conn = sqlcipher.connect(path)
    c = conn.cursor()
    c.execute(f"PRAGMA key='{password}';")
    if not exists:
        c.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            contact TEXT NOT NULL,
            direction TEXT NOT NULL,
            timestamp INTEGER,
            payload BLOB
        );
        """)
        c.execute("""
        CREATE TABLE IF NOT EXISTS contacts (
            username TEXT PRIMARY KEY,
            fingerprint TEXT,
            pubkey TEXT
        );
        """)
        conn.commit()
    return conn

def store_message(contact, direction, payload):
    conn = sqlcipher_connect()
    c = conn.cursor()
    c.execute("INSERT INTO messages (contact, direction, timestamp, payload) VALUES (?, ?, ?, ?)",
              (contact, direction, int(time.time()), payload))
    conn.commit()
    conn.close()

def fetch_messages(contact):
    conn = sqlcipher_connect()
    c = conn.cursor()
    c.execute("SELECT direction, timestamp, payload FROM messages WHERE contact=? ORDER BY timestamp ASC", (contact,))
    msgs = c.fetchall()
    conn.close()
    return msgs

def store_contact(username, fingerprint, pubkey):
    conn = sqlcipher_connect()
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO contacts (username, fingerprint, pubkey) VALUES (?, ?, ?)",
              (username, fingerprint, pubkey))
    conn.commit()
    conn.close()

def fetch_contacts():
    conn = sqlcipher_connect()
    c = conn.cursor()
    c.execute("SELECT username, fingerprint, pubkey FROM contacts")
    lst = c.fetchall()
    conn.close()
    return lst

# Sealed Sender
def make_sender_certificate(sender, privkey, ephemeral_pubkey):
    ts = int(time.time())
    cert = {
        "sender": sender,
        "timestamp": ts,
        "ephemeral_key": str(ephemeral_pubkey)
    }
    # Sign (ECDSA, see ecdsa.py)
    msg = (sender + str(ts) + str(ephemeral_pubkey)).encode()
    signature = sign_message(privkey, msg)
    cert["signature"] = [int(signature[0]), int(signature[1])]
    return cert

def verify_sender_certificate(cert, pubkey):
    sender = cert["sender"]
    ts = cert["timestamp"]
    ephemeral_key = cert["ephemeral_key"]
    sig = tuple(cert["signature"])
    msg = (sender + str(ts) + str(ephemeral_key)).encode()
    return verify_signature(pubkey, msg, sig) == 'signature matches'

# Socket.IO Client
class SocketClient(QObject):
    sealed_message_received = Signal(dict)
    contact_list_updated = Signal(list)

    def __init__(self, username):
        super().__init__()
        self.username = username
        self.sio = socketio.Client()
        self.sio.on("sealed_message", self.on_sealed_message)
        self.contacts = set()
        self._connect()

    def _connect(self):
        self.sio.connect("http://localhost:5000")

    def register_user(self, ik, sik, spk, spk_sig):
        self.sio.emit('register_user', {
            "username": self.username,
            "ik": ik,
            "sik": sik,
            "spk": spk,
            "spk_sig": spk_sig
        })

    def request_users(self):
        users = self.sio.call('request_users')
        self.contact_list_updated.emit(users)
        return users

    def fetch_msgs(self):
        self.sio.emit("fetch_msgs", {"recipient_id": self.username})

    def relay(self, recipient_id, payload):
        self.sio.emit("relay", {
            "recipient_id": recipient_id,
            "sealed_sender": True,
            "payload": payload,
        })

    def on_sealed_message(self, data):
        self.sealed_message_received.emit(data)

# Double Ratchet Engine + Sealed Sender
class CryptoEngine:
    def __init__(self, username):
        self.username = username
        self.session_map = {}
        self.identity_priv, self.identity_pub = make_keypair()
        self.contacts = {}

    def add_contact(self, user, pubkey, fingerprint):
        self.contacts[user] = {
            "pubkey": pubkey,
            "fingerprint": fingerprint
        }
        store_contact(user, fingerprint, str(pubkey))

    def get_fingerprint(self, pubkey):
        return hashlib.sha256(str(pubkey).encode()).hexdigest()[:16]

    def start_dr_session(self, user):
        if user not in self.session_map:
            self.session_map[user] = DRSession()
        return self.session_map[user]

    def encrypt_message(self, user, plaintext):
        # DR: get/create session
        session = self.start_dr_session(user)
        # Prepare sender cert (Sealed Sender)
        ephemeral_priv, ephemeral_pub = make_keypair()
        sender_cert = make_sender_certificate(self.username, self.identity_priv, ephemeral_pub)
        # Encrypt
        associated_data = b"Signal-DR"
        msg = session.encrypt_message(plaintext, associated_data)
        header_bytes = bytes(msg.header)
        payload = {
            "ciphertext": base64.b64encode(msg.ct).decode(),
            "header": base64.b64encode(header_bytes).decode(),
            "sender_cert": sender_cert
        }
        payload_bytes = base64.b64encode(json.dumps(payload).encode())
        return payload_bytes

    def decrypt_payload(self, user, payload_bytes):
        payload = json.loads(base64.b64decode(payload_bytes).decode())
        # Verify sender certificate
        sender_cert = payload["sender_cert"]
        pubkey = self.contacts.get(sender_cert["sender"], {}).get("pubkey")
        if not pubkey:
            return ("[Unknown Sender]", "")
        if not verify_sender_certificate(sender_cert, pubkey):
            return ("[Signature Mismatch]", "")
        # DR session
        session = self.start_dr_session(sender_cert["sender"])
        header = base64.b64decode(payload["header"])
        ct = base64.b64decode(payload["ciphertext"])
        msg = Message(session._state._send.header.__class__.from_bytes(header), ct)
        plaintext = session.decrypt_message(msg, b"Signal-DR")
        return (sender_cert["sender"], plaintext)

# Indenticon avatar
def get_indenticon(username, size=56):
    img = pyindecticon.render(username, size=size)
    buffer = img.tobytes()
    qimage = QImage(buffer, img.width, img.height, QImage.Format_RGBA8888)
    pixmap = QPixmap.fromImage(qimage)
    return pixmap

# UI
class ChatScreen(QWidget):
    def __init__(self, parent, username, crypto, sock):
        super().__init__()
        self.parent = parent
        self.setWindowTitle("Secure Chat")
        self.crypto = crypto
        self.sock = sock
        self.username = username
        self.active_contact = None

        # Left: contacts
        self.contacts_list = QListWidget()
        self.contacts_list.setMaximumWidth(220)
        self.contacts_list.setFont(QFont("Arial", 12))
        self.contacts_list.itemClicked.connect(self.select_contact)

        # Right: chat history + input
        self.chat_history = QTextEdit()
        self.chat_history.setReadOnly(True)
        self.chat_history.setFont(QFont("Consolas", 11))
        self.input_field = QLineEdit()
        self.input_field.setFont(QFont("Arial", 12))
        self.input_field.returnPressed.connect(self.send_message)
        self.send_btn = QPushButton("Send")
        self.send_btn.clicked.connect(self.send_message)

        self.fingerprint_label = QLabel()
        self.fingerprint_label.setFont(QFont("Monospace", 9))
        self.fingerprint_label.setStyleSheet("background: #f4f4f4; padding: 6px;")
        self.fingerprint_label.setMinimumHeight(22)

        input_box = QHBoxLayout()
        input_box.addWidget(self.input_field)
        input_box.addWidget(self.send_btn)

        chat_box = QVBoxLayout()
        chat_box.addWidget(self.fingerprint_label)
        chat_box.addWidget(self.chat_history)
        chat_box.addLayout(input_box)

        # Splitter layout
        splitter = QSplitter(Qt.Horizontal)
        left = QWidget()
        left.setLayout(QVBoxLayout())
        left.layout().addWidget(self.contacts_list)
        splitter.addWidget(left)

        right = QWidget()
        right.setLayout(chat_box)
        splitter.addWidget(right)

        layout = QHBoxLayout()
        layout.addWidget(splitter)
        self.setLayout(layout)

        # Poll for incoming messages
        self.poll_timer = QTimer()
        self.poll_timer.timeout.connect(self.refresh_contacts)
        self.poll_timer.start(3500)

        self.sock.sealed_message_received.connect(self.handle_sealed_message)
        self.sock.contact_list_updated.connect(self.update_contacts)

        self.refresh_contacts()

    def refresh_contacts(self):
        users = self.sock.request_users()
        self.update_contacts(users)

    def update_contacts(self, users):
        self.contacts_list.clear()
        for u in users:
            if u != self.username:
                item = QListWidget.QListWidgetItem(u)
                item.setData(Qt.UserRole, u)
                pixmap = get_indenticon(u, 40)
                item.setIcon(pixmap)
                self.contacts_list.addItem(item)

    def select_contact(self, item):
        contact = item.data(Qt.UserRole)
        self.active_contact = contact
        self.load_history()
        pubkey = self.crypto.contacts.get(contact, {}).get("pubkey")
        fp = self.crypto.get_fingerprint(pubkey) if pubkey else "[No fingerprint]"
        self.fingerprint_label.setText(f"Fingerprint: <b>{fp}</b>")

    def load_history(self):
        if not self.active_contact:
            return
        msgs = fetch_messages(self.active_contact)
        self.chat_history.clear()
        for direction, ts, payload in msgs:
            if direction == "out":
                self.chat_history.append(f"<font color='green'><b>Me:</b></font> {self._decrypt_and_display(payload, self.active_contact, outbound=True)} <span style='color: #888;'>[{time.strftime('%H:%M', time.localtime(ts))}]</span>")
            else:
                sender, msg = self.crypto.decrypt_payload(self.active_contact, payload)
                self.chat_history.append(f"<font color='blue'><b>{sender}:</b></font> {msg} <span style='color: #888;'>[{time.strftime('%H:%M', time.localtime(ts))}]</span>")

        self.chat_history.moveCursor(QTextCursor.End)

    def send_message(self):
        if not self.active_contact:
            return
        msg = self.input_field.text().strip()
        if not msg:
            return
        payload = self.crypto.encrypt_message(self.active_contact, msg)
        self.sock.relay(self.active_contact, payload)
        store_message(self.active_contact, "out", payload)
        self.input_field.clear()
        self.load_history()

    def handle_sealed_message(self, data):
        recipient_id = data.get("recipient_id")
        payload = data.get("payload")
        if recipient_id == self.username and self.active_contact:
            store_message(self.active_contact, "in", payload)
            self.load_history()

    def _decrypt_and_display(self, payload, contact, outbound=False):
        if outbound:
            # Display own message
            try:
                p = json.loads(base64.b64decode(payload).decode())
                return base64.b64decode(p["ciphertext"]).decode(errors="replace")
            except Exception:
                return "[error]"
        else:
            try:
                sender, msg = self.crypto.decrypt_payload(contact, payload)
                return msg
            except Exception:
                return "[error]"

class ContactsScreen(QWidget):
    def __init__(self, parent, crypto, sock, username):
        super().__init__()
        self.parent = parent
        self.crypto = crypto
        self.sock = sock
        self.username = username
        self.setWindowTitle("Contacts")
        self.contacts_list = QListWidget()
        self.contacts_list.setFont(QFont("Arial", 12))
        self.contacts_list.itemDoubleClicked.connect(self.open_chat)
        self.import_btn = QPushButton("Import Contact")
        self.import_btn.clicked.connect(self.import_contact)
        layout = QVBoxLayout()
        layout.addWidget(QLabel(f"Welcome <b>{username}</b>"))
        layout.addWidget(self.contacts_list)
        layout.addWidget(self.import_btn)
        self.setLayout(layout)
        self.refresh_contacts()

    def refresh_contacts(self):
        users = self.sock.request_users()
        self.contacts_list.clear()
        for u in users:
            if u != self.username:
                item = QListWidget.QListWidgetItem(u)
                item.setData(Qt.UserRole, u)
                pixmap = get_indenticon(u, 40)
                item.setIcon(pixmap)
                self.contacts_list.addItem(item)

    def import_contact(self):
        text, ok = QInputDialog.getText(self, "Import Contact", "Paste public key:")
        if ok and text:
            # Assume format: username|pubkey
            try:
                username, pubkey = text.split("|", 1)
                fingerprint = self.crypto.get_fingerprint(pubkey)
                self.crypto.add_contact(username, pubkey, fingerprint)
                store_contact(username, fingerprint, pubkey)
                self.refresh_contacts()
            except Exception:
                pass

    def open_chat(self, item):
        contact = item.data(Qt.UserRole)
        self.parent.open_chat_screen(contact)

class FingerprintDialog(QWidget):
    def __init__(self, username, pubkey, fingerprint):
        super().__init__()
        self.setWindowTitle("Fingerprint Verification")
        layout = QVBoxLayout()
        layout.addWidget(QLabel(f"<b>Contact:</b> {username}"))
        layout.addWidget(QLabel(f"<b>Public Key:</b> {pubkey}"))
        layout.addWidget(QLabel(f"<b>Fingerprint:</b> {fingerprint}"))
        self.setLayout(layout)

class MainWindow(QMainWindow):
    def __init__(self, username):
        super().__init__()
        self.setWindowTitle("Encrypted Messenger")
        self.username = username
        self.crypto = CryptoEngine(username)
        self.sock = SocketClient(username)
        self.stacked = QStackedWidget()
        self.contacts_screen = ContactsScreen(self, self.crypto, self.sock, username)
        self.chat_screen = ChatScreen(self, username, self.crypto, self.sock)
        self.stacked.addWidget(self.contacts_screen)
        self.stacked.addWidget(self.chat_screen)
        self.setCentralWidget(self.stacked)
        self.resize(980, 680)
        self.contacts_screen.contacts_list.itemDoubleClicked.connect(self.switch_to_chat)

    def open_chat_screen(self, contact):
        self.chat_screen.active_contact = contact
        self.chat_screen.load_history()
        self.stacked.setCurrentWidget(self.chat_screen)

    def switch_to_chat(self, item):
        contact = item.data(Qt.UserRole)
        self.open_chat_screen(contact)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    username, ok = QInputDialog.getText(None, "Login", "Enter your username:")
    if not ok or not username:
        sys.exit(0)
    mw = MainWindow(username)
    mw.show()
    sys.exit(app.exec())
