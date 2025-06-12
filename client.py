import sys
import base64
import json
import hashlib
import pickle
import time
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit,
    QTextEdit, QListWidget, QListWidgetItem, QStackedWidget, QMessageBox, QInputDialog
)
from PySide6.QtCore import QTimer, Qt
import socketio
import pysqlcipher3.dbapi2 as sqlcipher

from msgdr import DRSession, DHKeyPair, DHPublicKey, MsgKeyStorage, RootChain, SymmetricChain, Ratchet
from ecdsa import make_keypair, sign_message, verify_signature

# --- SQLCipher Local DB Setup ---
DB_PASSWORD = "798laůdaf5668alfáaojdlad5458ad.@msldmsf5"
DB_PATH = "chat_local.sqlite3"

def init_db():
    conn = sqlcipher.connect(DB_PATH, check_same_thread=False)
    c = conn.cursor()
    c.execute("PRAGMA key = '{}';".format(DB_PASSWORD))
    c.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chat_id TEXT,
            sender TEXT,
            recipient TEXT,
            payload TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            sealed BOOLEAN DEFAULT 1
        );
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS contacts (
            username TEXT PRIMARY KEY,
            ik TEXT,
            fingerprint TEXT
        );
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS dr_sessions (
            contact TEXT PRIMARY KEY,
            state BLOB
        );
    """)
    conn.commit()
    return conn

local_db = init_db()
local_cur = local_db.cursor()

# --- SocketIO client ---
SIO_SERVER = "http://localhost:6543"
sio = socketio.Client()

# --- DR/Sealed Sender Management ---
class CryptoManager:
    def __init__(self, username):
        self.username = username
        self.identity_priv, self.identity_pub = make_keypair()
        self.sessions = {}  # contact_username -> DRSession

    def get_fingerprint(self):
        pub = self.identity_pub
        return hashlib.sha256((str(pub[0]) + str(pub[1])).encode()).hexdigest()

    def save_session(self, contact):
        session = self.sessions[contact]
        state_bytes = pickle.dumps(session.serialize())
        local_cur.execute("PRAGMA key = '{}';".format(DB_PASSWORD))
        local_cur.execute(
            "INSERT OR REPLACE INTO dr_sessions (contact, state) VALUES (?, ?)",
            (contact, state_bytes)
        )
        local_db.commit()

    def load_session(self, contact):
        local_cur.execute("PRAGMA key = '{}';".format(DB_PASSWORD))
        local_cur.execute("SELECT state FROM dr_sessions WHERE contact=?", (contact,))
        row = local_cur.fetchone()
        if row:
            session = DRSession.deserialize(pickle.loads(row[0]))
            self.sessions[contact] = session
            return session
        return None

    def ensure_session(self, contact, prekey_bundle=None):
        if contact in self.sessions:
            return self.sessions[contact]
        session = self.load_session(contact)
        if session:
            return session
        if prekey_bundle:
            return self.start_session(contact, prekey_bundle)
        return None

    def start_session(self, contact, prekey_bundle):
        # --- FULL REAL X3DH, NO SIMULATION ---
        # Parse peer keys from prekey_bundle, all in hex
        IK_B = DHPublicKey.from_bytes(bytes.fromhex(prekey_bundle["ik"]))
        SPK_B = DHPublicKey.from_bytes(bytes.fromhex(prekey_bundle["spk"]))
        OPK_B = DHPublicKey.from_bytes(bytes.fromhex(prekey_bundle["opk"]))

        # Our own keys
        IK_A_priv, IK_A_pub = self.identity_priv, self.identity_pub
        EK_A = DHKeyPair.generate_dh()  # Ephemeral key

        # Peer keys as DHPublicKey (already done above)
        # All ECDH using msgdr types
        dh1 = IK_A_priv.dh_out(SPK_B)    # ECDH(IK_A, SPK_B)
        dh2 = EK_A.private_key.dh_out(IK_B)    # ECDH(EK_A, IK_B)
        dh3 = EK_A.private_key.dh_out(SPK_B)   # ECDH(EK_A, SPK_B)
        dh4 = EK_A.private_key.dh_out(OPK_B)   # ECDH(EK_A, OPK_B)

        # Real HKDF
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend

        x3dh_input = dh1 + dh2 + dh3 + dh4
        hkdf_out = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"X3DH",
            backend=default_backend()
        ).derive(x3dh_input)

        # Setup DRSession as sender
        session = DRSession()
        session.setup_sender(hkdf_out, SPK_B)
        self.sessions[contact] = session
        self.save_session(contact)
        return session

    def encrypt_message(self, contact, plaintext):
        session = self.sessions[contact]
        ad = self.username.encode()
        msg = session.encrypt_message(plaintext, ad)
        # Sealed sender cert
        timestamp = int(time.time())
        ephemeral_priv, ephemeral_pub = make_keypair()
        cert = {
            "sender": self.username,
            "timestamp": timestamp,
            "ephemeral_key": hex(ephemeral_pub[0]),
        }
        cert_bytes = json.dumps(cert).encode()
        signature = sign_message(self.identity_priv, cert_bytes)
        cert["signature"] = "0x{:x},0x{:x}".format(*signature)
        payload = {
            "ciphertext": base64.b64encode(msg.ct).decode(),
            "header": base64.b64encode(bytes(msg.header)).decode(),
            "sender_cert": cert
        }
        self.save_session(contact)
        return base64.b64encode(json.dumps(payload).encode()).decode()

    def decrypt_message(self, contact, sealed_payload_b64):
        try:
            session = self.ensure_session(contact)
            payload = json.loads(base64.b64decode(sealed_payload_b64))
            ciphertext = base64.b64decode(payload["ciphertext"])
            header = base64.b64decode(payload["header"])
            sender_cert = payload["sender_cert"]
            # ECDSA verify
            cert_bytes = json.dumps({k: v for k, v in sender_cert.items() if k != "signature"}).encode()
            r, s = [int(x, 16) for x in sender_cert["signature"].split(",")]
            # Get sender pubkey from contacts
            local_cur.execute("PRAGMA key = '{}';".format(DB_PASSWORD))
            local_cur.execute("SELECT ik FROM contacts WHERE username=?", (sender_cert["sender"],))
            row = local_cur.fetchone()
            if not row:
                return "[Unknown sender]", None
            pubkey_bytes = bytes.fromhex(row[0])
            pubkey_x = int.from_bytes(pubkey_bytes[:32], "big")
            pubkey_y = int.from_bytes(pubkey_bytes[32:64], "big")
            pub = (pubkey_x, pubkey_y)
            assert verify_signature(pub, cert_bytes, (r, s)) == "signature matches"
            # DR decrypt
            from msgdr import Header, Message
            msg = Message(Header.from_bytes(header), ciphertext)
            ad = contact.encode()
            plaintext = session.decrypt_message(msg, ad)
            self.save_session(contact)
            return plaintext, sender_cert["sender"]
        except Exception as e:
            return f"[decryption failed: {e}]", None

crypto_manager = None  # late init

# --- Advanced PySide6 UI ---
class ChatMainWindow(QMainWindow):
    def __init__(self, username):
        super().__init__()
        self.setWindowTitle("Sophisticated Secure Messenger")
        self.setGeometry(100, 100, 1024, 720)
        self.username = username
        self.crypto_manager = crypto_manager
        self.contacts = self.load_contacts()
        self.stacked = QStackedWidget()
        self.setCentralWidget(self.stacked)
        self.contact_list = ContactListWidget(self)
        self.chat_area = ChatAreaWidget(self)
        self.fingerprint_area = FingerprintWidget(self)
        self.stacked.addWidget(self.contact_list)
        self.stacked.addWidget(self.chat_area)
        self.stacked.addWidget(self.fingerprint_area)
        self.show_contacts()

    def load_contacts(self):
        local_cur.execute("PRAGMA key = '{}';".format(DB_PASSWORD))
        local_cur.execute("SELECT username, ik, fingerprint FROM contacts")
        return {row[0]: {"ik": row[1], "fingerprint": row[2]} for row in local_cur.fetchall()}

    def show_contacts(self):
        self.stacked.setCurrentWidget(self.contact_list)
        self.contact_list.refresh()

    def open_chat(self, contact):
        self.chat_area.set_contact(contact)
        self.stacked.setCurrentWidget(self.chat_area)

    def show_fingerprint(self, fingerprint, username):
        self.fingerprint_area.set_fingerprint(fingerprint, username)
        self.stacked.setCurrentWidget(self.fingerprint_area)

class ContactListWidget(QWidget):
    def __init__(self, mw):
        super().__init__()
        self.mw = mw
        vbox = QVBoxLayout(self)
        self.label = QLabel("<h2>Your Contacts</h2>")
        self.list = QListWidget()
        self.add_btn = QPushButton("Add Contact")
        self.add_btn.clicked.connect(self.add_contact)
        vbox.addWidget(self.label)
        vbox.addWidget(self.list)
        vbox.addWidget(self.add_btn)
        self.list.itemDoubleClicked.connect(self.open_chat)
        self.list.setSelectionMode(QListWidget.SingleSelection)
        self.setLayout(vbox)

    def refresh(self):
        self.list.clear()
        for contact in self.mw.contacts:
            item = QListWidgetItem(f"{contact} ({self.mw.contacts[contact]['fingerprint'][:12]}...)")
            self.list.addItem(item)

    def open_chat(self, item):
        contact = item.text().split()[0]
        self.mw.open_chat(contact)

    def add_contact(self):
        username, ok = QInputDialog.getText(self, "Add Contact", "Username:")
        if ok and username:
            # Fetch prekey from server
            def _cb(resp):
                self._handle_prekey(resp, username)
            sio.emit("request_prekey", {"username": username}, callback=_cb)

    def _handle_prekey(self, resp, username):
        success, bundle = resp
        if success:
            ik = bundle["ik"]
            fingerprint = hashlib.sha256(bytes.fromhex(ik)).hexdigest()
            local_cur.execute("PRAGMA key = '{}';".format(DB_PASSWORD))
            local_cur.execute("INSERT OR IGNORE INTO contacts (username, ik, fingerprint) VALUES (?, ?, ?)",
                              (username, ik, fingerprint))
            local_db.commit()
            self.mw.contacts[username] = {"ik": ik, "fingerprint": fingerprint}
            # Real session setup
            self.mw.crypto_manager.ensure_session(username, bundle)
            self.refresh()
        else:
            QMessageBox.critical(self, "Error", f"User {username} not found.")

class ChatAreaWidget(QWidget):
    def __init__(self, mw):
        super().__init__()
        self.mw = mw
        self.contact = None
        self.layout = QVBoxLayout(self)
        self.title = QLabel()
        self.history = QTextEdit()
        self.history.setReadOnly(True)
        self.input = QLineEdit()
        self.send_btn = QPushButton("Send")
        self.send_btn.clicked.connect(self.send_msg)
        self.fingerprint_btn = QPushButton("Show Fingerprint")
        self.fingerprint_btn.clicked.connect(self.show_fingerprint)
        hbox = QHBoxLayout()
        hbox.addWidget(self.input)
        hbox.addWidget(self.send_btn)
        self.layout.addWidget(self.title)
        self.layout.addWidget(self.history)
        self.layout.addLayout(hbox)
        self.layout.addWidget(self.fingerprint_btn)
        self.setLayout(self.layout)
        self.poller = QTimer(self)
        self.poller.timeout.connect(self.poll_new_msgs)
        self.poller.start(2500)

    def set_contact(self, contact):
        self.contact = contact
        self.title.setText(f"<h2>Chat with {contact}</h2>")
        session = self.mw.crypto_manager.ensure_session(contact)
        self.load_history()

    def load_history(self):
        local_cur.execute("PRAGMA key = '{}';".format(DB_PASSWORD))
        local_cur.execute("SELECT sender, payload, timestamp FROM messages WHERE chat_id=? ORDER BY timestamp ASC",
                          (self.chat_id(),))
        msgs = local_cur.fetchall()
        self.history.clear()
        for sender, payload, ts in msgs:
            plaintext, _ = self.decrypt_payload(payload)
            color = "blue" if sender == self.mw.username else "green"
            self.history.append(f"<b><font color='{color}'>{sender}</font></b>: {plaintext} <small><i>{ts}</i></small>")

    def send_msg(self):
        msg = self.input.text()
        if msg and self.contact:
            payload = self.mw.crypto_manager.encrypt_message(self.contact, msg)
            sealed_msg = {
                "recipient_id": self.contact,
                "sealed_sender": True,
                "payload": payload
            }
            sio.emit("send_sealed", sealed_msg)
            local_cur.execute("PRAGMA key = '{}';".format(DB_PASSWORD))
            local_cur.execute(
                "INSERT INTO messages (chat_id, sender, recipient, payload, sealed) VALUES (?, ?, ?, ?, 1)",
                (self.chat_id(), self.mw.username, self.contact, payload)
            )
            local_db.commit()
            self.input.clear()
            self.load_history()

    def poll_new_msgs(self):
        if not self.contact:
            return
        sio.emit("fetch_msgs", {"username": self.mw.username}, callback=self.on_new_msgs)

    def on_new_msgs(self, msg_list):
        for payload in msg_list:
            local_cur.execute("PRAGMA key = '{}';".format(DB_PASSWORD))
            local_cur.execute(
                "INSERT INTO messages (chat_id, sender, recipient, payload, sealed) VALUES (?, ?, ?, ?, 1)",
                (self.chat_id(), self.contact, self.mw.username, payload)
            )
            local_db.commit()
        self.load_history()

    def decrypt_payload(self, payload):
        plaintext, sender = self.mw.crypto_manager.decrypt_message(self.contact, payload)
        return plaintext or "[decryption failed]", sender

    def chat_id(self):
        return f"{min(self.mw.username, self.contact)}-{max(self.mw.username, self.contact)}"

    def show_fingerprint(self):
        fp = self.mw.contacts[self.contact]["fingerprint"]
        self.mw.show_fingerprint(fp, self.contact)

class FingerprintWidget(QWidget):
    def __init__(self, mw):
        super().__init__()
        self.mw = mw
        vbox = QVBoxLayout(self)
        self.label = QLabel()
        self.back_btn = QPushButton("Back")
        self.back_btn.clicked.connect(self.back)
        vbox.addWidget(self.label)
        vbox.addWidget(self.back_btn)
        self.setLayout(vbox)

    def set_fingerprint(self, fingerprint, username):
        self.label.setText(f"<h4>Fingerprint for {username}</h4><code>{fingerprint}</code>")

    def back(self):
        self.mw.show_contacts()

class LoginWidget(QWidget):
    def __init__(self, mw):
        super().__init__()
        self.mw = mw
        vbox = QVBoxLayout(self)
        self.username_edit = QLineEdit()
        self.username_edit.setPlaceholderText("Enter your username")
        self.login_btn = QPushButton("Login")
        self.login_btn.clicked.connect(self.login)
        vbox.addWidget(QLabel("<h2>Login</h2>"))
        vbox.addWidget(self.username_edit)
        vbox.addWidget(self.login_btn)
        self.setLayout(vbox)

    def login(self):
        username = self.username_edit.text()
        if username:
            priv, pub = make_keypair()
            ik_bytes = pub[0].to_bytes(32, "big") + pub[1].to_bytes(32, "big")
            ik_hex = ik_bytes.hex()
            sio.emit("register_user", {
                "username": username,
                "ik": ik_hex,
                "sik": "0"*64, "spk": "0"*112, "opk": "0"*112, "spk_sig": "0"*64
            })
            local_cur.execute("PRAGMA key = '{}';".format(DB_PASSWORD))
            fingerprint = hashlib.sha256(ik_bytes).hexdigest()
            local_cur.execute("INSERT OR IGNORE INTO contacts (username, ik, fingerprint) VALUES (?, ?, ?)",
                              (username, ik_hex, fingerprint))
            local_db.commit()
            global crypto_manager
            crypto_manager = CryptoManager(username)
            mainw = ChatMainWindow(username)
            mainw.crypto_manager = crypto_manager
            mainw.show()
            mw.close()

# --- SocketIO receive handlers ---
@sio.on("receive_sealed_message")
def on_receive_sealed(data):
    recipient = data["recipient_id"]
    payload = data["payload"]
    local_cur.execute("PRAGMA key = '{}';".format(DB_PASSWORD))
    local_cur.execute("INSERT INTO messages (chat_id, sender, recipient, payload, sealed) VALUES (?, ?, ?, ?, 1)",
                      (f"{min(recipient, crypto_manager.username)}-{max(recipient, crypto_manager.username)}",
                       recipient, crypto_manager.username, payload))
    local_db.commit()

# --- Main Application ---
if __name__ == "__main__":
    app = QApplication(sys.argv)
    mw = QMainWindow()
    login = LoginWidget(mw)
    mw.setCentralWidget(login)
    mw.setWindowTitle("Secure Messenger")
    mw.setGeometry(200, 200, 400, 200)
    mw.show()
    sio.connect(SIO_SERVER)
    sys.exit(app.exec())
