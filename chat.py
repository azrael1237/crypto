import sys
import socketio
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac, padding, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from PySide6.QtWidgets import QApplication, QPushButton, QVBoxLayout, QHBoxLayout, QTextEdit, QLineEdit, QWidget, QLabel, QMainWindow
from PySide6.QtCore import QObject, QThread, Signal
import base64
import argparse

# ================= UTILS =================

MAX_SKIP = 10

def serialize(val):
    return base64.standard_b64encode(val).decode('utf-8')

def deserialize(val):
    return base64.standard_b64decode(val.encode('utf-8'))

def GENERATE_DH():
    sk = x25519.X25519PrivateKey.generate()
    return sk

def DH(dh_pair, dh_pub):
    dh_out = dh_pair.exchange(dh_pub)
    return dh_out

def KDF_RK(rk, dh_out):
    # rk is hkdf salt, dh_out is hkdf input key material
    if isinstance(rk, x25519.X25519PublicKey):
        rk_bytes = rk.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    else:
        rk_bytes = rk
    info = b"kdf_rk_info"
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=rk_bytes,
        info=info,
    )
    h_out = hkdf.derive(dh_out)
    root_key = h_out[:32]
    chain_key = h_out[32:]
    return (root_key, chain_key)

def KDF_CK(ck):
    if isinstance(ck, x25519.X25519PublicKey):
        ck_bytes = ck.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    else:
        ck_bytes = ck
    h = hmac.HMAC(ck_bytes, hashes.SHA256())
    h.update(bytearray([0x01]))
    message_key = h.finalize()
    h = hmac.HMAC(ck_bytes, hashes.SHA256())
    h.update(bytearray([0x02]))
    next_ck = h.finalize()
    return (next_ck, message_key)

class Header:
    def __init__(self, dh, pn, n):
        self.dh = dh
        self.pn = pn
        self.n = n

    def serialize(self):
        return {'dh': serialize(self.dh), 'pn': serialize(self.pn), 'n': serialize(self.n)}

    @staticmethod
    def deserialize(val):
        return Header(deserialize(val['dh']), deserialize(val['pn']), deserialize(val['n']))

def HEADER(dh_pair, pn, n):
    pk = dh_pair.public_key()
    pk_bytes = pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return Header(pk_bytes, pn.to_bytes(pn.bit_length()), n.to_bytes(n.bit_length()))

def CONCAT(ad, header):
    return (ad, header)

def RatchetEncrypt(state, plaintext, AD):
    state["CKs"], mk = KDF_CK(state["CKs"])
    header = HEADER(state["DHs"], state["PN"], state["Ns"])
    state["Ns"] += 1
    return header, ENCRYPT_DOUB_RATCH(mk, plaintext, CONCAT(AD, header))

def RatchetDecrypt(state, header, ciphertext, AD):
    plaintext = TrySkippedMessageKeys(state, header, ciphertext, AD)
    if plaintext is not None:
        return plaintext
    if x25519.X25519PublicKey.from_public_bytes(header.dh) != state["DHr"]:
        SkipMessageKeys(state, int.from_bytes(header.pn))
        DHRatchet(state, header)
    SkipMessageKeys(state, int.from_bytes(header.n))
    state["CKr"], mk = KDF_CK(state["CKr"])
    state["Nr"] += 1
    padded_plain_text = DECRYPT_DOUB_RATCH(mk, ciphertext, CONCAT(AD, header))
    unpadder = padding.PKCS7(256).unpadder()
    return unpadder.update(padded_plain_text) + unpadder.finalize()

def TrySkippedMessageKeys(state, header, ciphertext, AD):
    key = (header.dh, int.from_bytes(header.n))
    if key in state["MKSKIPPED"]:
        mk = state["MKSKIPPED"][key]
        del state["MKSKIPPED"][key]
        return DECRYPT_DOUB_RATCH(mk, ciphertext, CONCAT(AD, header))
    else:
        return None

def SkipMessageKeys(state, until):
    if state["Nr"] + MAX_SKIP < until:
        raise Exception("Too many skipped messages")
    if state["CKr"] is not None:
        while state["Nr"] < until:
            state["CKr"], mk = KDF_CK(state["CKr"])
            DHr_bytes = state["DHr"].public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            state["MKSKIPPED"][DHr_bytes, state["Nr"]] = mk
            state["Nr"] += 1

def DHRatchet(state, header):
    state["PN"] = state["Ns"]
    state["Ns"] = 0
    state["Nr"] = 0
    state["DHr"] = x25519.X25519PublicKey.from_public_bytes(header.dh)
    state["RK"], state["CKr"] = KDF_RK(state["RK"], DH(state["DHs"], state["DHr"]))
    state["DHs"] = GENERATE_DH()
    state["RK"], state["CKs"] = KDF_RK(state["RK"], DH(state["DHs"], state["DHr"]))

def ENCRYPT_DOUB_RATCH(mk, plaintext, associated_data):
    info = b"encrypt_info_kdf"
    zero_filled = b"\x00"*80
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=80,
        salt=zero_filled,
        info=info,
    )
    hkdf_out = hkdf.derive(mk)
    enc_key = hkdf_out[:32]
    auth_key = hkdf_out[32:64]
    iv = hkdf_out[64:]
    cipher = Cipher(algorithms.AES256(enc_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(256).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    ad, header = associated_data
    pk, pn, n = header.dh, header.pn, header.n
    assoc_data = ad + pk + pn + n
    padder = padding.PKCS7(256).padder()
    padded_assoc_data = padder.update(assoc_data) + padder.finalize()
    h = hmac.HMAC(auth_key, hashes.SHA256())
    h.update(padded_assoc_data + ciphertext)
    h_out = h.finalize()
    return (ciphertext, h_out)

def DECRYPT_DOUB_RATCH(mk, cipherout, associated_data):
    ciphertext = cipherout[0]
    mac = cipherout[1]
    info = b"encrypt_info_kdf"
    zero_filled = b"\x00"*80
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=80,
        salt=zero_filled,
        info=info,
    )
    hkdf_out = hkdf.derive(mk)
    enc_key = hkdf_out[:32]
    auth_key = hkdf_out[32:64]
    iv = hkdf_out[64:]
    cipher = Cipher(algorithms.AES256(enc_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    h = hmac.HMAC(auth_key, hashes.SHA256())
    ad, header = associated_data
    pk, pn, n = header.dh, header.pn, header.n
    assoc_data = ad + pk + pn + n
    padder = padding.PKCS7(256).padder()
    padded_assoc_data = padder.update(assoc_data) + padder.finalize()
    h.update(padded_assoc_data + ciphertext)
    try:
        h.verify(mac)
    except:
        raise Exception("MAC verification failed")
    return plaintext

def ENCRYPT_X3DH(mk, plaintext, associated_data):
    zero_filled = b"\x00"*80
    info = b"X3DH"
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=80,
        salt=zero_filled,
        info=info,
    )
    hkdf_out = hkdf.derive(mk)
    enc_key = hkdf_out[:32]
    auth_key = hkdf_out[32:64]
    iv = hkdf_out[64:]
    cipher = Cipher(algorithms.AES256(enc_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(256).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    padder = padding.PKCS7(256).padder()
    padded_assoc_data = padder.update(associated_data) + padder.finalize()
    h = hmac.HMAC(auth_key, hashes.SHA256())
    h.update(padded_assoc_data + ciphertext)
    h_out = h.finalize()
    return (ciphertext, h_out)

def DECRYPT_X3DH(mk, ciphertext, mac, associated_data):
    zero_filled = b"\x00"*80
    info = b"X3DH"
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=80,
        salt=zero_filled,
        info=info,
    )
    hkdf_out = hkdf.derive(mk)
    enc_key = hkdf_out[:32]
    auth_key = hkdf_out[32:64]
    iv = hkdf_out[64:]
    cipher = Cipher(algorithms.AES256(enc_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    h = hmac.HMAC(auth_key, hashes.SHA256())
    padder = padding.PKCS7(256).padder()
    padded_assoc_data = padder.update(associated_data) + padder.finalize()
    h.update(padded_assoc_data + ciphertext)
    try:
        h.verify(mac)
    except:
        return (False, "")
    unpadder = padding.PKCS7(256).unpadder()
    plaintext =  unpadder.update(plaintext) + unpadder.finalize()
    return (True, plaintext)

# ================= CLIENT =================

SERVER = 'http://localhost:8080'
sio = socketio.Client(logger=True)
sio.connect(SERVER)

class User:
    def __init__(self, username):
        self.username = username
        self.sessions = {}
        self.x3dh_session = {}
        self.ratchet_session = {}
        self.messages = {}
        self.generate_user()

    def init_ratchet_transmission(self, username):
        self.messages[username] = []
        SK = self.x3dh_session[username]['sk']
        self.ratchet_session[username] = {}
        recipient_dh_pk = self.x3dh_session[username]['spk']
        self.ratchet_session[username]["DHs"] = GENERATE_DH()
        self.ratchet_session[username]["DHr"] = recipient_dh_pk
        self.ratchet_session[username]["RK"], self.ratchet_session[username]["CKs"] = KDF_RK(SK, DH(self.ratchet_session[username]["DHs"], self.ratchet_session[username]["DHr"]))
        self.ratchet_session[username]["RK"] = x25519.X25519PublicKey.from_public_bytes(self.ratchet_session[username]["RK"])
        self.ratchet_session[username]["CKs"] = x25519.X25519PublicKey.from_public_bytes(self.ratchet_session[username]["CKs"])
        self.ratchet_session[username]["CKr"] = None
        self.ratchet_session[username]["Ns"] = 0
        self.ratchet_session[username]["Nr"] = 0
        self.ratchet_session[username]["PN"] = 0
        self.ratchet_session[username]["MKSKIPPED"] = {}

    def init_ratchet_reciever(self, username):
        self.messages[username] = []
        SK = self.x3dh_session[username]['sk']
        recipient_dh_sk = self.x3dh_session[username]['spk']
        self.ratchet_session[username] = {}
        self.ratchet_session[username]["DHs"] = recipient_dh_sk
        self.ratchet_session[username]["DHr"] = None
        self.ratchet_session[username]["RK"] = SK
        self.ratchet_session[username]["CKs"] = None
        self.ratchet_session[username]["CKr"] = None
        self.ratchet_session[username]["Ns"] = 0
        self.ratchet_session[username]["Nr"] = 0
        self.ratchet_session[username]["PN"] = 0
        self.ratchet_session[username]["MKSKIPPED"] = {}

    def generate_user(self, opk_size=10):
        self.ik = x25519.X25519PrivateKey.generate()
        self.sik = ed25519.Ed25519PrivateKey.generate()
        self.spk = x25519.X25519PrivateKey.generate()
        spk_bytes = self.spk.public_key().public_bytes_raw()
        self.spk_sig = self.sik.sign(spk_bytes)

    def serialize_user(self):
        ik_bytes = self.ik.public_key().public_bytes_raw()
        sik_bytes = self.sik.public_key().public_bytes_raw()
        spk_bytes = self.spk.public_key().public_bytes_raw()
        return {
            "username": self.username,
            "ik": serialize(ik_bytes),
            "sik": serialize(sik_bytes),
            "spk": serialize(spk_bytes),
            "spk_sig": serialize(self.spk_sig)
        }

    def register_user(self):
        user = self.serialize_user()
        return sio.call("register_user", user)

    def request_user_prekey_bundle(self, username):
        res = sio.call("request_prekey", {"username": username})
        if not res[0]:
            raise Exception(f"User {username} not registered")
        data = res[1]
        ik_bytes = deserialize(data["ik"])
        sik_bytes = deserialize(data["sik"])
        spk_bytes = deserialize(data["spk"])
        spk_sig_bytes = deserialize(data["spk_sign"])
        ik = x25519.X25519PublicKey.from_public_bytes(ik_bytes)
        sik = ed25519.Ed25519PublicKey.from_public_bytes(sik_bytes)
        spk = x25519.X25519PublicKey.from_public_bytes(spk_bytes)
        try:
            sik.verify(spk_sig_bytes, spk_bytes)
        except:
            raise Exception("SPK verification failed")
        self.sessions[username] = {
            'ik': ik,
            'spk': spk
        }

    def send_message(self, username, msg):
        ad = self.x3dh_session[username]['ad']
        header, ciphertext = RatchetEncrypt(self.ratchet_session[username], msg.encode('utf-8'), ad.encode('utf-8'))
        ciphertext, mac = ciphertext
        self.messages[username].append((self.username, msg))
        return sio.call("ratchet_msg", {'username': username, 'cipher': serialize(ciphertext), 'header': header.serialize(), 'hmac': serialize(mac), 'from': self.username})

    def is_connected(self, username):
        return username in self.x3dh_session

    def recieve_message(self, username, msg):
        header = Header.deserialize(msg['header'])
        ciphertext = deserialize(msg['cipher'])
        hmac_val = deserialize(msg['hmac'])
        ad = self.x3dh_session[username]['ad']
        plaintext = RatchetDecrypt(self.ratchet_session[username], header, (ciphertext, hmac_val), ad.encode('utf-8'))
        self.messages[username].append((username, plaintext.decode('utf-8')))
        return plaintext.decode('utf-8')

    def receive_x3dh(self, username, data):
        ika_bytes = deserialize(data["ik"])
        epk_bytes = deserialize(data["epk"])
        cipher = deserialize(data["cipher"])
        hmac_val = deserialize(data["hmac"])
        ika = x25519.X25519PublicKey.from_public_bytes(ika_bytes)
        epk = x25519.X25519PublicKey.from_public_bytes(epk_bytes)
        dh1 = self.spk.exchange(ika)
        dh2 = self.ik.exchange(epk)
        dh3 = self.spk.exchange(epk)
        info = b"extended_triple_diffie_hellman"
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"\x00"*32,
            info=info,
        )
        f = b"\xff" * 32
        km = dh1 + dh2 + dh3
        SK = hkdf.derive(f + km)
        ad = serialize(ika_bytes) + serialize(self.ik.public_key().public_bytes_raw())
        res = DECRYPT_X3DH(SK, cipher, hmac_val, ad.encode('utf-8'))
        if res[0]:
            self.x3dh_session[username] = {"sk": SK, "spk": self.spk, "ad": ad}
            self.init_ratchet_reciever(username)
        else:
            print("DH Failed")
            return False
        return True

    def perform_x3dh(self, username):
        if username not in self.sessions:
            print("User key bundles not requested!")
        self.epk = x25519.X25519PrivateKey.generate()
        dh1 = self.ik.exchange(self.sessions[username]['spk'])
        dh2 = self.epk.exchange(self.sessions[username]['ik'])
        dh3 = self.epk.exchange(self.sessions[username]['spk'])
        info = b"extended_triple_diffie_hellman"
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"\x00"*32,
            info=info,
        )
        f = b"\xff" * 32
        km = dh1 + dh2 + dh3
        SK = hkdf.derive(f + km)
        self.epk_pub = self.epk.public_key()
        epk_pub_bytes = self.epk_pub.public_bytes_raw()
        ik_bytes = self.ik.public_key().public_bytes_raw()
        ik_b_bytes = self.sessions[username]['ik'].public_bytes_raw()
        del self.epk
        del dh1, dh2, dh3
        ad = serialize(ik_bytes) + serialize(ik_b_bytes)
        msg = "##CHAT_START##"
        ciphertext, hmac_val = ENCRYPT_X3DH(SK, msg.encode('utf-8'), ad.encode('utf-8'))
        self.x3dh_session[username] = {"sk": SK, "spk": self.sessions[username]['spk'], "ad": ad}
        res = sio.call("x3dh_message", {"username": username, "from": self.username, "ik": serialize(ik_bytes), "epk": serialize(epk_pub_bytes), "cipher": serialize(ciphertext), "hmac": serialize(hmac_val)})
        if res:
            self.init_ratchet_transmission(username)
        else:
            print("DH Failed!")
        return res

def reg_callback(user, msg_event=lambda x: x):
    @sio.on('x3dh_message')
    def on_x3dh_message(data):
        user.receive_x3dh(data["from"], data)
        return True

    @sio.on('ratchet_msg')
    def on_ratchet_msg(data):
        msg_event(user.recieve_message(data["from"], data))
        return True

# ================= GUI =================

username = None
user = User(None)
target_user = None

class SocketIOClient(QObject):
    message_received = Signal(str)
    def __init__(self):
        super().__init__()
    def run(self):
        def on_message(data):
            self.message_received.emit(data)
        reg_callback(user, on_message)
        sio.wait()

class Worker(QThread):
    def __init__(self):
        super().__init__()
    def run(self):
        self.client = SocketIOClient()
        self.client.message_received.connect(self.on_message_received)
        self.client.run()
    def on_message_received(self, message):
        global mw, target_user
        if target_user is not None:
            mw.update_chat(user.messages[target_user])

app = QApplication(sys.argv)

class LoginScreen(QWidget):
    def __init__(self, parent=None):
        super(LoginScreen, self).__init__(parent)
        self.setWindowTitle("Login")
        self.username_label = QLabel("Username:")
        self.username_edit = QLineEdit()
        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self.handle_login)
        layout = QVBoxLayout()
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_edit)
        layout.addWidget(self.login_button)
        self.setLayout(layout)
    def handle_login(self):
        global username, user
        username = self.username_edit.text()
        user.username = username
        if user.register_user():
            self.parent().switch_to_select_screen()

class SelectScreen(QWidget):
    def __init__(self, parent=None):
        super(SelectScreen, self).__init__(parent)
        self.setWindowTitle("Select")
        self.main_layout = QVBoxLayout()
        self.main_layout.addWidget(QLabel(f"Hi {username}!"))
        self.main_layout.addWidget(QLabel("<h2>Connect to:</h2>"))
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self.refresh)
        self.main_layout.addWidget(self.refresh_button)
        self.user_layout = QVBoxLayout()
        self.main_layout.addLayout(self.user_layout)
        self.refresh()
        self.setLayout(self.main_layout)
    def refresh(self):
        for i in reversed(range(self.user_layout.count())):
            widget = self.user_layout.itemAt(i).widget()
            if widget is not None:
                widget.deleteLater()
        users = sio.call('request_users')
        for u in users:
            if u != username:
                button = QPushButton(u)
                button.clicked.connect(lambda _, name=u: self.user_clicked(name))
                self.user_layout.addWidget(button)
    def user_clicked(self, name):
        global target_user
        target_user = name
        if not user.is_connected(target_user):
            user.request_user_prekey_bundle(target_user)
            user.perform_x3dh(target_user)
        self.parent().switch_to_chat_screen()

class ChatScreen(QWidget):
    def __init__(self, parent=None):
        super(ChatScreen, self).__init__(parent)
        self.setWindowTitle("Chat")
        xlayout = QVBoxLayout()
        chat_layout = QHBoxLayout()
        back_button = QPushButton("Back")
        back_button.clicked.connect(self.back_message)
        toolbar_layout = QHBoxLayout()
        xlayout.addLayout(toolbar_layout)
        toolbar_layout.addWidget(back_button)
        toolbar_layout.addWidget(QLabel(f"{username} -> {target_user}"))
        self.chat_history = QTextEdit()
        self.chat_history.setReadOnly(True)
        xlayout.addWidget(self.chat_history)
        self.input_field = QLineEdit()
        send_button = QPushButton("Send")
        send_button.clicked.connect(self.send_message)
        chat_layout.addWidget(self.input_field)
        chat_layout.addWidget(send_button)
        xlayout.addLayout(chat_layout)
        self.setLayout(xlayout)
        self.update_messages(user.messages[target_user])
    def send_message(self):
        message = self.input_field.text()
        if message:
            self.input_field.clear()
            user.send_message(target_user, message)
            self.update_messages(user.messages[target_user])
    def update_messages(self, messages):
        self.chat_history.clear()
        for sender, msg in messages:
            color = "green" if sender == username else "red"
            self.append_colored_text(sender, msg, color)
    def back_message(self):
        self.parent().switch_to_select_screen()
    def append_colored_text(self, sender, msg, color):
        self.chat_history.append(f"<font color='{color}'> <strong>{sender}:</strong> {msg}</font><br>")

class MainWindow(QMainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()
        self.login_screen = LoginScreen(self)
        self.setCentralWidget(self.login_screen)
    def switch_to_chat_screen(self):
        self.chat_screen = ChatScreen(self)
        self.setCentralWidget(self.chat_screen)
    def switch_to_select_screen(self):
        self.select_screen = SelectScreen(self)
        self.setCentralWidget(self.select_screen)
    def update_chat(self, messages):
        self.chat_screen.update_messages(messages)

mw = MainWindow()
mw.show()
worker_thread = Worker()
worker_thread.start()
sys.exit(app.exec())
