# Created By Alfi Keita

from __future__ import absolute_import

import os
import pickle
from collections import OrderedDict
from abc import ABC, abstractmethod

# --- interfaces/serializable.py ---

class SerializableIface(ABC):
    """Serializable Interface"""

    @abstractmethod
    def serialize(self):
        """Returns serialized dict of class state."""
        pass

    @classmethod
    @abstractmethod
    def deserialize(cls, serialized_obj):
        """Class instance from serialized class state."""
        pass

# --- interfaces/aead.py ---

class AEADIFace(ABC):
    """Authenticated Encryption with Associated Data Interface"""

    @staticmethod
    @abstractmethod
    def encrypt(key, pt, associated_data = None):
        pass

    @staticmethod
    @abstractmethod
    def decrypt(key, ct, associated_data = None):
        pass

# --- interfaces/dhkey.py ---

class DHKeyPairIface(SerializableIface):
    """Diffie-Hellman Keypair"""

    @classmethod
    @abstractmethod
    def generate_dh(cls):
        pass

    @abstractmethod
    def dh_out(self, dh_pk):
        pass

    @property
    @abstractmethod
    def private_key(self):
        pass

    @property
    @abstractmethod
    def public_key(self):
        pass

class DHPublicKeyIface(SerializableIface):
    """Diffie-Hellman Public Key"""

    @abstractmethod
    def pk_bytes(self):
        pass

    @abstractmethod
    def is_equal_to(self, dh_pk):
        pass

    @classmethod
    @abstractmethod
    def from_bytes(cls, pk_bytes):
        pass

    @property
    @abstractmethod
    def public_key(self):
        pass

# --- interfaces/kdfchain.py ---

class KDFChainIface(SerializableIface):
    """KDF Chain Interface."""

    @property
    @abstractmethod
    def ck(self):
        pass

    @ck.setter
    @abstractmethod
    def ck(self, val):
        pass

class SymmetricChainIface(KDFChainIface):
    """Symmetric KDF Chain Interface (extends KDFChain Interface)."""

    @abstractmethod
    def ratchet(self):
        pass

    @property
    @abstractmethod
    def msg_no(self):
        pass

    @msg_no.setter
    @abstractmethod
    def msg_no(self, val):
        pass

class RootChainIface(KDFChainIface):
    """Root KDF Chain Interface (extends KDFChain Interface)."""

    @abstractmethod
    def ratchet(self, dh_out):
        pass

# --- interfaces/keystorage.py ---

class MsgKeyStorageIface(SerializableIface):
    """Dictionary-like Message Key Storage Interface"""

    @abstractmethod
    def front(self):
        pass

    @abstractmethod
    def lookup(self, key):
        pass

    @abstractmethod
    def put(self, key, value):
        pass

    @abstractmethod
    def delete(self, key):
        pass

    @abstractmethod
    def count(self):
        pass

    @abstractmethod
    def items(self):
        pass

    @abstractmethod
    def notify_event(self):
        pass

# --- interfaces/ratchet.py ---

class RatchetIface(ABC):
    """Double Ratchet Algorithm Communication Interface"""

    @staticmethod
    @abstractmethod
    def encrypt_message(state, pt, associated_data, aead):
        pass

    @staticmethod
    @abstractmethod
    def decrypt_message(state, msg, associated_data, aead, keypair):
        pass

# --- crypto/utils.py (needed by aead) ---

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac

def hkdf(key, length, salt, info, algorithm, backend):
    hkdf_obj = HKDF(
        algorithm=algorithm,
        length=length,
        salt=salt,
        info=info,
        backend=backend
    )
    return hkdf_obj.derive(key)

def hmac(key, data, algorithm, backend):
    h = crypto_hmac.HMAC(key, algorithm, backend=backend)
    h.update(data)
    return h.finalize()

def hmac_verify(key, data, algorithm, backend, tag):
    h = crypto_hmac.HMAC(key, algorithm, backend=backend)
    h.update(data)
    h.verify(tag)

# --- crypto/aead.py ---

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import padding
from cryptography.exceptions import InvalidSignature

class AuthenticationFailed(Exception):
    """Decrypting ciphertext with authenticated data failed."""
    pass

class AES256CBCHMAC(AEADIFace):
    """An implementation of the AEAD Interface."""

    KEY_LEN = 32 # 256-bit key
    IV_LEN = 16
    HKDF_LEN = 2 * KEY_LEN + IV_LEN
    TAG_LEN = 32

    @staticmethod
    def encrypt(key, pt, associated_data = None):
        if not isinstance(key, bytes):
            raise TypeError("key must be of type: bytes")
        if not len(key) == AES256GCM.KEY_LEN:
            raise ValueError("key must be 32 bytes")
        if not isinstance(pt, bytes):
            raise TypeError("pt must be of type: bytes")
        if associated_data and not isinstance(associated_data, bytes):
            raise TypeError("associated_data must be of type: bytes")

        aes_key, hmac_key, iv = AES256CBCHMAC._gen_keys(key)

        padder = padding.PKCS7(AES256CBCHMAC.IV_LEN * 8).padder()
        padded_pt = padder.update(pt) + padder.finalize()

        aes_cbc = AES256CBCHMAC._aes_cipher(aes_key, iv).encryptor()
        ct = aes_cbc.update(padded_pt) + aes_cbc.finalize()

        tag = hmac(hmac_key, (associated_data or b"") + ct, SHA256(), default_backend())
        return ct + tag

    @staticmethod
    def decrypt(key, ct, associated_data = None):
        if not isinstance(key, bytes):
            raise TypeError("key must be of type: bytes")
        if not len(key) == AES256GCM.KEY_LEN:
            raise ValueError("key must be 32 bytes")
        if not isinstance(ct, bytes):
            raise TypeError("ct must be of type: bytes")
        if associated_data and not isinstance(associated_data, bytes):
            raise TypeError("associated_data must be of type: bytes")

        aes_key, hmac_key, iv = AES256CBCHMAC._gen_keys(key)

        try:
            hmac_verify(hmac_key,
                (associated_data or b"") + ct[:-SHA256().digest_size],
                SHA256(),
                default_backend(),
                ct[-SHA256().digest_size:] # tag
            )
        except InvalidSignature:
            raise AuthenticationFailed("Invalid ciphertext")

        aes_cbc = AES256CBCHMAC._aes_cipher(aes_key, iv).decryptor()
        pt_padded = aes_cbc.update(ct[:-SHA256().digest_size]) + aes_cbc.finalize()

        unpadder = padding.PKCS7(AES256CBCHMAC.IV_LEN * 8).unpadder()
        pt = unpadder.update(pt_padded) + unpadder.finalize()

        return pt

    @staticmethod
    def _gen_keys(key):
        hkdf_out = hkdf(
            key,
            AES256CBCHMAC.HKDF_LEN,
            bytes(SHA256().digest_size),
            b"cbchmac_keys",
            SHA256(),
            default_backend()
        )

        return hkdf_out[:AES256CBCHMAC.KEY_LEN], \
            hkdf_out[AES256CBCHMAC.KEY_LEN:2*AES256CBCHMAC.KEY_LEN], \
            hkdf_out[-AES256CBCHMAC.IV_LEN:]

    @staticmethod
    def _aes_cipher(aes_key, iv):
        return Cipher(
            algorithms.AES(aes_key),
            modes.CBC(iv),
            backend = default_backend()
        )

class AES256GCM(AEADIFace):
    """An implementation of the AEAD Interface."""
    KEY_LEN = 32 # 256-bit key
    IV_LEN = 16

    @staticmethod
    def encrypt(key, pt, associated_data = None):
        if not isinstance(key, bytes):
            raise TypeError("key must be of type: bytes")
        if not len(key) == AES256GCM.KEY_LEN:
            raise ValueError("key must be 32 bytes")
        if not isinstance(pt, bytes):
            raise TypeError("pt must be of type: bytes")
        if associated_data and not isinstance(associated_data, bytes):
            raise TypeError("associated_data must be of type: bytes")

        aesgcm = AESGCM(key)
        iv = os.urandom(AES256GCM.IV_LEN)
        ct = aesgcm.encrypt(iv, pt, associated_data)

        return ct + iv

    @staticmethod
    def decrypt(key, ct, associated_data = None):
        if not isinstance(key, bytes):
            raise TypeError("key must be of type: bytes")
        if not len(key) == AES256GCM.KEY_LEN:
            raise ValueError("key must be 32 bytes")
        if not isinstance(ct, bytes):
            raise TypeError("ct must be of type: bytes")
        if associated_data and not isinstance(associated_data, bytes):
            raise TypeError("associated_data must be of type: bytes")

        try:
            aesgcm = AESGCM(key)
            pt = aesgcm.decrypt(
                ct[-AES256GCM.IV_LEN:],
                ct[:-AES256GCM.IV_LEN],
                associated_data
            )
        except InvalidSignature:
            raise AuthenticationFailed("Invalid ciphertext")

        return pt

# --- crypto/dhkey.py ---

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey

class DHKeyPair(DHKeyPairIface):
    """An implementation of the DHKeyPair Interface."""
    def __init__(self, dh_pair = None):
        if dh_pair:
            if not isinstance(dh_pair, X448PrivateKey):
                raise TypeError("dh_pair must be of type: X448PrivateKey")
            self._private_key = dh_pair
        else:
            self._private_key = X448PrivateKey.generate()
        self._public_key = self._private_key.public_key()

    @classmethod
    def generate_dh(cls):
        return cls(X448PrivateKey.generate())

    def dh_out(self, dh_pk):
        if not isinstance(dh_pk, DHPublicKey):
            raise TypeError("dh_pk must be of type: DHPublicKey")
        return self._private_key.exchange(dh_pk.public_key)

    def serialize(self):
        return {
            "private_key" : self._sk_bytes().hex(),
            "public_key" : pk_bytes(self._public_key).hex()
        }

    @classmethod
    def deserialize(cls, serialized_dh):
        if not isinstance(serialized_dh, dict):
            raise TypeError("serialized_dh must be of type: dict")

        private_key = X448PrivateKey.from_private_bytes(
            bytes.fromhex(serialized_dh["private_key"])
        )
        return cls(private_key)

    @property
    def private_key(self):
        return self._private_key

    @property
    def public_key(self):
        return DHPublicKey(self._public_key)

    def _sk_bytes(self):
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )

class DHPublicKey(DHPublicKeyIface):
    """An implementation of the DHPublicKey Interface."""
    KEY_LEN = 56

    def __init__(self, public_key):
        if not isinstance(public_key, X448PublicKey):
            raise TypeError("public_key must be of type: X448PublicKey")
        self._public_key = public_key

    def pk_bytes(self):
        return pk_bytes(self._public_key)

    def is_equal_to(self, dh_pk):
        if not isinstance(dh_pk, DHPublicKey):
            raise TypeError("dh_pk must be of type: DHPublicKey")
        return self.pk_bytes() == dh_pk.pk_bytes()

    @classmethod
    def from_bytes(cls, pk_bytes_val):
        if not isinstance(pk_bytes_val, bytes):
            raise TypeError("pk_bytes must be of type: bytes")
        if not len(pk_bytes_val) == DHPublicKey.KEY_LEN:
            raise ValueError("pk_bytes must be 56 bytes")

        return cls(X448PublicKey.from_public_bytes(pk_bytes_val))

    @property
    def public_key(self):
        return self._public_key

    def serialize(self):
        return {
            "public_key": pk_bytes(self._public_key).hex()
        }

    @classmethod
    def deserialize(cls, serialized_pk):
        if not isinstance(serialized_pk, dict):
            raise TypeError("serialized_pk must be of type: dict")

        public_key = X448PublicKey.from_public_bytes(
            bytes.fromhex(serialized_pk["public_key"])
        )
        return cls(public_key)

def pk_bytes(pk):
    return pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

# --- crypto/kdfchain.py ---

class SymmetricChain(SymmetricChainIface):
    def __init__(self, ck = None, msg_no = None):
        if ck:
            if not isinstance(ck, bytes):
                raise TypeError("ck must be of type: bytes")
            self._ck = ck
        else:
            self._ck = None

        if msg_no:
            if not isinstance(msg_no, int):
                raise TypeError("msg_no must be of type: int")
            if msg_no < 0:
                raise ValueError("msg_no  must be positive")
            self._msg_no = msg_no
        else:
            self._msg_no = 0

    def ratchet(self):
        if self._ck is None:
            raise ValueError("ck is not initialized")

        mk = hmac(self._ck, b"mk_ratchet", SHA256(), default_backend())
        self._ck = hmac(self._ck, b"ck_ratchet", SHA256(), default_backend())

        return mk

    def serialize(self):
        return {
            "ck" : self._ck,
            "msg_no" : self._msg_no
        }

    @classmethod
    def deserialize(cls, serialized_chain):
        if not isinstance(serialized_chain, dict):
            raise TypeError("serialized_chain must be of type: dict")

        return cls(serialized_chain["ck"], serialized_chain["msg_no"])

    @property
    def ck(self):
        return self._ck

    @ck.setter
    def ck(self, val):
        self._ck = val

    @property
    def msg_no(self):
        return self._msg_no

    @msg_no.setter
    def msg_no(self, val):
        self._msg_no = val

class RootChain(RootChainIface):
    KEY_LEN = 32
    DEFAULT_OUTPUTS = 1

    def __init__(self, ck = None):
        if ck:
            if not isinstance(ck, bytes):
                raise TypeError("ck must be of type: bytes")
            if not len(ck) == RootChain.KEY_LEN:
                raise ValueError("ck must be 32 bytes")
            self._ck = ck
        else:
            self._ck = None

    def ratchet(self, dh_out, outputs = DEFAULT_OUTPUTS):
        if not isinstance(dh_out, bytes):
            raise TypeError("dh_out must be of type: bytes")
        if not isinstance(outputs, int):
            raise TypeError("outputs must be of type: int")
        if outputs < 0:
            raise ValueError("outputs must be positive")
        if self._ck is None:
            raise ValueError("ck is not initialized")

        hkdf_out = hkdf(
            dh_out,
            RootChain.KEY_LEN * (outputs + 1),
            self._ck,
            b"rk_ratchet",
            SHA256(),
            default_backend()
        )

        self._rk = hkdf_out[-RootChain.KEY_LEN:]

        keys = []
        for i in range(0, outputs):
            keys.append(hkdf_out[i * RootChain.KEY_LEN:(i + 1) * RootChain.KEY_LEN])

        return keys

    def serialize(self):
        return {
            "ck" : self._ck
        }

    @classmethod
    def deserialize(cls, serialized_chain):
        if not isinstance(serialized_chain, dict):
            raise TypeError("serialized_chain must be of type: dict")
        return cls(serialized_chain["ck"])

    @property
    def ck(self):
        return self._ck

    @ck.setter
    def ck(self, val):
        self._ck = val

# --- keystorage.py ---

class MsgKeyStorage(MsgKeyStorageIface):
    EVENT_THRESH = 5

    def __init__(self, skipped_mks = None, event_count = 0):
        if skipped_mks:
            if not isinstance(skipped_mks, OrderedDict):
                raise TypeError("skipped_mks must be of type: OrderedDict")
            self._skipped_mks = skipped_mks
        else:
            self._skipped_mks = OrderedDict()

        if not isinstance(event_count, int):
            raise TypeError("event_count must be of type: int")
        if event_count < 0:
            raise ValueError("event_count must be positive")
        self._event_count = event_count

    def front(self):
        return next(iter(self._skipped_mks))

    def lookup(self, key):
        if key not in self._skipped_mks:
            return None
        return self._skipped_mks[key]

    def put(self, key, value):
        self._skipped_mks[key] = value

    def delete(self, key):
        del self._skipped_mks[key]

    def count(self):
        return len(self._skipped_mks)

    def items(self):
        return self._skipped_mks.items()

    def notify_event(self):
        if len(self._skipped_mks) == 0:
            self._event_count = 0
            return

        self._event_count = (self._event_count + 1) % MsgKeyStorage.EVENT_THRESH
        if self._event_count == 0:
            del self._skipped_mks[self.front()]

    def serialize(self):
        return {
            "skipped_mks": dict(self._skipped_mks),
            "event_count": self._event_count
        }

    @classmethod
    def deserialize(cls, serialized_dict):
        if not isinstance(serialized_dict, dict):
            raise TypeError("serialized_dict must be of type: dict")

        return cls(
            OrderedDict(serialized_dict["skipped_mks"]),
            serialized_dict["event_count"]
        )

# --- message.py ---

class Header:
    INT_ENCODE_BYTES = 4

    def __init__(self, dh_pk, prev_chain_len, msg_no):
        if not isinstance(dh_pk, DHPublicKey):
            raise TypeError("dh_pk must be of type: DHPublicKey")
        if not isinstance(prev_chain_len, int):
            raise TypeError("prev_chain_len must be of type: int")
        if prev_chain_len < 0:
            raise ValueError("prev_chain_len must be positive")
        if not isinstance(msg_no, int):
            raise TypeError("msg_no must be of type: int")
        if msg_no < 0:
            raise ValueError("msg_no must be positive")

        self._dh_pk = dh_pk
        self._prev_chain_len = prev_chain_len
        self._msg_no = msg_no

    def __bytes__(self):
        header_bytes = self._dh_pk.pk_bytes()
        header_bytes += self._prev_chain_len.to_bytes(
            Header.INT_ENCODE_BYTES,
            byteorder='little'
        )
        header_bytes += self._msg_no.to_bytes(
            Header.INT_ENCODE_BYTES,
            byteorder='little'
        )
        return header_bytes

    @classmethod
    def from_bytes(cls, header_bytes):
        if not isinstance(header_bytes, bytes):
            raise TypeError("header_bytes must be of type: bytes")

        if header_bytes is None or \
            len(header_bytes) != DHPublicKey.KEY_LEN + 2 * Header.INT_ENCODE_BYTES:
            raise ValueError("Inva")

        dh_pk = DHPublicKey.from_bytes(header_bytes[:DHPublicKey.KEY_LEN])
        prev_chain_len = int.from_bytes(
            header_bytes[DHPublicKey.KEY_LEN:-Header.INT_ENCODE_BYTES],
            byteorder='little'
        )
        msg_no = int.from_bytes(
            header_bytes[-Header.INT_ENCODE_BYTES:],
            byteorder='little'
        )
        return cls(dh_pk, prev_chain_len, msg_no)

    @property
    def dh_pk(self):
        return self._dh_pk

    @property
    def prev_chain_len(self):
        return self._prev_chain_len

    @property
    def msg_no(self):
        return self._msg_no

class Message:
    def __init__(self, header, ct):
        if not isinstance(header, Header):
            raise TypeError("header must be of type: Header")
        if not isinstance(ct, bytes):
            raise TypeError("ct must be of type: bytes")
        self._header = header
        self._ct = ct

    @property
    def header(self):
        return self._header

    @property
    def ct(self):
        return self._ct

class MessageHE:
    def __init__(self, header_ct, ct):
        if not isinstance(header_ct, bytes):
            raise TypeError("header_ct must be of type: bytes")
        if not isinstance(ct, bytes):
            raise TypeError("ct must be of type: bytes")
        self._header_ct = header_ct
        self._ct = ct

    @property
    def header_ct(self):
        return self._header_ct

    @property
    def ct(self):
        return self._ct

# --- state.py ---

class State(SerializableIface):
    def __init__(self, keypair, public_key, keystorage, root_chain, symmetric_chain):
        self._dh_pair = None
        self._dh_pk_r = None

        self._root = None
        self._send = None
        self._receive = None
        self._prev_send_len = 0

        self._hk_s = None
        self._hk_r = None
        self._next_hk_s = None
        self._next_hk_r = None

        self._delayed_send_ratchet = False

        self._skipped_mks = None
        self._skipped_count = 0

        self._keypair = keypair
        self._public_key = public_key
        self._keystorage = keystorage
        self._root_chain = root_chain
        self._symmetric_chain = symmetric_chain

    def init_sender(self, sk, dh_pk_r):
        self._dh_pair = self._keypair.generate_dh()
        self._dh_pk_r = dh_pk_r

        self._root = self._root_chain()
        self._root.ck = sk
        self._send = self._symmetric_chain()
        self._receive = self._symmetric_chain()
        self._prev_send_len = 0

        self._delayed_send_ratchet = True

        self._skipped_mks = self._keystorage()
        self._skipped_count = 0

    def init_sender_he(self, sk, dh_pk_r, hk_s, next_hk_r):
        self._dh_pair = self._keypair.generate_dh()
        self._dh_pk_r = dh_pk_r

        self._root = self._root_chain()
        self._root.ck = sk
        self._send = self._symmetric_chain()
        self._receive = self._symmetric_chain()
        self._prev_send_len = 0

        self._hk_s = hk_s
        self._hk_r = None
        self._next_hk_s = None
        self._next_hk_r = next_hk_r

        self._delayed_send_ratchet = True

        self._skipped_mks = self._keystorage()
        self._skipped_count = 0

    def init_receiver(self, sk, dh_pair):
        self._dh_pair = dh_pair
        self._dh_pk_r = None

        self._root = self._root_chain()
        self._root.ck = sk
        self._send = self._symmetric_chain()
        self._receive = self._symmetric_chain()
        self._prev_send_len = 0

        self._delayed_send_ratchet = False

        self._skipped_mks = self._keystorage()
        self._skipped_count = 0

    def init_receiver_he(self, sk, dh_pair, next_hk_s, next_hk_r):
        self._dh_pair = dh_pair
        self._dh_pk_r = None

        self._root = self._root_chain()
        self._root.ck = sk
        self._send = self._symmetric_chain()
        self._receive = self._symmetric_chain()
        self._prev_send_len = 0

        self._hk_s = None
        self._hk_r = None
        self._next_hk_s = next_hk_s
        self._next_hk_r = next_hk_r

        self._delayed_send_ratchet = False

        self._skipped_mks = self._keystorage()
        self._skipped_count = 0

    @property
    def dh_pair(self):
        return self._dh_pair

    @dh_pair.setter
    def dh_pair(self, val):
        self._dh_pair = val

    @property
    def dh_pk_r(self):
        return self._dh_pk_r

    @dh_pk_r.setter
    def dh_pk_r(self, val):
        self._dh_pk_r = val

    @property
    def root(self):
        return self._root

    @property
    def send(self):
        return self._send

    @property
    def receive(self):
        return self._receive

    @property
    def prev_send_len(self):
        return self._prev_send_len

    @prev_send_len.setter
    def prev_send_len(self, val):
        self._prev_send_len = val

    @property
    def hk_s(self):
        return self._hk_s

    @hk_s.setter
    def hk_s(self, val):
        self._hk_s = val

    @property
    def hk_r(self):
        return self._hk_r

    @hk_r.setter
    def hk_r(self, val):
        self._hk_r = val

    @property
    def next_hk_s(self):
        return self._next_hk_s

    @next_hk_s.setter
    def next_hk_s(self, val):
        self._next_hk_s = val

    @property
    def next_hk_r(self):
        return self._next_hk_r

    @next_hk_r.setter
    def next_hk_r(self, val):
        self._next_hk_r = val

    @property
    def delayed_send_ratchet(self):
        return self._delayed_send_ratchet

    @delayed_send_ratchet.setter
    def delayed_send_ratchet(self, val):
        self._delayed_send_ratchet = val

    @property
    def skipped_mks(self):
        return self._skipped_mks

    @property
    def skipped_count(self):
        return self._skipped_count

    @skipped_count.setter
    def skipped_count(self, val):
        self._skipped_count = val

    def serialize(self):
        return {
            "dh_pair" : self._dh_pair.serialize(),
            "dh_pk_r": self._dh_pk_r.serialize(),
            "root": self._root.serialize(),
            "send": self._send.serialize(),
            "receive": self._receive.serialize(),
            "prev_send_len": self._prev_send_len,
            "hk_s": self._hk_s,
            "hk_r": self._hk_r,
            "next_hk_s": self._next_hk_s,
            "next_hk_r": self._next_hk_r,
            "delayed_send_ratchet": self._delayed_send_ratchet,
            "skipped_mks": self._skipped_mks.serialize(),
            "skipped_count": self._skipped_count,
            "keypair_class": pickle.dumps(self._keypair),
            "pk_class": pickle.dumps(self._public_key),
            "keystorage_class": pickle.dumps(self._keystorage),
            "root_chain_class": pickle.dumps(self._root_chain),
            "symmetric_chain_class": pickle.dumps(self._symmetric_chain)
        }

    @classmethod
    def deserialize(cls, serialized_dict):
        if not isinstance(serialized_dict, dict):
            raise TypeError("serialized_dict must be of type: dict")

        keypair_class = pickle.loads(serialized_dict["keypair_class"])
        pk_class = pickle.loads(serialized_dict["pk_class"])
        keystorage_class = pickle.loads(serialized_dict["keystorage_class"])
        root_chain_class = pickle.loads(serialized_dict["root_chain_class"])
        symmetric_chain_class = pickle.loads(serialized_dict["symmetric_chain_class"])

        state = cls(keypair_class, pk_class, keystorage_class, root_chain_class, symmetric_chain_class)

        state._dh_pair = keypair_class.deserialize(serialized_dict["dh_pair"])
        state._dh_pk_r = pk_class.deserialize(serialized_dict["dh_pk_r"])
        state._root = root_chain_class.deserialize(serialized_dict["root"])
        state._send = symmetric_chain_class.deserialize(serialized_dict["send"])
        state._receive = symmetric_chain_class.deserialize(serialized_dict["receive"])
        state._prev_send_len = serialized_dict["prev_send_len"]
        state._hk_s = serialized_dict["hk_s"]
        state._hk_r = serialized_dict["hk_r"]
        state._next_hk_s = serialized_dict["next_hk_s"]
        state._next_hk_r = serialized_dict["next_hk_r"]
        state._delayed_send_ratchet = serialized_dict["delayed_send_ratchet"]
        state._skipped_mks = keystorage_class.deserialize(serialized_dict["skipped_mks"])
        state._skipped_count = serialized_dict["skipped_count"]

        return state

# --- ratchet.py ---

class MaxSkippedMksExceeded(Exception):
    pass

class Ratchet(RatchetIface):
    MAX_SKIP = 1000
    MAX_STORE = 2000

    @staticmethod
    def encrypt_message(state, pt, associated_data, aead):
        if not isinstance(state, State):
            raise TypeError("state must be of type: state")
        if not isinstance(pt, str):
            raise TypeError("pt must be of type: string")
        if not isinstance(associated_data, bytes):
            raise TypeError("associated_data must be of type: bytes")
        if not issubclass(aead, AEADIFace):
            raise TypeError("aead must implement AEADIface")

        if state.delayed_send_ratchet:
            state.send.ck = state.root.ratchet(state.dh_pair.dh_out(state.dh_pk_r))[0]
            state.delayed_send_ratchet = False

        mk = state.send.ratchet()
        header = Header(state.dh_pair.public_key, state.prev_send_len, state.send.msg_no)
        state.send.msg_no += 1

        ct = aead.encrypt(mk, pt.encode("utf-8"), associated_data + bytes(header))
        return Message(header, ct)

    @staticmethod
    def decrypt_message(state, msg, associated_data, aead, keypair):
        if not isinstance(state, State):
            raise TypeError("state must be of type: state")
        if not isinstance(msg, Message):
            raise TypeError("msg must be of type: Message")
        if not isinstance(associated_data, bytes):
            raise TypeError("associated_data must be of type: bytes")
        if not issubclass(aead, AEADIFace):
            raise TypeError("aead must implement AEADIface")
        if not issubclass(keypair, DHKeyPairIface):
            raise TypeError("keypair must implement DHKeyPairIface")

        pt = try_skipped_mks(state, msg.header, msg.ct, associated_data, aead)
        if pt is not None:
            state.skipped_mks.notify_event()
            return pt

        if not state.dh_pk_r:
            dh_ratchet(state, msg.header.dh_pk, keypair)
        elif not state.dh_pk_r.is_equal_to(msg.header.dh_pk):
            skip_over_mks(state, msg.header.prev_chain_len, state.dh_pk_r.pk_bytes())
            dh_ratchet(state, msg.header.dh_pk, keypair)

        skip_over_mks(state, msg.header.msg_no, state.dh_pk_r.pk_bytes())
        mk = state.receive.ratchet()
        state.receive.msg_no += 1

        pt_bytes = aead.decrypt(mk, msg.ct, associated_data + bytes(msg.header))
        state.skipped_mks.notify_event()

        return pt_bytes.decode("utf-8")

def try_skipped_mks(state, header, ct, associated_data, aead):
    hdr_pk_bytes = header.dh_pk.pk_bytes()
    mk = state.skipped_mks.lookup((hdr_pk_bytes, header.msg_no))
    if mk:
        state.skipped_mks.delete((hdr_pk_bytes, header.msg_no))
        pt_bytes = aead.decrypt(mk, ct, associated_data + bytes(header))
        return pt_bytes.decode("utf-8")
    return None

def skip_over_mks(state, end_msg_no, map_key):
    new_skip = end_msg_no - state.receive.msg_no
    if new_skip + state.skipped_count > Ratchet.MAX_SKIP:
        raise MaxSkippedMksExceeded("Too many messages skipped in current chain")
    if new_skip + state.skipped_mks.count() > Ratchet.MAX_STORE:
        raise MaxSkippedMksExceeded("Too many messages stored")
    elif state.receive.ck is not None:
        while state.receive.msg_no < end_msg_no:
            mk = state.receive.ratchet()
            if state.skipped_mks.count() == Ratchet.MAX_SKIP:
                state.skipped_mks.delete(state.skipped_mks.front())
            state.skipped_mks.put((map_key, state.receive.msg_no), mk)
            state.receive.msg_no += 1
        state.skipped_count += new_skip

def dh_ratchet(state, dh_pk_r, keypair):
    if state.delayed_send_ratchet:
        state.send.ck = state.root.ratchet(state.dh_pair.dh_out(dh_pk_r))[0]

    state.dh_pk_r = dh_pk_r
    state.receive.ck = state.root.ratchet(state.dh_pair.dh_out(state.dh_pk_r))[0]
    state.dh_pair = keypair.generate_dh()
    state.delayed_send_ratchet = True
    state.prev_send_len = state.send.msg_no
    state.send.msg_no = 0
    state.receive.msg_no = 0
    state.skipped_count = 0

# --- session.py ---

class DRSession(SerializableIface):
    def __init__(
        self,
        state: State = None,
        aead: AEADIFace = AES256CBCHMAC,
        keypair: DHKeyPairIface = DHKeyPair,
        public_key: DHPublicKeyIface = DHPublicKey,
        keystorage: MsgKeyStorageIface = MsgKeyStorage,
        root_chain: RootChainIface = RootChain,
        symmetric_chain: SymmetricChainIface = SymmetricChain,
        ratchet: RatchetIface = Ratchet) -> None:

        if state and not isinstance(state, State):
            raise TypeError("state must be of type: State")
        if not issubclass(aead, AEADIFace):
            raise TypeError("aead must implement AEADIFace")
        if not issubclass(keypair, DHKeyPairIface):
            raise TypeError("keypair must implement DHKeyPairIface")
        if not issubclass(public_key, DHPublicKeyIface):
            raise TypeError("public_key must implement DHPublicKeyIface")
        if not issubclass(keystorage, MsgKeyStorageIface):
            raise TypeError("keystorage must implement MsgKeyStorageIface")
        if not issubclass(root_chain, RootChainIface):
            raise TypeError("root_chain must implement KDFChainIface")
        if not issubclass(symmetric_chain, SymmetricChainIface):
            raise TypeError("symmetric_chain must implement SymmetricChainIface")
        if not issubclass(ratchet, RatchetIface):
            raise TypeError("ratchet must be of type: RatchetIface")

        self._aead = aead
        self._keypair = keypair
        self._ratchet = ratchet

        if state:
            self._state = state
        else:
            self._state = State(keypair, public_key, keystorage, root_chain, symmetric_chain)

    def setup_sender(self, sk: bytes, dh_pk_r: DHPublicKey) -> None:
        if not isinstance(sk, bytes):
            raise TypeError("sk must be of type: bytes")
        if not isinstance(dh_pk_r, DHPublicKey):
            raise TypeError("dh_pk_r must be of type: DHPublicKey")
        self._state.init_sender(sk, dh_pk_r)

    def setup_receiver(self, sk: bytes, dh_pair: DHKeyPair) -> None:
        if not isinstance(sk, bytes):
            raise TypeError("sk must be of type: bytes")
        if not isinstance(dh_pair, DHKeyPair):
            raise TypeError("dh_pair must be of type: DHKeyPair")
        self._state.init_receiver(sk, dh_pair)

    def encrypt_message(self, pt: str, associated_data: bytes) -> Message:
        if not isinstance(pt, str):
            raise TypeError("pt must be of type: string")
        if not isinstance(associated_data, bytes):
            raise TypeError("associated_data must be of type: bytes")

        msg = self._ratchet.encrypt_message(
            self._state, pt, associated_data, self._aead)
        return msg

    def decrypt_message(self, msg: Message, associated_data: bytes) -> str:
        if not isinstance(msg, Message):
            raise TypeError("msg must be of type: Message")
        if not isinstance(associated_data, bytes):
            raise TypeError("associated_data must be of type: bytes")

        pt = self._ratchet.decrypt_message(
            self._state, msg, associated_data, self._aead, self._keypair)
        return pt

    def generate_dh_keys(self) -> DHKeyPair:
        return self._keypair.generate_dh()

    def serialize(self) -> dict:
        return {
            "state" : self._state.serialize(),
            "aead": pickle.dumps(self._aead),
            "keypair": pickle.dumps(self._keypair),
            "ratchet": pickle.dumps(self._ratchet)
        }

    @classmethod
    def deserialize(cls, serialized_dict: dict):
        if not isinstance(serialized_dict, dict):
            raise TypeError("serialized_dict must be of type: dict")

        return cls(
            state=State.deserialize(serialized_dict["state"]),
            aead=pickle.loads(serialized_dict["aead"]),
            keypair=pickle.loads(serialized_dict["keypair"]),
            ratchet=pickle.loads(serialized_dict["ratchet"])
        )
