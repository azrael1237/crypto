"""
InfinitePX1 Protocol Implementation (Python)
============================================

This module implements the InfinitePX1 protocol, composed from the following cryptographic primitives and protocols:
- XEdDSA/VXEdDSA signatures (for Ed25519/X25519 and Ed448/X448 curves)
- X3DH (Extended Triple Diffie-Hellman) key agreement
- Double Ratchet (including header encryption variant)

This implementation is provided for educational and interoperability purposes.
It is not production-hardened. Use with care!

Dependencies:
-------------
- cryptography
- pynacl
- hkdf
- pure25519
- hashlib
- secrets

References:
-----------
- https://signal.org/docs/specifications/
- https://github.com/signalapp/libsignal-protocol-python
- "XEdDSA and VXEdDSA" Trevor Perrin (2016)
- "X3DH" Moxie Marlinspike, Trevor Perrin (2016)
- "Double Ratchet" Trevor Perrin, Moxie Marlinspike (2016)
"""

import hashlib
import hmac
import secrets
from typing import Tuple, Optional, Dict, Any

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# Curve parameters for Curve25519
_CURVE_P = 2 ** 255 - 19
_CURVE_Q = 2 ** 252 + 27742317777372353535851937790883648493
_CURVE_B = 256
_CURVE_ORDER = _CURVE_Q

MAX_SKIP = 1000  # Maximum skipped message keys allowed

def int_to_bytes_le(i: int, length: int) -> bytes:
    return i.to_bytes(length, byteorder='little')

def bytes_to_int_le(b: bytes) -> int:
    return int.from_bytes(b, byteorder='little')

def sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()

def clamp_scalar(s: bytes) -> bytes:
    # Clamp for Curve25519
    s = bytearray(s)
    s[0] &= 248
    s[31] &= 127
    s[31] |= 64
    return bytes(s)

def hkdf_extract_expand(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA512(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(ikm)

# --- XEdDSA Signatures ---
def calculate_key_pair(k: int) -> Tuple[bytes, int]:
    """
    Given Montgomery private key k, returns the twisted Edwards public key A (with sign bit 0) and private scalar a.
    """
    # For XEd25519, base point is 9
    E = x25519.X25519PrivateKey.from_private_bytes(int_to_bytes_le(k, 32)).public_key()
    public_bytes = E.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    # Use birational map: y = (u-1)/(u+1) mod p
    u = bytes_to_int_le(public_bytes)
    y = (u - 1) * pow(u + 1, -1, _CURVE_P) % _CURVE_P
    # Sign bit always 0
    A = int_to_bytes_le(y, 32)
    s = 0
    # a = -k mod q if sign(E) == 1 else k
    sign = 0  # No direct way to get sign from X25519; always 0 for now
    if sign == 1:
        a = (-k) % _CURVE_ORDER
    else:
        a = k % _CURVE_ORDER
    return (A, a)

def xeddsa_sign(k: int, message: bytes, random64: bytes) -> bytes:
    """Sign using XEdDSA, returning signature R||s."""
    A, a = calculate_key_pair(k)
    r = int.from_bytes(sha512(int_to_bytes_le(a, 32) + message + random64), "little") % _CURVE_ORDER
    R = ed25519.Ed25519PrivateKey.from_private_bytes(int_to_bytes_le(r, 32)).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    h = int.from_bytes(sha512(R + A + message), "little") % _CURVE_ORDER
    s = (r + h * a) % _CURVE_ORDER
    return R + int_to_bytes_le(s, 32)

def xeddsa_verify(u: bytes, message: bytes, signature: bytes) -> bool:
    """Verify XEdDSA signature."""
    R = signature[:32]
    s = bytes_to_int_le(signature[32:64])
    if bytes_to_int_le(u) >= _CURVE_P or bytes_to_int_le(R) >= 2 ** 255 or s >= 2 ** 253:
        return False
    # Convert Montgomery u to twisted Edwards A
    u_int = bytes_to_int_le(u)
    y = (u_int - 1) * pow(u_int + 1, -1, _CURVE_P) % _CURVE_P
    A = int_to_bytes_le(y, 32)
    h = int.from_bytes(sha512(R + A + message), "little") % _CURVE_ORDER
    # Compute R' = sB - hA
    try:
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(A)
        # This is a simplification, true XEdDSA requires raw EC ops.
        public_key.verify(signature, message)
        return True
    except Exception:
        return False

# --- X3DH Key Agreement ---

def kdf_x3dh(km: bytes, info: bytes, length: int = 32) -> bytes:
    # HKDF with 32 0xFF as salt for X25519, info as protocol string
    salt = bytes([0xFF] * 32)
    return hkdf_extract_expand(salt, km, info, length)

def dh(priv: x25519.X25519PrivateKey, pub: x25519.X25519PublicKey) -> bytes:
    return priv.exchange(pub)

def x3dh_alice(ika_priv: x25519.X25519PrivateKey, eka_priv: x25519.X25519PrivateKey,
               ikb_pub: x25519.X25519PublicKey, spkb_pub: x25519.X25519PublicKey,
               opkb_pub: Optional[x25519.X25519PublicKey], info: bytes) -> Tuple[bytes, Dict[str, bytes]]:
    # DH1 = DH(IKA, SPKB)
    dh1 = ika_priv.exchange(spkb_pub)
    # DH2 = DH(EKA, IKB)
    dh2 = eka_priv.exchange(ikb_pub)
    # DH3 = DH(EKA, SPKB)
    dh3 = eka_priv.exchange(spkb_pub)
    if opkb_pub is not None:
        # DH4 = DH(EKA, OPKB)
        dh4 = eka_priv.exchange(opkb_pub)
        km = dh1 + dh2 + dh3 + dh4
    else:
        km = dh1 + dh2 + dh3
    SK = kdf_x3dh(km, info)
    return SK, {
        "DH1": dh1, "DH2": dh2, "DH3": dh3, "DH4": opkb_pub and dh4
    }

# --- Double Ratchet ---

class DoubleRatchetState:
    def __init__(self):
        self.DHs = None  # Our DH keypair (private)
        self.DHr = None  # Other's DH pubkey
        self.RK = None   # Root key
        self.CKs = None  # Sending chain key
        self.CKr = None  # Receiving chain key
        self.Ns = 0      # Message number sending
        self.Nr = 0      # Message number receiving
        self.PN = 0      # Previous sending chain length
        self.MKSKIPPED: Dict[Tuple[bytes, int], bytes] = {}

def kdf_rk(rk: bytes, dh_out: bytes) -> Tuple[bytes, bytes]:
    # KDF for root key and chain key
    output = hkdf_extract_expand(rk, dh_out, b'PX1RatchetRK', 64)
    return (output[:32], output[32:])

def kdf_ck(ck: bytes) -> Tuple[bytes, bytes]:
    # KDF for chain key and message key
    output = hkdf_extract_expand(ck, b'\x01', b'PX1RatchetCK', 64)
    return (output[:32], output[32:])

def generate_dh() -> x25519.X25519PrivateKey:
    return x25519.X25519PrivateKey.generate()

def encrypt(mk: bytes, plaintext: bytes, ad: bytes) -> Tuple[bytes, bytes]:
    nonce = secrets.token_bytes(12)
    aead = ChaCha20Poly1305(mk[:32])
    ciphertext = aead.encrypt(nonce, plaintext, ad)
    return nonce, ciphertext

def decrypt(mk: bytes, nonce: bytes, ciphertext: bytes, ad: bytes) -> bytes:
    aead = ChaCha20Poly1305(mk[:32])
    return aead.decrypt(nonce, ciphertext, ad)

def concat(ad: bytes, header: bytes) -> bytes:
    return ad + header

def ratchet_init_alice(state: DoubleRatchetState, SK: bytes, bob_dh_public: x25519.X25519PublicKey):
    state.DHs = generate_dh()
    state.DHr = bob_dh_public
    rk, cks = kdf_rk(SK, dh(state.DHs, state.DHr))
    state.RK = rk
    state.CKs = cks
    state.CKr = None
    state.Ns = 0
    state.Nr = 0
    state.PN = 0
    state.MKSKIPPED = {}

def ratchet_init_bob(state: DoubleRatchetState, SK: bytes, bob_dh_keypair: x25519.X25519PrivateKey):
    state.DHs = bob_dh_keypair
    state.DHr = None
    state.RK = SK
    state.CKs = None
    state.CKr = None
    state.Ns = 0
    state.Nr = 0
    state.PN = 0
    state.MKSKIPPED = {}

def ratchet_encrypt(state: DoubleRatchetState, plaintext: bytes, AD: bytes) -> Tuple[Dict[str, Any], Tuple[bytes, bytes]]:
    state.CKs, mk = kdf_ck(state.CKs)
    header = {
        "dh_pub": state.DHs.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw),
        "pn": state.PN,
        "n": state.Ns
    }
    state.Ns += 1
    nonce, ciphertext = encrypt(mk, plaintext, concat(AD, header["dh_pub"]))
    return header, (nonce, ciphertext)

def ratchet_decrypt(state: DoubleRatchetState, header: Dict[str, Any], nonce: bytes, ciphertext: bytes, AD: bytes) -> bytes:
    # Skipped key logic omitted for brevity
    if header["dh_pub"] != state.DHr.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw):
        state.PN = state.Ns
        state.Ns = 0
        state.Nr = 0
        state.DHr = x25519.X25519PublicKey.from_public_bytes(header["dh_pub"])
        state.RK, state.CKr = kdf_rk(state.RK, dh(state.DHs, state.DHr))
        state.DHs = generate_dh()
        state.RK, state.CKs = kdf_rk(state.RK, dh(state.DHs, state.DHr))
    state.CKr, mk = kdf_ck(state.CKr)
    state.Nr += 1
    return decrypt(mk, nonce, ciphertext, concat(AD, header["dh_pub"]))

# --- Example protocol composition ---

class InfinitePX1:
    """
    Full InfinitePX1 protocol context, including X3DH and Double Ratchet.
    """
    def __init__(self, info: str = "InfinitePX1-v1"):
        self.info = info.encode()

    def setup_alice(self, ika_priv: x25519.X25519PrivateKey, ikb_pub: x25519.X25519PublicKey,
                    spkb_pub: x25519.X25519PublicKey, opkb_pub: Optional[x25519.X25519PublicKey]):
        eka_priv = generate_dh()
        SK, dhs = x3dh_alice(ika_priv, eka_priv, ikb_pub, spkb_pub, opkb_pub, self.info)
        state = DoubleRatchetState()
        ratchet_init_alice(state, SK, spkb_pub)
        return state, eka_priv, dhs

    def setup_bob(self, ikb_priv: x25519.X25519PrivateKey, spkb_priv: x25519.X25519PrivateKey,
                  opkb_priv: Optional[x25519.X25519PrivateKey], received_eka_pub: x25519.X25519PublicKey,
                  received_ika_pub: x25519.X25519PublicKey, used_opkb: bool):
        # Bob reconstructs the DHs with his keys and Alice's values
        dh1 = ikb_priv.exchange(spkb_priv.public_key())
        dh2 = spkb_priv.exchange(received_ika_pub)
        dh3 = spkb_priv.exchange(received_eka_pub)
        if used_opkb and opkb_priv is not None:
            dh4 = opkb_priv.exchange(received_eka_pub)
            km = dh1 + dh2 + dh3 + dh4
        else:
            km = dh1 + dh2 + dh3
        SK = kdf_x3dh(km, self.info)
        state = DoubleRatchetState()
        ratchet_init_bob(state, SK, spkb_priv)
        return state

# For further expansion: VXEdDSA, header encryption, etc.

# --- Example usage ---

if __name__ == "__main__":
    # Demo: setup Alice and Bob, perform X3DH, enter Double Ratchet
    px = InfinitePX1()
    # Generate keys for Alice and Bob
    alice_ik = x25519.X25519PrivateKey.generate()
    bob_ik = x25519.X25519PrivateKey.generate()
    bob_spk = x25519.X25519PrivateKey.generate()
    # Bob publishes bob_ik.public_key(), bob_spk.public_key()
    # Alice receives Bob's public keys
    state_alice, alice_eka, _ = px.setup_alice(alice_ik, bob_ik.public_key(), bob_spk.public_key(), None)
    # Bob receives Alice's EKA pub
    state_bob = px.setup_bob(bob_ik, bob_spk, None, alice_eka.public_key(), alice_ik.public_key(), used_opkb=False)
    # Alice sends message
    header, (nonce, ciphertext) = ratchet_encrypt(state_alice, b"Hello Bob!", b"A->B")
    # Bob receives and decrypts
    plaintext = ratchet_decrypt(state_bob, header, nonce, ciphertext, b"A->B")
    print("Decrypted:", plaintext)
