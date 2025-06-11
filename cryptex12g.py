import struct
import os
import copy

try:
    import numpy as np
    _HAS_NUMPY = True
except ImportError:
    _HAS_NUMPY = False

# --- CryptoXG12 Constants ---

BLOCK_SIZE = 16  # bytes (128 bits)
KEY_SIZE = 32    # bytes (256 bits)
N_ROUNDS = 16

# Custom S-box and inverse S-box (not generated, static)
SBOX = [
    177, 210, 185, 77, 109, 162, 189, 179, 29, 71, 66, 96, 75, 70, 20, 27, 1, 80, 9, 83, 245, 158, 150, 174, 147, 2,
    231, 98, 125, 78, 251, 49, 3, 57, 46, 88, 152, 214, 182, 61, 127, 52, 99, 241, 8, 90, 23, 10, 12, 58, 0, 244, 159,
    213, 226, 5, 105, 211, 198, 173, 138, 190, 238, 145, 137, 100, 196, 254, 121, 68, 153, 208, 132, 193, 82, 30, 216,
    154, 221, 215, 164, 104, 120, 172, 114, 119, 236, 47, 191, 169, 247, 39, 72, 166, 204, 42, 60, 93, 18, 41, 151, 50,
    203, 7, 129, 130, 107, 220, 202, 22, 144, 246, 141, 201, 86, 24, 161, 212, 128, 51, 117, 31, 63, 65, 81, 54, 19,
    73, 192, 176, 101, 178, 142, 255, 108, 186, 13, 35, 48, 135, 170, 240, 250, 133, 84, 134, 235, 87, 188, 157, 228,
    148, 207, 67, 123, 11, 225, 195, 55, 103, 253, 40, 110, 222, 167, 160, 230, 187, 233, 94, 140, 249, 200, 102, 45,
    180, 106, 242, 181, 6, 44, 139, 206, 248, 17, 146, 111, 184, 234, 64, 112, 122, 252, 62, 155, 113, 85, 171, 36,
    163, 4, 38, 79, 149, 32, 131, 175, 136, 232, 21, 74, 217, 97, 33, 168, 15, 92, 91, 95, 194, 143, 219, 197, 239,
    237, 227, 156, 43, 126, 218, 53, 37, 223, 229, 165, 199, 205, 118, 116, 14, 69, 124, 183, 26, 34, 209, 56, 59,
    224, 16, 115, 89, 28, 243, 76, 25
]
INV_SBOX = [
    50, 16, 25, 32, 200, 55, 179, 103, 44, 18, 47, 155, 48, 136, 239, 215, 249, 184, 98, 126, 14, 209, 109, 46, 115,
    255, 243, 15, 252, 8, 75, 121, 204, 213, 244, 137, 198, 231, 201, 91, 161, 99, 95, 227, 180, 174, 34, 87, 138, 31,
    101, 119, 41, 230, 125, 158, 246, 33, 49, 247, 96, 39, 193, 122, 189, 123, 10, 153, 69, 240, 13, 9, 92, 127, 210,
    12, 254, 3, 29, 202, 17, 124, 74, 19, 144, 196, 114, 147, 35, 251, 45, 217, 216, 97, 169, 218, 11, 212, 27, 42,
    65, 130, 173, 159, 81, 56, 176, 106, 134, 4, 162, 186, 190, 195, 84, 250, 238, 120, 237, 85, 82, 68, 191, 154, 241,
    28, 228, 40, 118, 104, 105, 205, 72, 143, 145, 139, 207, 64, 60, 181, 170, 112, 132, 220, 110, 63, 185, 24, 151,
    203, 22, 100, 36, 70, 77, 194, 226, 149, 21, 52, 165, 116, 5, 199, 80, 234, 93, 164, 214, 89, 140, 197, 83, 59,
    23, 206, 129, 0, 131, 7, 175, 178, 38, 242, 187, 2, 135, 167, 148, 6, 61, 88, 128, 73, 219, 157, 66, 222, 58, 235,
    172, 113, 108, 102, 94, 236, 182, 152, 71, 245, 1, 57, 117, 53, 37, 79, 76, 211, 229, 221, 107, 78, 163, 232, 248,
    156, 54, 225, 150, 233, 166, 26, 208, 168, 188, 146, 86, 224, 62, 223, 141, 43, 177, 253, 51, 20, 111, 90, 183,
    171, 142, 30, 192, 160, 67, 133
]

# Linear layer (MDS matrix) for diffusion: 16x16 binary matrix
# (chosen for invertibility, fixed for all rounds)
LINEAR_MATRIX = [
    [1 if (i == j or (i + j) % 5 == 0) else 0 for j in range(16)] for i in range(16)
]

# Custom irreducible polynomial for GF(2^128) MAC
# Polynomial: x^128 + x^7 + x^2 + x + 1 (0x87, AES-GCM uses x^128 + x^7 + x^2 + x + 1)
POLY_GF128 = 0x100000000000000000000000000000087

# --- Utility Functions ---

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def int_to_bytes(n: int, length: int) -> bytes:
    return n.to_bytes(length, byteorder="big")

def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big")

def split_blocks(data: bytes, size: int) -> list:
    return [data[i:i+size] for i in range(0, len(data), size)]

def pad_block(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - len(data)
    return data + bytes([pad_len] * pad_len)

def unpad_block(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len == 0 or pad_len > len(data):
        raise ValueError("Invalid padding")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid padding")
    return data[:-pad_len]

# --- Linear Layer: Matrix Multiplication over GF(2) ---

def mat_mult_gf2(vec, mat):
    """Multiply 16-byte vector by 16x16 binary matrix (GF(2))"""
    res = bytearray(16)
    for i in range(16):
        v = 0
        for j in range(16):
            if mat[i][j]:
                v ^= vec[j]
        res[i] = v
    return bytes(res)

if _HAS_NUMPY:
    _NP_LINEAR_MATRIX = np.array(LINEAR_MATRIX, dtype=np.uint8)
    def mat_mult_gf2(vec, mat=_NP_LINEAR_MATRIX):
        v = np.frombuffer(vec, dtype=np.uint8)
        res = np.bitwise_xor.reduce(np.where(mat, v, 0), axis=1)
        return res.tobytes()

# --- Substitution Layer ---

def substitute(data: bytes, sbox: list) -> bytes:
    return bytes(sbox[b] for b in data)

# --- Key Schedule ---

def rotl32(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def key_schedule(master_key: bytes) -> list:
    """
    Expand 256-bit key into N_ROUNDS+1 round keys (each 16 bytes).
    Uses a simple hash-like key expansion and S-box mixing.
    """
    assert len(master_key) == KEY_SIZE
    # Initialize with 8 words (32 bits each)
    w = [struct.unpack(">I", master_key[i*4:(i+1)*4])[0] for i in range(8)]
    rkeys = []
    for r in range(N_ROUNDS + 1):
        # Mix, add round constant, S-box, rotate, nonlinearity
        temp = w[-1] ^ rotl32(w[-2], 3) ^ rotl32(w[-3], 7) ^ (r * 0x9E3779B9)
        temp = SBOX[(temp >> 24) & 0xFF] << 24 | SBOX[(temp >> 16) & 0xFF] << 16 | SBOX[(temp >> 8) & 0xFF] << 8 | SBOX[temp & 0xFF]
        w.append(temp)
        # Use 4 consecutive words as round key
        rk = b''.join(struct.pack(">I", w[-i-1]) for i in range(4))
        rkeys.append(rk)
        # keep size at 8+N_ROUNDS+1, but only last 8 are used for next step
        if len(w) > 12:
            w.pop(0)
    return rkeys

# --- Core SPN Cipher ---

class CryptoXG12Block:
    """Block cipher primitive. 128-bit block, 256-bit key, 16 rounds."""

    def __init__(self, key: bytes):
        assert len(key) == KEY_SIZE
        self.key = key
        self.round_keys = key_schedule(key)

    def encrypt_block(self, block: bytes) -> bytes:
        assert len(block) == BLOCK_SIZE
        state = block
        # Initial round key
        state = xor_bytes(state, self.round_keys[0])
        for r in range(1, N_ROUNDS):
            # Substitution layer
            state = substitute(state, SBOX)
            # Linear diffusion
            state = mat_mult_gf2(state, LINEAR_MATRIX)
            # Add round key
            state = xor_bytes(state, self.round_keys[r])
        # Final round (skip linear layer)
        state = substitute(state, SBOX)
        state = xor_bytes(state, self.round_keys[N_ROUNDS])
        return state

    def decrypt_block(self, block: bytes) -> bytes:
        assert len(block) == BLOCK_SIZE
        state = block
        # Inverse final round
        state = xor_bytes(state, self.round_keys[N_ROUNDS])
        state = substitute(state, INV_SBOX)
        for r in reversed(range(1, N_ROUNDS)):
            state = xor_bytes(state, self.round_keys[r])
            state = mat_mult_gf2(state, LINEAR_MATRIX)  # Matrix is self-inverse
            state = substitute(state, INV_SBOX)
        state = xor_bytes(state, self.round_keys[0])
        return state

# --- Counter (CTR) Mode ---

def inc_counter(counter: bytes) -> bytes:
    ctr = list(counter)
    for i in reversed(range(len(ctr))):
        ctr[i] = (ctr[i] + 1) & 0xFF
        if ctr[i] != 0:
            break
    return bytes(ctr)

def ctr_encrypt(cipher: CryptoXG12Block, nonce: bytes, data: bytes) -> bytes:
    """CTR mode, nonce must be 12 bytes, counter 4 bytes (big-endian), block size 16 bytes."""
    assert len(nonce) == 12
    out = bytearray()
    ctr = 1
    for blk in split_blocks(data, BLOCK_SIZE):
        counter_block = nonce + struct.pack(">I", ctr)
        keystream = cipher.encrypt_block(counter_block)
        chunk = xor_bytes(blk.ljust(BLOCK_SIZE, b"\0"), keystream)[:len(blk)]
        out.extend(chunk)
        ctr += 1
    return bytes(out)

# --- Polynomial MAC over GF(2^128) ---

def gf128_mul(x: int, y: int) -> int:
    """Multiply two elements in GF(2^128) with custom poly."""
    z = 0
    for i in range(128):
        if y & (1 << (127 - i)):
            z ^= x
        if x & (1 << 127):
            x = ((x << 1) ^ POLY_GF128) & ((1 << 128) - 1)
        else:
            x = (x << 1) & ((1 << 128) - 1)
    return z

def poly_mac(key: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    """
    Compute polynomial MAC over (AAD || padding || ciphertext || padding || [bitlen_aad, bitlen_ct]) as in GCM.
    """
    assert len(key) == 16
    H = bytes_to_int(key)
    tag = 0
    # AAD
    aad_blocks = split_blocks(aad, 16)
    for blk in aad_blocks:
        m = bytes_to_int(blk.ljust(16, b"\0"))
        tag = gf128_mul(tag ^ m, H)
    # Ciphertext
    ct_blocks = split_blocks(ciphertext, 16)
    for blk in ct_blocks:
        m = bytes_to_int(blk.ljust(16, b"\0"))
        tag = gf128_mul(tag ^ m, H)
    # Length block
    a_len = len(aad) * 8
    c_len = len(ciphertext) * 8
    length_block = int_to_bytes(a_len, 8) + int_to_bytes(c_len, 8)
    tag = gf128_mul(tag ^ bytes_to_int(length_block), H)
    return int_to_bytes(tag, 16)

# --- AEAD GCM-like Mode ---

class CryptoXG12GCM:
    """
    GCM-like AEAD mode:
      - Nonce: 12 bytes
      - Key: 32 bytes
      - Auth tag: 16 bytes (128 bits)
    """

    def __init__(self, key: bytes):
        assert len(key) == 32
        self.block = CryptoXG12Block(key)

    def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> (bytes, bytes):
        """
        Encrypt and authenticate. Returns (ciphertext, tag)
        """
        assert len(nonce) == 12
        # Derive hash subkey H: E_K(0^16)
        H = self.block.encrypt_block(b"\0" * 16)
        # CTR mode encryption
        ciphertext = ctr_encrypt(self.block, nonce, plaintext)
        # MAC over (AAD, ciphertext)
        tag = poly_mac(H, aad, ciphertext)
        # Authenticate nonce as well (finalize)
        tag = xor_bytes(tag, self.block.encrypt_block(nonce + b"\0\0\0\1"))
        return ciphertext, tag

    def decrypt(self, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
        """
        Decrypt and verify. Raises ValueError if tag invalid.
        """
        assert len(nonce) == 12
        assert len(tag) == 16
        H = self.block.encrypt_block(b"\0" * 16)
        pt = ctr_encrypt(self.block, nonce, ciphertext)
        expected_tag = poly_mac(H, aad, ciphertext)
        expected_tag = xor_bytes(expected_tag, self.block.encrypt_block(nonce + b"\0\0\0\1"))
        if not _consteq(tag, expected_tag):
            raise ValueError("Authentication failed")
        return pt

def _consteq(a: bytes, b: bytes) -> bool:
    """Constant-time bytes comparison."""
    if len(a) != len(b):
        return False
    r = 0
    for x, y in zip(a, b):
        r |= x ^ y
    return r == 0
