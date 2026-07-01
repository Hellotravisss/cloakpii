"""
AES-256-GCM file encryption and decryption.

Wire format: [16-byte salt][12-byte nonce][ciphertext + 16-byte GCM tag]
Key derivation: PBKDF2-HMAC-SHA256 with 480 000 iterations.
"""

import os
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_LEN = 16
NONCE_LEN = 12
PBKDF2_ITERATIONS = 480_000
KEY_LEN = 32  # 256 bits


class CryptoError(Exception):
    """Raised when encryption/decryption fails."""


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from password + salt via PBKDF2."""
    if not password:
        raise CryptoError("Password must not be empty")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_data_with_key(plaintext: bytes, key: bytes, salt: bytes) -> bytes:
    """Encrypt with a pre-derived key. `salt` is stored in the header so the
    blob stays self-decryptable by password. Returns salt + nonce + ciphertext."""
    nonce = os.urandom(NONCE_LEN)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return salt + nonce + ciphertext


def decrypt_data_with_key(blob: bytes, key: bytes) -> bytes:
    """Decrypt with a pre-derived key (skips the stored salt / KDF step)."""
    min_len = SALT_LEN + NONCE_LEN + 16  # at least the GCM tag
    if len(blob) < min_len:
        raise CryptoError("Ciphertext too short — corrupted or truncated")
    nonce = blob[SALT_LEN : SALT_LEN + NONCE_LEN]
    ciphertext = blob[SALT_LEN + NONCE_LEN :]
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, None)
    except Exception:
        # Deliberately do not echo the underlying exception — it can leak
        # internal details and the cause is always the same to the caller.
        raise CryptoError("Decryption failed: wrong password or corrupted data")


def read_salt(blob: bytes) -> bytes:
    """Return the salt header from an encrypted blob."""
    if len(blob) < SALT_LEN:
        raise CryptoError("Ciphertext too short — corrupted or truncated")
    return blob[:SALT_LEN]


def encrypt_data(plaintext: bytes, password: str) -> bytes:
    """Encrypt raw bytes. Returns salt + nonce + ciphertext(+tag)."""
    salt = os.urandom(SALT_LEN)
    key = derive_key(password, salt)
    return encrypt_data_with_key(plaintext, key, salt)


def decrypt_data(blob: bytes, password: str) -> bytes:
    """Decrypt bytes produced by encrypt_data. Raises CryptoError on failure."""
    if len(blob) < SALT_LEN + NONCE_LEN + 16:
        raise CryptoError("Ciphertext too short — corrupted or truncated")
    key = derive_key(password, read_salt(blob))
    return decrypt_data_with_key(blob, key)


def encrypt_file(input_path: Path, output_path: Path, password: str) -> None:
    """Encrypt a file in-place on disk."""
    input_path = Path(input_path)
    output_path = Path(output_path)
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")
    plaintext = input_path.read_bytes()
    blob = encrypt_data(plaintext, password)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(blob)


def decrypt_file(input_path: Path, output_path: Path, password: str) -> None:
    """Decrypt a file produced by encrypt_file. Auto-detects the streaming format."""
    input_path = Path(input_path)
    output_path = Path(output_path)
    if not input_path.exists():
        raise FileNotFoundError(f"Encrypted file not found: {input_path}")
    if is_stream_file(input_path):
        salt = read_stream_salt(input_path)
        key = derive_key(password, salt)
        decrypt_file_stream_with_key(input_path, output_path, key)
        return
    blob = input_path.read_bytes()
    plaintext = decrypt_data(blob, password)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(plaintext)


def encrypt_file_with_key(input_path: Path, output_path: Path, key: bytes, salt: bytes) -> None:
    """Encrypt a file with a pre-derived key (avoids re-running the KDF per file)."""
    input_path = Path(input_path)
    output_path = Path(output_path)
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")
    blob = encrypt_data_with_key(input_path.read_bytes(), key, salt)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(blob)


def decrypt_file_with_key(input_path: Path, output_path: Path, key: bytes) -> None:
    """Decrypt a file with a pre-derived key. Auto-detects the streaming format."""
    input_path = Path(input_path)
    output_path = Path(output_path)
    if not input_path.exists():
        raise FileNotFoundError(f"Encrypted file not found: {input_path}")
    if is_stream_file(input_path):
        decrypt_file_stream_with_key(input_path, output_path, key)
        return
    plaintext = decrypt_data_with_key(input_path.read_bytes(), key)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(plaintext)


# ---------------------------------------------------------------------------
# Streaming (chunked) format — for files too large to hold in memory.
#
# Additive format, distinct from the legacy single-shot blob above and
# identified by an 8-byte magic header, so legacy ciphertext stays
# byte-compatible and decryption auto-detects which format it is reading.
#
# Layout (v2):
#   [8 magic][16 run_salt][16 file_salt] then repeated chunks:
#     [1 type][4 ct_len(BE)][ct_len bytes ciphertext+tag]
#   type 0x00 = data chunk, 0x01 = final terminator (empty plaintext).
#
# Each file derives its OWN key: file_key = HKDF-SHA256(run_key, salt=file_salt).
# With a per-file random 128-bit salt the file keys are independent, so the
# per-chunk nonce can be a simple 96-bit counter without any (key, nonce)
# reuse risk across files — fixing the v1 defect where a run-wide key was
# combined with only a 64-bit random nonce prefix. AAD = type(1) || counter(4)
# still binds chunk order + finality; reordering/truncation/tampering all fail
# the GCM tag.
# ---------------------------------------------------------------------------

STREAM_MAGIC = b"CPIISTM2"
STREAM_FILE_SALT_LEN = 16
STREAM_CHUNK_SIZE = 1024 * 1024  # 1 MiB plaintext per chunk
_STREAM_HEADER_LEN = len(STREAM_MAGIC) + SALT_LEN + STREAM_FILE_SALT_LEN
_STREAM_INFO = b"cloakpii-stream-v2-file-key"


def _stream_file_key(run_key: bytes, file_salt: bytes) -> bytes:
    """Derive an independent per-file key from the run key + a per-file salt."""
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    return HKDF(algorithm=hashes.SHA256(), length=KEY_LEN,
                salt=file_salt, info=_STREAM_INFO).derive(run_key)


def is_stream_file(path: Path) -> bool:
    """Return True if the file begins with the streaming-format magic header."""
    try:
        with open(path, "rb") as f:
            return f.read(len(STREAM_MAGIC)) == STREAM_MAGIC
    except OSError:
        return False


def read_stream_salt(path: Path) -> bytes:
    """Read the run salt (for password→run-key derivation) from a stream header."""
    with open(path, "rb") as f:
        header = f.read(_STREAM_HEADER_LEN)
    if len(header) < _STREAM_HEADER_LEN or header[:len(STREAM_MAGIC)] != STREAM_MAGIC:
        raise CryptoError("Not a CloakPII streaming file")
    return header[len(STREAM_MAGIC):len(STREAM_MAGIC) + SALT_LEN]


def encrypt_file_stream_with_key(input_path: Path, output_path: Path, key: bytes,
                                 salt: bytes, chunk_size: int = STREAM_CHUNK_SIZE) -> None:
    """Encrypt a file in fixed-size chunks (constant memory) with a pre-derived run key."""
    input_path = Path(input_path)
    output_path = Path(output_path)
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")
    file_salt = os.urandom(STREAM_FILE_SALT_LEN)
    aead = AESGCM(_stream_file_key(key, file_salt))
    output_path.parent.mkdir(parents=True, exist_ok=True)

    def _nonce(counter: int) -> bytes:
        return counter.to_bytes(NONCE_LEN, "big")  # 96-bit counter, unique per chunk

    with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
        fout.write(STREAM_MAGIC + salt + file_salt)
        counter = 0
        while True:
            chunk = fin.read(chunk_size)
            if not chunk:
                break
            aad = b"\x00" + counter.to_bytes(4, "big")
            ct = aead.encrypt(_nonce(counter), chunk, aad)
            fout.write(b"\x00" + len(ct).to_bytes(4, "big") + ct)
            counter += 1
        # Final terminator chunk (empty plaintext, final flag in type + AAD).
        aad = b"\x01" + counter.to_bytes(4, "big")
        ct = aead.encrypt(_nonce(counter), b"", aad)
        fout.write(b"\x01" + len(ct).to_bytes(4, "big") + ct)


def decrypt_file_stream_with_key(input_path: Path, output_path: Path, key: bytes) -> None:
    """Decrypt a streaming-format file with a pre-derived run key (constant memory).

    Writes to a temp file and atomically promotes it only after the final
    terminator chunk is authenticated — a truncated/tampered stream therefore
    NEVER leaves partial decrypted plaintext at output_path.
    """
    input_path = Path(input_path)
    output_path = Path(output_path)

    with open(input_path, "rb") as fin:
        header = fin.read(_STREAM_HEADER_LEN)
        if len(header) < _STREAM_HEADER_LEN or header[:len(STREAM_MAGIC)] != STREAM_MAGIC:
            raise CryptoError("Not a CloakPII streaming file")
        file_salt = header[len(STREAM_MAGIC) + SALT_LEN:]
        aead = AESGCM(_stream_file_key(key, file_salt))

        output_path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(dir=output_path.parent, suffix=".dec.tmp")
        os.close(fd)
        tmp_path = Path(tmp_name)
        counter = 0
        saw_final = False
        try:
            with open(tmp_path, "wb") as fout:
                while True:
                    head = fin.read(5)
                    if len(head) < 5:
                        raise CryptoError("Truncated stream — missing final chunk")
                    ctype = head[0]
                    ct_len = int.from_bytes(head[1:5], "big")
                    ct = fin.read(ct_len)
                    if len(ct) != ct_len:
                        raise CryptoError("Truncated stream — short chunk")
                    nonce = counter.to_bytes(NONCE_LEN, "big")
                    aad = bytes([ctype]) + counter.to_bytes(4, "big")
                    try:
                        plain = aead.decrypt(nonce, ct, aad)
                    except Exception:
                        raise CryptoError("Decryption failed: wrong password or corrupted data")
                    if ctype == 0x01:
                        saw_final = True
                        break
                    fout.write(plain)
                    counter += 1
            if not saw_final:
                raise CryptoError("Truncated stream — missing final chunk")
            os.replace(tmp_path, output_path)  # promote only after full auth
        except BaseException:
            try:
                tmp_path.unlink()
            except OSError:
                pass
            raise
