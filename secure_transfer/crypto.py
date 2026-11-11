"""
Cryptographic core of the Secure File Transfer System (SFT).

Design (summary - see docs/ENCRYPTION.md for the full explanation):

* Long-term identity  : Ed25519 key pair per device (RFC 8032).
* Key agreement       : Ephemeral X25519 per connection (RFC 7748)  -> Perfect Forward Secrecy.
* Authentication      : Each side signs its handshake message with its Ed25519 identity key.
                        The server's signature also covers the hash of the client's hello
                        (transcript binding, prevents replay / splicing).
* Key derivation      : HKDF-SHA256 (RFC 5869), salt = SHA-256(handshake transcript).
                        Produces two independent AES-256 keys (one per direction) and
                        two 4-byte nonce prefixes.
* Bulk encryption     : AES-256-GCM (NIST SP 800-38D), 96-bit nonce = prefix(4) || counter(8).
                        The counter is implicit, so any replayed / reordered / dropped /
                        modified frame fails authentication.
* Human verification  : 6-digit Short Authentication String (SAS) derived from the session
                        + identity-key fingerprints (TOFU, like SSH / Signal safety numbers).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import struct
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PROTOCOL_VERSION = 1
MAGIC_HANDSHAKE = b"SFT1"   # first 4 bytes of an encrypted session
MAGIC_PROBE = b"PING"       # first 4 bytes of a discovery probe (public info only)
MAX_FRAME = 4 * 1024 * 1024  # 4 MiB hard limit per frame (DoS protection)
MAX_MESSAGES = 2 ** 32       # nonce counter safety limit per direction

MSG_JSON = 0x01
MSG_DATA = 0x02


class SecurityError(Exception):
    """Raised on any cryptographic / protocol violation. The connection must be dropped."""


# --------------------------------------------------------------------------- helpers
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"), validate=True)


def canonical(obj) -> bytes:
    """Deterministic JSON encoding (used for everything that is signed)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def fingerprint(pub_raw: bytes) -> str:
    """Human-readable fingerprint of an Ed25519 public key: SHA-256, first 128 bits, grouped."""
    h = hashlib.sha256(b"SFT-v1-FPR|" + pub_raw).hexdigest().upper()[:32]
    return "-".join(h[i:i + 4] for i in range(0, 32, 4))


# --------------------------------------------------------------------------- framing
def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed by peer")
        buf.extend(chunk)
    return bytes(buf)


def send_frame(sock: socket.socket, payload: bytes) -> None:
    if len(payload) > MAX_FRAME:
        raise SecurityError("frame too large")
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def recv_frame(sock: socket.socket) -> bytes:
    (n,) = struct.unpack(">I", recv_exact(sock, 4))
    if n > MAX_FRAME:
        raise SecurityError(f"frame too large ({n} bytes)")
    return recv_exact(sock, n)


# --------------------------------------------------------------------------- identity
class Identity:
    """Long-term Ed25519 identity of this device."""

    def __init__(self, private_key: Ed25519PrivateKey):
        self._sk = private_key
        self.public_raw = private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.fingerprint = fingerprint(self.public_raw)

    @classmethod
    def load_or_create(cls, path: Path) -> "Identity":
        path = Path(path)
        if path.exists():
            sk = serialization.load_pem_private_key(path.read_bytes(), password=None)
            if not isinstance(sk, Ed25519PrivateKey):
                raise SecurityError("identity file is not an Ed25519 key")
            return cls(sk)
        sk = Ed25519PrivateKey.generate()
        pem = sk.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        # create the file with restrictive permissions where the OS supports it
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(pem)
        return cls(sk)

    @classmethod
    def generate(cls) -> "Identity":
        return cls(Ed25519PrivateKey.generate())

    def sign(self, data: bytes) -> bytes:
        return self._sk.sign(data)


# --------------------------------------------------------------------------- secure channel
class SecureChannel:
    """AES-256-GCM encrypted, authenticated, replay-protected message channel."""

    def __init__(self, sock, send_key, send_iv, recv_key, recv_iv, send_label, recv_label):
        self.sock = sock
        self._send = AESGCM(send_key)
        self._recv = AESGCM(recv_key)
        self._send_iv = send_iv
        self._recv_iv = recv_iv
        self._send_label = send_label
        self._recv_label = recv_label
        self._send_ctr = 0
        self._recv_ctr = 0
        # filled by the handshake
        self.peer_name = ""
        self.peer_device_id = ""
        self.peer_public = b""
        self.peer_fingerprint = ""
        self.sas = ""
        self.transcript_hash = b""

    @staticmethod
    def _nonce(prefix: bytes, ctr: int) -> bytes:
        return prefix + ctr.to_bytes(8, "big")

    def _aad(self, label: bytes, ctr: int) -> bytes:
        return b"SFT-v1|" + label + b"|" + ctr.to_bytes(8, "big")

    def send(self, plaintext: bytes) -> None:
        if self._send_ctr >= MAX_MESSAGES:
            raise SecurityError("nonce space exhausted - reconnect")
        ctr = self._send_ctr
        ct = self._send.encrypt(self._nonce(self._send_iv, ctr), plaintext, self._aad(self._send_label, ctr))
        self._send_ctr += 1
        send_frame(self.sock, ct)

    def recv(self) -> bytes:
        ct = recv_frame(self.sock)
        ctr = self._recv_ctr
        try:
            pt = self._recv.decrypt(self._nonce(self._recv_iv, ctr), ct, self._aad(self._recv_label, ctr))
        except InvalidTag:
            raise SecurityError("authentication failed: data was modified, replayed or forged")
        self._recv_ctr += 1
        return pt

    # typed messages ---------------------------------------------------------
    def send_json(self, obj) -> None:
        self.send(bytes([MSG_JSON]) + canonical(obj))

    def send_data(self, data: bytes) -> None:
        self.send(bytes([MSG_DATA]) + data)

    def recv_msg(self):
        pt = self.recv()
        if not pt:
            raise SecurityError("empty message")
        kind, body = pt[0], pt[1:]
        if kind == MSG_JSON:
            return "json", json.loads(body.decode("utf-8"))
        if kind == MSG_DATA:
            return "data", body
        raise SecurityError("unknown message type")

    def recv_json(self) -> dict:
        kind, body = self.recv_msg()
        if kind != "json":
            raise SecurityError("expected a control message")
        return body

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


# --------------------------------------------------------------------------- handshake
@dataclass
class _Hello:
    raw: bytes
    body: dict
    id_pub: bytes
    eph_pub: bytes


def _make_hello(identity: Identity, role: str, device_id: str, name: str,
                eph_pub: bytes, bind: bytes) -> bytes:
    body = {
        "v": PROTOCOL_VERSION,
        "role": role,
        "device_id": device_id,
        "name": name[:64],
        "id_pub": b64e(identity.public_raw),
        "eph_pub": b64e(eph_pub),
        "nonce": b64e(os.urandom(32)),
    }
    sig = identity.sign(b"SFT-v1-HELLO|" + role.encode() + b"|" + canonical(body) + b"|" + bind)
    return canonical({"body": body, "sig": b64e(sig)})


def _parse_hello(raw: bytes, expected_role: str, bind: bytes) -> _Hello:
    try:
        msg = json.loads(raw.decode("utf-8"))
        body, sig = msg["body"], b64d(msg["sig"])
        if body["v"] != PROTOCOL_VERSION:
            raise SecurityError(f"unsupported protocol version {body['v']}")
        if body["role"] != expected_role:
            raise SecurityError("unexpected handshake role")
        id_pub, eph_pub = b64d(body["id_pub"]), b64d(body["eph_pub"])
        if len(id_pub) != 32 or len(eph_pub) != 32 or len(b64d(body["nonce"])) != 32:
            raise SecurityError("malformed key material")
    except SecurityError:
        raise
    except Exception as e:  # noqa: BLE001
        raise SecurityError(f"malformed handshake: {e}")
    try:
        Ed25519PublicKey.from_public_bytes(id_pub).verify(
            sig, b"SFT-v1-HELLO|" + expected_role.encode() + b"|" + canonical(body) + b"|" + bind
        )
    except InvalidSignature:
        raise SecurityError("invalid handshake signature (possible man-in-the-middle)")
    return _Hello(raw, body, id_pub, eph_pub)


def _derive(eph_sk: X25519PrivateKey, peer_eph: bytes, transcript: bytes, ids: tuple[bytes, bytes]):
    shared = eph_sk.exchange(X25519PublicKey.from_public_bytes(peer_eph))
    if shared == b"\x00" * 32:
        raise SecurityError("invalid X25519 public key (low-order point)")
    okm = HKDF(
        algorithm=hashes.SHA256(), length=72, salt=transcript, info=b"SFT-v1 session keys"
    ).derive(shared)
    keys = {
        "c2s_key": okm[0:32], "s2c_key": okm[32:64],
        "c2s_iv": okm[64:68], "s2c_iv": okm[68:72],
    }
    sas_raw = HKDF(
        algorithm=hashes.SHA256(), length=8, salt=transcript,
        info=b"SFT-v1 SAS|" + min(ids) + max(ids),
    ).derive(shared)
    n = int.from_bytes(sas_raw, "big") % 1_000_000
    sas = f"{n:06d}"
    return keys, f"{sas[:3]} {sas[3:]}"


def client_handshake(sock, identity: Identity, device_id: str, name: str,
                     expected_fingerprint: str | None = None) -> SecureChannel:
    """Initiator side (the sender). Returns an authenticated SecureChannel."""
    sock.sendall(MAGIC_HANDSHAKE)
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ch_raw = _make_hello(identity, "client", device_id, name, eph_pub, b"")
    send_frame(sock, ch_raw)

    sh = _parse_hello(recv_frame(sock), "server", hashlib.sha256(ch_raw).digest())
    peer_fp = fingerprint(sh.id_pub)
    if expected_fingerprint and expected_fingerprint != peer_fp:
        raise SecurityError(
            f"peer identity mismatch! expected {expected_fingerprint}, got {peer_fp} "
            "(possible man-in-the-middle)"
        )
    transcript = hashlib.sha256(b"SFT-v1-TRANSCRIPT|" + ch_raw + b"|" + sh.raw).digest()
    keys, sas = _derive(eph, sh.eph_pub, transcript, (identity.public_raw, sh.id_pub))
    ch = SecureChannel(sock, keys["c2s_key"], keys["c2s_iv"], keys["s2c_key"], keys["s2c_iv"], b"c2s", b"s2c")
    _finish(ch, transcript)
    _fill_peer(ch, sh, peer_fp, sas, transcript)
    return ch


def server_handshake(sock, identity: Identity, device_id: str, name: str) -> SecureChannel:
    """Responder side (the receiver). Caller has already consumed MAGIC_HANDSHAKE."""
    ch_raw = recv_frame(sock)
    chl = _parse_hello(ch_raw, "client", b"")
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    sh_raw = _make_hello(identity, "server", device_id, name, eph_pub, hashlib.sha256(ch_raw).digest())
    send_frame(sock, sh_raw)
    transcript = hashlib.sha256(b"SFT-v1-TRANSCRIPT|" + ch_raw + b"|" + sh_raw).digest()
    keys, sas = _derive(eph, chl.eph_pub, transcript, (identity.public_raw, chl.id_pub))
    ch = SecureChannel(sock, keys["s2c_key"], keys["s2c_iv"], keys["c2s_key"], keys["c2s_iv"], b"s2c", b"c2s")
    _finish(ch, transcript)
    _fill_peer(ch, chl, fingerprint(chl.id_pub), sas, transcript)
    return ch


def _finish(ch: SecureChannel, transcript: bytes) -> None:
    """Key confirmation: both sides prove they derived the same keys from the same transcript."""
    ch.send_json({"type": "finished", "transcript": transcript.hex()})
    msg = ch.recv_json()
    if msg.get("type") != "finished" or msg.get("transcript") != transcript.hex():
        raise SecurityError("key confirmation failed")


def _fill_peer(ch: SecureChannel, hello: _Hello, fp: str, sas: str, transcript: bytes) -> None:
    ch.peer_name = str(hello.body.get("name", ""))[:64]
    ch.peer_device_id = str(hello.body.get("device_id", ""))[:64]
    ch.peer_public = hello.id_pub
    ch.peer_fingerprint = fp
    ch.sas = sas
    ch.transcript_hash = transcript
