import socket
import threading

import pytest

from secure_transfer.crypto import (
    Identity, SecurityError, client_handshake, recv_exact, server_handshake, MAGIC_HANDSHAKE,
)


def _pair(server_id=None, client_id=None, expected_fp=None):
    a, b = socket.socketpair()
    server_id = server_id or Identity.generate()
    client_id = client_id or Identity.generate()
    out = {}

    def srv():
        try:
            assert recv_exact(b, 4) == MAGIC_HANDSHAKE
            out["s"] = server_handshake(b, server_id, "dev-s", "Server")
        except Exception as e:  # noqa: BLE001
            out["se"] = e
            b.close()

    th = threading.Thread(target=srv)
    th.start()
    try:
        c = client_handshake(a, client_id, "dev-c", "Client", expected_fingerprint=expected_fp)
    finally:
        th.join(5)
    return c, out.get("s"), server_id, client_id


def test_handshake_and_roundtrip():
    c, s, sid, cid = _pair()
    assert c.sas == s.sas and len(c.sas) == 7
    assert c.peer_fingerprint == sid.fingerprint and s.peer_fingerprint == cid.fingerprint
    c.send_data(b"hello" * 1000)
    assert s.recv_msg() == ("data", b"hello" * 1000)
    s.send_json({"type": "ok"})
    assert c.recv_json() == {"type": "ok"}


def test_wrong_expected_fingerprint_aborts():
    with pytest.raises(SecurityError):
        _pair(expected_fp="0000-0000-0000-0000-0000-0000-0000-0000")


def test_tampered_ciphertext_is_detected():
    a, b = socket.socketpair()
    sid, cid = Identity.generate(), Identity.generate()
    res = {}
    th = threading.Thread(target=lambda: (recv_exact(b, 4), res.setdefault("s", server_handshake(b, sid, "s", "S"))))
    th.start()
    c = client_handshake(a, cid, "c", "C")
    th.join()
    s = res["s"]
    # encrypt a message manually and flip one bit of the ciphertext on the wire
    import struct
    nonce = c._nonce(c._send_iv, c._send_ctr)
    ct = bytearray(c._send.encrypt(nonce, b"\x02secret", c._aad(c._send_label, c._send_ctr)))
    ct[5] ^= 0x01
    a.sendall(struct.pack(">I", len(ct)) + bytes(ct))
    with pytest.raises(SecurityError):
        s.recv()


def test_replayed_frame_is_rejected():
    c, s, *_ = _pair()
    # capture the bytes of one frame by sending it through a second socket pair
    import struct
    n = c._send_ctr  # next counter value the receiver expects
    ct = c._send.encrypt(c._nonce(c._send_iv, n), b"\x02first", c._aad(c._send_label, n))
    frame = struct.pack(">I", len(ct)) + ct
    c.sock.sendall(frame)          # legit (expected counter)
    assert s.recv() == b"\x02first"
    c.sock.sendall(frame)          # replay of the same frame -> receiver expects n+1 -> must fail
    with pytest.raises(SecurityError):
        s.recv()


def test_sessions_use_fresh_keys():
    sid, cid = Identity.generate(), Identity.generate()
    c1, *_ = _pair(sid, cid)
    c2, *_ = _pair(sid, cid)
    assert c1.transcript_hash != c2.transcript_hash
