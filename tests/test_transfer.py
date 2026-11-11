import hashlib
import os
import socket
import threading
import time

from secure_transfer.config import Config
from secure_transfer.discovery import Discovery
from secure_transfer.transfer import TransferManager, safe_filename


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def node(tmp_path, name, port):
    cfg = Config(tmp_path / name, name=name)
    disc = Discovery(cfg, port, free_port(), log=lambda *_: None)
    mgr = TransferManager(cfg, port, discovery=disc, log=lambda *_: None)
    return cfg, disc, mgr


def auto_decide(mgr, accept=True, trust=True):
    def loop():
        for _ in range(200):
            for tid in list(mgr.pending):
                mgr.decide(tid, accept, trust)
            time.sleep(0.02)
    threading.Thread(target=loop, daemon=True).start()


def test_end_to_end_transfer(tmp_path):
    pa, pb = free_port(), free_port()
    ca, da, ma = node(tmp_path, "A", pa)
    cb, db, mb = node(tmp_path, "B", pb)
    mb.start_server("127.0.0.1")
    auto_decide(mb)
    data = os.urandom(3 * 1024 * 1024 + 123)
    src = tmp_path / "secret report.pdf"
    src.write_bytes(data)

    # discovery probe returns B's public info
    info = da.probe("127.0.0.1", pb)
    assert info["fp"] == cb.identity.fingerprint

    t = ma.send_file(src, "127.0.0.1", pb, expected_fp=info["fp"])
    assert t.status == "done", t.error
    got = cb.received_dir / "secret report.pdf"
    assert got.read_bytes() == data
    assert t.sha256 == hashlib.sha256(data).hexdigest()
    # both sides now trust each other (TOFU)
    assert ca.trust_status(cb.device_id, cb.identity.fingerprint) == "trusted"
    assert cb.trust_status(ca.device_id, ca.identity.fingerprint) == "trusted"
    mb.stop_server()


def test_reject(tmp_path):
    pb = free_port()
    _, _, ma = node(tmp_path, "A", free_port())
    cb, _, mb = node(tmp_path, "B", pb)
    mb.start_server("127.0.0.1")
    auto_decide(mb, accept=False)
    src = tmp_path / "x.txt"; src.write_text("hi")
    t = ma.send_file(src, "127.0.0.1", pb)
    assert t.status == "rejected"
    assert not any(cb.received_dir.iterdir())
    mb.stop_server()


def test_safe_filename():
    assert safe_filename("../../Windows/System32/evil.dll") == "evil.dll"
    assert safe_filename("..\\..\\boot.ini") == "boot.ini"
    assert safe_filename("CON.txt") == "_CON.txt"
    assert safe_filename('a<b>c:"d|e?.txt') == "a_b_c__d_e_.txt"
