"""
File transfer engine: TCP server (receiver) and client (sender) on top of SecureChannel.

Application protocol (all messages below travel *inside* the AES-256-GCM channel):

    sender                                   receiver
    ------                                   --------
    {"type":"offer", id, name, size, sha256, chunk}  ->
                                         <-  {"type":"accept"} | {"type":"reject", reason}
    DATA chunk #0 .. #n (64 KiB each)        ->   (written to .part file + SHA-256 updated)
    {"type":"end"}                           ->
                                         <-  {"type":"result", ok, sha256}
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import socket
import socketserver
import threading
import time
import uuid
from pathlib import Path

from .crypto import (
    MAGIC_HANDSHAKE,
    MAGIC_PROBE,
    SecurityError,
    canonical,
    client_handshake,
    recv_exact,
    send_frame,
    server_handshake,
)

CHUNK_SIZE = 64 * 1024
DECISION_TIMEOUT = 120  # seconds the receiver has to accept/reject
IO_TIMEOUT = 30

_WIN_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
                 *(f"LPT{i}" for i in range(1, 10))}


def safe_filename(name: str) -> str:
    """Neutralise path traversal & illegal Windows characters in a received file name."""
    name = name.replace("\\", "/").split("/")[-1]
    name = re.sub(r'[<>:"|?*\x00-\x1f]', "_", name).strip(" .")
    if not name:
        name = "file"
    stem, dot, ext = name.partition(".")
    if stem.upper() in _WIN_RESERVED:
        name = "_" + name
    if len(name) > 180:
        root, ext = os.path.splitext(name)
        name = root[: 180 - len(ext)] + ext
    return name


def unique_path(folder: Path, name: str) -> Path:
    p = folder / name
    root, ext = os.path.splitext(name)
    i = 1
    while p.exists():
        p = folder / f"{root} ({i}){ext}"
        i += 1
    return p


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


class Transfer:
    """State of a single transfer, shown in the dashboard."""

    def __init__(self, direction: str, filename: str, size: int, peer_ip: str):
        self.id = uuid.uuid4().hex[:12]
        self.direction = direction  # "send" | "receive"
        self.filename = filename
        self.size = size
        self.peer_ip = peer_ip
        self.peer_name = ""
        self.peer_fp = ""
        self.sas = ""
        self.trust = ""
        self.done = 0
        self.status = "connecting"
        self.error = ""
        self.sha256 = ""
        self.saved_as = ""
        self.started = time.time()
        self.finished = None
        self._t_last = time.time()
        self._b_last = 0
        self.speed = 0.0

    def progress(self, n: int):
        self.done += n
        now = time.time()
        if now - self._t_last >= 0.5:
            self.speed = (self.done - self._b_last) / (now - self._t_last)
            self._t_last, self._b_last = now, self.done

    def finish(self, status: str, error: str = ""):
        self.status = status
        self.error = error
        self.finished = time.time()
        dur = max(self.finished - self.started, 1e-3)
        if status == "done":
            self.speed = self.size / dur

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if not k.startswith("_")}


class TransferManager:
    def __init__(self, cfg, port: int, discovery=None, log=print):
        self.cfg = cfg
        self.port = port
        self.discovery = discovery
        self.log = log
        self.transfers: dict[str, Transfer] = {}
        self.pending: dict[str, dict] = {}  # incoming offers waiting for the user
        self._lock = threading.Lock()
        self._server = None

    # ================================================================ receiver (server)
    def start_server(self, host: str = "0.0.0.0") -> None:
        mgr = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                mgr._handle_connection(self.request, self.client_address[0])

        class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
            daemon_threads = True
            allow_reuse_address = os.name != "nt"  # on Windows SO_REUSEADDR allows port hijacking

        self._server = Server((host, self.port), Handler)
        threading.Thread(target=self._server.serve_forever, daemon=True, name="tcp-server").start()

    def stop_server(self):
        if self._server:
            self._server.shutdown()
            self._server.server_close()

    def _handle_connection(self, sock: socket.socket, ip: str) -> None:
        sock.settimeout(IO_TIMEOUT)
        try:
            magic = recv_exact(sock, 4)
        except (OSError, ConnectionError):
            return
        if magic == MAGIC_PROBE:
            info = self.discovery.info() if self.discovery else {}
            try:
                send_frame(sock, canonical(info))
            except OSError:
                pass
            # someone who probes us is probably a peer: remember them too (reverse discovery)
            return
        if magic != MAGIC_HANDSHAKE:
            return
        t = None
        ch = None
        try:
            ch = server_handshake(sock, self.cfg.identity, self.cfg.device_id, self.cfg.name)
            offer = ch.recv_json()
            if offer.get("type") != "offer":
                raise SecurityError("expected an offer")
            name = safe_filename(str(offer["name"]))
            size = int(offer["size"])
            expected_hash = str(offer["sha256"]).lower()
            if size < 0 or not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
                raise SecurityError("bad offer")

            t = Transfer("receive", name, size, ip)
            t.peer_name, t.peer_fp, t.sas = ch.peer_name, ch.peer_fingerprint, ch.sas
            t.trust = self.cfg.trust_status(ch.peer_device_id, ch.peer_fingerprint)
            t.status = "waiting"
            with self._lock:
                self.transfers[t.id] = t

            if shutil.disk_usage(self.cfg.received_dir).free < size + 50 * 1024 * 1024:
                ch.send_json({"type": "reject", "reason": "not enough disk space"})
                t.finish("rejected", "not enough disk space")
                return

            accepted, trust_it = self._ask_user(t, ch.peer_device_id)
            if not accepted:
                ch.send_json({"type": "reject", "reason": "rejected by receiver"})
                t.finish("rejected", "rejected by you")
                return
            if trust_it:
                self.cfg.trust(ch.peer_device_id, ch.peer_fingerprint, ch.peer_name)
                t.trust = "trusted"
            if self.discovery:
                self.discovery.probe_and_add_async(ip)
            ch.send_json({"type": "accept"})
            t.status = "transferring"
            self._receive_file(ch, t, expected_hash)
        except SecurityError as e:
            self.log(f"[security] connection from {ip} rejected: {e}")
            if t:
                t.finish("failed", f"security: {e}")
        except (OSError, ConnectionError, ValueError, KeyError) as e:
            if t and t.status not in ("done", "rejected"):
                t.finish("failed", str(e))
        finally:
            if ch:
                ch.close()

    def _ask_user(self, t: Transfer, peer_device_id: str):
        if t.trust == "trusted" and self.cfg.auto_accept_trusted:
            return True, False
        ev = threading.Event()
        req = {"event": ev, "accept": False, "trust": False, "device_id": peer_device_id}
        with self._lock:
            self.pending[t.id] = req
        self.log(f"[incoming] {t.peer_name} ({t.peer_ip}) wants to send '{t.filename}' "
                 f"({t.size} bytes) - SAS {t.sas} - approve in the dashboard")
        ev.wait(DECISION_TIMEOUT)
        with self._lock:
            self.pending.pop(t.id, None)
        return req["accept"], req["trust"]

    def decide(self, transfer_id: str, accept: bool, trust: bool) -> bool:
        with self._lock:
            req = self.pending.get(transfer_id)
        if not req:
            return False
        req["accept"], req["trust"] = bool(accept), bool(trust)
        req["event"].set()
        return True

    def _receive_file(self, ch, t: Transfer, expected_hash: str) -> None:
        part = self.cfg.tmp_dir / f"{t.id}.part"
        h = hashlib.sha256()
        try:
            with open(part, "wb") as f:
                while True:
                    kind, body = ch.recv_msg()
                    if kind == "data":
                        if t.done + len(body) > t.size:
                            raise SecurityError("sender sent more data than announced")
                        f.write(body)
                        h.update(body)
                        t.progress(len(body))
                        continue
                    if body.get("type") == "end":
                        break
                    if body.get("type") == "cancel":
                        raise ConnectionError("cancelled by sender")
                    raise SecurityError("unexpected message during transfer")
            digest = h.hexdigest()
            ok = digest == expected_hash and t.done == t.size
            ch.send_json({"type": "result", "ok": ok, "sha256": digest})
            if not ok:
                raise SecurityError("integrity check failed (SHA-256 mismatch)")
            dest = unique_path(self.cfg.received_dir, t.filename)
            os.replace(part, dest)
            t.sha256, t.saved_as = digest, str(dest)
            t.finish("done")
            self.log(f"[received] {dest} ({t.size} bytes) SHA-256 verified")
        finally:
            if part.exists():
                try:
                    part.unlink()
                except OSError:
                    pass

    # ================================================================ sender (client)
    def send_file_async(self, path: Path, ip: str, port: int, expected_fp: str | None = None,
                        display_name: str | None = None, delete_after: bool = False) -> Transfer:
        path = Path(path)
        t = Transfer("send", display_name or path.name, path.stat().st_size, ip)
        with self._lock:
            self.transfers[t.id] = t
        threading.Thread(target=self._send_file, args=(t, path, ip, port, expected_fp, delete_after),
                         daemon=True, name=f"send-{t.id}").start()
        return t

    def send_file(self, path, ip, port, expected_fp=None) -> Transfer:
        """Blocking variant (used by the CLI and the tests)."""
        path = Path(path)
        t = Transfer("send", path.name, path.stat().st_size, ip)
        with self._lock:
            self.transfers[t.id] = t
        self._send_file(t, path, ip, port, expected_fp, False)
        return t

    def _send_file(self, t: Transfer, path: Path, ip: str, port: int, expected_fp, delete_after):
        ch = None
        try:
            t.status = "hashing"
            t.sha256 = sha256_file(path)
            t.status = "connecting"
            sock = socket.create_connection((ip, port), timeout=10)
            sock.settimeout(IO_TIMEOUT)
            ch = client_handshake(sock, self.cfg.identity, self.cfg.device_id, self.cfg.name,
                                  expected_fingerprint=expected_fp or None)
            t.peer_name, t.peer_fp, t.sas = ch.peer_name, ch.peer_fingerprint, ch.sas
            t.trust = self.cfg.trust_status(ch.peer_device_id, ch.peer_fingerprint)
            if t.trust == "changed":
                raise SecurityError("the receiver's identity key CHANGED since last time "
                                    "(possible man-in-the-middle). Remove it from trusted devices "
                                    "only if you are sure.")
            ch.send_json({"type": "offer", "id": t.id, "name": t.filename, "size": t.size,
                          "sha256": t.sha256, "chunk": CHUNK_SIZE})
            t.status = "waiting"
            sock.settimeout(DECISION_TIMEOUT + 10)
            reply = ch.recv_json()
            sock.settimeout(IO_TIMEOUT)
            if reply.get("type") != "accept":
                t.finish("rejected", str(reply.get("reason", "rejected")))
                return
            # the receiver accepted: remember its key (TOFU) for future key-change detection
            if t.trust == "new":
                self.cfg.trust(ch.peer_device_id, ch.peer_fingerprint, ch.peer_name)
                t.trust = "trusted"
            t.status = "transferring"
            with open(path, "rb") as f:
                for block in iter(lambda: f.read(CHUNK_SIZE), b""):
                    ch.send_data(block)
                    t.progress(len(block))
            ch.send_json({"type": "end"})
            res = ch.recv_json()
            if res.get("type") == "result" and res.get("ok") and res.get("sha256") == t.sha256:
                t.finish("done")
                self.log(f"[sent] {t.filename} -> {t.peer_name} ({ip}) verified")
            else:
                t.finish("failed", "receiver reported integrity failure")
        except SecurityError as e:
            t.finish("failed", f"security: {e}")
            self.log(f"[security] {e}")
        except (OSError, ConnectionError, ValueError) as e:
            t.finish("failed", str(e) or e.__class__.__name__)
        finally:
            if ch:
                ch.close()
            if delete_after:
                try:
                    path.unlink()
                except OSError:
                    pass

    # ================================================================ dashboard data
    def list_transfers(self) -> list[dict]:
        with self._lock:
            items = [t.to_dict() for t in self.transfers.values()]
            pend = set(self.pending)
        for it in items:
            it["needs_decision"] = it["id"] in pend
        items.sort(key=lambda d: d["started"], reverse=True)
        return items[:100]
