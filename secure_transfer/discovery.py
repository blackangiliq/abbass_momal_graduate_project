"""
LAN peer discovery.

Two complementary mechanisms:
1. UDP broadcast beacons (passive, every few seconds) on DISCOVERY_PORT.
2. Active network scan: TCP connect + "PING" probe to every host of the local /24 subnet(s)
   on the transfer port. Works even where broadcasts are filtered (some Wi-Fi APs).

Discovery data is *public and unauthenticated* (name, port, fingerprint). It is only a hint:
the real identity of a peer is proven cryptographically during the handshake, and the sender
aborts if the key presented in the handshake does not match the fingerprint it was shown.
"""
from __future__ import annotations

import json
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import netutil
from .crypto import MAGIC_PROBE, PROTOCOL_VERSION

BEACON_INTERVAL = 3.0
PEER_TIMEOUT = 15.0
APP_ID = "SFT"


class Discovery:
    def __init__(self, cfg, transfer_port: int, discovery_port: int, log=print):
        self.cfg = cfg
        self.transfer_port = transfer_port
        self.discovery_port = discovery_port
        self.log = log
        self.peers: dict[str, dict] = {}
        self.scanning = False
        self.last_scan = None
        self._lock = threading.Lock()
        self._stop = threading.Event()

    # ------------------------------------------------------------------ public info
    def info(self) -> dict:
        return {
            "app": APP_ID,
            "v": PROTOCOL_VERSION,
            "id": self.cfg.device_id,
            "name": self.cfg.name,
            "port": self.transfer_port,
            "fp": self.cfg.identity.fingerprint,
        }

    def _add_peer(self, info: dict, ip: str, via: str) -> None:
        if info.get("app") != APP_ID or info.get("id") == self.cfg.device_id:
            return
        try:
            port = int(info["port"])
        except (KeyError, ValueError, TypeError):
            return
        key = f"{info['id']}"
        with self._lock:
            old = self.peers.get(key, {})
            self.peers[key] = {
                "device_id": str(info["id"])[:64],
                "name": str(info.get("name", "?"))[:64],
                "ip": ip,
                "port": port,
                "fingerprint": str(info.get("fp", ""))[:64],
                "last_seen": time.time(),
                "via": via if old.get("via") in (None, via) else "broadcast+scan",
            }

    def list_peers(self) -> list[dict]:
        now = time.time()
        with self._lock:
            out = []
            for p in self.peers.values():
                q = dict(p)
                q["online"] = now - p["last_seen"] < PEER_TIMEOUT or p["via"] == "manual"
                q["trust"] = self.cfg.trust_status(p["device_id"], p["fingerprint"])
                out.append(q)
        out.sort(key=lambda p: (not p["online"], p["name"].lower()))
        return out

    # ------------------------------------------------------------------ broadcast
    def start(self) -> None:
        threading.Thread(target=self._listen, daemon=True, name="disc-listen").start()
        threading.Thread(target=self._beacon, daemon=True, name="disc-beacon").start()

    def stop(self) -> None:
        self._stop.set()

    def _listen(self) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass
        try:
            s.bind(("", self.discovery_port))
        except OSError as e:
            self.log(f"[discovery] cannot bind UDP {self.discovery_port}: {e} (scan still works)")
            return
        s.settimeout(1.0)
        while not self._stop.is_set():
            try:
                data, (ip, _port) = s.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                continue
            try:
                msg = json.loads(data.decode("utf-8"))
            except ValueError:
                continue
            if msg.get("type") == "who-is-there" and msg.get("id") != self.cfg.device_id:
                self._send_beacon(extra_targets=[ip])
            elif msg.get("type") == "beacon":
                self._add_peer(msg, ip, "broadcast")

    def _send_beacon(self, extra_targets=(), kind="beacon") -> None:
        payload = dict(self.info(), type=kind)
        data = json.dumps(payload).encode()
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            for addr in list(extra_targets) + netutil.broadcast_addresses():
                try:
                    s.sendto(data, (addr, self.discovery_port))
                except OSError:
                    pass
        finally:
            s.close()

    def _beacon(self) -> None:
        self._send_beacon(kind="who-is-there")
        while not self._stop.is_set():
            try:
                self._send_beacon()
            except Exception as e:  # noqa: BLE001
                self.log(f"[discovery] beacon error: {e}")
            self._stop.wait(BEACON_INTERVAL)

    # ------------------------------------------------------------------ active scan
    @staticmethod
    def probe(ip: str, port: int, timeout: float = 0.6) -> dict | None:
        """Connect to ip:port and ask for its public info. Returns info dict or None."""
        try:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                s.settimeout(2.0)
                s.sendall(MAGIC_PROBE)
                hdr = b""
                while len(hdr) < 4:
                    chunk = s.recv(4 - len(hdr))
                    if not chunk:
                        return None
                    hdr += chunk
                (n,) = struct.unpack(">I", hdr)
                if n > 4096:
                    return None
                body = b""
                while len(body) < n:
                    chunk = s.recv(n - len(body))
                    if not chunk:
                        return None
                    body += chunk
                info = json.loads(body.decode("utf-8"))
                return info if info.get("app") == APP_ID else None
        except (OSError, ValueError):
            return None

    def probe_and_add(self, ip: str, port: int, via="manual") -> dict | None:
        info = self.probe(ip, port, timeout=2.0)
        if info:
            self._add_peer(info, ip, via)
        return info

    def probe_and_add_async(self, ip: str, port: int | None = None) -> None:
        """Reverse discovery: a peer that sent us a file is probably listening too."""
        threading.Thread(target=self.probe_and_add, args=(ip, port or self.transfer_port, "scan"),
                         daemon=True).start()

    def scan(self, ports=None) -> int:
        """Scan local subnet(s). Returns number of peers found."""
        if self.scanning:
            return 0
        self.scanning = True
        found = 0
        try:
            ports = sorted(set(ports or [self.transfer_port]))
            targets = [(ip, p) for ip in netutil.scan_targets() for p in ports]
            # also probe ourselves on other ports (useful when running two instances on one PC)
            for ip in ["127.0.0.1"]:
                for p in ports:
                    if p != self.transfer_port:
                        targets.append((ip, p))
            self.log(f"[discovery] scanning {len(targets)} address(es)...")
            with ThreadPoolExecutor(max_workers=128) as pool:
                for (ip, port), info in zip(targets, pool.map(lambda t: self.probe(*t), targets)):
                    if info and info.get("id") != self.cfg.device_id:
                        self._add_peer(info, ip, "scan")
                        found += 1
            self.log(f"[discovery] scan finished, {found} device(s) found")
        finally:
            self.scanning = False
            self.last_scan = time.time()
        return found
