"""Persistent settings, identity and trusted-peer store (Trust On First Use)."""
from __future__ import annotations

import json
import os
import socket
import threading
import time
import uuid
from pathlib import Path

from .crypto import Identity

DEFAULT_TRANSFER_PORT = 5001
DEFAULT_WEB_PORT = 8000
DEFAULT_DISCOVERY_PORT = 50505


def default_data_dir() -> Path:
    return Path(os.environ.get("SFT_HOME", Path.home() / "SecureTransfer"))


def _atomic_write(path: Path, data: dict) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)


class Config:
    def __init__(self, data_dir: Path, name: str | None = None):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.received_dir = self.data_dir / "Received"
        self.tmp_dir = self.data_dir / "tmp"
        self.received_dir.mkdir(exist_ok=True)
        self.tmp_dir.mkdir(exist_ok=True)
        self._lock = threading.Lock()
        self._settings_path = self.data_dir / "settings.json"
        self._peers_path = self.data_dir / "known_peers.json"

        s = self._load(self._settings_path)
        self.device_id = s.get("device_id") or uuid.uuid4().hex
        self.name = name or s.get("name") or socket.gethostname()
        self.auto_accept_trusted = bool(s.get("auto_accept_trusted", False))
        self.known_peers: dict = self._load(self._peers_path)
        self.identity = Identity.load_or_create(self.data_dir / "identity_ed25519.pem")
        self.save()

    @staticmethod
    def _load(path: Path) -> dict:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def save(self) -> None:
        with self._lock:
            _atomic_write(self._settings_path, {
                "device_id": self.device_id,
                "name": self.name,
                "auto_accept_trusted": self.auto_accept_trusted,
            })

    # ---------------------------------------------------------------- TOFU trust store
    def trust_status(self, device_id: str, fp: str) -> str:
        """'trusted' | 'new' | 'changed' (same device id, different key => possible attack)."""
        with self._lock:
            rec = self.known_peers.get(device_id)
            if rec is None:
                # the same key may be known under another id (re-installed settings)
                if any(r["fingerprint"] == fp for r in self.known_peers.values()):
                    return "trusted"
                return "new"
            return "trusted" if rec["fingerprint"] == fp else "changed"

    def trust(self, device_id: str, fp: str, name: str) -> None:
        with self._lock:
            self.known_peers[device_id] = {"fingerprint": fp, "name": name, "trusted_at": int(time.time())}
            _atomic_write(self._peers_path, self.known_peers)

    def forget(self, device_id: str) -> None:
        with self._lock:
            self.known_peers.pop(device_id, None)
            _atomic_write(self._peers_path, self.known_peers)
