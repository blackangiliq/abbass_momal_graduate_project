"""
Local web dashboard (Flask).

Security of the dashboard itself:
* It listens on 127.0.0.1 only - other machines on the LAN can NOT open it.
* Every API call needs a random per-run token (X-SFT-Token header) that is only embedded in the
  page served to the local browser -> other web sites cannot drive the API (CSRF protection).
* The Host header must be localhost/127.0.0.1 -> DNS-rebinding protection.
"""
from __future__ import annotations

import os
import secrets
import subprocess
import sys
import threading
import time
from pathlib import Path

from flask import Flask, abort, jsonify, render_template, request

from . import netutil
from .transfer import safe_filename

TOKEN = secrets.token_urlsafe(32)


def create_app(cfg, manager, discovery, transfer_port: int, log=print) -> Flask:
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.config["MAX_CONTENT_LENGTH"] = None  # local uploads, no limit

    @app.before_request
    def _guard():
        host = (request.host or "").rsplit(":", 1)[0]
        if host not in ("127.0.0.1", "localhost"):
            abort(403)
        if request.path.startswith("/api/") and request.headers.get("X-SFT-Token") != TOKEN:
            abort(403)

    @app.after_request
    def _headers(resp):
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.get("/")
    def index():
        return render_template("index.html", token=TOKEN)

    @app.get("/api/state")
    def state():
        return jsonify({
            "me": {
                "name": cfg.name,
                "device_id": cfg.device_id,
                "fingerprint": cfg.identity.fingerprint,
                "port": transfer_port,
                "interfaces": netutil.interfaces(),
                "primary_ip": netutil.primary_ip(),
                "received_dir": str(cfg.received_dir),
                "auto_accept_trusted": cfg.auto_accept_trusted,
            },
            "peers": discovery.list_peers(),
            "scanning": discovery.scanning,
            "last_scan": discovery.last_scan,
            "transfers": manager.list_transfers(),
            "known_peers": cfg.known_peers,
            "time": time.time(),
        })

    @app.post("/api/scan")
    def scan():
        ports = {transfer_port, 5001}
        threading.Thread(target=discovery.scan, args=(list(ports),), daemon=True).start()
        return jsonify(ok=True)

    @app.post("/api/probe")
    def probe():
        data = request.get_json(force=True)
        ip = str(data.get("ip", "")).strip()
        port = int(data.get("port") or 5001)
        if not ip:
            return jsonify(ok=False, error="IP مطلوب"), 400
        info = discovery.probe_and_add(ip, port)
        if not info:
            return jsonify(ok=False, error=f"لا يوجد جهاز يعمل عليه النظام على {ip}:{port} "
                                           "(تأكد من تشغيل البرنامج والجدار الناري)"), 404
        return jsonify(ok=True, peer=info)

    @app.post("/api/send")
    def send():
        ip = request.form.get("ip", "").strip()
        port = int(request.form.get("port") or 5001)
        fp = request.form.get("fingerprint") or None
        files = request.files.getlist("files")
        if not ip or not files:
            return jsonify(ok=False, error="اختر جهازاً وملفاً"), 400
        ids = []
        for f in files:
            name = safe_filename(f.filename or "file")
            tmp = cfg.tmp_dir / f"up_{secrets.token_hex(6)}_{name}"
            f.save(tmp)
            t = manager.send_file_async(tmp, ip, port, expected_fp=fp, display_name=name, delete_after=True)
            ids.append(t.id)
        return jsonify(ok=True, ids=ids)

    @app.post("/api/decision/<tid>")
    def decision(tid):
        data = request.get_json(force=True)
        ok = manager.decide(tid, bool(data.get("accept")), bool(data.get("trust")))
        return jsonify(ok=ok)

    @app.post("/api/settings")
    def settings():
        data = request.get_json(force=True)
        if "name" in data and str(data["name"]).strip():
            cfg.name = str(data["name"]).strip()[:64]
        if "auto_accept_trusted" in data:
            cfg.auto_accept_trusted = bool(data["auto_accept_trusted"])
        cfg.save()
        return jsonify(ok=True)

    @app.post("/api/forget/<device_id>")
    def forget(device_id):
        cfg.forget(device_id)
        return jsonify(ok=True)

    @app.post("/api/open-folder")
    def open_folder():
        p = str(cfg.received_dir)
        data = request.get_json(silent=True) or {}
        target = data.get("path")
        if target and Path(target).resolve().parent == cfg.received_dir.resolve():
            p = target
        try:
            if sys.platform.startswith("win"):
                if p != str(cfg.received_dir):
                    subprocess.Popen(["explorer", "/select,", p])
                else:
                    os.startfile(p)  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(cfg.received_dir)])
            else:
                subprocess.Popen(["xdg-open", str(cfg.received_dir)])
        except Exception as e:  # noqa: BLE001
            return jsonify(ok=False, error=str(e)), 500
        return jsonify(ok=True)

    return app
