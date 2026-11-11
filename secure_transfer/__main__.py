"""
Entry point:  python -m secure_transfer [options]

Starts:  the encrypted TCP receiver, LAN discovery, and the local dashboard,
then prints this machine's IP address and opens the dashboard in the browser.
Also offers a small CLI:  python -m secure_transfer send <ip> <file>
"""
from __future__ import annotations

import argparse
import logging
import sys
import threading
import time
import webbrowser
from pathlib import Path

from . import __version__, netutil
from .config import (
    DEFAULT_DISCOVERY_PORT,
    DEFAULT_TRANSFER_PORT,
    DEFAULT_WEB_PORT,
    Config,
    default_data_dir,
)
from .discovery import Discovery
from .transfer import TransferManager

BANNER = r"""
  ____                             _____ _ _        _____                     __
 / ___|  ___  ___ _   _ _ __ ___  |  ___(_) | ___  |_   _| __ __ _ _ __  ___ / _| ___ _ __
 \___ \ / _ \/ __| | | | '__/ _ \ | |_  | | |/ _ \   | || '__/ _` | '_ \/ __| |_ / _ \ '__|
  ___) |  __/ (__| |_| | | |  __/ |  _| | | |  __/   | || | | (_| | | | \__ \  _|  __/ |
 |____/ \___|\___|\__,_|_|  \___| |_|   |_|_|\___|   |_||_|  \__,_|_| |_|___/_|  \___|_|
            End-to-End Encrypted  |  X25519 + Ed25519 + HKDF-SHA256 + AES-256-GCM
"""


def _enable_ansi():
    if sys.platform.startswith("win"):
        try:
            import ctypes
            k = ctypes.windll.kernel32
            k.SetConsoleMode(k.GetStdHandle(-11), 7)
        except Exception:  # noqa: BLE001
            pass
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:  # noqa: BLE001
        pass


def log(msg: str) -> None:
    print(time.strftime("[%H:%M:%S] ") + msg, flush=True)


def build(args):
    cfg = Config(Path(args.data_dir), name=args.name)
    disc = Discovery(cfg, args.port, args.discovery_port, log=log)
    mgr = TransferManager(cfg, args.port, discovery=disc, log=log)
    return cfg, disc, mgr


def cmd_run(args):
    cfg, disc, mgr = build(args)
    try:
        mgr.start_server()
    except OSError as e:
        print(f"\n[!] Cannot listen on TCP port {args.port}: {e}\n"
              f"    Is another copy already running?  Try:  --port {args.port + 1}")
        sys.exit(1)
    disc.start()
    threading.Thread(target=disc.scan, daemon=True).start()

    url = f"http://127.0.0.1:{args.web_port}/"
    G, C, Y, R = "\033[92m", "\033[96m", "\033[93m", "\033[0m"
    print(C + BANNER + R)
    print(f"  Version          : {__version__}")
    print(f"  Device name      : {G}{cfg.name}{R}")
    print("  Identity (Ed25519) fingerprint:")
    print(f"                     {Y}{cfg.identity.fingerprint}{R}")
    print(f"  {G}>>> YOUR IP ADDRESS(ES) - give this to the other device:{R}")
    for itf in netutil.interfaces():
        tag = " (virtual)" if itf["virtual"] else ""
        print(f"        {G}{itf['ip']:<16}{R} port {args.port}   [{itf['name']}{tag}]")
    print(f"  Received files   : {cfg.received_dir}")
    print(f"  Dashboard        : {C}{url}{R}")
    print("  Press Ctrl+C to stop.\n")

    from .web import create_app
    app = create_app(cfg, mgr, disc, args.port, log=log)
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    if not args.no_browser:
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()
    try:
        app.run(host="127.0.0.1", port=args.web_port, threaded=True, use_reloader=False)
    except OSError as e:
        print(f"[!] Cannot start dashboard on port {args.web_port}: {e}. Try --web-port {args.web_port + 1}")
        sys.exit(1)


def cmd_send(args):
    cfg, disc, mgr = build(args)
    path = Path(args.file)
    print(f"Sending {path.name} to {args.ip}:{args.port} ... (waiting for receiver to accept)")
    t = mgr.send_file(path, args.ip, args.port, expected_fp=args.fingerprint)
    print(f"Peer           : {t.peer_name}  fingerprint {t.peer_fp}")
    print(f"Safety code    : {t.sas}   (must match the code on the receiver)")
    print(f"Result         : {t.status} {t.error}")
    print(f"SHA-256        : {t.sha256}")
    sys.exit(0 if t.status == "done" else 1)


def cmd_scan(args):
    cfg, disc, mgr = build(args)
    disc.scan([args.port])
    for p in disc.list_peers():
        print(f"{p['ip']:<16} {p['port']:<6} {p['name']:<24} {p['fingerprint']}")


def main(argv=None):
    _enable_ansi()
    ap = argparse.ArgumentParser(prog="secure_transfer", description="Secure LAN file transfer (E2EE)")
    ap.add_argument("--name", help="device name shown to others (default: computer name)")
    ap.add_argument("--port", type=int, default=DEFAULT_TRANSFER_PORT, help="TCP transfer port (5001)")
    ap.add_argument("--web-port", type=int, default=DEFAULT_WEB_PORT, help="dashboard port (8000)")
    ap.add_argument("--discovery-port", type=int, default=DEFAULT_DISCOVERY_PORT, help="UDP discovery port")
    ap.add_argument("--data-dir", default=str(default_data_dir()), help="folder for keys and received files")
    ap.add_argument("--no-browser", action="store_true", help="do not open the browser automatically")
    sub = ap.add_subparsers(dest="cmd")
    s = sub.add_parser("send", help="send a file from the command line")
    s.add_argument("ip")
    s.add_argument("file")
    s.add_argument("--port", type=int, default=argparse.SUPPRESS, help="receiver port (5001)")
    s.add_argument("--fingerprint", help="expected receiver fingerprint (optional, recommended)")
    sub.add_parser("scan", help="scan the local network for devices")
    args = ap.parse_args(argv)
    {"send": cmd_send, "scan": cmd_scan}.get(args.cmd, cmd_run)(args)


if __name__ == "__main__":
    main()
