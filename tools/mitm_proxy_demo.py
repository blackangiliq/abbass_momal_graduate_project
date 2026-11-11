"""
Security demonstration: an "attacker" TCP proxy placed between sender and receiver.

    sender  --->  proxy (listen :6001)  --->  receiver (:5001)

Modes
  --mode sniff   : forwards everything and prints what an eavesdropper sees (only ciphertext).
  --mode tamper  : flips ONE bit in a data frame -> the receiver detects it (AES-GCM tag fails)
                   and aborts the transfer; the partial file is deleted.

Usage (3 terminals or 2 PCs):
  python -m secure_transfer --port 5001 ...              (receiver)
  python tools/mitm_proxy_demo.py --listen 6001 --target 127.0.0.1:5001 --mode sniff
  python -m secure_transfer send 127.0.0.1 secret.txt --port 6001     (sender talks to the proxy)
"""
import argparse
import socket
import string
import threading

PRINTABLE = set(string.printable.encode()) - set(b"\t\n\r\x0b\x0c")


def hexdump(data: bytes, width: int = 16, limit: int = 64) -> str:
    out = []
    for i in range(0, min(len(data), limit), width):
        chunk = data[i:i + width]
        hx = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if b in PRINTABLE else "." for b in chunk)
        out.append(f"    {i:04x}  {hx:<{width * 3}} {asc}")
    return "\n".join(out)


def pipe(src, dst, label, mode, state):
    total = 0
    while True:
        try:
            data = src.recv(65536)
        except OSError:
            break
        if not data:
            break
        total += len(data)
        if state["shown"] < 6:
            state["shown"] += 1
            print(f"\n[{label}] {len(data)} bytes captured:")
            print(hexdump(data))
        if mode == "tamper" and label == "sender->receiver" and total > 20000 and not state["tampered"]:
            b = bytearray(data)
            b[len(b) // 2] ^= 0x01
            data = bytes(b)
            state["tampered"] = True
            print(f"\n[ATTACK] flipped 1 bit in the middle of a {len(data)}-byte segment!")
        try:
            dst.sendall(data)
        except OSError:
            break
    for s in (src, dst):
        try:
            s.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
    print(f"[{label}] closed after {total} bytes")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", type=int, default=6001)
    ap.add_argument("--target", default="127.0.0.1:5001")
    ap.add_argument("--mode", choices=["sniff", "tamper"], default="sniff")
    ap.add_argument("--once", action="store_true", help="handle a single connection then exit")
    a = ap.parse_args()
    host, port = a.target.rsplit(":", 1)
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", a.listen))
    srv.listen()
    print(f"[proxy] {a.mode} mode, listening on :{a.listen} -> {a.target}")
    while True:
        c, addr = srv.accept()
        s = socket.create_connection((host, int(port)))
        st = {"shown": 0, "tampered": False}
        t1 = threading.Thread(target=pipe, args=(c, s, "sender->receiver", a.mode, st))
        t2 = threading.Thread(target=pipe, args=(s, c, "receiver->sender", a.mode, {"shown": 3, "tampered": False}))
        t1.start(); t2.start()
        if a.once:
            t1.join(); t2.join()
            break


if __name__ == "__main__":
    main()
