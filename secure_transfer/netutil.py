"""Network helpers: local IPv4 addresses, subnets to scan, broadcast addresses."""
from __future__ import annotations

import ipaddress
import socket

try:
    import ifaddr  # pure-python, works on Windows / Linux / macOS
except ImportError:  # pragma: no cover
    ifaddr = None


def primary_ip() -> str:
    """IP of the interface used for the default route (no packet is actually sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def _is_virtual(name: str) -> bool:
    n = name.lower()
    return any(k in n for k in ("vmware", "virtualbox", "vethernet", "hyper-v", "docker",
                                "wsl", "loopback", "vbox", "tailscale", "zerotier"))


def interfaces() -> list[dict]:
    """List of usable IPv4 interfaces: {name, ip, prefix, network, broadcast}."""
    out: list[dict] = []
    seen = set()
    if ifaddr is not None:
        for adapter in ifaddr.get_adapters():
            for ip in adapter.ips:
                if not isinstance(ip.ip, str):
                    continue  # IPv6
                addr = ipaddress.IPv4Address(ip.ip)
                if addr.is_loopback or addr.is_link_local or ip.ip in seen:
                    continue
                net = ipaddress.IPv4Network(f"{ip.ip}/{ip.network_prefix}", strict=False)
                seen.add(ip.ip)
                out.append({
                    "name": adapter.nice_name,
                    "ip": ip.ip,
                    "prefix": ip.network_prefix,
                    "network": str(net),
                    "broadcast": str(net.broadcast_address),
                    "virtual": _is_virtual(adapter.nice_name),
                })
    p = primary_ip()
    if p not in seen and p != "127.0.0.1":
        net = ipaddress.IPv4Network(f"{p}/24", strict=False)
        out.append({"name": "default", "ip": p, "prefix": 24, "network": str(net),
                    "broadcast": str(net.broadcast_address), "virtual": False})
    # primary first, then physical adapters, then virtual ones
    out.sort(key=lambda i: (i["ip"] != p, i["virtual"]))
    return out


def local_ips() -> list[str]:
    return [i["ip"] for i in interfaces()]


def scan_targets(max_prefix: int = 24) -> list[str]:
    """Host addresses to probe. Large networks are limited to the /24 around our IP."""
    hosts: list[str] = []
    mine = set(local_ips())
    for itf in interfaces():
        if itf["virtual"]:
            continue
        prefix = max(itf["prefix"], max_prefix)
        net = ipaddress.IPv4Network(f"{itf['ip']}/{prefix}", strict=False)
        for h in net.hosts():
            s = str(h)
            if s not in mine and s not in hosts:
                hosts.append(s)
    return hosts


def broadcast_addresses() -> list[str]:
    addrs = ["255.255.255.255"]
    for itf in interfaces():
        if itf["broadcast"] not in addrs:
            addrs.append(itf["broadcast"])
    return addrs
