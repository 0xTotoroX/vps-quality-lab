"""Keep client/server HTTP, TCP and ICMP observations separate."""

import json
import shlex
import socket
import sys
import time

from .network import resolve
from .process import execute


def tcp_probe(host: str, port: int, interface: str, count=3):
    rows = []
    for _ in range(count):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                if sys.platform == "darwin":
                    sock.setsockopt(socket.IPPROTO_IP, 25, socket.if_nametoindex(interface))
                else:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode() + b"\0")
                start = time.monotonic()
                sock.connect((host, port))
                rows.append({"status": "success", "seconds": time.monotonic() - start})
        except OSError as exc:
            rows.append({"status": "failed", "error_type": type(exc).__name__})
    return {"transport": "TCP", "bound_interface": interface, "port": port, "samples": rows}


def routes(remote, config, node_port=None):
    entry = resolve(config.entry_host, config)[0]
    data = {"tcp_entry": tcp_probe(entry, node_port or config.proxy_port, config.interface),
            "forward_icmp": {"status": "skipped", "reason": "local mtr and bound source required"},
            "return_icmp": {"status": "skipped", "reason": "return_target not configured"},
            "return_tcp": {"status": "skipped", "reason": "return_target not configured"},
            "udp": {"status": "skipped", "reason": "REALITY TCP measurements do not validate UDP"}}
    import shutil
    if shutil.which("mtr") and config.source_address:
        result = execute(["mtr", "--report", "--json", "--no-dns", "--report-cycles", "3",
                          "--max-ttl", "20", "--address", config.source_address, entry], timeout=35)
        data["forward_icmp"] = decode_route(result)
        data["forward_icmp"]["caution"] = "Source-bound ICMP may still be intercepted by a host tunnel"
    if config.return_target:
        for kind, options in [("icmp", []), ("tcp", ["--tcp", "--port", "443"])]:
            command = shlex.join(["mtr", "--report", "--json", "--no-dns", "--report-cycles", "3",
                                  "--max-ttl", "20", *options, config.return_target])
            data["return_" + kind] = decode_route(remote.run(command, timeout=35))
    return data


def decode_route(result):
    try:
        data = json.loads(result.stdout)
    except ValueError:
        data = None
    return {"status": "success" if result.returncode == 0 and data else "partial",
            "exit_code": result.returncode, "raw": data,
            "reason": None if data else "mtr unavailable, permission denied, timeout or invalid JSON"}


def server_http(remote, config):
    """Cross-check endpoint failures on the server, sequentially after client transfers."""
    rows = []
    for index, url in enumerate(config.download_urls):
        url = url.format(bytes=config.limits.download_bytes)
        args = ["curl", "--noproxy", "*", "-4", "-sS", "--connect-timeout", "8", "--max-time",
                str(config.limits.request_timeout), "--range", f"0-{config.limits.download_bytes-1}",
                "--max-filesize", str(config.limits.download_bytes), "-o", "/dev/null", "-w", "%{json}", url]
        result = remote.run(shlex.join(args), timeout=config.limits.request_timeout + 3)
        try:
            item = json.loads(result.stdout)
        except ValueError:
            item = {}
        rows.append({"endpoint": index, "exit_code": result.returncode,
                     "http_code": item.get("http_code"), "bytes": item.get("size_download"),
                     "ttfb_seconds": item.get("time_starttransfer"), "seconds": item.get("time_total"),
                     "valid": result.returncode == 0 and 200 <= item.get("http_code", 0) < 300
                              and item.get("size_download") == config.limits.download_bytes})
    return {"scope": "server-to-endpoint", "samples": rows}
