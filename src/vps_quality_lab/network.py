"""Independent client routes, verified egress, and comparable HTTP measurements."""

import ipaddress
import json
import os
import signal
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager

from .node import Node
from .process import execute
from .storage import LabError

EXIT_URLS = ["https://www.cloudflare.com/cdn-cgi/trace", "https://api.ipify.org"]


def resolve(host: str, config) -> list[str]:
    try:
        return [str(ipaddress.IPv4Address(host))]
    except ValueError:
        pass
    if config.resolver:
        result = execute(["dig", "-b", config.source_address, "@" + config.resolver,
                          host, "A", "+short", "+time=3", "+tries=1"], timeout=8)
        candidates = result.stdout.decode().splitlines() if result.returncode == 0 else []
    else:
        result = execute([sys.executable, "-c",
                          "import socket,sys,json; print(json.dumps([r[4][0] for r in socket.getaddrinfo(sys.argv[1],None,socket.AF_INET)]))",
                          host], timeout=8)
        candidates = json.loads(result.stdout) if result.returncode == 0 else []
    addresses = []
    for candidate in candidates:
        try:
            addresses.append(str(ipaddress.IPv4Address(candidate)))
        except ValueError:
            continue
    if not addresses:
        raise LabError("Entry DNS did not return a usable IPv4 address", 4)
    return sorted(set(addresses))


def kernel_config(node: Node, config, port: int):
    names = {name for _, name in socket.if_nameindex()}
    if config.interface not in names or config.interface.startswith(("utun", "tun", "tap", "lo")):
        raise LabError("A present physical interface is required for independent verification", 4)
    addresses = resolve(node.server, config)
    outbound = {"type": "vless", "tag": "vps", "server": addresses[0],
                "server_port": node.port, "uuid": node.uuid, "flow": node.flow,
                "tls": {"enabled": True, "server_name": node.server_name,
                        "utls": {"enabled": True, "fingerprint": node.fingerprint},
                        "reality": {"enabled": True, "public_key": node.public_key,
                                    "short_id": node.short_id}}}
    manifest = {"interface": config.interface, "entry_candidates": addresses,
                "entry_selected": addresses[0], "resolver": config.resolver or "system",
                "route": "direct", "expected_exit": config.expected_exit}
    outbounds = [outbound]
    if config.upstream_file:
        upstream = json.loads(config.upstream_file.read_text())
        if upstream.get("type") not in ("trojan", "socks", "vless", "shadowsocks"):
            raise LabError("Unsupported upstream type", 2)
        if upstream.get("detour") or upstream.get("tls", {}).get("insecure"):
            raise LabError("Upstream detours and insecure TLS are not accepted", 4)
        candidates = resolve(upstream["server"], config)
        upstream.update(tag="upstream", server=candidates[0], bind_interface=config.interface)
        if upstream.get("tls", {}).get("enabled") and not upstream["tls"].get("server_name"):
            raise LabError("TLS upstream requires an explicit server_name", 2)
        outbound["detour"] = "upstream"
        outbounds.append(upstream)
        manifest.update(route="upstream-to-vps", upstream_candidates=candidates,
                        upstream_selected=candidates[0])
    else:
        outbound["bind_interface"] = config.interface
    return {"log": {"level": "error"},
            "inbounds": [{"type": "mixed", "tag": "lab", "listen": "127.0.0.1", "listen_port": port}],
            "outbounds": outbounds, "route": {"final": "vps"}}, manifest


@contextmanager
def isolated_route(node: Node, config):
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
    document, manifest = kernel_config(node, config, port)
    payload = json.dumps(document).encode()
    checked = execute(["sing-box", "check", "-c", "/dev/stdin"], data=payload)
    if checked.returncode:
        raise LabError("sing-box rejected the independent client configuration", 4)
    process = subprocess.Popen(["sing-box", "run", "-c", "/dev/stdin"], stdin=subprocess.PIPE,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               start_new_session=True)
    try:
        process.stdin.write(payload)
        process.stdin.close()
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise LabError("Independent client exited before readiness", 4)
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise LabError("Independent client did not become ready", 4)
        yield f"socks5h://127.0.0.1:{port}", manifest
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()


def curl_base(proxy: str | None, timeout: int):
    args = ["curl", "-4", "--silent", "--show-error", "--connect-timeout", "8",
            "--max-time", str(timeout), "--proto", "=https"]
    args += ["--proxy", proxy, "--noproxy", ""] if proxy else ["--noproxy", "*"]
    return args


def verify_exit(proxy: str, expected: str, timeout: int):
    rows = []
    for url in EXIT_URLS:
        result = execute(curl_base(proxy, timeout) + ["--fail", "--max-filesize", "16384", url],
                         timeout=timeout + 2)
        text = result.stdout.decode(errors="replace").strip()
        candidate = next((line[3:] for line in text.splitlines() if line.startswith("ip=")), text)
        try:
            observed = str(ipaddress.IPv4Address(candidate))
        except ValueError:
            observed = None
        rows.append({"source": url, "ip": observed, "exit_code": result.returncode,
                     "matches": result.returncode == 0 and observed == expected})
    return {"verified": all(r["matches"] for r in rows), "observations": rows}


METRICS = ["http_code", "time_connect", "time_appconnect", "time_starttransfer", "time_total",
           "size_download", "size_upload", "speed_download", "speed_upload", "num_connects"]


def request(url: str, proxy: str | None, limits, kind="download", reuse=False):
    args = curl_base(proxy, limits.request_timeout)
    args += ["--output", os.devnull, "--write-out", "%{json}\n"]
    data = None
    if kind == "upload":
        data = b"0" * limits.upload_bytes
        args += ["--data-binary", "@-", "--header", "Content-Type: application/octet-stream"]
    elif kind == "download":
        args += ["--range", f"0-{limits.download_bytes - 1}",
                 "--max-filesize", str(limits.download_bytes)]
    else:
        args += ["--max-filesize", "16384"]
    args += [url]
    if reuse:
        args += ["--output", os.devnull, url]
    result = execute(args, timeout=limits.request_timeout * (2 if reuse else 1) + 3, data=data)
    rows = []
    for line in result.stdout.decode(errors="replace").splitlines():
        try:
            parsed = json.loads(line)
        except ValueError:
            continue
        row = {key: parsed.get(key) for key in METRICS}
        row.update(kind=kind, exit_code=parsed.get("exitcode", result.returncode))
        row["valid"] = (row["exit_code"] == 0 and result.returncode == 0
                        and 200 <= (row["http_code"] or 0) < 300
                        and (row["time_total"] or 0) > 0)
        if kind == "download":
            row["valid"] &= row["size_download"] == limits.download_bytes
        if kind == "upload":
            row["valid"] &= row["size_upload"] == limits.upload_bytes
        rows.append(row)
    if not rows:
        rows = [{"kind": kind, "exit_code": result.returncode, "valid": False,
                 "error": "curl produced no JSON metrics"}]
    return rows


def measure(proxy: str, config):
    limits = config.limits
    before = verify_exit(proxy, config.expected_exit, limits.request_timeout)
    if not before["verified"]:
        return {"eligible": False, "exit_before": before, "reason": "Unexpected or missing exit"}
    ttfb = [request(EXIT_URLS[0], proxy, limits, "ttfb", reuse=True)
            for _ in range(limits.samples)]
    urls = [url.format(bytes=limits.download_bytes) for url in config.download_urls]
    singles = []
    for index, url in enumerate(urls):
        for _ in range(limits.samples):
            singles.append({"endpoint": index, **request(url, proxy, limits)[0]})
    start = time.monotonic()
    with ThreadPoolExecutor(max_workers=limits.concurrency) as pool:
        parallel = list(pool.map(lambda _: request(urls[0], proxy, limits)[0],
                                 range(limits.concurrency)))
    elapsed = time.monotonic() - start
    uploads = [request(config.upload_url, proxy, limits, "upload")[0]
               for _ in range(limits.samples)]
    after = verify_exit(proxy, config.expected_exit, limits.request_timeout)
    eligible = before["verified"] and after["verified"]
    all_rows = singles + parallel + uploads + [r for group in ttfb for r in group]
    # An incomplete transfer or an incorrect exit must never contribute a throughput score.
    parallel_mbps = (sum(r["size_download"] for r in parallel) * 8 / elapsed / 1e6
                     if eligible and all(r["valid"] for r in parallel) else None)
    return {"eligible": eligible, "complete": eligible and all(r["valid"] for r in all_rows),
            "exit_before": before, "exit_after": after, "ttfb_pairs": ttfb,
            "single": singles, "parallel": parallel, "parallel_seconds": elapsed,
            "parallel_mbps": parallel_mbps, "upload": uploads,
            "shapes": limits.model_dump(), "download_endpoints": urls,
            "notes": ["time_connect is local SOCKS connection time, not remote RTT",
                      "TTFB pairs report num_connects so actual reuse is observable"]}
