"""Add-only URL import requests and read-only Shadowrocket verification."""

import json
import plistlib
import sys
from pathlib import Path
from urllib.parse import urlsplit

from .network import verify_exit
from .node import Node, uri
from .process import execute
from .storage import LabError, load_run, now, write_json


def decode_archive(data: bytes):
    document = plistlib.loads(data)
    objects = document.get("$objects", [])
    def resolve(value, ancestors=()):
        if isinstance(value, plistlib.UID):
            if value.data in ancestors:
                return None
            return resolve(objects[value.data], (*ancestors, value.data))
        if isinstance(value, dict):
            if "NS.keys" in value:
                return {resolve(k, ancestors): resolve(v, ancestors)
                        for k, v in zip(value["NS.keys"], value["NS.objects"])}
            if "NS.objects" in value:
                return [resolve(v, ancestors) for v in value["NS.objects"]]
            return {k: resolve(v, ancestors) for k, v in value.items() if k != "$class"}
        if isinstance(value, list):
            return [resolve(v, ancestors) for v in value]
        return value
    return resolve(document.get("$top", {}).get("root"))


def library_path():
    return Path.home() / "Library/Mobile Documents/iCloud~com~liguangming~Shadowrocket/Documents/shadowrocket.v2.model"


def imported(node: Node, library: Path):
    if not library.is_file():
        return False
    nodes = decode_archive(library.read_bytes())
    if not isinstance(nodes, list):
        raise LabError("Unrecognized Shadowrocket archive shape", 4)
    return any(isinstance(n, dict) and n.get("type") == "VLESS" and n.get("tls") is True
               and n.get("xtls") == 2 and not n.get("allowInsecure") and not n.get("mux")
               and n.get("host") == node.server and str(n.get("port", "")) == str(node.port)
               and n.get("password") == node.uuid and n.get("publicKey") == node.public_key
               and n.get("peer") == node.server_name and (n.get("shortId") or "") == node.short_id
               for n in nodes)


def request_import(run: Path):
    if sys.platform != "darwin":
        raise LabError("Shadowrocket import requests require macOS", 4)
    state = load_run(run)
    node = Node.model_validate_json((run / "private/node.json").read_text())
    if imported(node, library_path()):
        state.node_delivery = "imported"
        message = "Matching node is already present; no import requested"
    else:
        # Feed AppleScript over stdin to keep the credential URI out of argv/process listings.
        script = "open location " + json.dumps("shadowrocket://add/" + uri(node))
        result = execute(["osascript", "-"], timeout=15, data=script.encode())
        if result.returncode:
            raise LabError("Shadowrocket did not accept the URL import request", 4)
        state.node_delivery = "import_requested"
        message = "Import requested; confirm the native app dialog, then run client-check"
    write_json(run / "state.json", state.model_dump(mode="json"))
    return {"status": state.node_delivery, "message": message}


def check(run: Path, library: Path | None = None, proxy: str | None = None):
    state = load_run(run)
    node = Node.model_validate_json((run / "private/node.json").read_text())
    present = imported(node, library or library_path())
    data = {"imported": present, "verified": False, "checked_at": now()}
    state.node_delivery = "imported" if present else "generated"
    if proxy:
        parsed = urlsplit(proxy)
        if (parsed.scheme not in ("socks5h", "http") or parsed.hostname not in ("127.0.0.1", "localhost")
                or parsed.username or parsed.password or not parsed.port):
            raise LabError("Client verification requires a credential-free loopback proxy URL", 2)
        # Check listener ownership so another process cannot be labelled Shadowrocket.
        owner = execute(["lsof", "-a", f"-iTCP:{parsed.port}", "-sTCP:LISTEN", "-Fnc"], timeout=8)
        if owner.returncode or not any(token in owner.stdout for token in [b"Shadowrocket", b"MacPacketTunnel"]):
            raise LabError("The listener could not be identified as Shadowrocket", 4)
        config = json.loads((run / "private/config.json").read_text())
        data["exit"] = verify_exit(proxy, config["expected_exit"], 20)
        data["verified"] = present and data["exit"]["verified"]
        if data["verified"]:
            state.node_delivery = "verified"
    write_json(run / "client-check.json", data)
    write_json(run / "state.json", state.model_dump(mode="json"))
    return data
