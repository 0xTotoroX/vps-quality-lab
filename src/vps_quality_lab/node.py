"""Adopt a verified direct Xray config and generate private client artifacts."""

import base64
import hashlib
import json
import re
import uuid
from pathlib import Path
from urllib.parse import quote, urlencode

import qrcode
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from pydantic import Field, field_validator

from .models import Model
from .storage import LabError, write_json, write_private


class Node(Model):
    name: str
    server: str
    port: int = Field(ge=1, le=65535)
    uuid: str = Field(repr=False)
    public_key: str = Field(repr=False)
    short_id: str = Field(repr=False)
    server_name: str
    fingerprint: str = "chrome"
    flow: str = "xtls-rprx-vision"

    @field_validator("uuid")
    @classmethod
    def valid_uuid(cls, value):
        return str(uuid.UUID(value))

    @field_validator("short_id")
    @classmethod
    def valid_short_id(cls, value):
        if not re.fullmatch(r"(?:[0-9a-fA-F]{2}){0,8}", value):
            raise ValueError("invalid REALITY short ID")
        return value

    @field_validator("public_key")
    @classmethod
    def valid_public_key(cls, value):
        if len(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))) != 32:
            raise ValueError("REALITY public key must have 32 bytes")
        return value


def public_key(private: str) -> str:
    raw = base64.urlsafe_b64decode(private + "=" * (-len(private) % 4))
    key = X25519PrivateKey.from_private_bytes(raw).public_key()
    return base64.urlsafe_b64encode(key.public_bytes(serialization.Encoding.Raw,
                                                   serialization.PublicFormat.Raw)).decode().rstrip("=")


def adopt(document: dict, config) -> Node:
    outbounds = document.get("outbounds", [])
    if not outbounds or any(o.get("protocol") not in ("freedom", "blackhole") for o in outbounds):
        raise LabError("Existing Xray has non-direct exits; refusing fixed-exit adoption", 4)
    if outbounds[0].get("protocol") != "freedom":
        raise LabError("Default outbound is not direct", 4)
    candidates = [i for i in document.get("inbounds", [])
                  if i.get("protocol") == "vless"
                  and i.get("streamSettings", {}).get("security") == "reality"
                  and (not config.inbound_tag or i.get("tag") == config.inbound_tag)]
    if len(candidates) != 1:
        raise LabError("Select exactly one REALITY inbound with inbound_tag", 4)
    inbound = candidates[0]
    if inbound.get("streamSettings", {}).get("network", "tcp") not in ("tcp", "raw"):
        raise LabError("Only TCP/raw REALITY is supported", 4)
    clients = [c for c in inbound.get("settings", {}).get("clients", [])
               if c.get("flow") == "xtls-rprx-vision"
               and (not config.client_id or c.get("id") == config.client_id)]
    if len(clients) != 1:
        raise LabError("Select exactly one Vision client with client_id", 4)
    reality = inbound["streamSettings"]["realitySettings"]
    if not reality.get("serverNames") or not reality.get("shortIds"):
        raise LabError("REALITY SNI or shortIds are missing", 4)
    return Node(name=config.name, server=config.entry_host, port=inbound["port"],
                uuid=clients[0]["id"], public_key=public_key(reality["privateKey"]),
                short_id=reality["shortIds"][0], server_name=reality["serverNames"][0])


def uri(node: Node) -> str:
    params = dict(encryption="none", security="reality", sni=node.server_name,
                  fp=node.fingerprint, pbk=node.public_key, sid=node.short_id,
                  type="tcp", flow=node.flow)
    host = f"[{node.server}]" if ":" in node.server else node.server
    return f"vless://{node.uuid}@{host}:{node.port}?{urlencode(params)}#{quote(node.name)}"


def save_node(node: Node, directory: Path):
    # Do not regenerate stable node artifacts during resume.
    payload = node.model_dump()
    target = directory / "node.json"
    manifest_path = directory / "node-manifest.json"
    if target.exists() and manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text())
            if manifest["fingerprint"] == fingerprint(node) and all(
                (directory / file).is_file() and hashlib.sha256((directory / file).read_bytes()).hexdigest() == value
                for file, value in manifest["files"].items()
            ) and set(manifest["files"]) == {"node.json", "node.txt", "node.png"}:
                return
        except (ValueError, KeyError):
            pass
    write_json(target, payload)
    write_private(directory / "node.txt", uri(node) + "\n")
    import io
    buffer = io.BytesIO()
    qrcode.make(uri(node)).save(buffer, format="PNG")
    write_private(directory / "node.png", buffer.getvalue())
    write_json(manifest_path, {"fingerprint": fingerprint(node), "files": {
        name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
        for name in ["node.json", "node.txt", "node.png"]}})


def fingerprint(node: Node) -> str:
    return hashlib.sha256(node.model_dump_json().encode()).hexdigest()
