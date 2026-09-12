"""Verified upstream downloads; source versions are release-controlled."""

import hashlib
import json
import urllib.request
from importlib.resources import files
from pathlib import Path

from .storage import LabError, write_private


def manifest():
    return json.loads(files("vps_quality_lab").joinpath("assets/sources.json").read_text())


def fetch(name: str, cache: Path) -> tuple[Path, dict]:
    source = manifest()[name]
    target = cache / f'{name}-{source["sha256"][:16]}.sh'
    if target.exists():
        data = target.read_bytes()
    else:
        request = urllib.request.Request(source["url"], headers={"User-Agent": "vps-quality-lab/0.1"})
        with urllib.request.urlopen(request, timeout=30) as response:
            data = response.read(2_000_001)
    if len(data) > 2_000_000 or hashlib.sha256(data).hexdigest() != source["sha256"]:
        raise LabError(f"{name} source digest mismatch; refusing execution", 4)
    write_private(target, data)
    return target, source
