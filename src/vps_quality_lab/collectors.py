"""Server inventory, externally sourced diagnostics and raw evidence."""

import hashlib
import json
import re
import shlex
import uuid
from pathlib import Path

from .models import StageResult, Status
from .sources import fetch
from .storage import LabError, write_json, write_private

INVENTORY = """import json,os,pathlib,platform,shutil
os_release={}
for line in pathlib.Path('/etc/os-release').read_text().splitlines():
 if '=' in line:
  k,v=line.split('=',1);os_release[k]=v.strip('"')
mem={line.split(':')[0]:line.split(':')[1].strip() for line in pathlib.Path('/proc/meminfo').read_text().splitlines()}
print(json.dumps({'os':os_release.get('ID'),'version':os_release.get('VERSION_ID'),
 'kernel':platform.release(),'arch':platform.machine(),'cpu_count':os.cpu_count(),
 'memory_total':mem.get('MemTotal'),'memory_available':mem.get('MemAvailable'),
 'load':list(os.getloadavg()),'disk_free_bytes':shutil.disk_usage('/').free,
 'commands':{c:shutil.which(c) is not None for c in ['bash','curl','timeout','systemctl','python3','jq','ss','mtr','ping','sysbench']}}))
"""


def inventory(remote):
    result = remote.python(INVENTORY)
    if result.returncode:
        raise LabError("Server inventory failed; Python 3 and /proc are required", 4)
    data = json.loads(result.stdout)
    if data.get("os") not in ("debian", "ubuntu"):
        raise LabError("Only Debian and Ubuntu servers are supported", 4)
    return data


def hardware(remote, config):
    data = inventory(remote)
    data["cpu_benchmark"] = {"status": "skipped", "reason": "allow_stress is false"}
    if config.allow_stress:
        script = ("import hashlib,json,time\n"
                  f"end=time.monotonic()+{config.limits.cpu_seconds};start=time.monotonic();n=0\n"
                  "block=b'0'*1048576\nwhile time.monotonic()<end:\n hashlib.sha256(block).digest();n+=1\n"
                  "print(json.dumps({'algorithm':'SHA256','threads':1,'bytes':n*len(block),'seconds':time.monotonic()-start}))")
        result = remote.run("python3 -", timeout=config.limits.cpu_seconds + 10,
                            data=script.encode(), resource_scope=True)
        data["cpu_benchmark"] = ({"status": "success", **json.loads(result.stdout)}
                                 if result.returncode == 0 else {"status": "failed", "exit_code": result.returncode})
    return data


def parse_json_evidence(raw: bytes) -> dict:
    # Upstreams sometimes leave a CR or BOM. Never invent values from terminal text.
    parsed = json.loads(raw.decode("utf-8-sig").strip())
    if not isinstance(parsed, dict) or not parsed:
        raise ValueError("expected a nonempty object")
    return parsed


def conflicts(structured: dict, ansi: bytes):
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", ansi.decode(errors="replace"))
    rows = []
    # Explicitly compare keyed IPQS values when both representations expose one.
    candidates = re.findall(r"(?:IPQS|IPQualityScore)\s*[:：=]\s*(\d+(?:\.\d+)?)", text, re.I)
    scores = structured.get("Score", {})
    for key, value in scores.items():
        if key.lower() in ("ipqs", "ipqualityscore") and candidates and str(value) not in candidates:
            rows.append({"metric": "IPQS", "json": value, "terminal": candidates,
                         "resolution": "unresolved; retain both, do not rank"})
    return rows


def substantive(value):
    if isinstance(value, dict):
        return any(substantive(v) for v in value.values())
    if isinstance(value, list):
        return any(substantive(v) for v in value)
    return value not in (None, "", "null", "N/A", "-", 0, False)


def measured_number(value):
    if isinstance(value, dict):
        return any(measured_number(v) for k, v in value.items() if k not in ("Code", "Name", "City"))
    if isinstance(value, list):
        return any(measured_number(v) for v in value)
    try:
        return float(value) > 0
    except (ValueError, TypeError):
        return False


def validate_external(name: str, structured: dict | None, expected: str, raw: bytes, low_data=False):
    if not structured:
        return False, ["No usable structured result"]
    issues = []
    if name in ("ip", "net") and structured.get("Head", {}).get("IP") != expected:
        issues.append("Upstream measured an unexpected or missing exit")
    if name == "ip":
        asn = structured.get("Info", {}).get("ASN")
        if not substantive(asn):
            issues.append("IPQuality JSON has no usable ASN")
    elif name == "net":
        for field in (["Delay", "Transfer"] if low_data else ["Delay", "Transfer", "Speedtest"]):
            if not measured_number(structured.get(field)):
                issues.append(f"NetQuality {field} observations are missing")
    elif name == "hardware":
        for field in ["CPU", "Memory", "OS"]:
            if not substantive(structured.get(field)):
                issues.append(f"HardwareQuality {field} observations are missing")
    if b"Resource temporarily unavailable" in raw:
        issues.append("Process creation failed inside the bounded diagnostic environment; resource limits or host exhaustion may be responsible")
    if re.search(rb"firstTTL\([^)]*\) cannot be larger than maxTTL|command not found|Traceback \(most recent call last\)", raw):
        issues.append("Original terminal stream contains an upstream execution error")
    return not issues, issues


def external(remote, name: str, config, cache: Path, evidence: Path) -> StageResult:
    source_file, source = fetch(name, cache)
    remote_dir = "/tmp/vps-quality-lab-" + uuid.uuid4().hex
    remote.mkdir(remote_dir)
    remote_script = remote_dir + "/check.sh"
    remote.write(remote_script, source_file.read_bytes())
    flags = ["-p", "-n", "-l", "en", "-o", remote_dir + "/result.json"]
    if config.allow_external_install:
        flags[flags.index("-n")] = "-y"
    if name in ("ip", "net"):
        flags += ["-4", "-f"]
    if name == "net":
        flags += ["-L"]
    if name == "hardware":
        flags += ["-F"]
    result = None
    structured = None
    try:
        command = "env TERM=xterm-256color bash " + shlex.quote(remote_script) + " " + shlex.join(flags)
        result = remote.run(command, timeout=config.limits.external_timeout, pty=True, resource_scope=True)
        raw = result.stdout + result.stderr
        write_private(evidence / (name + ".ansi"), raw)
        try:
            raw_json = remote.read(remote_dir + "/result.json")
            write_private(evidence / (name + ".json"), raw_json)
            structured = parse_json_evidence(raw_json)
        except (OSError, ValueError):
            pass
    finally:
        # Only this invocation's random, tool-owned scratch directory is removed.
        try:
            remote.run("rm -rf -- " + shlex.quote(remote_dir), timeout=10)
        except Exception:
            pass
    conflict_rows = conflicts(structured or {}, raw)
    validated, issues = validate_external(name, structured, config.expected_exit, raw, low_data=name == "net")
    valid = result.returncode == 0 and validated
    reason = "Upstream result and original terminal stream saved"
    if not valid:
        reason = "Upstream failed, timed out or did not provide usable JSON"
    if issues:
        reason = "; ".join(issues)
    if conflict_rows:
        valid = False
        reason = "Terminal and structured evidence conflict"
    data = {"tool": name, "source": source, "exit_code": result.returncode,
            "timed_out": result.timed_out, "structured": structured, "conflicts": conflict_rows, "issues": issues,
            "mode": "low-data" if name == "net" else "standard",
            "skipped_checks": ["Speedtest throughput", "iperf throughput"] if name == "net" else [],
            "resource_limits": {"cpu_percent": 100, "memory_mb": 512, "tasks": 256,
                                "timeout_seconds": config.limits.external_timeout},
            "eligible": valid, "terminal_sha256": hashlib.sha256(raw).hexdigest()}
    write_json(evidence / (name + "-provenance.json"), {k: v for k, v in data.items() if k != "structured"})
    return StageResult(status=Status.success if valid else Status.partial, message=reason, data=data,
                       evidence=[str(evidence / (name + ".ansi")), str(evidence / (name + ".json"))])
