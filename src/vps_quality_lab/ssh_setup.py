"""Additive SSH bootstrap, dedicated aliases and a second public-key connection."""

import base64
import hashlib
import json
import socket
import sys
from pathlib import Path

from .models import SSH
from .process import execute
from .remote import Remote
from . import ssh_policy
from .storage import LabError, digest, now, private_dir, write_json, write_private


def trust_host(host: str, port: int, fingerprint: str, output: Path):
    import paramiko
    with socket.create_connection((host, port), timeout=10) as sock:
        transport = paramiko.Transport(sock)
        try:
            transport.start_client(timeout=10)
            key = transport.get_remote_server_key()
        finally:
            transport.close()
    observed = "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
    if observed != fingerprint:
        raise LabError("Server fingerprint does not match the provided trusted fingerprint", 4)
    label = host if port == 22 else f"[{host}]:{port}"
    old = output.read_bytes() if output.exists() else b""
    keys = paramiko.HostKeys()
    if output.exists():
        keys.load(str(output))
    existing = keys.lookup(label)
    if existing and key.get_name() in existing:
        if existing[key.get_name()] != key:
            raise LabError("known_hosts has a conflicting key; refusing replacement", 4)
        return {"verified": True, "added": False, "known_hosts": str(output), "fingerprint": observed}
    entry = f"{label} {key.get_name()} {key.get_base64()}\n".encode()
    write_private(output, old + (b"\n" if old and not old.endswith(b"\n") else b"") + entry)
    return {"verified": True, "added": True, "known_hosts": str(output), "fingerprint": observed}


def identity_dir(ssh: SSH, root: Path):
    return root / "identities" / digest([ssh.host, ssh.port, ssh.user])[:20]


def effective_ssh(ssh: SSH, root: Path) -> SSH:
    saved = identity_dir(ssh, root) / "connection.json"
    if saved.exists():
        candidate = SSH.model_validate_json(saved.read_text())
        if (candidate.host, candidate.port, candidate.user) == (ssh.host, ssh.port, ssh.user):
            if ssh.key_file and ssh.key_file != candidate.key_file:
                return ssh
            return candidate.model_copy(update={"known_hosts": ssh.known_hosts,
                                               "connect_timeout": ssh.connect_timeout,
                                               "enable_public_key": ssh.enable_public_key})
    return ssh


def alias_config(ssh: SSH, alias: str) -> str:
    # OpenSSH config uses double-quoted paths; reject newlines and quotes.
    def path(value):
        text = str(value)
        if any(c in text for c in ['\n', '\r', '"']):
            raise LabError("SSH configuration path contains unsupported characters", 2)
        return f'"{text}"'
    return (f"Host {alias}\n  HostName {ssh.host}\n  Port {ssh.port}\n  User {ssh.user}\n"
            f"  IdentityFile {path(ssh.key_file)}\n  UserKnownHostsFile {path(ssh.known_hosts)}\n"
            "  StrictHostKeyChecking yes\n  IdentitiesOnly yes\n  BatchMode yes\n"
            "  PasswordAuthentication no\n  KbdInteractiveAuthentication no\n"
            f"  ConnectTimeout {ssh.connect_timeout}\n")


def verify_batch(config_file: Path, alias: str) -> bool:
    result = execute(["ssh", "-F", str(config_file), "-o", "ControlMaster=no",
                      "-o", "ControlPath=none", alias, "printf vps-lab-ready"], timeout=20)
    return result.returncode == 0 and result.stdout == b"vps-lab-ready"


def append_key_script(public_key: str, expected_sha: str) -> str:
    # Compare-and-swap under flock preserves concurrent and pre-existing keys.
    return "\n".join([
        "import base64,fcntl,hashlib,json,os,pathlib,tempfile",
        "home=pathlib.Path.home(); directory=home/'.ssh'; target=directory/'authorized_keys'",
        "if directory.is_symlink() or target.is_symlink(): raise SystemExit('symlink rejected')",
        "directory.mkdir(mode=0o700,exist_ok=True)",
        "lock=open(directory/'.vps-lab.lock','a'); os.chmod(lock.name,0o600)",
        "fcntl.flock(lock,fcntl.LOCK_EX)",
        "old=target.read_bytes() if target.exists() else b''",
        f"assert hashlib.sha256(old).hexdigest()=={expected_sha!r}, 'authorized_keys changed; retry'",
        f"key={public_key.strip()!r}",
        "parts=key.split(); blob=parts[1]",
        "present=any(blob in line.split() for line in old.decode().splitlines() if not line.lstrip().startswith('#'))",
        "if not present:",
        " fd,tmp=tempfile.mkstemp(dir=directory,prefix='.vps-lab-')",
        " with os.fdopen(fd,'wb') as f: f.write(old+(b'\\n' if old and not old.endswith(b'\\n') else b'')+key.encode()+b'\\n'); f.flush(); os.fsync(f.fileno())",
        " os.replace(tmp,target)",
        "os.chmod(directory,0o700); os.chmod(target,0o600)",
        "print(json.dumps({'added':not present,'key_count':len(target.read_text().splitlines())}))",
    ])


def bootstrap(ssh: SSH, root: Path):
    directory = private_dir(identity_dir(ssh, root))
    alias = "vps-lab-" + directory.name[:10]
    ready = effective_ssh(ssh, root)
    key = ready.key_file or directory / "id_ed25519"
    key = key.expanduser().resolve()
    config_file = directory / "ssh_config"
    ready = ready.model_copy(update={"key_file": key, "password_env": None})
    if key.exists():
        write_private(config_file, alias_config(ready, alias))
        if verify_batch(config_file, alias):
            write_json(directory / "connection.json", ready.model_dump(mode="json"))
            return ready, {"configured": True, "verified": True, "key_added": False,
                           "alias": alias, "ssh_config": str(config_file), "adopted": True}
    elif ssh.key_file:
        raise LabError("Configured SSH key_file does not exist", 2)
    else:
        generated = execute(["ssh-keygen", "-t", "ed25519", "-N", "", "-C", alias,
                             "-f", str(key)], timeout=15)
        if generated.returncode:
            raise LabError("Could not generate the dedicated SSH key")
    key.chmod(0o600)
    public = execute(["ssh-keygen", "-y", "-f", str(key)], timeout=10)
    if public.returncode:
        raise LabError("Could not read public key; unlock the key in your SSH agent", 4)
    public_key = public.stdout.decode().strip() + " " + alias
    write_private(config_file, alias_config(ready, alias))
    with Remote(ssh) as remote:
        before = remote.python("import base64,json,pathlib\np=pathlib.Path.home()/'.ssh'/'authorized_keys'\n"
                               "assert not p.is_symlink()\nb=p.read_bytes() if p.exists() else b''\n"
                               "print(json.dumps({'exists':p.exists(),'data':base64.b64encode(b).decode(),'path':str(p)}))")
        if before.returncode:
            raise LabError("Cannot safely read authorized_keys for backup", 4)
        original = json.loads(before.stdout)
        old = base64.b64decode(original["data"])
        present = public_key.split()[1] in old.decode().split()
        base = (Path.home() / "Documents/Backups-archive/vps-quality-lab" if sys.platform == "darwin"
                else Path.home() / ".local/state/vps-quality-lab/backups")
        backup_path = base / ("ssh-" + directory.name) / now().replace(":", "-")
        if not present:
            private_dir(backup_path)
            write_private(backup_path / "authorized_keys", old)
            write_json(backup_path / "restore.json", {"host": ssh.host, "port": ssh.port,
                       "user": ssh.user, "path": original["path"], "existed": original["exists"],
                       "sha256": hashlib.sha256(old).hexdigest(),
                       "method": "Compare current authorized_keys before restoring; preserve keys added later."})
        updated = remote.python(append_key_script(public_key, hashlib.sha256(old).hexdigest()))
        if updated.returncode:
            raise LabError("SSH public key update failed; original login remains available", 4)
        pending = {"configured": True, "verified": False, "key_added": json.loads(updated.stdout)["added"],
                   "alias": alias, "ssh_config": str(config_file),
                   "backup": str(backup_path) if backup_path.exists() else None}
        write_json(directory / "bootstrap.json", pending)
        try:
            policy_change = ssh_policy.enable(remote, ssh, backup_path)
        except LabError as exc:
            pending["reason"] = str(exc)
            write_json(directory / "bootstrap.json", pending)
            return ready, pending
        try:
            verified = verify_batch(config_file, alias)
        except BaseException:
            if policy_change:
                ssh_policy.rollback(remote, policy_change)
            raise
        if not verified and policy_change:
            ssh_policy.rollback(remote, policy_change)
    data = {"configured": True, "verified": verified,
            "key_added": json.loads(updated.stdout)["added"], "alias": alias,
            "ssh_config": str(config_file), "backup": str(backup_path) if backup_path.exists() else None,
            "public_key_policy_enabled": bool(policy_change) and verified}
    write_json(directory / "bootstrap.json", data)
    if verified:
        write_json(directory / "connection.json", ready.model_dump(mode="json"))
    return ready, data
