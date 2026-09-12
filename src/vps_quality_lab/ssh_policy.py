"""Optional, scoped public-key enablement with policy checks and rollback."""

import hashlib
import json
import shlex
import uuid
from pathlib import Path

from .storage import LabError, write_json, write_private

PROTECTED = ["passwordauthentication", "permitrootlogin", "authenticationmethods",
             "authorizedkeysfile", "port", "kbdinteractiveauthentication", "pubkeyauthentication"]


def policy(remote, config_file=None):
    script = """import json,os,subprocess
parts=os.environ.get('SSH_CONNECTION','').split()
assert len(parts)==4, 'SSH connection context unavailable'
user=subprocess.check_output(['id','-un'],text=True).strip()
context=f'user={user},addr={parts[0]},host={parts[0]},laddr={parts[2]},lport={parts[3]}'
args=['/usr/sbin/sshd','-T','-C',context]
"""
    if config_file:
        script += f"args += ['-f',{config_file!r}]\n"
    script += """p=subprocess.run(args,capture_output=True,text=True)
assert p.returncode==0, 'cannot inspect effective sshd policy'
values=dict(line.split(' ',1) for line in p.stdout.splitlines() if ' ' in line)
print(json.dumps({k:values.get(k) for k in """ + repr(PROTECTED) + """}))
"""
    result = remote.python(script)
    if result.returncode:
        raise LabError("Cannot inspect effective SSH authentication policy", 4)
    return json.loads(result.stdout)


def scoped_config(old: bytes, user: str) -> bytes:
    marker = f"# BEGIN VPS QUALITY LAB PUBLIC KEY {user}"
    if marker.encode() in old:
        raise LabError("Managed public-key block already exists but is ineffective; review SSH policy", 4)
    return old + (b"\n" if not old.endswith(b"\n") else b"") + (
        f"\n{marker}\nMatch User {user}\n    PubkeyAuthentication yes\n"
        f"# END VPS QUALITY LAB PUBLIC KEY {user}\n").encode()


def enable(remote, ssh, backup_dir: Path):
    before = policy(remote)
    if before.get("pubkeyauthentication") == "yes":
        return None
    if not ssh.enable_public_key:
        raise LabError("Server disables public-key authentication; set ssh.enable_public_key=true if SSH setup is authorized", 4)
    if ssh.user != "root" or remote.run("systemctl is-active --quiet ssh").returncode:
        raise LabError("Scoped public-key enablement currently requires root and standard Debian/Ubuntu ssh.service", 4)
    active = remote.run("systemctl show ssh --property=ExecStart --value")
    if active.returncode or b" -f " in active.stdout:
        raise LabError("Nonstandard sshd config path; refusing to modify the default file", 4)
    target = "/etc/ssh/sshd_config"
    old = remote.read(target)
    new = scoped_config(old, ssh.user)
    write_private(backup_dir / "sshd_config", old)
    record = {"path": target, "host": ssh.host, "port": ssh.port, "user": ssh.user,
              "before_sha256": hashlib.sha256(old).hexdigest(),
              "after_sha256": hashlib.sha256(new).hexdigest(), "before_policy": before,
              "recovery": "Restore only if current file matches after_sha256; validate with sshd -t then reload ssh."}
    write_json(backup_dir / "sshd-restore.json", record)
    candidate = "/etc/ssh/.vps-lab-candidate-" + uuid.uuid4().hex
    remote.write(candidate, new)
    try:
        checked = remote.run("/usr/sbin/sshd -t -f " + candidate)
        if checked.returncode:
            raise LabError("Scoped public-key candidate failed sshd syntax validation", 4)
        after = policy(remote, candidate)
        if after.get("pubkeyauthentication") != "yes":
            raise LabError("Existing Match policy prevents scoped public-key enablement", 4)
        if any(before[k] != after[k] for k in PROTECTED if k != "pubkeyauthentication"):
            raise LabError("Candidate would change other SSH authentication settings; refused", 4)
        result = remote.python(f"""import hashlib,os,pathlib
target=pathlib.Path({target!r});candidate=pathlib.Path({candidate!r})
assert not target.is_symlink()
assert hashlib.sha256(target.read_bytes()).hexdigest()=={record['before_sha256']!r},'configuration changed'
os.chmod(candidate,target.stat().st_mode&0o777);os.replace(candidate,target)
""")
        if result.returncode:
            raise LabError("SSH config changed concurrently; candidate was not applied", 4)
        record["old"] = old
        if remote.run("/usr/sbin/sshd -t && systemctl reload ssh", timeout=15).returncode:
            rollback(remote, record)
            raise LabError("SSH reload failed; original authentication policy restored", 4)
        return record
    finally:
        remote.run("rm -f -- " + shlex.quote(candidate), timeout=10)


def rollback(remote, record):
    path = "/etc/ssh/.vps-lab-rollback-" + uuid.uuid4().hex
    remote.write(path, record["old"])
    result = remote.python(f"""import hashlib,os,pathlib
target=pathlib.Path({record['path']!r});candidate=pathlib.Path({path!r})
assert hashlib.sha256(target.read_bytes()).hexdigest()=={record['after_sha256']!r},'configuration changed'
os.chmod(candidate,target.stat().st_mode&0o777);os.replace(candidate,target)
""")
    if result.returncode or remote.run("/usr/sbin/sshd -t && systemctl reload ssh", timeout=15).returncode:
        raise LabError("SSH policy rollback needs attention; use the recorded backup and existing password connection", 4)
