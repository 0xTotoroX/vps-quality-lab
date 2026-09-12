import base64
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from vps_quality_lab import ssh_setup
from vps_quality_lab.process import CommandResult
from vps_quality_lab.ssh_policy import scoped_config
from vps_quality_lab.storage import write_json


def test_scoped_policy_with_real_sshd_parser(tmp_path):
    sshd = shutil.which("sshd") or "/usr/sbin/sshd"
    if not Path(sshd).exists() or not shutil.which("ssh-keygen"):
        pytest.skip("OpenSSH server parser is not installed")
    key = tmp_path / "host-key"
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(key)],
                   capture_output=True, check=True, timeout=10)
    old = f"HostKey {key}\nPubkeyAuthentication no\nPasswordAuthentication yes\nPermitRootLogin yes\nPort 22022\n".encode()
    config = tmp_path / "sshd_config"
    config.write_bytes(scoped_config(old, "root"))
    for user, expected in [("root", "yes"), ("another-user", "no")]:
        result = subprocess.run([sshd, "-T", "-f", str(config), "-C", f"user={user},host=localhost,addr=127.0.0.1"],
                                capture_output=True, text=True, timeout=10)
        if result.returncode and "Missing privilege separation directory" in result.stderr:
            pytest.skip("OpenSSH parser requires system privilege separation setup")
        assert result.returncode == 0, result.stderr
        values = dict(line.split(" ", 1) for line in result.stdout.splitlines() if " " in line)
        assert values["pubkeyauthentication"] == expected
        assert values["passwordauthentication"] == "yes"
        assert values["permitrootlogin"] == "yes"
        assert values["port"] == "22022"


def test_existing_public_key_block_not_duplicated():
    from vps_quality_lab.storage import LabError
    old = scoped_config(b"PubkeyAuthentication no\n", "root")
    with pytest.raises(LabError, match="already exists"):
        scoped_config(old, "root")


def test_saved_identity_does_not_bypass_new_known_hosts(config, tmp_path):
    directory = ssh_setup.identity_dir(config.ssh, tmp_path)
    saved = config.ssh.model_copy(update={"key_file": tmp_path / "id_ed25519"})
    write_json(directory / "connection.json", saved.model_dump(mode="json"))
    changed = config.ssh.model_copy(update={"known_hosts": tmp_path / "different_known_hosts"})
    assert ssh_setup.effective_ssh(changed, tmp_path).known_hosts == changed.known_hosts


def test_failed_second_connection_rolls_back_policy_without_marking_ready(config, tmp_path, monkeypatch):
    config.ssh.key_file = tmp_path / "existing-key"
    config.ssh.key_file.write_text("test-only-key-reference")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(ssh_setup, "verify_batch", lambda *_: False)
    monkeypatch.setattr(ssh_setup, "execute", lambda *_a, **_k: CommandResult(0, b"ssh-ed25519 AAAAEXAMPLEKEY", b""))
    replies = iter([CommandResult(0, json.dumps({"exists": True, "data": base64.b64encode(b"existing-key\n").decode(),
                                               "path": "/root/.ssh/authorized_keys"}).encode(), b""),
                    CommandResult(0, b'{"added":true}', b"")])
    class FakeRemote:
        def __enter__(self):
            return self
        def __exit__(self, *_):
            pass
        def python(self, *_):
            return next(replies)
    monkeypatch.setattr(ssh_setup, "Remote", lambda _: FakeRemote())
    monkeypatch.setattr(ssh_setup.ssh_policy, "enable", lambda *_: {"old": b"original"})
    rolled_back = []
    monkeypatch.setattr(ssh_setup.ssh_policy, "rollback", lambda *_: rolled_back.append(True))
    _, data = ssh_setup.bootstrap(config.ssh, tmp_path / "store")
    assert data["configured"] and not data["verified"] and rolled_back
    assert not (ssh_setup.identity_dir(config.ssh, tmp_path / "store") / "connection.json").exists()
