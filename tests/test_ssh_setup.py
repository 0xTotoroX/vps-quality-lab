import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from vps_quality_lab.ssh_setup import append_key_script

KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLEPUBLICKEYONLY vps-lab-test"


def apply_key(home: Path, expected):
    script = ("from pathlib import Path\nfrom unittest.mock import patch\n"
              f"patch('pathlib.Path.home',return_value=Path({str(home)!r})).start()\n"
              + append_key_script(KEY, expected))
    return subprocess.run([sys.executable, "-c", script], capture_output=True, timeout=10)


def test_preserves_multiple_keys_and_appends_only_once(tmp_path):
    folder = tmp_path / ".ssh"
    folder.mkdir()
    original = b'# a comment\nssh-rsa AAAAOLD1 owner1\nrestrict ssh-ed25519 AAAAOLD2 owner2'
    file = folder / "authorized_keys"
    file.write_bytes(original)
    first = apply_key(tmp_path, hashlib.sha256(original).hexdigest())
    assert first.returncode == 0 and json.loads(first.stdout)["added"]
    updated = file.read_bytes()
    assert updated.startswith(original + b"\n")
    second = apply_key(tmp_path, hashlib.sha256(updated).hexdigest())
    assert second.returncode == 0 and not json.loads(second.stdout)["added"]
    assert file.read_bytes() == updated
    assert file.stat().st_mode & 0o777 == 0o600
    assert folder.stat().st_mode & 0o777 == 0o700


def test_concurrent_key_change_fails_without_overwrite(tmp_path):
    (tmp_path / ".ssh").mkdir()
    file = tmp_path / ".ssh/authorized_keys"
    file.write_bytes(b"new-concurrent-key\n")
    result = apply_key(tmp_path, hashlib.sha256(b"old-key\n").hexdigest())
    assert result.returncode != 0
    assert file.read_bytes() == b"new-concurrent-key\n"


def test_symlink_keys_are_not_overwritten(tmp_path):
    (tmp_path / ".ssh").mkdir()
    other = tmp_path / "other"
    other.write_bytes(b"other data")
    (tmp_path / ".ssh/authorized_keys").symlink_to(other)
    result = apply_key(tmp_path, hashlib.sha256(other.read_bytes()).hexdigest())
    assert result.returncode != 0 and other.read_bytes() == b"other data"


def test_unknown_host_key_fails_closed(monkeypatch, config):
    import paramiko
    from vps_quality_lab.remote import Remote
    from vps_quality_lab.storage import LabError
    config.ssh.known_hosts.write_text("")
    remote = Remote(config.ssh)
    assert isinstance(remote.client._policy, paramiko.RejectPolicy)
    monkeypatch.setattr(remote.client, "connect", lambda *_a, **_k: (_ for _ in ()).throw(paramiko.SSHException("untrusted")))
    with pytest.raises(LabError, match="SSH connection rejected"):
        with remote:
            pytest.fail("must not authenticate an unknown server")


def test_second_connection_uses_batch_mode_and_no_shared_socket(monkeypatch, tmp_path):
    from vps_quality_lab import ssh_setup
    from vps_quality_lab.process import CommandResult
    seen = []
    def run(args, **kwargs):
        seen.extend(args)
        return CommandResult(255, b"", b"authentication failed")
    monkeypatch.setattr(ssh_setup, "execute", run)
    assert not ssh_setup.verify_batch(tmp_path / "ssh_config", "vps-lab-example")
    assert "ControlMaster=no" in seen and "ControlPath=none" in seen
