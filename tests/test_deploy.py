import json

import pytest

from vps_quality_lab import deploy
from vps_quality_lab.process import CommandResult
from vps_quality_lab.storage import LabError

OWNER = "/var/lib/vps-quality-lab"
CONFIG = "/usr/local/etc/xray/config.json"


class InstallerRemote:
    """A server whose installer copies a binary before failing once."""

    def __init__(self):
        self.files = {}
        self.binary = False
        self.active = False
        self.installs = 0

    def read(self, path):
        if path not in self.files:
            raise FileNotFoundError(path)
        return self.files[path]

    def write(self, path, data):
        if path in self.files:
            raise FileExistsError(path)
        self.files[path] = data

    def python(self, script, **kwargs):
        if "'managed':" in script:
            data = {"managed": OWNER + "/owner.json" in self.files,
                    "existing": [CONFIG] if CONFIG in self.files or self.binary else []}
            return CommandResult(0, json.dumps(data).encode(), b"")
        if "s.bind" in script:
            return CommandResult(0, b"", b"")
        assert "vps-lab-pending.json" in script
        assert OWNER + "/install-complete.json" in self.files
        self.files[CONFIG] = self.files[OWNER + "/pending.json"]
        self.active = True
        return CommandResult(0, b'{"configured":true,"running":true}', b"")

    def run(self, command, **kwargs):
        if command.startswith("install -d"):
            return CommandResult(0, b"", b"")
        if command == "test -x /usr/local/bin/xray":
            return CommandResult(0 if self.binary else 1, b"", b"")
        if command == "systemctl is-active --quiet xray":
            return CommandResult(0 if self.active else 1, b"", b"")
        assert command.startswith("bash ") and "install --without-geodata --version" in command
        self.binary = True
        self.installs += 1
        return CommandResult(1 if self.installs == 1 else 0, b"installer output", b"")


@pytest.fixture
def deployment(config, tmp_path, monkeypatch):
    installer = tmp_path / "installer.sh"
    installer.write_bytes(b"reviewed test installer")
    monkeypatch.setattr(deploy, "fetch", lambda *_: (installer, {"sha256": "test-source", "xray_version": "test-version"}))
    config.mode, config.allow_deploy = "deploy", True
    return config, InstallerRemote()


def test_partial_binary_install_resumes_and_reuses_keys(deployment, tmp_path):
    config, remote = deployment
    with pytest.raises(LabError, match="Official installer failed"):
        deploy.deploy(remote, config, tmp_path, tmp_path)
    pending = remote.files[OWNER + "/pending.json"]
    assert remote.binary and not remote.active
    assert OWNER + "/install-complete.json" not in remote.files
    node = deploy.deploy(remote, config, tmp_path, tmp_path)
    assert remote.installs == 2 and remote.active
    assert remote.files[CONFIG] == pending
    assert deploy.deploy(remote, config, tmp_path, tmp_path) == node
    assert remote.installs == 2


def test_unowned_xray_is_never_replaced(deployment, tmp_path):
    config, remote = deployment
    remote.files[CONFIG] = b'{"existing":"service"}'
    before = remote.files.copy()
    with pytest.raises(LabError, match="not owned"):
        deploy.deploy(remote, config, tmp_path, tmp_path)
    assert remote.files == before and remote.installs == 0


def test_changed_request_does_not_reuse_another_pending_node(deployment, tmp_path):
    config, remote = deployment
    with pytest.raises(LabError):
        deploy.deploy(remote, config, tmp_path, tmp_path)
    before = remote.files.copy()
    config.proxy_port = 8443
    with pytest.raises(LabError, match="Pending deployment differs"):
        deploy.deploy(remote, config, tmp_path, tmp_path)
    assert remote.files == before and remote.installs == 1
