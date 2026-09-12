import base64

import pytest

from vps_quality_lab.models import Config, SSH
from vps_quality_lab.node import Node


@pytest.fixture
def config(tmp_path):
    return Config(name="Example VPS", ssh=SSH(host="192.0.2.10", known_hosts=tmp_path / "known_hosts"),
                  entry_host="192.0.2.10", expected_exit="192.0.2.10", interface="en0")


@pytest.fixture
def node():
    return Node(name="Example VPS", server="192.0.2.10", port=443,
                uuid="12345678-1234-4234-8234-123456789abc", public_key=base64.urlsafe_b64encode(b"x"*32).decode().rstrip("="),
                short_id="0123456789abcdef", server_name="example.com")
