import pytest

from vps_quality_lab import client
from vps_quality_lab.models import RunResult
from vps_quality_lab.node import save_node
from vps_quality_lab.storage import load_run, now, write_json


def archive_row(node):
    return {"type": "VLESS", "tls": True, "xtls": 2, "allowInsecure": 0, "mux": False,
            "host": node.server, "port": node.port, "password": node.uuid,
            "publicKey": node.public_key, "peer": node.server_name, "shortId": node.short_id}


@pytest.mark.parametrize("change", [{"type": "VMess"}, {"tls": False}, {"xtls": 0},
                                   {"allowInsecure": 1}, {"mux": True}, {"port": "invalid"}])
def test_mismatched_protocol_options_are_not_imported(node, tmp_path, monkeypatch, change):
    library = tmp_path / "archive"
    library.write_bytes(b"fixture")
    row = archive_row(node)
    monkeypatch.setattr(client, "decode_archive", lambda _: [row])
    assert client.imported(node, library)
    row.update(change)
    assert not client.imported(node, library)


def test_removed_node_downgrades_previous_verified_state(node, tmp_path, monkeypatch):
    save_node(node, tmp_path / "private")
    state = RunResult(run_id="test", name="Example", profile="ai", created_at=now(),
                      config_digest="test", node_delivery="verified")
    write_json(tmp_path / "state.json", state.model_dump(mode="json"))
    monkeypatch.setattr(client, "imported", lambda *_: False)
    result = client.check(tmp_path)
    assert not result["imported"] and not result["verified"]
    assert load_run(tmp_path).node_delivery == "generated"
