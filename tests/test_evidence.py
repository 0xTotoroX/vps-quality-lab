
import pytest

from vps_quality_lab.collectors import conflicts, parse_json_evidence
from vps_quality_lab.deploy import server_document
from vps_quality_lab.models import RunResult, StageResult, Status
from vps_quality_lab.node import adopt, save_node
from vps_quality_lab.report import metrics, report_text
from vps_quality_lab.storage import LabError, now


def test_invalid_json_is_not_success():
    for value in [b"", b"{}", b"[]", b"upstream failure"]:
        with pytest.raises(ValueError):
            parse_json_evidence(value)


def test_terminal_json_conflict_retains_both_values():
    found = conflicts({"Score": {"IPQS": 12}}, b"\x1b[31mIPQS: 85\x1b[0m")
    assert found[0]["json"] == 12 and found[0]["terminal"] == ["85"]


def test_ipqs_factor_flags_are_not_misread_as_scores():
    found = conflicts({"Score": {"IPQS": "85"}, "Factor": {"Country": {"IPQS": "US"},
                       "VPN": {"IPQS": False}}}, b"IPQS: 85")
    assert not found


def test_empty_network_values_and_ttl_errors_are_partial():
    from vps_quality_lab.collectors import validate_external
    data = {"Head": {"IP": "192.0.2.10"}, "Delay": [], "Transfer": [], "Speedtest": []}
    valid, issues = validate_external("net", data, "192.0.2.10", b"firstTTL(100) cannot be larger than maxTTL(30)")
    assert not valid and len(issues) == 4


def test_low_data_mode_records_intentional_throughput_skip():
    from vps_quality_lab.collectors import validate_external
    data = {"Head": {"IP": "192.0.2.10"}, "Delay": [{"Name": "A", "Average": "12.3"}],
            "Transfer": [{"City": "B", "Delay": {"Average": "22"}}], "Speedtest": []}
    assert validate_external("net", data, "192.0.2.10", b"", low_data=True) == (True, [])
    data["Transfer"][0]["Delay"]["Average"] = "null"
    assert not validate_external("net", data, "192.0.2.10", b"", low_data=True)[0]


def test_resource_exhaustion_is_not_attributed_to_network_quality():
    from vps_quality_lab.collectors import validate_external
    data = {"Head": {"IP": "192.0.2.10"}, "Info": {"ASN": 64500}}
    valid, issues = validate_external("ip", data, "192.0.2.10", b"fork: Resource temporarily unavailable")
    assert not valid and "resource limits or host exhaustion" in issues[0]


def test_adopt_fixed_exit_rejects_other_outbound(config):
    document = server_document(config)
    document["outbounds"].append({"protocol": "socks", "tag": "warp"})
    with pytest.raises(LabError, match="non-direct"):
        adopt(document, config)


def test_generated_config_has_no_implicit_geoip_asset_dependency(config):
    document = server_document(config)
    import ipaddress
    blocked = document["routing"]["rules"][0]["ip"]
    networks = [ipaddress.ip_network(value) for value in blocked]
    assert any(ipaddress.ip_address("192.168.1.1") in net for net in networks)
    assert not any(ipaddress.ip_address("8.8.8.8") in net for net in networks)


def test_reality_adoption_and_node_idempotence(config, tmp_path):
    document = server_document(config)
    node = adopt(document, config)
    save_node(node, tmp_path / "private")
    first = (tmp_path / "private/node.png").stat().st_mtime_ns
    save_node(adopt(document, config), tmp_path / "private")
    assert (tmp_path / "private/node.png").stat().st_mtime_ns == first
    assert (tmp_path / "private/node.json").stat().st_mode & 0o777 == 0o600


def test_interrupted_node_bundle_is_repaired(node, tmp_path):
    save_node(node, tmp_path / "private")
    original = (tmp_path / "private/node.png").read_bytes()
    (tmp_path / "private/node.png").write_bytes(b"stale or interrupted QR")
    save_node(node, tmp_path / "private")
    assert (tmp_path / "private/node.png").read_bytes() == original


def test_wrong_exit_hides_metrics_in_report(tmp_path):
    state = RunResult(run_id="test", name="Example", profile="ai", created_at=now(), config_digest="x",
                      ranking_eligible=False, stages={"network": StageResult(status=Status.success,
                      message="fixture", data={"eligible": False, "parallel_mbps": 999})})
    assert all(value is None for value in metrics(state).values())
    assert "999" not in report_text(state, tmp_path)
