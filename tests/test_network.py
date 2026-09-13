import json

from vps_quality_lab import network
from vps_quality_lab.process import CommandResult


def test_wrong_exit_rejects_benchmark_before_transfer(monkeypatch, config):
    monkeypatch.setattr(network, "verify_exit", lambda *_: {"verified": False})
    monkeypatch.setattr(network, "request", lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("must not transfer")))
    assert network.measure("socks5h://127.0.0.1:1234", config)["eligible"] is False


def test_partial_download_not_valid(monkeypatch, config):
    metric = {"http_code": 200, "time_total": 1.0, "size_download": 100, "exitcode": 0}
    monkeypatch.setattr(network, "execute", lambda *_a, **_k: CommandResult(0, json.dumps(metric).encode(), b""))
    assert not network.request("https://example.com", None, config.limits)[0]["valid"]


def test_http_failure_not_counted_as_speed(monkeypatch, config):
    metric = {"http_code": 503, "time_total": 1.0, "size_download": config.limits.download_bytes, "exitcode": 0}
    monkeypatch.setattr(network, "execute", lambda *_a, **_k: CommandResult(0, json.dumps(metric).encode(), b""))
    assert not network.request("https://example.com", None, config.limits)[0]["valid"]


def test_two_exit_sources_must_agree(monkeypatch):
    answers = iter([CommandResult(0, b"ip=192.0.2.10\n", b""), CommandResult(0, b"192.0.2.11", b"")])
    monkeypatch.setattr(network, "execute", lambda *_a, **_k: next(answers))
    result = network.verify_exit("socks5h://127.0.0.1:1234", "192.0.2.10", 5)
    assert not result["verified"]
    assert result["observations"][0]["matches"]


def test_post_measurement_exit_change_removes_ranking(monkeypatch, config):
    exits = iter([{"verified": True}, {"verified": False}])
    monkeypatch.setattr(network, "verify_exit", lambda *_: next(exits))
    monkeypatch.setattr(network, "request", lambda *_a, **_k: [{"valid": True, "size_download": 5_000_000}])
    data = network.measure("socks5h://127.0.0.1:1234", config)
    assert not data["eligible"] and data["parallel_mbps"] is None


def test_missing_second_ttfb_sample_is_incomplete(monkeypatch, config):
    monkeypatch.setattr(network, "verify_exit", lambda *_: {"verified": True})
    monkeypatch.setattr(network, "request", lambda *_a, **_k: [
        {"valid": True, "size_download": config.limits.download_bytes}])
    data = network.measure("socks5h://127.0.0.1:1234", config)
    assert data["eligible"] and not data["complete"]
