"""Regression coverage for interrupted runs, report writes and comparison contracts."""

import json

import pytest
from jsonschema import ValidationError as SchemaError, validate
from pydantic import ValidationError

from vps_quality_lab import cli, collectors, report
from vps_quality_lab.engine import Engine
from vps_quality_lab.measurements import MeasurementContract, NetworkMeasurement, result_schema
from vps_quality_lab.models import RunResult, StageResult, Status
from vps_quality_lab.storage import load_run, now, write_json, write_private
from vps_quality_lab.process import CommandResult


def success(data=None):
    return StageResult(status=Status.success, message="fixture", data=data or {})


def ready(config, name="fixture"):
    contract = MeasurementContract(profile=config.profile, limits=config.limits,
        download_endpoints=config.download_urls, upload_endpoint=config.upload_url,
        ttfb_endpoint="https://example.com/trace", exit_endpoints=["https://example.com/trace", "https://example.org/ip"])
    return RunResult(run_id=name, name=name, profile=config.profile, created_at=now(),
        config_digest="fixture", attempt=1, verified_attempt=1, lifecycle="complete",
        status=Status.success, ranking_eligible=True,
        stages={**{s: success() for s in ("ssh", "check", "node", "verify")},
                "network": success({"eligible": True, "complete": True, "contract": contract.model_dump(mode="json"),
                    "ttfb_pairs": [[{"valid": True, "time_starttransfer": 0.1}]]})})


@pytest.mark.parametrize("stage", ["ssh", "check", "node", "verify"])
def test_interrupted_reverification_cannot_rank(config, tmp_path, monkeypatch, capsys, stage):
    state = ready(config)
    engine = Engine(config, tmp_path / "run", tmp_path, state, lambda _: None)
    def execute(name):
        if name == stage:
            raise KeyboardInterrupt
        return success()
    monkeypatch.setattr(engine, "execute", execute)
    with pytest.raises(KeyboardInterrupt):
        engine.perform("network")
    saved = load_run(engine.run)
    assert saved.lifecycle == "interrupted" and not saved.ranking_eligible
    assert saved.stages["network"].data["complete"]  # historical samples survive
    # Even a legacy or incorrectly cached flag cannot bypass comparison checks.
    saved.ranking_eligible = True
    write_json(engine.run / "state.json", saved.model_dump(mode="json"))
    assert cli.main(["--json", "compare", str(engine.run), str(engine.run)]) == 3
    assert json.loads(capsys.readouterr().out)["data"]["ranking"] == []


def test_report_write_failure_is_saved_and_retryable(config, tmp_path, monkeypatch):
    state = ready(config)
    engine = Engine(config, tmp_path / "run", tmp_path, state, lambda _: None)
    real_generate = report.generate
    def fail(*_):
        raise OSError("disk write failed")
    monkeypatch.setattr(report, "generate", fail)
    result = engine.perform("report")
    assert result.status == Status.partial
    assert load_run(engine.run).stages["report"].status == Status.failed
    assert not (engine.run / "report.md").exists()
    monkeypatch.setattr(report, "generate", real_generate)
    result = engine.perform("report")
    assert result.stages["report"].status == Status.success
    assert "**success**" in (engine.run / "report.md").read_text()


def test_report_failure_does_not_mask_interruption(config, tmp_path, monkeypatch):
    engine = Engine(config, tmp_path / "run", tmp_path, ready(config), lambda _: None)
    monkeypatch.setattr(engine, "execute", lambda _: (_ for _ in ()).throw(KeyboardInterrupt()))
    monkeypatch.setattr(report, "generate", lambda *_: (_ for _ in ()).throw(OSError()))
    with pytest.raises(KeyboardInterrupt):
        engine.perform("network")
    saved = load_run(engine.run)
    assert saved.lifecycle == "interrupted" and saved.stages["report"].status == Status.failed


@pytest.mark.parametrize("change", ["upload_endpoint", "ttfb_endpoint", "legacy"])
def test_compare_rejects_incompatible_or_unknown_contracts(config, tmp_path, capsys, change):
    first, second = ready(config, "one"), ready(config, "two")
    if change == "legacy":
        second.stages["network"].data.pop("contract")
    else:
        second.stages["network"].data["contract"][change] = "https://example.net/changed"
    paths = [tmp_path / "one", tmp_path / "two"]
    for state, path in zip([first, second], paths):
        write_json(path / "state.json", state.model_dump(mode="json"))
    code = cli.main(["--json", "compare", *map(str, paths)])
    assert code == (3 if change == "legacy" else 4)
    output = json.loads(capsys.readouterr().out)
    if change == "legacy":
        assert output["data"]["exclusion_reasons"][0]["run_id"] == "two"


def test_compatible_measurements_still_compare(config, tmp_path, capsys):
    paths = [tmp_path / "one", tmp_path / "two"]
    for path in paths:
        write_json(path / "state.json", ready(config, path.name).model_dump(mode="json"))
    assert cli.main(["--json", "compare", *map(str, paths)]) == 0
    assert len(json.loads(capsys.readouterr().out)["data"]["ranking"]) == 2


@pytest.mark.parametrize("read_failed", [False, True])
def test_interrupted_external_salvages_before_cleanup(config, tmp_path, monkeypatch, read_failed):
    source = tmp_path / "tool.sh"
    source.write_text("fixture")
    monkeypatch.setattr(collectors, "fetch", lambda *_: (source, {}))
    events = []
    class Remote:
        def mkdir(self, *_): pass
        def write(self, *_): pass
        def read(self, *_):
            events.append("read")
            if read_failed:
                raise OSError("transport unavailable")
            return b'{"partial":true}'
        def run(self, command, **kwargs):
            if command.startswith("rm -rf"):
                events.append("cleanup")
                return CommandResult(0, b"", b"")
            write_private(kwargs["output_path"], b"original ANSI before interruption")
            raise KeyboardInterrupt
    evidence = tmp_path / "evidence"
    with pytest.raises(KeyboardInterrupt):
        collectors.external(Remote(), "ip", config, tmp_path, evidence)
    assert (evidence / "ip.ansi").read_bytes() == b"original ANSI before interruption"
    recovery = json.loads((evidence / "ip-recovery.json").read_text())
    assert recovery["remote_cleaned"] == (not read_failed)
    if read_failed:
        assert events == ["read"] and recovery["remote_directory"].startswith("/tmp/vps-quality-lab-")
    else:
        assert events == ["read", "cleanup"]
        assert json.loads((evidence / "ip.json").read_text()) == {"partial": True}


def test_current_measurement_schema_rejects_missing_or_mistyped_fields(config):
    contract = ready(config).stages["network"].data["contract"]
    data = {"measurement_version": 1, "contract": contract, "eligible": False, "complete": False,
            "exit_before": {"verified": False, "observations": [
                {"source": source, "ip": None, "exit_code": 1, "matches": False}
                for source in contract["exit_endpoints"]]}}
    NetworkMeasurement.model_validate(data)
    state = ready(config).model_dump(mode="json")
    state["stages"]["network"]["data"] = data
    validate(state, result_schema())
    RunResult.model_validate(state)
    data["complete"] = "false"
    with pytest.raises(ValidationError):
        RunResult.model_validate(state)
    with pytest.raises(SchemaError):
        validate(state, result_schema())
    data["complete"] = True
    with pytest.raises(ValidationError, match="all expected valid samples"):
        RunResult.model_validate(state)


def test_remote_stream_is_on_disk_when_channel_interrupts(config, tmp_path):
    from vps_quality_lab.remote import Remote
    class Channel:
        sent = False
        closed = False
        def exec_command(self, *_): pass
        def shutdown_write(self): pass
        def recv_ready(self):
            if self.sent:
                raise KeyboardInterrupt
            return True
        def recv(self, *_):
            self.sent = True
            return b"\x1b[31moriginal live terminal\x1b[0m"
        def close(self): self.closed = True
    channel = Channel()
    class Transport:
        def open_session(self, **_): return channel
    class Client:
        def get_transport(self): return Transport()
    remote = Remote(config.ssh)
    remote.client = Client()
    output = tmp_path / "evidence/tool.ansi"
    with pytest.raises(KeyboardInterrupt):
        remote.run("fixture", output_path=output)
    assert output.read_bytes() == b"\x1b[31moriginal live terminal\x1b[0m"
    assert output.stat().st_mode & 0o777 == 0o600 and channel.closed
