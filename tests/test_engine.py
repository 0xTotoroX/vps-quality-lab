
import pytest

from vps_quality_lab.engine import Engine
from vps_quality_lab.models import RunResult, StageResult, Status
from vps_quality_lab.storage import digest, load_run, now


def make_engine(config, tmp_path):
    state = RunResult(run_id="test-batch", name=config.name, profile=config.profile, created_at=now(),
                      config_digest=digest(config.model_dump(mode="json")), attempt=1)
    run = tmp_path / "runs/test-batch"
    return Engine(config, run, tmp_path, state, lambda _: None)


def test_failed_ssh_blocks_node_and_measurements(config, tmp_path, monkeypatch):
    engine = make_engine(config, tmp_path)
    visited = []
    def execute(stage):
        visited.append(stage)
        if stage == "report":
            return Engine.execute(engine, stage)
        return StageResult(status=Status.failed if stage == "ssh" else Status.success, message="test fixture")
    monkeypatch.setattr(engine, "execute", execute)
    state = engine.perform("network")
    assert visited == ["ssh", "report"]
    assert state.status == Status.failed
    assert state.stages["network"].status == Status.skipped
    assert not state.ranking_eligible
    assert (engine.run / "report.md").exists()


def test_resume_rechecks_prerequisites_and_keeps_completed_samples(config, tmp_path, monkeypatch):
    engine = make_engine(config, tmp_path)
    visited = []
    def execute(stage):
        visited.append(stage)
        return StageResult(status=Status.success, message="test fixture", data={"eligible": True})
    monkeypatch.setattr(engine, "execute", execute)
    engine.perform("network")
    visited.clear()
    engine.perform("network")
    assert visited == ["ssh", "check", "node", "verify", "report"]


def test_interruption_persists_resume_state(config, tmp_path, monkeypatch):
    engine = make_engine(config, tmp_path)
    def execute(stage):
        if stage == "network":
            raise KeyboardInterrupt
        return StageResult(status=Status.success, message="test fixture")
    monkeypatch.setattr(engine, "execute", execute)
    with pytest.raises(KeyboardInterrupt):
        engine.perform("network")
    state = load_run(engine.run)
    assert state.lifecycle == "interrupted"
    assert state.stages["network"].status == Status.partial
    assert (engine.run / "report.md").exists()
