import json
import os
import subprocess
import sys

from jsonschema import validate

from vps_quality_lab import cli
from vps_quality_lab.models import Config


def test_version_is_machine_readable(capsys):
    assert cli.main(["--json", "--version"]) == 0
    output = capsys.readouterr()
    assert json.loads(output.out)["data"]["version"] == "0.1.1"
    assert not output.err


def test_help_is_machine_readable(capsys):
    assert cli.main(["--json", "run", "--help"]) == 0
    assert "--config" in json.loads(capsys.readouterr().out)["data"]["help"]


def test_missing_args_never_prompt(capsys):
    assert cli.main(["--json", "run"]) == 2
    assert json.loads(capsys.readouterr().out)["status"] == "failed"


def test_invalid_input_does_not_echo_secret(config, tmp_path, capsys):
    data = config.model_dump(mode="json")
    data["ssh"]["password"] = "do-not-echo-my-private-password"
    path = tmp_path / "config.json"
    path.write_text(json.dumps(data))
    assert cli.main(["plan", "--config", str(path), "--json"]) == 2
    output = capsys.readouterr()
    assert "do-not-echo" not in output.out + output.err
    assert json.loads(output.out)["error"]["code"] == 2


def test_plan_json_and_schema(config, tmp_path, capsys):
    config.ssh.known_hosts.write_text("")
    data = config.model_dump(mode="json")
    validate(data, Config.model_json_schema())
    path = tmp_path / "config.json"
    path.write_text(json.dumps(data))
    assert cli.main(["plan", "--config", str(path), "--stages", "network", "--json"]) == 0
    output = capsys.readouterr()
    stages = json.loads(output.out)["data"]["stages"]
    assert stages == ["ssh", "check", "node", "verify", "network", "report"]
    assert not (tmp_path / "runs").exists()


def test_plan_reports_missing_local_references(config, tmp_path, capsys):
    path = tmp_path / "config.json"
    path.write_text(config.model_dump_json())
    assert cli.main(["--json", "plan", "--config", str(path)]) == 3
    output = json.loads(capsys.readouterr().out)
    assert not output["data"]["ready_for_attempt"]
    assert output["data"]["local_references"]["known_hosts"] is False


def test_installed_entrypoint_exit_code():
    result = subprocess.run([sys.executable, "-m", "vps_quality_lab", "--json", "run"],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 2
    assert json.loads(result.stdout)["status"] == "failed"


def test_machine_help_remains_plain_when_ci_forces_color():
    result = subprocess.run([sys.executable, "-m", "vps_quality_lab", "--json", "run", "--help"],
                            capture_output=True, text=True, timeout=10,
                            env={**os.environ, "FORCE_COLOR": "1", "GITHUB_ACTIONS": "true"})
    text = json.loads(result.stdout)["data"]["help"]
    assert result.returncode == 0 and "--config" in text and "\x1b" not in text
