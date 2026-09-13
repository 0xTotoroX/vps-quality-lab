"""A persisted pipeline with fresh prerequisite checks on every resume."""

import hashlib
import json
import shutil
import uuid
from pathlib import Path

from . import collectors, diagnostics, network, report
from .deploy import deploy
from .models import Config, RunResult, StageResult, Status, overall, ranking_ready, read_config
from .measurements import NetworkMeasurement, VerifyMeasurement
from .node import Node, adopt, fingerprint, save_node
from .remote import Remote
from .ssh_setup import bootstrap, effective_ssh
from .storage import LabError, digest, load_run, now, private_dir, run_lock, write_json

STAGES = ["ssh", "check", "node", "verify", "hardware", "ip", "network", "routes", "net",
          "hardware-full", "screenshots", "report"]
PREREQUISITES = {"check": ["ssh"], "node": ["check"], "verify": ["node"],
                 "hardware": ["check"], "ip": ["verify"], "network": ["verify"],
                 "routes": ["verify"], "net": ["verify"], "hardware-full": ["check"]}
FRESH = {"ssh", "check", "node", "verify", "screenshots", "report"}


def selected_stages(config: Config, selection: str):
    if selection == "all":
        selected = set(STAGES)
        for tool, stage in [("ip", "ip"), ("net", "net"), ("hardware", "hardware-full")]:
            if tool not in config.external_tools:
                selected.discard(stage)
    else:
        selected = set(selection.split(","))
        if not selected.issubset(STAGES):
            raise LabError("Unknown stage; see vps-lab run --help", 2)
        selected.add("report")
    def require(stage):
        for dependency in PREREQUISITES.get(stage, []):
            selected.add(dependency)
            require(dependency)
    for stage in list(selected):
        require(stage)
    return [stage for stage in STAGES if stage in selected]


class Engine:
    def __init__(self, config: Config, run: Path, root: Path, state: RunResult, progress=print):
        self.config, self.run, self.root, self.state = config, run, root, state
        self.progress = progress
        self.evidence = run / "evidence" / f"attempt-{state.attempt:03}"
        private_dir(self.evidence)
        self.ssh = effective_ssh(config.ssh, root)

    def save(self):
        self.state.status = overall(self.state.stages)
        self.state.ranking_eligible = ranking_ready(self.state)
        write_json(self.run / "state.json", self.state.model_dump(mode="json"))

    def result(self, message, data=None, status=Status.success, evidence=None):
        return StageResult(status=status, message=message, data=data or {}, evidence=evidence or [])

    def execute(self, stage):
        config = self.config
        if stage == "ssh":
            if config.bootstrap_ssh:
                self.ssh, data = bootstrap(config.ssh, self.root)
                self.state.ssh_delivery = "verified" if data["verified"] else "configured"
                return self.result("SSH public-key login verified" if data["verified"] else
                                   "Key configured but second public-key connection failed; original login retained",
                                   data, Status.success if data["verified"] else Status.failed)
            with Remote(self.ssh) as remote:
                check = remote.run("printf vps-lab-ready")
            if check.returncode or check.stdout != b"vps-lab-ready":
                raise LabError("Existing SSH login did not pass validation", 4)
            self.state.ssh_delivery = "verified"
            return self.result("Existing SSH login verified; bootstrap explicitly disabled")
        if stage == "screenshots":
            return report.screenshots(self.run)
        if stage == "report":
            result = self.result("Report generated", {"report": str(self.run / "report.md")})
            candidate = self.state.model_copy(deep=True)
            candidate.stages["report"] = result
            candidate.lifecycle = "complete"
            candidate.status = overall(candidate.stages)
            candidate.ranking_eligible = ranking_ready(candidate)
            report.generate(candidate, self.run)
            return result
        if stage == "verify":
            node = Node.model_validate_json((self.run / "private/node.json").read_text())
            with network.isolated_route(node, config) as (proxy, route):
                data = network.verify_exit(proxy, config.expected_exit, config.limits.request_timeout)
            data["route"] = route
            data["upstream_digest"] = hashlib.sha256(config.upstream_file.read_bytes()).hexdigest() if config.upstream_file else None
            data = VerifyMeasurement.model_validate(data).model_dump(mode="json")
            previous = self.state.stages.get("verify")
            if previous and (previous.data.get("route") != route or previous.data.get("upstream_digest") != data["upstream_digest"]):
                for downstream in ["ip", "network", "routes", "net"]:
                    self.state.stages.pop(downstream, None)
            write_json(self.evidence / "exit.json", data)
            return self.result("Independent REALITY handshake and two-source exit verified" if data["verified"]
                               else "Wrong or missing exit; performance conclusions are blocked", data,
                               Status.success if data["verified"] else Status.failed,
                               [str(self.evidence / "exit.json")])
        if stage == "network":
            node = Node.model_validate_json((self.run / "private/node.json").read_text())
            with network.isolated_route(node, config) as (proxy, route):
                data = network.measure(proxy, config)
            data["route"] = route
            with Remote(self.ssh) as remote:
                data["server_crosscheck"] = diagnostics.server_http(remote, config)
            data = NetworkMeasurement.model_validate(data).model_dump(mode="json")
            write_json(self.evidence / "network.json", data)
            return self.result("Bounded HTTP measurements completed" if data.get("complete") else
                               "Some endpoint measurements or exit checks failed; missing data is not zero",
                               data, Status.success if data.get("complete") else Status.partial,
                               [str(self.evidence / "network.json")])
        with Remote(self.ssh) as remote:
            if stage == "check":
                required = ["ssh", "ssh-keygen", "curl", "sing-box"]
                missing = [name for name in required if not shutil.which(name)]
                if missing:
                    raise LabError("Missing local tools: " + ", ".join(missing), 4)
                data = collectors.inventory(remote)
                if not all(data["commands"].get(c) for c in ["bash", "curl", "timeout", "systemctl", "python3"]):
                    raise LabError("Server requires bash, curl, timeout, systemctl and Python 3", 4)
                data["entry_dns"] = network.resolve(config.entry_host, config)
                return self.result("Local tools, server OS and entry DNS checked", data)
            if stage == "node":
                if config.node_file:
                    node = Node.model_validate_json(config.node_file.read_text())
                    if node.server != config.entry_host:
                        raise LabError("Node server and configured entry_host differ", 4)
                else:
                    if config.mode == "deploy":
                        document = deploy(remote, config, self.root / "cache", self.evidence)
                    else:
                        document = json.loads(remote.read(config.server_config))
                    node = adopt(document, config)
                    # Verify the actual running unit is using this config, rather than a stale file.
                    service = remote.run("systemctl show xray --property=ActiveState --property=ExecStart --value")
                    if service.returncode or config.server_config.encode() not in service.stdout or b"active" not in service.stdout.splitlines():
                        raise LabError("Xray service is not active on the selected config", 4)
                    checked = remote.run("/usr/local/bin/xray run -test -config " + config.server_config)
                    if checked.returncode:
                        raise LabError("Xray configuration validation failed", 4)
                previous = self.state.stages.get("node")
                changed = previous and previous.data.get("fingerprint") != fingerprint(node)
                if changed:
                    for downstream in ["verify", "ip", "network", "routes", "net"]:
                        self.state.stages.pop(downstream, None)
                save_node(node, self.run / "private")
                if changed or self.state.node_delivery == "not_generated":
                    self.state.node_delivery = "generated"
                return self.result("Private node link and QR generated; Shadowrocket import tracked separately",
                                   {"fingerprint": fingerprint(node), "server_port": node.port,
                                    "config_changed": bool(changed)})
            if stage == "hardware":
                data = collectors.hardware(remote, config)
                write_json(self.evidence / "hardware.json", data)
                return self.result("Server inventory collected; CPU benchmark requires allow_stress", data,
                                   Status.partial if data["cpu_benchmark"]["status"] == "failed" else Status.success)
            if stage == "routes":
                node = Node.model_validate_json((self.run / "private/node.json").read_text())
                data = diagnostics.routes(remote, config, node.port)
                write_json(self.evidence / "routes.json", data)
                return self.result("TCP, ICMP and return routes kept separate; unavailable probes are explicit", data,
                                   Status.partial if any(v.get("status") in ("skipped", "partial")
                                                        for v in data.values()) else Status.success)
            if stage in ("ip", "net", "hardware-full"):
                tool = "hardware" if stage == "hardware-full" else stage
                if tool == "hardware" and not config.allow_stress:
                    return self.result("HardwareQuality requires allow_stress", status=Status.skipped)
                return collectors.external(remote, tool, config, self.root / "cache", self.evidence)
        raise LabError("Unknown pipeline stage", 2)

    def perform(self, selection: str, rerun: bool = False):
        selected = selected_stages(self.config, selection)
        self.state.lifecycle = "running"
        self.state.verified_attempt = None
        for name in STAGES:
            if name not in selected and name not in self.state.stages:
                self.state.stages[name] = self.result("Not selected", status=Status.skipped)
        self.save()
        active = None
        try:
            for stage in selected:
                previous = self.state.stages.get(stage)
                if previous and previous.status == Status.success and stage not in FRESH and not rerun:
                    continue
                active = stage
                self.progress(f"[{stage}] running")
                started = now()
                failed = [d for d in PREREQUISITES.get(stage, [])
                          if self.state.stages.get(d) is None or self.state.stages[d].status != Status.success]
                if failed:
                    result = self.result("Prerequisite unavailable: " + ", ".join(failed), status=Status.skipped)
                else:
                    try:
                        result = self.execute(stage)
                    except LabError as exc:
                        result = self.result(str(exc), {"error_code": exc.code}, Status.failed)
                    except (OSError, ValueError, KeyError) as exc:
                        result = self.result(f"{stage} could not complete ({type(exc).__name__}); inspect inputs and evidence",
                                             status=Status.failed)
                result.started_at, result.finished_at = started, now()
                self.state.stages[stage] = result
                if stage == "verify" and result.status == Status.success:
                    self.state.verified_attempt = self.state.attempt
                self.save()
                self.progress(f"[{stage}] {result.status.value}: {result.message}")
                active = None
        except KeyboardInterrupt:
            if active:
                self.state.stages[active] = self.result("Interrupted; resume rechecks prerequisites", status=Status.partial)
            self.state.lifecycle = "interrupted"
            self.save()
            try:
                report.generate(self.state, self.run)
            except Exception:
                self.state.stages["report"] = self.result("Interrupted report could not be saved", status=Status.failed)
                self.save()
            raise
        self.state.lifecycle = "complete"
        self.save()
        return self.state


def start(config_path: Path, root: Path, selection="all", label="", progress=print):
    config = read_config(config_path)
    run_id = now().replace(":", "-") + "-" + uuid.uuid4().hex[:8]
    run = private_dir(root / "runs" / run_id)
    write_json(run / "private/config.json", config.model_dump(mode="json"))
    state = RunResult(run_id=run_id, name=config.name, profile=config.profile, label=label,
                      created_at=now(), config_digest=digest(config.model_dump(mode="json")), attempt=1)
    with run_lock(run), run_lock(root / "host-locks" / digest([config.ssh.host, config.ssh.port, config.ssh.user])[:20]):
        state = Engine(config, run, root, state, progress).perform(selection)
    return run, state


def resume(run: Path, root: Path, selection="all", rerun=False, progress=print):
    with run_lock(run):
        state = load_run(run)
        config = read_config(run / "private/config.json")
        if digest(config.model_dump(mode="json")) != state.config_digest:
            raise LabError("Run configuration changed; create a new batch instead", 4)
        write_json(run / "evidence" / f"attempt-{state.attempt + 1:03}" / "state-before-resume.json",
                   state.model_dump(mode="json"))
        state.attempt += 1
        with run_lock(root / "host-locks" / digest([config.ssh.host, config.ssh.port, config.ssh.user])[:20]):
            return Engine(config, run, root, state, progress).perform(selection, rerun)
