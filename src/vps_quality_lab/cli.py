"""Human CLI and JSON-only machine entry point."""

import contextlib
import io
import json
import os
import signal
import sys
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from . import __version__, client, engine, report
from .models import Config, RunResult, SSH, Status, read_config
from .security import redact_urls, safe_output
from .ssh_setup import bootstrap, effective_ssh, identity_dir, trust_host, verify_batch
from .storage import LabError, load_run, run_lock, write_json

app = typer.Typer(no_args_is_help=True, invoke_without_command=True, add_completion=False, pretty_exceptions_enable=False,
                  help="Deliver a REALITY node and a reproducible VPS assessment. Never switches your system proxy.")


def root_path():
    return Path(os.environ.get("VPS_LAB_HOME", str(Path.home() / ".local/share/vps-quality-lab"))).expanduser().resolve()


def emit(ctx, data, status="success"):
    envelope = {"schema_version": 1, "status": status, "data": safe_output(data)}
    if ctx.obj and ctx.obj.get("json"):
        typer.echo(json.dumps(envelope, ensure_ascii=False, default=str))
    else:
        typer.echo(json.dumps(envelope, ensure_ascii=False, indent=2, default=str))


def finish_run(ctx, path, state):
    emit(ctx, {"run_dir": str(path), "result": state.model_dump(mode="json")}, state.status.value)
    raise typer.Exit({Status.success: 0, Status.partial: 3, Status.failed: 1, Status.skipped: 3}[state.status])


@app.callback()
def options(ctx: typer.Context,
            json_output: Annotated[bool, typer.Option("--json", help="Emit one JSON document; logs go to stderr.")] = False,
            version: Annotated[bool, typer.Option("--version", is_eager=True)] = False):
    ctx.ensure_object(dict)
    ctx.obj["json"] = ctx.obj.get("json", False) or json_output
    if version:
        emit(ctx, {"version": __version__})
        raise typer.Exit()


@app.command("init")
def initialize(ctx: typer.Context,
               host: Annotated[str, typer.Option(help="VPS SSH host.")],
               expected_exit: Annotated[str, typer.Option(help="Expected fixed IPv4 egress.")],
               interface: Annotated[str, typer.Option(help="Physical client interface, e.g. en0.")],
               known_hosts: Annotated[Path, typer.Option(help="Already verified SSH known_hosts file.")],
               output: Annotated[Path, typer.Option(help="New private JSON configuration file.")],
               name: str = "My VPS", ssh_port: int = 22, user: str = "root",
               profile: str = "ai",
               entry_host: str | None = None, password_env: str | None = None,
               key_file: Path | None = None):
    """Create strict configuration; does not contact the server."""
    if output.exists():
        raise LabError("Output already exists; refusing to replace configuration", 4)
    config = Config(name=name, ssh=SSH(host=host, port=ssh_port, user=user,
                    known_hosts=known_hosts.expanduser().resolve(), key_file=key_file.expanduser().resolve() if key_file else None,
                    password_env=password_env), entry_host=entry_host or host,
                    expected_exit=expected_exit, interface=interface, profile=profile)
    write_json(output, config.model_dump(mode="json"))
    emit(ctx, {"config": str(output.resolve()), "next": "vps-lab plan --config <file>"})


@app.command()
def schema(ctx: typer.Context, kind: str = "config"):
    """Print the current JSON Schema for config or result."""
    if kind not in ("config", "result"):
        raise LabError("Schema kind must be config or result", 2)
    emit(ctx, (Config if kind == "config" else RunResult).model_json_schema())


@app.command()
def plan(ctx: typer.Context, config: Annotated[Path, typer.Option(exists=True, dir_okay=False)], stages: str = "all"):
    """Validate input and show exact stages, budgets and side effects without connecting."""
    parsed = read_config(config)
    selected = engine.selected_stages(parsed, stages)
    ssh = effective_ssh(parsed.ssh, root_path())
    references = {"known_hosts": ssh.known_hosts.is_file()}
    for name, path in [("key_file", ssh.key_file), ("node_file", parsed.node_file), ("upstream_file", parsed.upstream_file)]:
        if path:
            references[name] = path.is_file()
    if ssh.password_env:
        references["password_environment_present"] = bool(os.environ.get(ssh.password_env))
    prepared = all(references.values())
    emit(ctx, {"stages": selected, "profile": parsed.profile, "mode": parsed.mode,
               "connection": {"ssh_host": parsed.ssh.host, "ssh_port": parsed.ssh.port, "ssh_user": parsed.ssh.user,
                              "entry_host": parsed.entry_host, "expected_exit": parsed.expected_exit,
                              "interface": parsed.interface, "resolver": parsed.resolver or "system",
                              "source_address": parsed.source_address, "upstream_file": str(parsed.upstream_file) if parsed.upstream_file else None},
               "package": parsed.plan, "download_endpoints": parsed.download_urls,
               "upload_endpoint": parsed.upload_url,
               "local_references": references, "ready_for_attempt": prepared,
               "ssh_bootstrap": parsed.bootstrap_ssh, "limits": parsed.limits.model_dump(),
               "side_effects": ["Private local run and key files", "Add missing authorized public key when bootstrap enabled",
                   "Fresh managed Xray install only in deploy mode", "Bounded requests and selected external tools",
                   "Optional external dependencies only when allow_external_install is true"],
               "external_tools": parsed.external_tools,
               "note": "Local reference checks do not prove SSH login or network readiness; run doctor for live checks"},
         "success" if prepared else "partial")
    if not prepared:
        raise typer.Exit(3)


@app.command()
def doctor(ctx: typer.Context, config: Annotated[Path, typer.Option(exists=True, dir_okay=False)]):
    """Read-only local/server checks; never adds a key or installs a service."""
    import shutil
    from .collectors import inventory
    from .remote import Remote
    parsed = read_config(config)
    local = {name: shutil.which(name) for name in ["ssh", "ssh-keygen", "curl", "sing-box"]}
    with Remote(effective_ssh(parsed.ssh, root_path())) as remote:
        server = inventory(remote)
    good = all(local.values())
    emit(ctx, {"local": local, "server": server}, "success" if good else "partial")
    if not good:
        raise typer.Exit(3)


@app.command("ssh-bootstrap")
def ssh_bootstrap(ctx: typer.Context, config: Annotated[Path, typer.Option(exists=True, dir_okay=False)]):
    """Install or adopt a dedicated public key and verify a fresh BatchMode connection."""
    parsed = read_config(config)
    with run_lock(identity_dir(parsed.ssh, root_path())):
        _, data = bootstrap(parsed.ssh, root_path())
    emit(ctx, data, "success" if data["verified"] else "partial")
    if not data["verified"]:
        raise typer.Exit(3)


@app.command("trust-host")
def trust(ctx: typer.Context, host: str, fingerprint: str,
          output: Annotated[Path, typer.Option(help="Dedicated known_hosts file; existing entries preserved.")],
          port: int = 22):
    """Record a host key only after matching a fingerprint obtained from a trusted source."""
    # Reuse SSH input validation before opening a socket.
    SSH(host=host, port=port, known_hosts=output)
    emit(ctx, trust_host(host, port, fingerprint, output))


@app.command("ssh-status")
def ssh_status(ctx: typer.Context, config: Annotated[Path, typer.Option(exists=True, dir_okay=False)]):
    """Recheck the tool's saved public-key alias without changing SSH configuration."""
    parsed = read_config(config)
    directory = identity_dir(parsed.ssh, root_path())
    file = directory / "ssh_config"
    verified = file.is_file() and verify_batch(file, "vps-lab-" + directory.name[:10])
    emit(ctx, {"configured": file.is_file(), "verified": verified, "ssh_config": str(file)},
         "success" if verified else "partial")
    if not verified:
        raise typer.Exit(3)


@app.command()
def run(ctx: typer.Context, config: Annotated[Path, typer.Option(exists=True, dir_okay=False)],
        stages: Annotated[str, typer.Option(help="all, or comma-separated stages; prerequisites are included.")] = "all",
        label: Annotated[str, typer.Option(help="Batch label, e.g. daytime or evening.")] = ""):
    """Run SSH → checks → node → exit → measurements → original screenshots → report."""
    path, state = engine.start(config, root_path(), stages, label,
                               progress=lambda message: typer.echo(message, err=True))
    finish_run(ctx, path, state)


@app.command()
def resume(ctx: typer.Context, run_dir: Annotated[Path, typer.Argument(exists=True, file_okay=False)],
           stages: str = "all", rerun: Annotated[bool, typer.Option(help="Repeat completed measurement stages.")] = False):
    """Recheck live SSH/node/exit, then continue incomplete stages in a new attempt."""
    state = engine.resume(run_dir.resolve(), root_path(), stages, rerun,
                          progress=lambda message: typer.echo(message, err=True))
    finish_run(ctx, run_dir, state)


@app.command()
def status(ctx: typer.Context, run_dir: Annotated[Path, typer.Argument(exists=True, file_okay=False)]):
    """Read stored status; it does not claim a fresh live verification."""
    state = load_run(run_dir)
    emit(ctx, state.model_dump(mode="json"), state.status.value)


@app.command("report")
def export_report(ctx: typer.Context, run_dir: Annotated[Path, typer.Argument(exists=True, file_okay=False)],
                  output: Annotated[Path | None, typer.Option(help="Export parent directory.")] = None,
                  obsidian: Annotated[bool, typer.Option(help="Use the currently open Obsidian vault.")] = False,
                  share: Annotated[bool, typer.Option(help="Redacted summary without original private evidence.")] = False):
    """Generate or export a report with original terminal screenshots."""
    if obsidian and output:
        raise LabError("Choose either --obsidian or --output", 2)
    state = load_run(run_dir)
    report.generate(state, run_dir)
    destination = report.current_vault() / "VPS 评测" if obsidian else output
    path = report.export(state, run_dir, destination, share) if destination else run_dir / ("report-share.md" if share else "report.md")
    emit(ctx, {"report": str(path)})


@app.command("capture")
def capture(ctx: typer.Context, ansi: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
            output: Annotated[Path, typer.Option(help="Destination PNG; original ANSI is not altered.")]):
    """Capture original ANSI output in xterm.js, without OCR or rewritten text."""
    emit(ctx, report.capture_ansi(ansi, output))


@app.command("node-export")
def node_export(ctx: typer.Context, run_dir: Annotated[Path, typer.Argument(exists=True, file_okay=False)],
                output: Annotated[Path, typer.Option(help="New private directory for node link, JSON and QR.")]):
    """Copy credential-bearing node artifacts to an explicit private destination."""
    from .node import Node, save_node
    if output.exists():
        raise LabError("Node export directory already exists", 4)
    node = Node.model_validate_json((run_dir / "private/node.json").read_text())
    save_node(node, output)
    emit(ctx, {"directory": str(output.resolve()), "files": ["node.txt", "node.json", "node.png"]})


@app.command("client-import")
def client_import(ctx: typer.Context, run_dir: Annotated[Path, typer.Argument(exists=True, file_okay=False)]):
    """Request native add-only Shadowrocket import; does not select a route."""
    with run_lock(run_dir):
        emit(ctx, client.request_import(run_dir))


@app.command("client-check")
def client_check(ctx: typer.Context, run_dir: Annotated[Path, typer.Argument(exists=True, file_okay=False)],
                 library: Path | None = None, proxy: str | None = None):
    """Verify imported fields; optionally check exit through a Shadowrocket-owned loopback proxy."""
    with run_lock(run_dir):
        data = client.check(run_dir, library, proxy)
    emit(ctx, data, "success" if data["verified"] else "partial")
    if not data["verified"]:
        raise typer.Exit(3)


@app.command()
def compare(ctx: typer.Context, run_dirs: Annotated[list[Path], typer.Argument(help="Two or more batch directories.")]):
    """Compare eligible batches only when their measurement shapes match."""
    if len(run_dirs) < 2:
        raise LabError("Provide at least two runs", 2)
    states = [load_run(path) for path in run_dirs]
    rows, shape = [], None
    for state in states:
        net = state.stages.get("network")
        signature = json.dumps({"shapes": net.data.get("shapes"), "endpoints": net.data.get("download_endpoints"),
                                "profile": state.profile}, sort_keys=True) if net else None
        if state.ranking_eligible and net and net.data.get("complete"):
            if shape is not None and shape != signature:
                raise LabError("Batch measurement shapes differ; refuse a misleading ranking", 4)
            shape = signature
            rows.append({"run_id": state.run_id, "label": state.label, "metrics": report.metrics(state)})
    key = "single_mbps" if states[0].profile == "video" else "fresh_ttfb_ms"
    ranked = [r for r in rows if r["metrics"].get(key) is not None]
    ranked.sort(key=lambda r: r["metrics"][key], reverse=key == "single_mbps")
    emit(ctx, {"ranking_metric": key, "ranking": ranked,
               "excluded": [s.run_id for s in states if s.run_id not in {r["run_id"] for r in ranked}]},
         "success" if len(ranked) == len(states) else "partial")
    if len(ranked) != len(states):
        raise typer.Exit(3)


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    machine = "--json" in args
    args = [arg for arg in args if arg != "--json"]
    # Help remains machine-readable too. All normal progress goes through stderr.
    help_output = io.StringIO() if machine and ("--help" in args or not args) else None
    def interrupted(*_):
        raise KeyboardInterrupt
    previous = signal.signal(signal.SIGTERM, interrupted)
    code = 0
    try:
        with contextlib.redirect_stdout(help_output) if help_output else contextlib.nullcontext():
            result = app(args=args or ["--help"], standalone_mode=False, obj={"json": machine})
        code = result if isinstance(result, int) else 0
        if help_output:
            typer.echo(json.dumps({"schema_version": 1, "status": "success", "data": {"help": help_output.getvalue()}}))
    except KeyboardInterrupt:
        code = 130
        typer.echo(json.dumps({"schema_version": 1, "status": "partial", "error": {"code": code, "message": "Interrupted; resume the saved run"}}))
    except Exception as exc:
        if isinstance(exc, LabError):
            code, message = exc.code, str(exc)
        elif isinstance(exc, ValidationError):
            code, message = 2, "Invalid configuration: " + json.dumps(exc.errors(include_input=False, include_context=False), default=str)
        elif isinstance(exc, (FileNotFoundError, json.JSONDecodeError)):
            code, message = 2, "Required file missing or invalid JSON"
        elif hasattr(exc, "format_message") and hasattr(exc, "exit_code"):
            code, message = exc.exit_code, exc.format_message()
        else:
            code, message = 1, f"Operation failed ({type(exc).__name__}); no success claimed"
        message = redact_urls(message)
        if machine:
            typer.echo(json.dumps({"schema_version": 1, "status": "failed", "error": {"code": code, "message": message}}))
        else:
            typer.echo(f"Error: {message}", err=True)
    finally:
        signal.signal(signal.SIGTERM, previous)
    if argv is None:
        raise SystemExit(code)
    return code
