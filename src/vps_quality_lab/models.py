"""Versioned, strict inputs and results. Secrets are file/environment references."""

import ipaddress
import json
import re
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Status(StrEnum):
    success = "success"
    partial = "partial"
    failed = "failed"
    skipped = "skipped"


class SSH(Model):
    host: str
    port: int = Field(default=22, ge=1, le=65535)
    user: str = "root"
    known_hosts: Path
    key_file: Path | None = None
    password_env: str | None = None
    connect_timeout: int = Field(default=10, ge=2, le=60)
    enable_public_key: bool = False

    @field_validator("host", "user")
    @classmethod
    def safe_name(cls, value):
        if not re.fullmatch(r"[A-Za-z0-9_.:@-]+", value) or value.startswith("-"):
            raise ValueError("invalid SSH host/user")
        return value

    @field_validator("password_env")
    @classmethod
    def env_name(cls, value):
        if value is not None and not re.fullmatch(r"[A-Z_][A-Z0-9_]*", value):
            raise ValueError("password_env must name an environment variable")
        return value


class Limits(Model):
    request_timeout: int = Field(default=25, ge=3, le=120)
    samples: int = Field(default=3, ge=1, le=10)
    download_bytes: int = Field(default=5_000_000, ge=100_000, le=50_000_000)
    upload_bytes: int = Field(default=1_000_000, ge=100_000, le=10_000_000)
    concurrency: int = Field(default=3, ge=1, le=4)
    external_timeout: int = Field(default=240, ge=30, le=900)
    cpu_seconds: int = Field(default=3, ge=1, le=10)


class Config(Model):
    schema_version: Literal[1] = 1
    name: str = Field(min_length=1, max_length=80)
    ssh: SSH
    entry_host: str
    expected_exit: str
    interface: str
    resolver: str | None = None
    source_address: str | None = None
    profile: Literal["ai", "video", "balanced"] = "ai"
    plan: dict[str, str | int | float] = Field(default_factory=dict)
    mode: Literal["adopt", "deploy"] = "adopt"
    server_config: str = "/usr/local/etc/xray/config.json"
    inbound_tag: str | None = None
    client_id: str | None = None
    node_file: Path | None = None
    upstream_file: Path | None = None
    proxy_port: int = Field(default=443, ge=1, le=65535)
    reality_target: str = "www.bing.com:443"
    server_name: str = "www.bing.com"
    external_tools: list[Literal["ip", "net", "hardware"]] = Field(default_factory=lambda: ["ip"])
    allow_deploy: bool = False
    allow_external_install: bool = False
    allow_stress: bool = False
    bootstrap_ssh: bool = True
    limits: Limits = Field(default_factory=Limits)
    download_urls: list[str] = Field(default_factory=lambda: [
        "https://speed.cloudflare.com/__down?bytes={bytes}",
        "https://proof.ovh.net/files/10Mb.dat",
    ], min_length=2, max_length=4)
    upload_url: str = "https://speed.cloudflare.com/__up"
    return_target: str | None = None

    @model_validator(mode="before")
    @classmethod
    def profile_defaults(cls, value):
        if isinstance(value, dict) and "limits" not in value:
            defaults = {"ai": {"download_bytes": 5_000_000, "upload_bytes": 1_000_000, "request_timeout": 25},
                        "video": {"download_bytes": 20_000_000, "upload_bytes": 5_000_000, "request_timeout": 45},
                        "balanced": {"download_bytes": 10_000_000, "upload_bytes": 3_000_000, "request_timeout": 35}}
            value = {**value, "limits": defaults.get(value.get("profile", "ai"), {})}
        return value

    @field_validator("name")
    @classmethod
    def clean_name(cls, value):
        if any(ord(c) < 32 for c in value):
            raise ValueError("name must not contain control characters")
        return value

    @field_validator("entry_host", "server_name", "reality_target", "interface")
    @classmethod
    def safe_token(cls, value):
        if not re.fullmatch(r"[A-Za-z0-9_.:\[\]-]+", value) or value.startswith("-"):
            raise ValueError("invalid network parameter")
        return value

    @field_validator("expected_exit", "resolver", "source_address", "return_target")
    @classmethod
    def ip_literal(cls, value):
        if value is not None:
            return str(ipaddress.IPv4Address(value))
        return value

    @field_validator("server_config")
    @classmethod
    def remote_path(cls, value):
        if not re.fullmatch(r"/[A-Za-z0-9_./-]+", value) or ".." in value.split("/"):
            raise ValueError("server_config must be an absolute simple path")
        return value

    @model_validator(mode="after")
    def valid_policy(self):
        from urllib.parse import urlsplit
        for url in [*self.download_urls, self.upload_url]:
            parsed = urlsplit(url)
            if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
                raise ValueError("test endpoints must use HTTPS without URL credentials")
        if self.mode == "deploy" and not self.allow_deploy:
            raise ValueError("deploy requires allow_deploy=true after deployment authorization")
        if "hardware" in self.external_tools and not self.allow_stress:
            raise ValueError("HardwareQuality requires allow_stress=true")
        if self.resolver and not self.source_address:
            raise ValueError("resolver requires source_address for independently bound DNS")
        return self


class StageResult(Model):
    status: Status
    message: str
    data: dict[str, Any] = Field(default_factory=dict)
    evidence: list[str] = Field(default_factory=list)
    started_at: str | None = None
    finished_at: str | None = None


class RunResult(Model):
    schema_version: Literal[1] = 1
    run_id: str
    name: str
    profile: str
    label: str = ""
    status: Status = Status.partial
    lifecycle: Literal["running", "complete", "interrupted"] = "running"
    created_at: str
    config_digest: str
    attempt: int = 0
    verified_attempt: int | None = None
    stages: dict[str, StageResult] = Field(default_factory=dict)
    node_delivery: Literal["not_generated", "generated", "import_requested", "imported", "verified"] = "not_generated"
    ranking_eligible: bool = False
    ssh_delivery: Literal["not_configured", "configured", "verified"] = "not_configured"

    @model_validator(mode="after")
    def validate_measurements(self):
        from .measurements import NetworkMeasurement, VerifyMeasurement
        for name, model in [("network", NetworkMeasurement), ("verify", VerifyMeasurement)]:
            stage = self.stages.get(name)
            if stage and "measurement_version" in stage.data:
                model.model_validate(stage.data)
        return self


def ranking_ready(state: RunResult) -> bool:
    verify, net = state.stages.get("verify"), state.stages.get("network")
    return bool(state.lifecycle == "complete" and state.verified_attempt == state.attempt
                and state.verified_attempt is not None
                and all(state.stages.get(s) and state.stages[s].status == Status.success
                        for s in ("ssh", "check", "node", "verify"))
                and verify and net and net.status == Status.success
                and net.data.get("eligible") and net.data.get("complete"))


def read_config(path: Path) -> Config:
    data = json.loads(path.read_text())
    config = Config.model_validate(data)
    # Resolve paths relative to the config, never the caller's working directory.
    for obj, fields in [(config.ssh, ["known_hosts", "key_file"]),
                        (config, ["node_file", "upstream_file"])]:
        for key in fields:
            value = getattr(obj, key)
            if value is not None:
                value = value.expanduser()
                setattr(obj, key, value if value.is_absolute() else (path.parent / value).resolve())
    return config


def overall(stages: dict[str, StageResult]) -> Status:
    essential = ("ssh", "check", "node", "verify")
    if any(stages.get(s) and stages[s].status == Status.failed for s in essential):
        return Status.failed
    active = [s.status for s in stages.values() if s.message != "Not selected"]
    if not active or all(s == Status.skipped for s in active):
        return Status.skipped
    if all(s == Status.success for s in active):
        return Status.success
    return Status.partial
