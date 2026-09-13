"""Versioned measurement contracts; legacy run records remain readable."""

from typing import Any, Literal

from pydantic import Field, StrictBool, StrictInt, model_validator
from pydantic.json_schema import models_json_schema

from .models import Limits, Model, RunResult


class ExitObservation(Model):
    source: str
    ip: str | None
    exit_code: StrictInt
    matches: StrictBool


class ExitResult(Model):
    verified: StrictBool
    observations: list[ExitObservation] = Field(min_length=2, max_length=2)

    @model_validator(mode="after")
    def consistent(self):
        if self.verified != all(row.matches and row.exit_code == 0 and row.ip for row in self.observations):
            raise ValueError("exit verification contradicts observations")
        if len({row.source for row in self.observations}) != 2:
            raise ValueError("two distinct exit sources are required")
        return self


class VerifyMeasurement(ExitResult):
    measurement_version: Literal[1] = 1
    route: dict[str, Any]
    upstream_digest: str | None


class HTTPSample(Model):
    kind: Literal["download", "upload", "ttfb"]
    exit_code: StrictInt
    valid: StrictBool
    endpoint: int | None = None
    error: str | None = None
    http_code: int | None = None
    time_connect: float | None = None
    time_appconnect: float | None = None
    time_starttransfer: float | None = None
    time_total: float | None = None
    size_download: float | None = None
    size_upload: float | None = None
    speed_download: float | None = None
    speed_upload: float | None = None
    num_connects: int | None = None


class MeasurementContract(Model):
    protocol_version: Literal[1] = 1
    profile: Literal["ai", "video", "balanced"]
    limits: Limits
    download_endpoints: list[str] = Field(min_length=2)
    upload_endpoint: str
    ttfb_endpoint: str
    exit_endpoints: list[str] = Field(min_length=2, max_length=2)


class NetworkMeasurement(Model):
    measurement_version: Literal[1] = 1
    contract: MeasurementContract
    eligible: StrictBool
    complete: StrictBool
    exit_before: ExitResult
    exit_after: ExitResult | None = None
    reason: str | None = None
    ttfb_pairs: list[list[HTTPSample]] = Field(default_factory=list)
    single: list[HTTPSample] = Field(default_factory=list)
    parallel: list[HTTPSample] = Field(default_factory=list)
    upload: list[HTTPSample] = Field(default_factory=list)
    parallel_seconds: float | None = None
    parallel_mbps: float | None = None
    shapes: Limits | None = None
    download_endpoints: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    route: dict[str, Any] = Field(default_factory=dict)
    server_crosscheck: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def complete_samples(self):
        exits_ok = bool(self.exit_before.verified and self.exit_after and self.exit_after.verified)
        if self.eligible != exits_ok:
            raise ValueError("eligibility contradicts exit observations")
        if self.complete:
            limits = self.contract.limits
            counts = (len(self.ttfb_pairs) == limits.samples,
                      all(len(pair) == 2 for pair in self.ttfb_pairs),
                      len(self.single) == limits.samples * len(self.contract.download_endpoints),
                      len(self.parallel) == limits.concurrency, len(self.upload) == limits.samples)
            rows = self.single + self.parallel + self.upload + [r for pair in self.ttfb_pairs for r in pair]
            if not self.eligible or not all(counts) or not all(r.valid for r in rows):
                raise ValueError("complete measurement requires all expected valid samples and exits")
        if self.shapes and self.shapes != self.contract.limits:
            raise ValueError("measurement limits contradict contract")
        if self.download_endpoints and self.download_endpoints != self.contract.download_endpoints:
            raise ValueError("measurement endpoints contradict contract")
        return self


def result_schema():
    mapping, schema = models_json_schema([(m, "validation") for m in
                                         (RunResult, NetworkMeasurement, VerifyMeasurement)])
    schema.update(mapping[(RunResult, "validation")])
    stages = schema["$defs"]["RunResult"]["properties"]["stages"]
    stages["properties"] = {
        name: {"allOf": [{"$ref": "#/$defs/StageResult"}],
               "if": {"properties": {"data": {"required": ["measurement_version"]}},
                       "required": ["data"]},
               "then": {"properties": {"data": {"$ref": f"#/$defs/{model.__name__}"}}}}
        for name, model in [("network", NetworkMeasurement), ("verify", VerifyMeasurement)]
    }
    return schema
