"""Offline detection-SLA measurement over committed JSONL evidence.

These measurements validate the repository's fixture evidence. They do not
claim production sensor or wall-clock performance.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Literal

import yaml


ROOT = Path(__file__).resolve().parent.parent
SPEC_PATH = ROOT / "controls" / "control_spec.yaml"
EVIDENCE_FILE = "detection_events.jsonl"
SlaStatus = Literal["HIT", "MISS", "UNMEASURED"]


@dataclass(frozen=True)
class SlaSpec:
    rule_id: int
    name: str
    event: str
    target_seconds: int
    phase: str


@dataclass(frozen=True)
class Observation:
    attempt_id: str
    rule_id: int
    subject_id: str
    event: str
    occurred_at: str
    alerted_at: str | None
    detected: bool


@dataclass
class SlaResult:
    rule_id: int
    name: str
    event: str
    phase: str
    target_seconds: int
    status: SlaStatus
    attempts: int = 0
    latencies_seconds: list[float] = field(default_factory=list)
    detail: str = ""

    def to_dict(self):
        return asdict(self)


@dataclass
class SlaReport:
    target: str
    evidence_kind: str
    results: list[SlaResult]
    evidence_errors: list[str] = field(default_factory=list)

    @property
    def counts(self):
        return {
            status: sum(result.status == status for result in self.results)
            for status in ("HIT", "MISS", "UNMEASURED")
        }

    def to_dict(self):
        return {
            "target": self.target,
            "evidence_kind": self.evidence_kind,
            "counts": self.counts,
            "evidence_errors": self.evidence_errors,
            "results": [result.to_dict() for result in self.results],
        }


def parse_aware_timestamp(value, field_name="timestamp") -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field_name} is not valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field_name} must include a UTC offset")
    return parsed


def calculate_latency_seconds(occurred_at, alerted_at) -> float:
    occurred = parse_aware_timestamp(occurred_at, "occurred_at")
    alerted = parse_aware_timestamp(alerted_at, "alerted_at")
    latency = (alerted - occurred).total_seconds()
    if latency < 0:
        raise ValueError("alerted_at precedes occurred_at")
    return latency


def load_sla_specs(spec_path: Path = SPEC_PATH) -> list[SlaSpec]:
    controls = yaml.safe_load(spec_path.read_text())["controls"]
    specs = []
    for control in controls:
        rule_id = control.get("id")
        event = control.get("detection_event")
        target = control.get("detection_sla_seconds")
        phase = control.get("detection_phase")
        if type(rule_id) is not int:
            raise ValueError(f"control has invalid id: {rule_id!r}")
        if not isinstance(event, str) or not event:
            raise ValueError(f"rule {rule_id} has no detection_event")
        if type(target) is not int or target < 0:
            raise ValueError(f"rule {rule_id} has invalid detection_sla_seconds")
        if phase not in {"package pull", "predeployment", "runtime"}:
            raise ValueError(f"rule {rule_id} has invalid detection_phase")
        specs.append(SlaSpec(rule_id, control["name"], event, target, phase))
    return specs


def _parse_observation(raw, line_number, known_rules):
    prefix = f"line {line_number}"
    if not isinstance(raw, dict):
        return None, None, f"{prefix}: record must be a JSON object"

    rule_id = raw.get("rule_id")
    if type(rule_id) is not int or rule_id not in known_rules:
        return None, None, f"{prefix}: rule_id must identify a configured control"

    errors = []
    for field_name in ("attempt_id", "subject_id", "event", "occurred_at"):
        if not isinstance(raw.get(field_name), str) or not raw[field_name]:
            errors.append(f"{field_name} must be a non-empty string")
    if type(raw.get("detected")) is not bool:
        errors.append("detected must be a boolean")
    alerted_at = raw.get("alerted_at")
    if alerted_at is not None and not isinstance(alerted_at, str):
        errors.append("alerted_at must be a string when present")
    if raw.get("detected") is True and not alerted_at:
        errors.append("detected event is missing alerted_at")

    if errors:
        return None, rule_id, f"{prefix}: " + "; ".join(errors)

    return Observation(
        attempt_id=raw["attempt_id"],
        rule_id=rule_id,
        subject_id=raw["subject_id"],
        event=raw["event"],
        occurred_at=raw["occurred_at"],
        alerted_at=alerted_at,
        detected=raw["detected"],
    ), rule_id, None


def measure_sla(
    target: str | Path,
    spec_path: Path = SPEC_PATH,
    evidence_kind: str = "synthetic fixture",
) -> SlaReport:
    target_path = Path(target)
    specs = load_sla_specs(spec_path)
    known_rules = {spec.rule_id for spec in specs}
    evidence_path = target_path / EVIDENCE_FILE

    if not evidence_path.is_file():
        return SlaReport(
            target=str(target_path),
            evidence_kind=evidence_kind,
            results=[
                SlaResult(
                    spec.rule_id, spec.name, spec.event, spec.phase,
                    spec.target_seconds, "UNMEASURED", detail="no detection evidence file",
                )
                for spec in specs
            ],
        )

    observations = []
    errors_by_rule = {rule_id: [] for rule_id in known_rules}
    global_errors = []
    for line_number, line in enumerate(evidence_path.read_text().splitlines(), 1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            global_errors.append(f"line {line_number}: invalid JSON")
            continue
        observation, rule_id, error = _parse_observation(raw, line_number, known_rules)
        if error:
            if rule_id in known_rules:
                errors_by_rule[rule_id].append(error)
            else:
                global_errors.append(error)
            continue
        observations.append(observation)

    attempt_rules = {}
    for observation in observations:
        if observation.attempt_id in attempt_rules:
            first_rule = attempt_rules[observation.attempt_id]
            message = f"duplicate attempt_id {observation.attempt_id!r}"
            errors_by_rule[first_rule].append(message)
            errors_by_rule[observation.rule_id].append(message)
        else:
            attempt_rules[observation.attempt_id] = observation.rule_id

    grouped = {rule_id: [] for rule_id in known_rules}
    for observation in observations:
        grouped[observation.rule_id].append(observation)

    results = []
    for spec in specs:
        rule_observations = grouped[spec.rule_id]
        rule_errors = list(errors_by_rule[spec.rule_id])
        latencies = []
        misses = []

        for observation in rule_observations:
            if observation.event != spec.event:
                misses.append(
                    f"attempt {observation.attempt_id}: expected event {spec.event!r}, "
                    f"got {observation.event!r}"
                )
                continue
            try:
                parse_aware_timestamp(observation.occurred_at, "occurred_at")
            except ValueError as exc:
                misses.append(f"attempt {observation.attempt_id}: {exc}")
                continue
            if not observation.detected:
                misses.append(f"attempt {observation.attempt_id}: event was not detected")
                continue
            try:
                latency = calculate_latency_seconds(
                    observation.occurred_at, observation.alerted_at
                )
            except ValueError as exc:
                misses.append(f"attempt {observation.attempt_id}: {exc}")
                continue
            latencies.append(latency)
            if latency > spec.target_seconds:
                misses.append(
                    f"attempt {observation.attempt_id}: {latency:g}s exceeds "
                    f"{spec.target_seconds}s target"
                )

        if global_errors:
            status = "MISS"
            detail_parts = ["evidence file has global structural errors"]
        elif rule_errors or misses:
            status = "MISS"
            detail_parts = rule_errors + misses
        elif not rule_observations:
            status = "UNMEASURED"
            detail_parts = ["no observation for this rule"]
        else:
            status = "HIT"
            detail_parts = [
                f"{len(rule_observations)} attempt(s); worst latency {max(latencies):g}s"
            ]

        results.append(SlaResult(
            rule_id=spec.rule_id,
            name=spec.name,
            event=spec.event,
            phase=spec.phase,
            target_seconds=spec.target_seconds,
            status=status,
            attempts=len(rule_observations),
            latencies_seconds=latencies,
            detail="; ".join(detail_parts),
        ))

    return SlaReport(
        target=str(target_path),
        evidence_kind=evidence_kind,
        results=results,
        evidence_errors=global_errors,
    )
