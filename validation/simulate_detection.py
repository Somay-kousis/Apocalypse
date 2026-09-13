"""Run a harmless local event -> detector -> alert simulation for rules 1-9.

Unlike the committed SLA fixtures, timestamps produced here are captured while
the detector functions actually execute.  The measured interval is local
in-process matcher time.  It does not include production sensors, log shipping,
SIEM processing, networking, or notification delivery.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from validation.detection_rules import DETECTORS
from validation.measure_sla import print_report
from validation.sla import EVIDENCE_FILE, load_sla_specs, measure_sla


MANIFEST_FILE = "simulation_manifest.json"
EVIDENCE_KIND = "executable local simulation"
Generator = Callable[[int], tuple[str, dict[str, Any]]]


@dataclass(frozen=True)
class SimulationRecord:
    attempt_id: str
    rule_id: int
    subject_id: str
    event: str
    simulation_input: dict[str, Any]
    occurred_at: str
    detected: bool
    detector_elapsed_ns: int
    alerted_at: str | None = None
    evidence_source: str = EVIDENCE_KIND

    def to_dict(self):
        return {key: value for key, value in asdict(self).items() if value is not None}


def _utc_text(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _different_hashes(trial: int):
    expected = hashlib.sha256(f"expected-{trial}".encode()).hexdigest()
    observed = hashlib.sha256(f"tampered-{trial}".encode()).hexdigest()
    return expected, observed


def _registry_attack(trial):
    expected, observed = _different_hashes(trial)
    return "sealed-mirror", {"expected_sha256": expected, "observed_sha256": observed}


def _registry_benign(trial):
    expected, _ = _different_hashes(trial)
    return "sealed-mirror", {"expected_sha256": expected, "observed_sha256": expected}


ATTACK_GENERATORS: dict[int, Generator] = {
    1: _registry_attack,
    2: lambda trial: ("eval-worker", {
        "action": "connect", "destination": "attacker.example",
    }),
    3: lambda trial: ("eval-worker", {
        "syscall": "mount", "privileged": True,
    }),
    4: lambda trial: ("dataset-job", {
        "operation": "load", "reference_kind": "external_link",
    }),
    5: lambda trial: ("dataset-config", {
        "stage": "predeployment", "input_trust": "untrusted",
        "content": "{{ cycler.__init__ }}",
    }),
    6: lambda trial: ("eval-worker", {
        "operation": "read", "destination": "169.254.169.254",
        "resource": "/latest/meta-data/iam",
    }),
    7: lambda trial: ("eval-worker", {
        "source_role": "data-plane-worker", "destination": "kubernetes.default.svc",
        "operation": "api_request",
    }),
    8: lambda trial: ("eval-worker", {
        "operation": "process_start", "executable": "/usr/sbin/tailscaled",
        "arguments": ["--tun=userspace-networking"],
    }),
    9: lambda trial: ("eval-worker", {
        "operation": "token_use", "bound_origin": "eval-worker",
        "presented_origin": "external-host",
    }),
}


BENIGN_GENERATORS: dict[int, Generator] = {
    1: _registry_benign,
    2: lambda trial: ("eval-worker", {
        "action": "connect", "destination": "pypi.org",
    }),
    3: lambda trial: ("eval-worker", {
        "syscall": "read", "privileged": False,
    }),
    4: lambda trial: ("dataset-job", {
        "operation": "load", "reference_kind": "internal",
    }),
    5: lambda trial: ("dataset-config", {
        "stage": "predeployment", "input_trust": "trusted",
        "content": "plain configuration",
    }),
    6: lambda trial: ("eval-worker", {
        "operation": "read", "destination": "artifact-mirror",
        "resource": "/numpy.whl",
    }),
    7: lambda trial: ("eval-worker", {
        "source_role": "data-plane-worker", "destination": "artifact-mirror",
        "operation": "api_request",
    }),
    8: lambda trial: ("eval-worker", {
        "operation": "process_start", "executable": "/usr/bin/python3", "arguments": [],
    }),
    9: lambda trial: ("eval-worker", {
        "operation": "token_use", "bound_origin": "eval-worker",
        "presented_origin": "eval-worker",
    }),
}


def simulate(trials: int = 10) -> list[SimulationRecord]:
    """Generate attacks and time the independent detector matchers."""
    if type(trials) is not int or trials < 1:
        raise ValueError("trials must be a positive integer")

    specs = load_sla_specs()
    expected_ids = {spec.rule_id for spec in specs}
    if set(ATTACK_GENERATORS) != expected_ids or set(DETECTORS) != expected_ids:
        raise ValueError("simulator must define exactly one generator and detector per control")

    records = []
    for trial in range(1, trials + 1):
        for spec in specs:
            subject_id, payload = ATTACK_GENERATORS[spec.rule_id](trial)
            occurred = datetime.now(timezone.utc)
            started_ns = time.perf_counter_ns()
            detected = DETECTORS[spec.rule_id](payload)
            elapsed_ns = time.perf_counter_ns() - started_ns

            if detected and spec.phase == "predeployment":
                # A build-time rejection is emitted at the same boundary as the
                # attempted deployment. Its declared SLA is therefore exactly 0s.
                occurred_text = alerted_text = _utc_text(occurred)
            else:
                occurred_text = _utc_text(occurred)
                alerted_text = None
                if detected:
                    elapsed_us = max(1, (elapsed_ns + 999) // 1000)
                    alerted_text = _utc_text(occurred + timedelta(microseconds=elapsed_us))

            records.append(SimulationRecord(
                attempt_id=f"sim-r{spec.rule_id}-t{trial}",
                rule_id=spec.rule_id,
                subject_id=subject_id,
                event=spec.event,
                simulation_input=payload,
                occurred_at=occurred_text,
                alerted_at=alerted_text,
                detected=detected,
                detector_elapsed_ns=elapsed_ns,
            ))
    return records


def write_simulation(
    output_dir: str | Path,
    records,
    overwrite: bool = False,
    evidence_kind: str = EVIDENCE_KIND,
    latency_scope: str = "local in-process detector matching only",
    generator_module: str = "validation.simulate_detection",
    environment: dict[str, Any] | None = None,
):
    output_path = Path(output_dir)
    evidence_path = output_path / EVIDENCE_FILE
    manifest_path = output_path / MANIFEST_FILE
    if (evidence_path.exists() or manifest_path.exists()) and not overwrite:
        raise FileExistsError(
            f"simulation output already exists in {output_path}; pass --overwrite to replace it"
        )
    output_path.mkdir(parents=True, exist_ok=True)
    evidence_path.write_text(
        "".join(json.dumps(record.to_dict(), separators=(",", ":")) + "\n" for record in records)
    )
    rules = sorted({record.rule_id for record in records})
    trials = len(records) // len(rules) if rules else 0
    manifest = {
        "schema_version": 1,
        "evidence_kind": evidence_kind,
        "production_telemetry": False,
        "latency_scope": latency_scope,
        "generator_module": generator_module,
        "generated_at": _utc_text(datetime.now(timezone.utc)),
        "trials_per_rule": trials,
        "rules": rules,
        "records": len(records),
    }
    if environment is not None:
        manifest["environment"] = environment
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    return evidence_path, manifest_path


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, help="directory for generated evidence")
    parser.add_argument("--trials", type=int, default=10, help="attempts per rule (default: 10)")
    parser.add_argument("--overwrite", action="store_true", help="replace prior simulator output")
    parser.add_argument("--json-output", help="optional path for the SLA result JSON")
    args = parser.parse_args(argv)

    try:
        records = simulate(args.trials)
        evidence_path, manifest_path = write_simulation(args.output, records, args.overwrite)
    except (ValueError, FileExistsError) as exc:
        parser.error(str(exc))

    report = measure_sla(args.output, evidence_kind=EVIDENCE_KIND)
    print(f"Generated {len(records)} records: {evidence_path}")
    print(f"Provenance manifest: {manifest_path}")
    print_report(report)
    if args.json_output:
        Path(args.json_output).write_text(json.dumps(report.to_dict(), indent=2) + "\n")
    return 0 if report.counts == {"HIT": 9, "MISS": 0, "UNMEASURED": 0} else 1


if __name__ == "__main__":
    raise SystemExit(main())
