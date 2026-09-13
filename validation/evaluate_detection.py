"""Evaluate the independent observer against attack and benign variants."""
from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from validation.measure_sla import print_report
from validation.observer_client import ObserverClient
from validation.simulate_detection import SimulationRecord, write_simulation
from validation.sla import load_sla_specs, measure_sla


EVIDENCE_KIND = "independent observer adversarial evaluation"
CLASSIFICATION_FILE = "classification_events.jsonl"


@dataclass(frozen=True)
class DetectionCase:
    rule_id: int
    name: str
    expected_detected: bool
    payload: dict


@dataclass
class RuleQuality:
    rule_id: int
    true_positive: int = 0
    false_positive: int = 0
    false_negative: int = 0
    true_negative: int = 0

    @property
    def status(self):
        return "PASS" if self.false_positive == self.false_negative == 0 else "FAIL"


def _hash(text):
    return hashlib.sha256(text.encode()).hexdigest()


def build_cases() -> list[DetectionCase]:
    expected = _hash("approved")
    observed = _hash("tampered")
    return [
        DetectionCase(1, "changed package bytes", True, {
            "expected_sha256": expected, "observed_sha256": observed,
        }),
        DetectionCase(1, "uppercase hash mismatch", True, {
            "expected_sha256": expected.upper(), "observed_sha256": observed.upper(),
        }),
        DetectionCase(1, "matching package bytes", False, {
            "expected_sha256": expected, "observed_sha256": expected,
        }),
        DetectionCase(1, "matching uppercase hashes", False, {
            "expected_sha256": expected.upper(), "observed_sha256": expected.upper(),
        }),
        DetectionCase(2, "external hostname", True, {
            "action": "connect", "destination": "attacker.example",
        }),
        DetectionCase(2, "allowlist-lookalike hostname", True, {
            "action": "connect", "destination": "pypi.org.attacker.example",
        }),
        DetectionCase(2, "allowed pypi", False, {
            "action": "connect", "destination": "pypi.org",
        }),
        DetectionCase(2, "allowed package files", False, {
            "action": "connect", "destination": "files.pythonhosted.org",
        }),
        DetectionCase(3, "privileged mount", True, {
            "syscall": "mount", "privileged": True,
        }),
        DetectionCase(3, "setuid root", True, {
            "syscall": "setuid", "target_id": 0,
        }),
        DetectionCase(3, "ordinary read", False, {
            "syscall": "read", "privileged": False,
        }),
        DetectionCase(3, "setuid non-root", False, {
            "syscall": "setuid", "target_id": 1000,
        }),
        DetectionCase(4, "HDF5 external link", True, {
            "operation": "load", "reference_kind": "external_link",
        }),
        DetectionCase(4, "HDF5 external storage", True, {
            "operation": "load", "reference_kind": "external_storage",
        }),
        DetectionCase(4, "internal dataset", False, {
            "operation": "load", "reference_kind": "internal",
        }),
        DetectionCase(4, "ordinary dataset write", False, {
            "operation": "write", "reference_kind": "internal",
        }),
        DetectionCase(5, "Jinja expression", True, {
            "stage": "predeployment", "input_trust": "untrusted",
            "content": "{{ cycler.__init__ }}",
        }),
        DetectionCase(5, "Jinja statement", True, {
            "stage": "predeployment", "input_trust": "untrusted",
            "content": "{% for x in values %}{{ x }}{% endfor %}",
        }),
        DetectionCase(5, "plain untrusted data", False, {
            "stage": "predeployment", "input_trust": "untrusted", "content": "key: value",
        }),
        DetectionCase(5, "trusted template", False, {
            "stage": "predeployment", "input_trust": "trusted", "content": "{{ approved }}",
        }),
        DetectionCase(6, "metadata endpoint", True, {
            "operation": "connect", "destination": "169.254.169.254",
        }),
        DetectionCase(6, "service-account token", True, {
            "operation": "read", "resource": "/var/run/secrets/kubernetes.io/serviceaccount/token",
        }),
        DetectionCase(6, "artifact mirror", False, {
            "operation": "connect", "destination": "artifact-mirror",
        }),
        DetectionCase(6, "ordinary configuration", False, {
            "operation": "read", "resource": "/workspace/config.yaml",
        }),
        DetectionCase(7, "worker core API request", True, {
            "source_role": "data-plane-worker", "destination": "kubernetes.default.svc",
            "operation": "api_request",
        }),
        DetectionCase(7, "worker APIs request", True, {
            "source_role": "data-plane-worker", "destination": "kubernetes.default.svc",
            "operation": "api_request", "path": "/apis/apps/v1/deployments",
        }),
        DetectionCase(7, "control-plane API request", False, {
            "source_role": "control-plane", "destination": "kubernetes.default.svc",
            "operation": "api_request",
        }),
        DetectionCase(7, "worker artifact request", False, {
            "source_role": "data-plane-worker", "destination": "artifact-mirror",
            "operation": "api_request",
        }),
        DetectionCase(8, "tailscaled executable", True, {
            "operation": "process_start", "executable": "/usr/sbin/tailscaled", "arguments": [],
        }),
        DetectionCase(8, "renamed userspace VPN process", True, {
            "operation": "process_start", "executable": "/tmp/vpn-helper",
            "arguments": ["--tun=userspace-networking", "--socks5-server=:1055"],
        }),
        DetectionCase(8, "ordinary Python process", False, {
            "operation": "process_start", "executable": "/usr/bin/python3", "arguments": [],
        }),
        DetectionCase(8, "ordinary sleep process", False, {
            "operation": "process_start", "executable": "/bin/sleep", "arguments": ["1"],
        }),
        DetectionCase(9, "origin mismatch", True, {
            "operation": "token_use", "bound_origin": "eval-worker",
            "presented_origin": "external-host", "bound_purpose": "eval",
            "presented_purpose": "eval",
        }),
        DetectionCase(9, "purpose mismatch", True, {
            "operation": "token_use", "bound_origin": "eval-worker",
            "presented_origin": "eval-worker", "bound_purpose": "eval",
            "presented_purpose": "admin",
        }),
        DetectionCase(9, "matching origin and purpose", False, {
            "operation": "token_use", "bound_origin": "eval-worker",
            "presented_origin": "eval-worker", "bound_purpose": "eval",
            "presented_purpose": "eval",
        }),
        DetectionCase(9, "ordinary non-token request", False, {
            "operation": "read", "resource": "/healthz",
        }),
    ]


def evaluate_cases(cases=None):
    cases = build_cases() if cases is None else list(cases)
    specs = {spec.rule_id: spec for spec in load_sla_specs()}
    quality = {rule_id: RuleQuality(rule_id) for rule_id in specs}
    attack_records = []
    classification_records = []

    with ObserverClient() as observer:
        observer_pid = None
        for index, case in enumerate(cases, 1):
            request_id = f"quality-r{case.rule_id}-c{index}"
            occurred = datetime.now(timezone.utc).isoformat(timespec="microseconds")
            response = observer.observe(request_id, case.rule_id, case.payload)
            observer_pid = response.get("observer_pid")
            detected = response["detected"]
            bucket = quality[case.rule_id]
            if case.expected_detected and detected:
                bucket.true_positive += 1
            elif case.expected_detected and not detected:
                bucket.false_negative += 1
            elif not case.expected_detected and detected:
                bucket.false_positive += 1
            else:
                bucket.true_negative += 1

            classification_records.append({
                "case_id": request_id,
                "rule_id": case.rule_id,
                "name": case.name,
                "expected_detected": case.expected_detected,
                "detected": detected,
                "payload": case.payload,
                "occurred_at": occurred,
                "alerted_at": response.get("alerted_at"),
                "observer_pid": observer_pid,
            })
            if case.expected_detected:
                spec = specs[case.rule_id]
                if spec.phase == "predeployment" and detected:
                    sla_occurred = response["received_at"]
                    sla_alerted = response["received_at"]
                else:
                    sla_occurred = occurred
                    sla_alerted = response.get("alerted_at")
                attack_records.append(SimulationRecord(
                    attempt_id=request_id,
                    rule_id=case.rule_id,
                    subject_id="adversarial-observer-evaluation",
                    event=spec.event,
                    simulation_input={"case": case.name, "payload": case.payload},
                    occurred_at=sla_occurred,
                    alerted_at=sla_alerted,
                    detected=detected,
                    detector_elapsed_ns=response.get("observer_elapsed_ns", 0),
                    evidence_source=EVIDENCE_KIND,
                ))
    return attack_records, classification_records, quality, observer_pid


def write_evaluation(output_dir, attack_records, classification_records, quality, overwrite=False):
    output_path = Path(output_dir)
    classification_path = output_path / CLASSIFICATION_FILE
    if classification_path.exists() and not overwrite:
        raise FileExistsError(
            f"evaluation output already exists in {output_path}; pass --overwrite to replace it"
        )
    evidence_path, manifest_path = write_simulation(
        output_path,
        attack_records,
        overwrite=overwrite,
        evidence_kind=EVIDENCE_KIND,
        latency_scope="generator timestamp through separate observer process",
        generator_module="validation.evaluate_detection",
        environment={"process_separation": "generator and detector use different PIDs"},
    )
    classification_path.write_text(
        "".join(json.dumps(record, separators=(",", ":")) + "\n" for record in classification_records)
    )
    manifest = json.loads(manifest_path.read_text())
    manifest["classification"] = {
        "cases": len(classification_records),
        "attack_cases": sum(record["expected_detected"] for record in classification_records),
        "benign_cases": sum(not record["expected_detected"] for record in classification_records),
        "rules": {str(rule_id): asdict(result) | {"status": result.status}
                  for rule_id, result in quality.items()},
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    return evidence_path, classification_path, manifest_path


def print_quality(quality):
    print("\n=== Independent observer detection quality ===")
    print("  Rule  TP  FN  FP  TN  Status")
    for rule_id in sorted(quality):
        result = quality[rule_id]
        print(
            f"  {rule_id:>4}  {result.true_positive:>2}  {result.false_negative:>2}  "
            f"{result.false_positive:>2}  {result.true_negative:>2}  {result.status}"
        )
    totals = {
        name: sum(getattr(result, name) for result in quality.values())
        for name in ("true_positive", "false_negative", "false_positive", "true_negative")
    }
    print(
        f"\n  {totals['true_positive']} TP, {totals['false_negative']} FN, "
        f"{totals['false_positive']} FP, {totals['true_negative']} TN"
    )


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, help="directory for evaluation evidence")
    parser.add_argument("--overwrite", action="store_true", help="replace prior evaluation output")
    args = parser.parse_args(argv)

    try:
        attacks, classifications, quality, _ = evaluate_cases()
        evidence_path, classification_path, manifest_path = write_evaluation(
            args.output, attacks, classifications, quality, args.overwrite
        )
    except (ValueError, FileExistsError, RuntimeError) as exc:
        parser.error(str(exc))

    print(f"Attack evidence: {evidence_path}")
    print(f"Classification evidence: {classification_path}")
    print(f"Provenance manifest: {manifest_path}")
    print_quality(quality)
    report = measure_sla(args.output, evidence_kind=EVIDENCE_KIND)
    print_report(report)
    quality_ok = all(result.status == "PASS" for result in quality.values())
    sla_ok = report.counts == {"HIT": 9, "MISS": 0, "UNMEASURED": 0}
    return 0 if quality_ok and sla_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
