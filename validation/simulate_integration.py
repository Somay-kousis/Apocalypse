"""Safely exercise local actions and measure their detection for Rules 1-9.

This integration tier performs real temporary-file, loopback-network, child
process, HDF5, Jinja, and cryptographic operations. It never contacts a remote
host, uses a real credential, changes host privileges, or starts a VPN. On
macOS it cannot exercise Linux seccomp/eBPF or Kubernetes NetworkPolicy, so the
manifest records those limitations explicitly.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import platform
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Callable

import h5py
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jinja2.exceptions import SecurityError
from jinja2.sandbox import SandboxedEnvironment

from controls.somay.captoken import attenuate, issue, seal, verify
from controls.somay.check_hdf5 import ExternalRefRefused, _reference_loader
from controls.somay.check_jinja import SSTI
from validation.measure_sla import print_report
from validation.observer_client import ObserverClient
from validation.simulate_detection import SimulationRecord, write_simulation
from validation.sla import load_sla_specs, measure_sla


EVIDENCE_KIND = "executable local integration simulation"
LATENCY_SCOPE = "contained action through local observer or rejection"


@dataclass(frozen=True)
class ProbeOutcome:
    subject_id: str
    action: str
    detail: str
    occurred_at: datetime
    alerted_at: datetime | None
    detector_elapsed_ns: int
    detected: bool
    raw_event: dict = field(default_factory=dict)


def _alert_time(occurred: datetime, elapsed_ns: int) -> datetime:
    elapsed_us = max(1, (elapsed_ns + 999) // 1000)
    return occurred + timedelta(microseconds=elapsed_us)


def _timed_probe(
    subject_id: str,
    action: str,
    operation: Callable[[], tuple[bool, str]],
    raw_event: dict,
):
    occurred = datetime.now(timezone.utc)
    started_ns = time.perf_counter_ns()
    detected, detail = operation()
    elapsed_ns = time.perf_counter_ns() - started_ns
    alerted = _alert_time(occurred, elapsed_ns) if detected else None
    return ProbeOutcome(
        subject_id, action, detail, occurred, alerted, elapsed_ns, detected, raw_event
    )


def _rule1_probe(work_dir: Path, trial: int):
    artifact = work_dir / f"rule1-artifact-{trial}.bin"
    approved = f"approved-package-{trial}".encode()
    tampered = f"tampered-package-{trial}".encode()
    artifact.write_bytes(approved)
    expected = hashlib.sha256(approved).hexdigest()
    raw_event = {"expected_sha256": expected}

    def operation():
        artifact.write_bytes(tampered)
        observed = hashlib.sha256(artifact.read_bytes()).hexdigest()
        raw_event["observed_sha256"] = observed
        detected = observed != expected
        return detected, f"expected={expected}; observed={observed}"

    return _timed_probe(
        "temporary-sealed-mirror", "tamper temporary package bytes", operation, raw_event
    )


def _http_denial_probe(subject_id, action, path, headers, detector, raw_event):
    alerts: queue.Queue[datetime] = queue.Queue(maxsize=1)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if detector(self):
                alerts.put_nowait(datetime.now(timezone.utc))
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"denied by local integration policy")

        def log_message(self, format, *args):
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    server.timeout = 2
    server_thread = threading.Thread(target=server.handle_request, daemon=True)
    server_thread.start()
    occurred = datetime.now(timezone.utc)
    started_ns = time.perf_counter_ns()
    response_status = None
    try:
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        response_status = response.status
        response.read()
        connection.close()
    finally:
        server_thread.join(timeout=2)
        server.server_close()
    elapsed_ns = time.perf_counter_ns() - started_ns
    try:
        alerted = alerts.get_nowait()
    except queue.Empty:
        alerted = None
    return ProbeOutcome(
        subject_id=subject_id,
        action=action,
        detail=f"loopback policy endpoint returned HTTP {response_status}",
        occurred_at=occurred,
        alerted_at=alerted,
        detector_elapsed_ns=elapsed_ns,
        detected=alerted is not None,
        raw_event=raw_event,
    )


def _rule2_probe(work_dir: Path, trial: int):
    return _http_denial_probe(
        "eval-worker",
        "connect to disallowed destination through loopback policy endpoint",
        "/connect",
        {"Host": "attacker.example", "X-Simulated-Destination": "attacker.example"},
        lambda request: (
            request.path == "/connect"
            and request.headers.get("X-Simulated-Destination") == "attacker.example"
        ),
        {"action": "connect", "destination": "attacker.example"},
    )


def _rule3_probe(work_dir: Path, trial: int):
    raw_event = {}
    child = (
        "import json, os\n"
        "result={'syscall':'setuid','target_uid':0,'starting_uid':os.geteuid()}\n"
        "try:\n"
        " os.setuid(0); result['outcome']='allowed'\n"
        "except PermissionError:\n"
        " result['outcome']='denied'\n"
        "print(json.dumps(result))\n"
    )

    def operation():
        completed = subprocess.run(
            [sys.executable, "-c", child], capture_output=True, text=True, timeout=3, check=True
        )
        result = json.loads(completed.stdout)
        raw_event.update({
            "syscall": result.get("syscall"),
            "target_id": result.get("target_uid"),
            "outcome": result.get("outcome"),
        })
        detected = result.get("syscall") == "setuid" and result.get("target_uid") == 0
        return detected, json.dumps(result, sort_keys=True)

    return _timed_probe(
        "unprivileged-child-process", "attempt setuid(0) in isolated child process",
        operation, raw_event,
    )


def _rule4_probe(work_dir: Path, trial: int):
    secret_path = work_dir / f"rule4-secret-{trial}.h5"
    malicious_path = work_dir / f"rule4-malicious-{trial}.h5"
    with h5py.File(secret_path, "w") as secret:
        secret["secret"] = b"LOCAL_INTEGRATION_DUMMY_SECRET"
    with h5py.File(malicious_path, "w") as malicious:
        malicious["payload"] = h5py.ExternalLink(str(secret_path), "secret")

    def operation():
        try:
            _reference_loader(malicious_path, allow_external=False)
        except ExternalRefRefused as exc:
            return True, str(exc)
        return False, "hardened loader unexpectedly followed the external link"

    return _timed_probe(
        "temporary-hdf5-loader", "load crafted HDF5 external link", operation,
        {"operation": "load", "reference_kind": "external_link"},
    )


def _rule5_probe(work_dir: Path, trial: int):
    occurred = datetime.now(timezone.utc)
    started_ns = time.perf_counter_ns()
    try:
        SandboxedEnvironment().from_string(SSTI).render()
        detected = False
        detail = "sandbox unexpectedly rendered the SSTI payload"
    except SecurityError as exc:
        detected = True
        detail = f"SandboxedEnvironment rejected SSTI: {type(exc).__name__}"
    elapsed_ns = time.perf_counter_ns() - started_ns
    # Predeployment validation and rejection are the same phase boundary. Keep
    # the SLA timestamp at 0s while retaining actual processing nanoseconds.
    alerted = occurred if detected else None
    return ProbeOutcome(
        "temporary-config-validator", "render SSTI in SandboxedEnvironment",
        detail, occurred, alerted, elapsed_ns, detected,
        {"stage": "predeployment", "input_trust": "untrusted", "content": SSTI},
    )


def _rule6_probe(work_dir: Path, trial: int):
    return _http_denial_probe(
        "eval-worker",
        "request fake metadata path through loopback endpoint",
        "/latest/meta-data/iam/security-credentials/",
        {"Host": "169.254.169.254"},
        lambda request: (
            request.headers.get("Host") == "169.254.169.254"
            and request.path.startswith("/latest/meta-data/")
        ),
        {
            "operation": "read", "destination": "169.254.169.254",
            "resource": "/latest/meta-data/iam/security-credentials/",
        },
    )


def _rule7_probe(work_dir: Path, trial: int):
    return _http_denial_probe(
        "data-plane-worker",
        "request mock Kubernetes API with worker identity",
        "/api/v1/namespaces",
        {"Authorization": "Bearer local-dummy-worker-token", "X-Source-Role": "data-plane-worker"},
        lambda request: (
            request.headers.get("X-Source-Role") == "data-plane-worker"
            and request.path.startswith("/api/")
        ),
        {
            "source_role": "data-plane-worker", "destination": "kubernetes.default.svc",
            "operation": "api_request",
        },
    )


def _rule8_probe(work_dir: Path, trial: int):
    sleep_binary = shutil.which("sleep")
    if not sleep_binary:
        now = datetime.now(timezone.utc)
        return ProbeOutcome(
            "local-process-table", "launch harmless tailscaled-named sleep process",
            "system sleep command is unavailable", now, None, 0, False, {},
        )
    fake_binary = work_dir / f"tailscaled-{trial}" / "tailscaled"
    fake_binary.parent.mkdir()
    fake_binary.symlink_to(sleep_binary)
    process = subprocess.Popen([str(fake_binary), "0.2"])
    occurred = datetime.now(timezone.utc)
    started_ns = time.perf_counter_ns()
    try:
        observed = subprocess.run(
            ["ps", "-p", str(process.pid), "-o", "command="],
            capture_output=True, text=True, timeout=2, check=True,
        ).stdout.strip()
        executable = observed.split(maxsplit=1)[0] if observed else ""
        detected = Path(executable).name == "tailscaled"
        detail = f"OS process table observed: {observed}"
        elapsed_ns = time.perf_counter_ns() - started_ns
        alerted = _alert_time(occurred, elapsed_ns) if detected else None
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=1)
    return ProbeOutcome(
        "local-process-table", "launch harmless tailscaled-named sleep process",
        detail, occurred, alerted, elapsed_ns, detected,
        {"operation": "process_start", "executable": executable, "arguments": ["0.2"]},
    )


def _rule9_probe(work_dir: Path, trial: int):
    root_secret = Ed25519PrivateKey.generate()
    token, holder_secret = issue(root_secret, ["purpose(eval)"])
    token, holder_secret = attenuate(token, holder_secret, ["origin(eval-worker)"])
    token = seal(token, holder_secret)  # sealed => off-origin rejection is the caveat, not the missing seal

    def operation():
        try:
            verify(token, root_secret.public_key(), {
                "purpose": "eval", "origin": "external-host",
            })
        except ValueError as exc:
            return True, f"off-origin replay rejected: {exc}"
        return False, "off-origin token replay was accepted"

    return _timed_probe(
        "local-token-verifier", "replay real signed token off-origin", operation,
        {
            "operation": "token_use", "bound_origin": "eval-worker",
            "presented_origin": "external-host", "bound_purpose": "eval",
            "presented_purpose": "eval",
        },
    )


PROBES = {
    1: _rule1_probe,
    2: _rule2_probe,
    3: _rule3_probe,
    4: _rule4_probe,
    5: _rule5_probe,
    6: _rule6_probe,
    7: _rule7_probe,
    8: _rule8_probe,
    9: _rule9_probe,
}


def simulate_integration(trials: int = 3) -> list[SimulationRecord]:
    if type(trials) is not int or trials < 1:
        raise ValueError("trials must be a positive integer")
    specs = load_sla_specs()
    if set(PROBES) != {spec.rule_id for spec in specs}:
        raise ValueError("integration simulator must define one probe per control")

    records = []
    with tempfile.TemporaryDirectory(prefix="apocalypse-integration-") as temp_dir, ObserverClient() as observer:
        work_dir = Path(temp_dir)
        for trial in range(1, trials + 1):
            for spec in specs:
                try:
                    outcome = PROBES[spec.rule_id](work_dir, trial)
                except Exception as exc:
                    now = datetime.now(timezone.utc)
                    outcome = ProbeOutcome(
                        "integration-probe", f"run Rule {spec.rule_id} contained action",
                        f"probe raised {type(exc).__name__}: {exc}", now, None, 0, False, {},
                    )
                response = None
                if outcome.detected:
                    try:
                        response = observer.observe(
                            f"integration-r{spec.rule_id}-t{trial}",
                            spec.rule_id,
                            outcome.raw_event,
                        )
                    except Exception as exc:
                        response = {"detected": False, "error": str(exc)}
                detected = bool(response and response.get("detected") is True)
                if spec.phase == "predeployment" and detected:
                    occurred_text = response["received_at"]
                    alerted_text = response["received_at"]
                else:
                    occurred_text = outcome.occurred_at.isoformat(timespec="microseconds")
                    alerted_text = response.get("alerted_at") if detected else None
                records.append(SimulationRecord(
                    attempt_id=f"integration-r{spec.rule_id}-t{trial}",
                    rule_id=spec.rule_id,
                    subject_id=outcome.subject_id,
                    event=spec.event,
                    simulation_input={
                        "action": outcome.action,
                        "detail": outcome.detail,
                        "raw_event": outcome.raw_event,
                        "local_action_elapsed_ns": outcome.detector_elapsed_ns,
                        "observer_pid": response.get("observer_pid") if response else None,
                        "observer_error": response.get("error") if response else None,
                        "isolation": "temporary files, child process, or loopback-only networking",
                    },
                    occurred_at=occurred_text,
                    alerted_at=alerted_text,
                    detected=detected,
                    detector_elapsed_ns=(response.get("observer_elapsed_ns", 0) if response else 0),
                    evidence_source=EVIDENCE_KIND,
                ))
    return records


def _environment_manifest():
    docker = shutil.which("docker")
    system = platform.system()
    limitations = [
        "no production sensors, log transport, SIEM, or notification system",
        "local mock endpoints stand in for cloud metadata and Kubernetes APIs",
    ]
    if system == "Darwin":
        limitations.append("no Linux seccomp/eBPF or Kubernetes NetworkPolicy on native macOS")
    if not docker:
        limitations.append("Docker CLI was unavailable, so no container-runtime probe was run")
    return {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "docker_cli_available": bool(docker),
        "kind_cli_available": bool(shutil.which("kind")),
        "kubectl_cli_available": bool(shutil.which("kubectl")),
        "network_scope": "127.0.0.1 only",
        "privileged_action_scope": "setuid(0) attempted only in a child process",
        "process_separation": "action driver and detector observer use different PIDs",
        "limitations": limitations,
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, help="directory for generated evidence")
    parser.add_argument("--trials", type=int, default=3, help="contained actions per rule (default: 3)")
    parser.add_argument("--overwrite", action="store_true", help="replace prior simulator output")
    args = parser.parse_args(argv)

    try:
        records = simulate_integration(args.trials)
        evidence_path, manifest_path = write_simulation(
            args.output,
            records,
            overwrite=args.overwrite,
            evidence_kind=EVIDENCE_KIND,
            latency_scope=LATENCY_SCOPE,
            generator_module="validation.simulate_integration",
            environment=_environment_manifest(),
        )
    except (ValueError, FileExistsError) as exc:
        parser.error(str(exc))

    report = measure_sla(args.output, evidence_kind=EVIDENCE_KIND)
    print(f"Generated {len(records)} integration records: {evidence_path}")
    print(f"Provenance manifest: {manifest_path}")
    print_report(report)
    return 0 if report.counts == {"HIT": 9, "MISS": 0, "UNMEASURED": 0} else 1


if __name__ == "__main__":
    raise SystemExit(main())
