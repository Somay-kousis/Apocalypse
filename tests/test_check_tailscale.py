import base64
import gzip
import json

from controls.junyi import check_tailscale
from tests.conftest import write


def clean_env():
    return "PATH=/usr/bin\nTS_AUTHKEY_MODE=ephemeral\nTS_AUTHKEY_EXPIRATION_HOURS=12\n"


def detection_sequence(workload="worker-1", vpn_delay_seconds=20):
    rows = [
        ("env_dump", "00:00:00", "00:00:05"),
        ("binary_stage", "00:01:00", "00:01:05"),
        ("imds_access", "00:02:00", "00:02:05"),
        ("vpn_binary_start", "00:03:00", f"00:03:{vpn_delay_seconds:02d}"),
    ]
    return "".join(
        json.dumps({
            "event": event,
            "workload_id": workload,
            "occurred_at": f"2026-07-12T{occurred}Z",
            "alerted_at": f"2026-07-12T{alerted}Z",
            "detected": True,
        }) + "\n"
        for event, occurred, alerted in rows
    )


def test_pass_when_no_key_and_detection_fired(tmp_path):
    write(tmp_path, "b8_tailscale", "worker_env.txt", clean_env())
    write(tmp_path, "b8_tailscale", "alert_log.jsonl", detection_sequence())
    res = check_tailscale.run(str(tmp_path))
    assert res.status == "PASS"


def test_fail_when_reusable_key_present(tmp_path):
    write(tmp_path, "b8_tailscale", "worker_env.txt",
          clean_env() + "TS_AUTHKEY=tskey-auth-abc123-REUSABLE0000000000000000\n")
    write(tmp_path, "b8_tailscale", "alert_log.jsonl", detection_sequence())
    res = check_tailscale.run(str(tmp_path))
    assert res.status == "FAIL"
    assert "authkey" in res.detail.lower()


def test_fail_when_key_clean_but_no_detection(tmp_path):
    """Adversarial case: worker env is clean, but there's no detection
    evidence at all - the control also requires proof startup is caught."""
    write(tmp_path, "b8_tailscale", "worker_env.txt", clean_env())
    write(tmp_path, "b8_tailscale", "alert_log.jsonl", "")
    res = check_tailscale.run(str(tmp_path))
    assert res.status == "FAIL"
    assert "vpn_binary_start" in res.detail


def test_fail_when_single_event_claims_sequence_matched(tmp_path):
    write(tmp_path, "b8_tailscale", "worker_env.txt", clean_env())
    write(
        tmp_path,
        "b8_tailscale",
        "alert_log.jsonl",
        '{"event":"vpn_binary_start","detected":true,"sequence_matched":true}\n',
    )
    res = check_tailscale.run(str(tmp_path))
    assert res.status == "FAIL"
    assert "no single workload" in res.detail


def test_fail_when_sequence_is_split_across_workloads(tmp_path):
    first = "\n".join(detection_sequence("worker-a").splitlines()[:2]) + "\n"
    second = "\n".join(detection_sequence("worker-b").splitlines()[2:]) + "\n"
    write(tmp_path, "b8_tailscale", "worker_env.txt", clean_env())
    write(tmp_path, "b8_tailscale", "alert_log.jsonl", first + second)
    res = check_tailscale.run(str(tmp_path))
    assert res.status == "FAIL"


def test_fail_when_vpn_alert_misses_sla(tmp_path):
    rows = detection_sequence().replace(
        '"alerted_at": "2026-07-12T00:03:20Z"',
        '"alerted_at": "2026-07-12T00:04:01Z"',
    )
    write(tmp_path, "b8_tailscale", "worker_env.txt", clean_env())
    write(tmp_path, "b8_tailscale", "alert_log.jsonl", rows)
    res = check_tailscale.run(str(tmp_path))
    assert res.status == "FAIL"
    assert "SLA" in res.detail


def test_fail_when_ephemeral_key_expiration_is_too_long(tmp_path):
    env = clean_env().replace("=12", "=876000")
    write(tmp_path, "b8_tailscale", "worker_env.txt", env)
    write(tmp_path, "b8_tailscale", "alert_log.jsonl", detection_sequence())
    res = check_tailscale.run(str(tmp_path))
    assert res.status == "FAIL"
    assert "EXPIRATION_HOURS" in res.detail


def test_fail_when_authkey_is_nested_base64_gzip(tmp_path):
    key = b"tskey-auth-abc123-REUSABLE0000000000000000"
    wrapped = base64.b64encode(base64.b64encode(gzip.compress(key))).decode()
    write(tmp_path, "b8_tailscale", "worker_env.txt", clean_env() + f"BLOB={wrapped}\n")
    write(tmp_path, "b8_tailscale", "alert_log.jsonl", detection_sequence())
    res = check_tailscale.run(str(tmp_path))
    assert res.status == "FAIL"
    assert "decoder-obfuscated" in res.detail


def test_fail_when_missing_files(tmp_path):
    res = check_tailscale.run(str(tmp_path))
    assert res.status == "FAIL"
