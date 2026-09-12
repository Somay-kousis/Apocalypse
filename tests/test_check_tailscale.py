from controls.junyi import check_tailscale
from tests.conftest import write


def test_pass_when_no_key_and_detection_fired(tmp_path):
    write(tmp_path, "b8_tailscale", "worker_env.txt", "PATH=/usr/bin\n")
    write(tmp_path, "b8_tailscale", "alert_log.jsonl",
          '{"event": "vpn_binary_start", "detected": true, "sequence_matched": true}\n')
    res = check_tailscale.run(str(tmp_path))
    assert res.status == "PASS"


def test_fail_when_reusable_key_present(tmp_path):
    write(tmp_path, "b8_tailscale", "worker_env.txt",
          "TS_AUTHKEY=tskey-auth-abc123-REUSABLE0000000000000000\n")
    write(tmp_path, "b8_tailscale", "alert_log.jsonl",
          '{"event": "vpn_binary_start", "detected": true, "sequence_matched": true}\n')
    res = check_tailscale.run(str(tmp_path))
    assert res.status == "FAIL"
    assert "authkey" in res.detail.lower()


def test_fail_when_key_clean_but_no_detection(tmp_path):
    """Adversarial case: worker env is clean, but there's no detection
    evidence at all - the control also requires proof startup is caught."""
    write(tmp_path, "b8_tailscale", "worker_env.txt", "PATH=/usr/bin\n")
    write(tmp_path, "b8_tailscale", "alert_log.jsonl", "")
    res = check_tailscale.run(str(tmp_path))
    assert res.status == "FAIL"
    assert "vpn_binary_start" in res.detail


def test_fail_when_missing_files(tmp_path):
    res = check_tailscale.run(str(tmp_path))
    assert res.status == "FAIL"
