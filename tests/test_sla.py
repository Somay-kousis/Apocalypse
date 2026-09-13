import json
from pathlib import Path

from validation.sla import EVIDENCE_FILE, calculate_latency_seconds, measure_sla


ROOT = Path(__file__).resolve().parent.parent


def observation(
    rule_id=1,
    attempt_id="attempt-1",
    event="mirror_hash_mismatch",
    occurred_at="2026-07-12T00:00:00Z",
    alerted_at="2026-07-12T00:00:10Z",
    detected=True,
):
    record = {
        "attempt_id": attempt_id,
        "rule_id": rule_id,
        "subject_id": "subject-1",
        "event": event,
        "occurred_at": occurred_at,
        "detected": detected,
    }
    if alerted_at is not None:
        record["alerted_at"] = alerted_at
    return record


def write_events(tmp_path, records):
    lines = [record if isinstance(record, str) else json.dumps(record) for record in records]
    (tmp_path / EVIDENCE_FILE).write_text("\n".join(lines) + "\n")


def result_for(report, rule_id):
    return next(result for result in report.results if result.rule_id == rule_id)


def test_on_time_and_boundary_time_are_hits(tmp_path):
    write_events(tmp_path, [
        observation(attempt_id="early", alerted_at="2026-07-12T00:00:10Z"),
        observation(attempt_id="boundary", alerted_at="2026-07-12T00:01:00Z"),
    ])
    result = result_for(measure_sla(tmp_path), 1)
    assert result.status == "HIT"
    assert result.latencies_seconds == [10.0, 60.0]


def test_one_late_observation_makes_whole_rule_miss(tmp_path):
    write_events(tmp_path, [
        observation(attempt_id="early"),
        observation(attempt_id="late", alerted_at="2026-07-12T00:01:01Z"),
    ])
    result = result_for(measure_sla(tmp_path), 1)
    assert result.status == "MISS"
    assert "exceeds" in result.detail


def test_undetected_and_missing_alert_are_misses(tmp_path):
    write_events(tmp_path, [
        observation(attempt_id="undetected", detected=False, alerted_at=None),
        observation(attempt_id="missing-alert", alerted_at=None),
    ])
    result = result_for(measure_sla(tmp_path), 1)
    assert result.status == "MISS"
    assert "not detected" in result.detail or "missing alerted_at" in result.detail


def test_missing_evidence_is_unmeasured(tmp_path):
    report = measure_sla(tmp_path)
    assert report.counts == {"HIT": 0, "MISS": 0, "UNMEASURED": 9}


def test_malformed_json_fails_closed_for_every_rule(tmp_path):
    write_events(tmp_path, ['{"attempt_id":"broken"'])
    report = measure_sla(tmp_path)
    assert report.counts == {"HIT": 0, "MISS": 9, "UNMEASURED": 0}
    assert report.evidence_errors


def test_duplicate_attempt_id_marks_both_rules_miss(tmp_path):
    write_events(tmp_path, [
        observation(attempt_id="duplicate"),
        observation(
            rule_id=2,
            attempt_id="duplicate",
            event="egress_denied",
            alerted_at="2026-07-12T00:00:10Z",
        ),
    ])
    report = measure_sla(tmp_path)
    assert result_for(report, 1).status == "MISS"
    assert result_for(report, 2).status == "MISS"


def test_wrong_event_type_is_a_miss(tmp_path):
    write_events(tmp_path, [observation(event="package_ok")])
    result = result_for(measure_sla(tmp_path), 1)
    assert result.status == "MISS"
    assert "expected event" in result.detail


def test_negative_latency_is_a_miss(tmp_path):
    write_events(tmp_path, [observation(
        occurred_at="2026-07-12T00:00:02Z",
        alerted_at="2026-07-12T00:00:01Z",
    )])
    result = result_for(measure_sla(tmp_path), 1)
    assert result.status == "MISS"
    assert "precedes" in result.detail


def test_timezone_free_timestamp_is_a_miss(tmp_path):
    write_events(tmp_path, [observation(
        occurred_at="2026-07-12T00:00:00",
        alerted_at="2026-07-12T00:00:10",
    )])
    result = result_for(measure_sla(tmp_path), 1)
    assert result.status == "MISS"
    assert "UTC offset" in result.detail


def test_strict_detected_boolean(tmp_path):
    record = observation()
    record["detected"] = "true"
    write_events(tmp_path, [record])
    result = result_for(measure_sla(tmp_path), 1)
    assert result.status == "MISS"
    assert "boolean" in result.detail


def test_latency_utility_rejects_negative_and_accepts_offsets():
    assert calculate_latency_seconds(
        "2026-07-12T00:00:00+00:00", "2026-07-12T00:01:00+00:00"
    ) == 60.0


def test_committed_lab_fixtures_have_expected_outcomes():
    fixed = measure_sla(ROOT / "environments/fixed_lab/configs")
    broken = measure_sla(ROOT / "environments/broken_lab/configs")
    exploit = measure_sla(ROOT / "environments/exploit_lab/configs")
    adversarial = measure_sla(ROOT / "environments/adversarial_lab/configs")

    assert fixed.counts == {"HIT": 9, "MISS": 0, "UNMEASURED": 0}
    assert broken.counts == {"HIT": 0, "MISS": 9, "UNMEASURED": 0}
    assert exploit.counts == {"HIT": 0, "MISS": 9, "UNMEASURED": 0}
    assert adversarial.counts == {"HIT": 0, "MISS": 9, "UNMEASURED": 0}
    assert result_for(fixed, 8).latencies_seconds == [24.0]
