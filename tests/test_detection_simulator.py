import json

import pytest

from validation.simulate_detection import (
    ATTACK_GENERATORS,
    BENIGN_GENERATORS,
    DETECTORS,
    EVIDENCE_KIND,
    MANIFEST_FILE,
    simulate,
    write_simulation,
)
from validation.sla import EVIDENCE_FILE, measure_sla, parse_aware_timestamp


def test_every_attack_matches_and_benign_event_does_not():
    assert set(ATTACK_GENERATORS) == set(BENIGN_GENERATORS) == set(DETECTORS) == set(range(1, 10))
    for rule_id, detector in DETECTORS.items():
        _, attack = ATTACK_GENERATORS[rule_id](1)
        _, benign = BENIGN_GENERATORS[rule_id](1)
        assert detector(attack) is True
        assert detector(benign) is False


def test_simulator_generates_unique_measured_records_for_every_rule():
    records = simulate(trials=3)
    assert len(records) == 27
    assert len({record.attempt_id for record in records}) == 27
    assert {record.rule_id for record in records} == set(range(1, 10))
    assert all(record.detected is True for record in records)
    assert all(record.simulation_input for record in records)
    assert all(record.detector_elapsed_ns >= 0 for record in records)
    assert all(parse_aware_timestamp(record.occurred_at) for record in records)
    assert all(parse_aware_timestamp(record.alerted_at) for record in records)


def test_generated_evidence_scores_all_rules_and_records_provenance(tmp_path):
    records = simulate(trials=2)
    write_simulation(tmp_path, records)

    report = measure_sla(tmp_path, evidence_kind=EVIDENCE_KIND)
    manifest = json.loads((tmp_path / MANIFEST_FILE).read_text())
    evidence = [json.loads(line) for line in (tmp_path / EVIDENCE_FILE).read_text().splitlines()]

    assert report.counts == {"HIT": 9, "MISS": 0, "UNMEASURED": 0}
    assert report.evidence_kind == EVIDENCE_KIND
    assert manifest["production_telemetry"] is False
    assert manifest["trials_per_rule"] == 2
    assert manifest["records"] == len(evidence) == 18
    rule5 = next(result for result in report.results if result.rule_id == 5)
    assert rule5.latencies_seconds == [0.0, 0.0]


def test_simulator_refuses_accidental_overwrite(tmp_path):
    records = simulate(trials=1)
    write_simulation(tmp_path, records)
    with pytest.raises(FileExistsError, match="--overwrite"):
        write_simulation(tmp_path, records)


@pytest.mark.parametrize("trials", [0, -1, True])
def test_trials_must_be_a_positive_integer(trials):
    with pytest.raises(ValueError, match="positive integer"):
        simulate(trials)
