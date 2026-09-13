import json
import os

import pytest

from validation.evaluate_detection import (
    CLASSIFICATION_FILE,
    build_cases,
    evaluate_cases,
    write_evaluation,
)
from validation.simulate_detection import MANIFEST_FILE
from validation.observer_client import ObserverClient
from validation.sla import measure_sla


def test_quality_matrix_covers_attack_and_benign_variants_for_every_rule():
    cases = build_cases()
    for rule_id in range(1, 10):
        rule_cases = [case for case in cases if case.rule_id == rule_id]
        assert len(rule_cases) == 4
        assert sum(case.expected_detected for case in rule_cases) == 2
        assert sum(not case.expected_detected for case in rule_cases) == 2


def test_independent_observer_has_no_false_results_and_meets_sla(tmp_path):
    attacks, classifications, quality, observer_pid = evaluate_cases()
    assert observer_pid != os.getpid()
    assert all(result.status == "PASS" for result in quality.values())
    assert sum(result.true_positive for result in quality.values()) == 18
    assert sum(result.true_negative for result in quality.values()) == 18
    assert sum(result.false_positive for result in quality.values()) == 0
    assert sum(result.false_negative for result in quality.values()) == 0

    write_evaluation(tmp_path, attacks, classifications, quality)
    report = measure_sla(tmp_path)
    manifest = json.loads((tmp_path / MANIFEST_FILE).read_text())
    recorded = (tmp_path / CLASSIFICATION_FILE).read_text().splitlines()
    assert report.counts == {"HIT": 9, "MISS": 0, "UNMEASURED": 0}
    assert len(recorded) == 36
    assert manifest["classification"]["attack_cases"] == 18
    assert manifest["classification"]["benign_cases"] == 18


def test_observer_fails_closed_on_unknown_rule():
    with ObserverClient() as observer:
        with pytest.raises(RuntimeError, match="configured detector"):
            observer.observe("unknown-rule", 99, {})
