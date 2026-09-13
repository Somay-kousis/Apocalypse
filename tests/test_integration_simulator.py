import json
import os

import pytest

from validation.simulate_detection import MANIFEST_FILE
from validation.simulate_integration import EVIDENCE_KIND, PROBES, simulate_integration
from validation.simulate_detection import write_simulation
from validation.sla import measure_sla, parse_aware_timestamp


def test_integration_simulator_executes_all_nine_contained_probes(tmp_path):
    records = simulate_integration(trials=1)
    assert len(records) == 9
    assert set(PROBES) == {record.rule_id for record in records} == set(range(1, 10))
    assert all(record.detected is True for record in records)
    assert all(record.evidence_source == EVIDENCE_KIND for record in records)
    assert all(record.simulation_input["action"] for record in records)
    observer_pids = {record.simulation_input["observer_pid"] for record in records}
    assert len(observer_pids) == 1
    assert os.getpid() not in observer_pids
    assert all(parse_aware_timestamp(record.occurred_at) for record in records)
    assert all(parse_aware_timestamp(record.alerted_at) for record in records)


def test_integration_evidence_scores_and_discloses_limits(tmp_path):
    records = simulate_integration(trials=1)
    write_simulation(
        tmp_path,
        records,
        evidence_kind=EVIDENCE_KIND,
        latency_scope="contained integration test",
        generator_module="validation.simulate_integration",
        environment={"network_scope": "127.0.0.1 only"},
    )
    report = measure_sla(tmp_path, evidence_kind=EVIDENCE_KIND)
    manifest = json.loads((tmp_path / MANIFEST_FILE).read_text())

    assert report.counts == {"HIT": 9, "MISS": 0, "UNMEASURED": 0}
    assert manifest["production_telemetry"] is False
    assert manifest["environment"]["network_scope"] == "127.0.0.1 only"


@pytest.mark.parametrize("trials", [0, -1, True])
def test_integration_trials_must_be_positive_integer(trials):
    with pytest.raises(ValueError, match="positive integer"):
        simulate_integration(trials)
