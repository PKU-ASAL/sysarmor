"""Execute the real capture function without a VM."""

import json
from pathlib import Path
import subprocess

import pytest


def snapshot(created, spooled, accepted, duplicate):
    return {"detection": {"learning": {"candidates": {
        "created": str(created), "spooled": str(spooled),
        "gatewayAccepted": str(accepted), "gatewayDuplicateAck": str(duplicate),
    }}}, "localStore": {"latestEventSequence": "100"}}


def capture(tmp_path, before, final):
    if before is not None:
        (tmp_path / "candidate-lifecycle-before.json").write_text(json.dumps(before))
    source = tmp_path / "health.json"
    source.write_text(json.dumps(final))
    output = tmp_path / "candidate-lifecycle-final.json"
    script = Path(__file__).with_name("run.sh").read_text()
    functions = script[script.index("capture_final_candidate_lifecycle() {"):
                       script.index("query_manager_metrics() {")]
    result = subprocess.run(["bash", "-c", functions + '''
AGENT_MODE=managed PROTECTION_MODE=hybrid AGENT_SOCK=/unused
vagrant() { cat "$health_source"; }
health_source="$1"
capture_final_candidate_lifecycle "$2"
''', "test", str(source), str(output)], capture_output=True, text=True)
    return result, json.loads(output.read_text())


def test_capture_preserves_raw_and_separates_duplicate_ack(tmp_path):
    final = snapshot(78, 78, 78, 76)
    result, output = capture(tmp_path, snapshot(15, 10, 5, 6), final)
    assert result.returncode == 0, result.stderr
    counters = output["detection"]["learning"]["candidates"]
    for key, value in final["detection"]["learning"]["candidates"].items():
        assert counters[key] == value
    assert [counters[key] for key in ("createdDelta", "spooledDelta",
                                     "acceptedUniqueDelta", "duplicateAckDelta")] == [63, 68, 73, 70]


@pytest.mark.parametrize("before", [None, snapshot(90, 90, 90, 90)])
def test_missing_baseline_or_counter_reset_fails(tmp_path, before):
    result, _ = capture(tmp_path, before, snapshot(78, 78, 78, 76))
    assert result.returncode != 0
    assert "failed to freeze" in result.stderr
