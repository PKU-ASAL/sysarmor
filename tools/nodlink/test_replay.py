import json

from google.protobuf.json_format import MessageToDict

from packages.contracts.proto.signal.v1 import signal_pb2
from tests.test_analysis import causal_events
from tests.test_nodlink import model_signal
from tools.nodlink.replay import _rfc3339_ns, replay_files


def test_replay_files_runs_streaming_state_across_batches(tmp_path):
    events = tmp_path / "events.ndjson"
    signals = tmp_path / "signals.ndjson"
    output = tmp_path / "replay"
    write_documents(events, (
        wrapper("event", item, 100 + index)
        for index, item in enumerate(causal_events())
    ))
    candidates = (
        model_signal("p-curl", "exec-curl"),
        model_signal("p-bash", "exec-bash"),
    )
    write_documents(signals, (
        wrapper("signal", item, 200 + index) for index, item in enumerate(candidates)
    ))

    summary = replay_files(events, signals, output, batch_size=1)

    assert summary["input_events"] == 4
    assert summary["input_model_signals"] == 2
    assert summary["conclusions"] == 1
    assert summary["incidents"] == 1
    assert (output / "summary.json").is_file()
    conclusion = json.loads((output / "conclusions.ndjson").read_text().splitlines()[0])
    assert conclusion["tenant_id"] == "tenant-a"
    assert conclusion["agent_id"] == "agent-a"
    assert conclusion["signal"]["name"] == "nodlink_campaign"


def test_rfc3339_nanoseconds_are_exact_on_python_310():
    assert _rfc3339_ns("2026-09-06T14:02:10.689056163Z") == 1788703330689056163


def test_replay_summary_is_independent_of_batch_size(tmp_path):
    events = tmp_path / "events.ndjson"
    signals = tmp_path / "signals.ndjson"
    write_documents(events, (
        wrapper("event", item, 100 + index)
        for index, item in enumerate(causal_events())
    ))
    write_documents(signals, (
        wrapper("signal", item, 200 + index)
        for index, item in enumerate((
            model_signal("p-curl", "exec-curl"),
            model_signal("p-bash", "exec-bash"),
        ))
    ))

    small = replay_files(events, signals, tmp_path / "small", batch_size=1)
    large = replay_files(events, signals, tmp_path / "large", batch_size=256)

    assert small == large
    assert (tmp_path / "small/conclusions.ndjson").read_text() == (
        tmp_path / "large/conclusions.ndjson"
    ).read_text()


def test_replay_isolates_same_agent_id_across_tenants(tmp_path):
    events = tmp_path / "events.ndjson"
    signals = tmp_path / "signals.ndjson"
    first = wrapper("signal", model_signal("p-curl", "exec-curl"), 100)
    second = wrapper("signal", model_signal("p-bash", "exec-bash"), 101)
    second["tenantId"] = "tenant-b"
    write_documents(events, ())
    write_documents(signals, (first, second))

    summary = replay_files(events, signals, tmp_path / "output", batch_size=1)

    assert summary["campaigns"] == 2
    assert summary["conclusions"] == 0


def wrapper(kind, message, observed_ns):
    return {
        "tenantId": "tenant-a",
        "agentId": "agent-a",
        "sequence": str(observed_ns),
        "observedAtUnixNano": str(observed_ns),
        kind: MessageToDict(message, preserving_proto_field_name=False),
    }


def write_documents(path, documents):
    path.write_text("".join(json.dumps(item, sort_keys=True) + "\n" for item in documents))
