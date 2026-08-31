import hashlib
import json

from google.protobuf import json_format


def signal_digest(signals, context=()) -> str:
    encoded = [_canonical_signal(signal) for signal in signals]
    payload = {"context": sorted(context), "signals": sorted(encoded)}
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _canonical_signal(signal) -> str:
    value = json_format.MessageToDict(
        signal, preserving_proto_field_name=True, including_default_value_fields=True
    )
    for field in ("entities", "event_refs", "signal_refs", "context_refs", "ioc_refs"):
        if field in value:
            value[field] = sorted(
                value[field], key=lambda item: json.dumps(item, sort_keys=True)
            )
    return json.dumps(value, sort_keys=True, separators=(",", ":"))
