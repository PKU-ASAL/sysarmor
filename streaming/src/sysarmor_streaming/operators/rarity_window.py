from dataclasses import dataclass

from packages.contracts.proto.streaming.v1 import streaming_pb2

from sysarmor_streaming.operators.rarity import workload_key


DEFAULT_BASELINE_WINDOW_NS = 86_400_000_000_000
MAX_RARITY_OBSERVATIONS = 100_000


@dataclass(frozen=True, order=True)
class RarityObservation:
    observed_ns: int
    expires_ns: int
    workload: str
    signal: str


class RarityWindow:
    def __init__(self, max_observations=MAX_RARITY_OBSERVATIONS):
        self._observations = []
        self._max_observations = max_observations

    def process(self, record, policy):
        result = streaming_pb2.NormalizedTelemetry()
        result.CopyFrom(record)
        if result.WhichOneof("payload") != "signal":
            return result
        observed_ns = result.context.observed_at_unix_nano
        window_ns = policy.detection.rarity.baseline_window_ns or DEFAULT_BASELINE_WINDOW_NS
        self.cleanup(observed_ns)
        signal = result.signal
        name = signal.name.strip() or signal.id.strip()
        workload = workload_key(signal)
        count = self._count(workload, name)
        signal.global_rarity = (signal.global_rarity or 1) / (count + 1)
        if name:
            self._observations.append(
                RarityObservation(observed_ns, observed_ns + window_ns, workload, name)
            )
            self._observations = sorted(self._observations)[-self._max_observations :]
        return result

    def restore(self, observations) -> None:
        self._observations = sorted(observations)[-self._max_observations :]

    def observations(self):
        return tuple(self._observations)

    def observation_count(self) -> int:
        return len(self._observations)

    def next_expiry_ns(self) -> int:
        return min((item.expires_ns for item in self._observations), default=0)

    def cleanup(self, timestamp_ns: int) -> None:
        self._observations = [
            item for item in self._observations if item.expires_ns > timestamp_ns
        ]

    def _count(self, workload: str, signal: str) -> int:
        local = sum(
            item.signal == signal and item.workload == workload
            for item in self._observations
        )
        if local or workload == "global":
            return local
        return sum(item.signal == signal for item in self._observations)
