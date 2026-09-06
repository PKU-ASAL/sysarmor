class Baseline:
    def __init__(self, workload_counts=None):
        self.workload_counts = {
            workload: dict(counts)
            for workload, counts in (workload_counts or {}).items()
        }

    def count(self, workload: str, signal: str) -> int:
        count = self.workload_counts.get(workload, {}).get(signal, 0)
        if count:
            return count
        return self.workload_counts.get("global", {}).get(signal, 0)

    def add(self, workload: str, signal: str, count: int = 1) -> None:
        workload = workload.strip() or "global"
        signal = signal.strip()
        if not signal or count <= 0:
            return
        values = self.workload_counts.setdefault(workload, {})
        values[signal] = values.get(signal, 0) + count

    def observe(self, signals) -> None:
        for signal in signals:
            key = signal.name.strip() or signal.id.strip()
            if not key:
                continue
            workload = workload_key(signal)
            self.add(workload, key)
            if workload != "global":
                self.add("global", key)

    def snapshot(self):
        return Baseline(self.workload_counts)


def count_score(signals) -> float:
    counts = {}
    score = 0.0
    ordered = sorted(
        signals,
        key=lambda signal: (
            signal.name,
            signal.id,
            signal.base_risk,
            signal.global_rarity,
            signal.SerializeToString(deterministic=True),
        ),
    )
    for signal in ordered:
        key = signal.name.strip() or signal.id.strip()
        counts[key] = counts.get(key, 0) + 1
        score += signal.base_risk * signal_rarity(signal) / counts[key]
    return score


def workload_score(signals, baseline: Baseline) -> float:
    return sum(
        signal.base_risk
        * signal_rarity(signal)
        * workload_rarity(baseline, signal)
        for signal in signals
    )


def workload_rarity(baseline: Baseline, signal) -> float:
    count = baseline.count(workload_key(signal), signal.name.strip() or signal.id.strip())
    return 1 if count == 0 else 1 / (count + 1)


def signal_rarity(signal) -> float:
    return signal.global_rarity or 1


def workload_key(signal) -> str:
    for kind in ("pod", "container", "host", "user"):
        for entity in signal.entities:
            if entity.kind == kind and entity.key:
                prefix = f"{kind}:"
                key = entity.key.removeprefix(prefix)
                return prefix + key
    if signal.labels.get("workload"):
        return "workload:" + signal.labels["workload"]
    if signal.labels.get("scenario"):
        return "scenario:" + signal.labels["scenario"]
    return "global"
