import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class OpenSearchProjector:
    def __init__(self, base_url: str, timeout_seconds: float = 10.0, batch_size: int = 100):
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout_seconds
        self._batch_size = max(1, batch_size)
        self._batch = []

    def put(self, document: bytes) -> None:
        payload = json.loads(document)
        kind = payload.get("projection_kind")
        _index_for(kind)
        identity = payload.get("id", "").strip()
        if not identity:
            raise ValueError("projected document id is required")
        self._batch.append((kind, identity, document))
        if len(self._batch) >= self._batch_size:
            self.flush()

    def flush(self) -> None:
        if not self._batch:
            return
        lines = []
        for kind, identity, document in self._batch:
            lines.extend(
                (
                    json.dumps({"index": {"_index": _index_for(kind), "_id": identity}}),
                    document.decode(),
                )
            )
        request = Request(
            f"{self._base_url}/_bulk",
            data=("\n".join(lines) + "\n").encode(),
            method="POST",
            headers={"Content-Type": "application/x-ndjson"},
        )
        try:
            with urlopen(request, timeout=self._timeout) as response:
                if response.status < 200 or response.status >= 300:
                    raise RuntimeError(f"OpenSearch projection status {response.status}")
        except (HTTPError, URLError) as error:
            raise RuntimeError("OpenSearch projection request failed") from error
        self._batch.clear()

    def close(self) -> None:
        self.flush()


def _index_for(kind: str) -> str:
    if kind == "signal":
        return "sysarmor-signals-write"
    if kind == "incident":
        return "sysarmor-incidents-write"
    raise ValueError("unsupported projected document kind")
