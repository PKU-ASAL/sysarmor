import json
import threading
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class OpenSearchProjector:
    def __init__(
        self,
        base_url: str,
        timeout_seconds: float = 10.0,
        batch_size: int = 100,
        flush_interval_seconds: float = 0.5,
    ):
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout_seconds
        self._batch_size = max(1, batch_size)
        self._batch = []
        self._lock = threading.Lock()
        self._closed = False
        self._error = None
        self._stop = threading.Event()
        self._flush_interval = max(0.01, flush_interval_seconds)
        self._thread = threading.Thread(target=self._flush_loop, daemon=True)
        self._thread.start()

    def __getstate__(self):
        return {
            "_base_url": self._base_url,
            "_timeout": self._timeout,
            "_batch_size": self._batch_size,
            "_batch": self._batch,
            "_flush_interval": self._flush_interval,
        }

    def __setstate__(self, state):
        self._base_url = state["_base_url"]
        self._timeout = state["_timeout"]
        self._batch_size = state["_batch_size"]
        self._batch = state["_batch"]
        self._flush_interval = state["_flush_interval"]
        self._lock = threading.Lock()
        self._closed = False
        self._error = None
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._flush_loop, daemon=True)
        self._thread.start()

    def put(self, document: bytes) -> None:
        payload = json.loads(document)
        kind = payload.get("projection_kind")
        _index_for(kind)
        identity = payload.get("id", "").strip()
        if not identity:
            raise ValueError("projected document id is required")
        with self._lock:
            self._raise_error()
            if self._closed:
                raise RuntimeError("OpenSearch projector is closed")
            self._batch.append((kind, identity, document))
            should_flush = len(self._batch) >= self._batch_size
        if should_flush:
            self.flush()

    def flush(self) -> None:
        with self._lock:
            self._raise_error()
            batch, self._batch = self._batch, []
        if not batch:
            return
        lines = []
        for kind, identity, document in batch:
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
        except (HTTPError, URLError, RuntimeError) as error:
            with self._lock:
                self._batch = batch + self._batch
                self._error = error
            raise RuntimeError("OpenSearch projection request failed") from error

    def close(self) -> None:
        self.flush()
        with self._lock:
            self._closed = True
        self._stop.set()
        self._thread.join(timeout=self._flush_interval * 2)

    def _flush_loop(self) -> None:
        while not self._stop.wait(self._flush_interval):
            try:
                self.flush()
            except RuntimeError:
                return

    def _raise_error(self) -> None:
        if self._error is not None:
            raise RuntimeError("OpenSearch projection request failed") from self._error


def _index_for(kind: str) -> str:
    if kind == "signal":
        return "sysarmor-signals-write"
    if kind == "incident":
        return "sysarmor-incidents-write"
    raise ValueError("unsupported projected document kind")
