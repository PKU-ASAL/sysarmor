import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class OpenSearchProjector:
    def __init__(self, base_url: str, timeout_seconds: float = 10.0):
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout_seconds

    def put(self, document: bytes) -> None:
        payload = json.loads(document)
        kind = payload.get("projection_kind")
        index = _index_for(kind)
        identity = payload.get("id", "").strip()
        if not identity:
            raise ValueError("projected document id is required")
        request = Request(
            f"{self._base_url}/{index}/_doc/{identity}",
            data=document,
            method="PUT",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urlopen(request, timeout=self._timeout) as response:
                if response.status < 200 or response.status >= 300:
                    raise RuntimeError(f"OpenSearch projection status {response.status}")
        except (HTTPError, URLError) as error:
            raise RuntimeError("OpenSearch projection request failed") from error


def _index_for(kind: str) -> str:
    if kind == "signal":
        return "sysarmor-signals-write"
    if kind == "incident":
        return "sysarmor-incidents-write"
    raise ValueError("unsupported projected document kind")
