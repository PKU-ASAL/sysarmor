"""Create missing seed policies; never overwrite an existing policy version."""

import json
import sys
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


def request_policy(url, token, document=None):
    data = None if document is None else json.dumps(document).encode()
    request = Request(url, data=data, headers={
        "Authorization": f"Bearer {token}", "Content-Type": "application/json",
    })
    try:
        with urlopen(request, timeout=30) as response:
            return json.load(response)
    except HTTPError as error:
        body = error.read().decode(errors="replace")
        if error.code == 404 and document is None:
            return None
        raise RuntimeError(f"policy request HTTP {error.code}: {body}") from error


def policy_content(document):
    content = {key: value for key, value in document.items()
               if key not in {"created_at", "updated_at", "published"}}
    collection = dict(content.get("collection", {}))
    # The Manager's collection decoder drops the legacy observe_only=true field.
    if collection.get("observe_only") is True:
        collection.pop("observe_only")
    content["collection"] = collection
    return content


def ensure_policy(desired, token, base_url="http://127.0.0.1:9443"):
    if not token:
        raise ValueError("Manager JWT is required")
    endpoint = base_url.rstrip("/") + "/api/v1/policies"
    query = urlencode({"policy_id": desired["policy_id"], "version": desired["version"]})
    existing = request_policy(endpoint + "?" + query, token)
    if existing is None:
        existing = request_policy(endpoint, token, desired)
    if not isinstance(existing, dict) or not isinstance(existing.get("published"), bool):
        raise ValueError("invalid seed policy response")
    if policy_content(existing) != policy_content(desired):
        raise ValueError(f"seed policy content conflict: {desired['policy_id']}@{desired['version']}")
    return existing


def main():
    try:
        with open(sys.argv[1]) as source:
            desired = json.load(source)
        result = ensure_policy(desired, sys.stdin.readline().strip())
        print(json.dumps(result, sort_keys=True))
    except (OSError, ValueError, RuntimeError) as error:
        print(f"[managed-enrollment][ERROR] {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
