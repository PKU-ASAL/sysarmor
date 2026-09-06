"""Idempotently create the S3 bucket used by Flink state storage."""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import os
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


def _request(endpoint: str, access: str, secret: str, bucket: str) -> Request:
    host = urlsplit(endpoint.rstrip("/")).netloc
    path = "/" + bucket
    now = dt.datetime.now(dt.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    short_date = now.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(b"").hexdigest()
    headers = f"host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n"
    signed = "host;x-amz-content-sha256;x-amz-date"
    canonical = f"PUT\n{path}\n\n{headers}\n{signed}\n{payload_hash}"
    scope = f"{short_date}/us-east-1/s3/aws4_request"
    string_to_sign = f"AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{hashlib.sha256(canonical.encode()).hexdigest()}"
    key = hmac.new(("AWS4" + secret).encode(), short_date.encode(), hashlib.sha256).digest()
    for part in (b"us-east-1", b"s3", b"aws4_request"):
        key = hmac.new(key, part, hashlib.sha256).digest()
    signature = hmac.new(key, string_to_sign.encode(), hashlib.sha256).hexdigest()
    authorization = f"AWS4-HMAC-SHA256 Credential={access}/{scope}, SignedHeaders={signed}, Signature={signature}"
    request = Request(endpoint.rstrip("/") + path, data=b"", method="PUT")
    request.add_header("Host", host)
    request.add_header("X-Amz-Date", amz_date)
    request.add_header("X-Amz-Content-Sha256", payload_hash)
    request.add_header("Authorization", authorization)
    return request


def main() -> None:
    endpoint = os.environ.get("S3_ENDPOINT", "http://rustfs:9000")
    request = _request(endpoint, os.environ.get("S3_ACCESS_KEY", "sysarmor"), os.environ.get("S3_SECRET_KEY", "sysarmor-secret"), os.environ.get("S3_BUCKET", "sysarmor-flink"))
    try:
        with urlopen(request, timeout=10) as response:
            if response.status not in (200, 201, 204):
                raise RuntimeError(f"bucket creation returned HTTP {response.status}")
    except Exception as error:
        if "HTTP Error 409" not in str(error):
            raise


if __name__ == "__main__":
    main()
