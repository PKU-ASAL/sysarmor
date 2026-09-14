import unittest

from streaming.runtime.s3_init import _request


class S3InitTest(unittest.TestCase):
    def test_bucket_request_uses_sigv4_and_configured_endpoint(self):
        request = _request("http://rustfs:9000", "sysarmor", "sysarmor-secret", "sysarmor-flink")
        self.assertEqual("PUT", request.method)
        self.assertEqual("http://rustfs:9000/sysarmor-flink", request.full_url)
        self.assertIn("AWS4-HMAC-SHA256", request.headers["Authorization"])
        self.assertEqual("rustfs:9000", request.headers["Host"])


if __name__ == "__main__":
    unittest.main()
