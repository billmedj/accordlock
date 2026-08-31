import hashlib
import json
import struct
import unittest

from accordlock_demos.canonical import (
    canonical_json_bytes,
    json_digest,
    length_prefixed_domain_digest,
)


class CanonicalProfileTests(unittest.TestCase):
    def test_recursively_sorts_compact_utf8_json(self) -> None:
        value = {"z": 1, "a": {"é": "✓", "b": [3, {"y": 2, "a": 1}]}}
        self.assertEqual(
            canonical_json_bytes(value),
            '{"a":{"b":[3,{"a":1,"y":2}],"é":"✓"},"z":1}'.encode(),
        )

    def test_plain_and_length_prefixed_digests_are_distinct_and_reproducible(self) -> None:
        value = {"schema_version": 2, "value": "fixed"}
        encoded = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
        expected_plain = f"sha256:{hashlib.sha256(encoded).hexdigest()}"
        domain = b"accordlock:test"
        expected_domain = f"sha256:{hashlib.sha256(domain + bytes([0]) + struct.pack('>Q', len(encoded)) + encoded).hexdigest()}"
        self.assertEqual(json_digest(value), expected_plain)
        self.assertEqual(length_prefixed_domain_digest(domain, value), expected_domain)
        self.assertNotEqual(expected_plain, expected_domain)


if __name__ == "__main__":
    unittest.main()
