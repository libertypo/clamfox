#!/usr/bin/env python3
"""
ClamFox Security Test Suite (Python)

Tests for critical security functions in the native host:
- YARA rule validation
- Timestamp validation  
- Process pool management
- Error message filtering
"""

import unittest
import time
import re
import hashlib
import json
import os
import concurrent.futures
from unittest.mock import patch, MagicMock


class YaraValidationTests(unittest.TestCase):
    """Test YARA rule validation function"""

    def validate_yara_rule_safety(self, rule_content):
        """Mock of validate_yara_rule_safety from clamav_engine.py"""
        MAX_RULE_SIZE = 1024 * 1024  # 1MB per rule
        if len(rule_content) > MAX_RULE_SIZE:
            raise ValueError(f"Rule exceeds size limit: {len(rule_content)} > {MAX_RULE_SIZE}")
        
        dangerous_patterns = [
            r'entrypoint',
            r'filesize',
            r'import\s+"',
            r'all\s+of\s+them',
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, rule_content, re.IGNORECASE):
                raise ValueError(f"Dangerous pattern detected: {pattern}")
        
        return hashlib.sha256(rule_content.encode()).hexdigest()

    def test_accept_safe_rule(self):
        """Should accept and hash safe YARA rules"""
        safe_rule = """
            rule ExampleRule {
                strings:
                    $a = "test"
                condition:
                    $a
            }
        """
        hash_result = self.validate_yara_rule_safety(safe_rule)
        self.assertEqual(len(hash_result), 64)  # SHA256 hex is 64 chars
        self.assertRegex(hash_result, r'^[a-f0-9]{64}$')

    def test_reject_oversized_rule(self):
        """Should reject rules exceeding 1MB"""
        oversized_rule = "x" * (1024 * 1024 + 1)
        with self.assertRaises(ValueError) as ctx:
            self.validate_yara_rule_safety(oversized_rule)
        self.assertIn("exceeds size limit", str(ctx.exception))

    def test_reject_entrypoint_pattern(self):
        """Should reject 'entrypoint' pattern"""
        bad_rule = """
            rule Bad {
                strings:
                    $a = "test"
                condition:
                    $a at entrypoint
            }
        """
        with self.assertRaises(ValueError) as ctx:
            self.validate_yara_rule_safety(bad_rule)
        self.assertIn("Dangerous", str(ctx.exception))

    def test_reject_filesize_pattern(self):
        """Should reject 'filesize' pattern"""
        bad_rule = """
            rule SizeBomb {
                condition:
                    filesize > 1000000
            }
        """
        with self.assertRaises(ValueError) as ctx:
            self.validate_yara_rule_safety(bad_rule)
        self.assertIn("Dangerous", str(ctx.exception))

    def test_reject_all_of_them_pattern(self):
        """Should reject 'all of them' pattern"""
        bad_rule = """
            rule MultiMatch {
                strings:
                    $a = "test"
                    $b = "bad"
                condition:
                    all of them
            }
        """
        with self.assertRaises(ValueError) as ctx:
            self.validate_yara_rule_safety(bad_rule)
        self.assertIn("Dangerous", str(ctx.exception))

    def test_reject_import_pattern(self):
        """Should reject 'import' pattern"""
        bad_rule = """
            import "pe"
            rule WithImport {
                strings:
                    $a = "test"
                condition:
                    $a
            }
        """
        with self.assertRaises(ValueError) as ctx:
            self.validate_yara_rule_safety(bad_rule)
        self.assertIn("Dangerous", str(ctx.exception))

    def test_consistent_hash_output(self):
        """Same rule should always produce same hash"""
        rule = "rule Test { strings: $a = \"x\" condition: $a }"
        hash1 = self.validate_yara_rule_safety(rule)
        hash2 = self.validate_yara_rule_safety(rule)
        self.assertEqual(hash1, hash2)


class TimestampValidationTests(unittest.TestCase):
    """Test timestamp validation function"""

    def validate_message_timestamp(self, timestamp, max_drift_seconds=60):
        """Mock of validate_message_timestamp from clamav_engine.py"""
        current_time = time.time()
        drift = abs(current_time - timestamp)
        
        if drift > max_drift_seconds:
            raise ValueError(f"Message timestamp invalid (drift: {drift:.1f}s > {max_drift_seconds}s)")
        
        return True

    def test_accept_current_timestamp(self):
        """Should accept current timestamp"""
        current = time.time()
        result = self.validate_message_timestamp(current)
        self.assertTrue(result)

    def test_accept_timestamp_within_drift(self):
        """Should accept timestamp within acceptable drift"""
        current = time.time()
        thirty_seconds_ago = current - 30
        result = self.validate_message_timestamp(thirty_seconds_ago)
        self.assertTrue(result)

    def test_reject_timestamp_outside_drift(self):
        """Should reject timestamp outside acceptable drift"""
        current = time.time()
        two_minutes_ago = current - 120
        with self.assertRaises(ValueError) as ctx:
            self.validate_message_timestamp(two_minutes_ago, max_drift_seconds=60)
        self.assertIn("drift", str(ctx.exception))

    def test_reject_future_timestamp(self):
        """Should reject timestamp in future"""
        current = time.time()
        future = current + 120
        with self.assertRaises(ValueError) as ctx:
            self.validate_message_timestamp(future, max_drift_seconds=60)
        self.assertIn("drift", str(ctx.exception))

    def test_custom_drift_threshold(self):
        """Should respect custom drift threshold"""
        current = time.time()
        ninety_seconds_ago = current - 90
        
        # Should fail with 60s threshold
        with self.assertRaises(ValueError):
            self.validate_message_timestamp(ninety_seconds_ago, max_drift_seconds=60)
        
        # Should pass with 120s threshold
        result = self.validate_message_timestamp(ninety_seconds_ago, max_drift_seconds=120)
        self.assertTrue(result)

    def test_boundary_conditions(self):
        """Should handle boundary conditions correctly (using patched time to avoid race)."""
        # Patch time.time() so our "current" value stays constant during checks
        fixed_now = 1_700_000_000.0  # arbitrary timestamp
        with patch('time.time', return_value=fixed_now):
            # Exactly at threshold should pass
            exactly_at_threshold = fixed_now - 60
            result = self.validate_message_timestamp(exactly_at_threshold, max_drift_seconds=60)
            self.assertTrue(result)

            # Just beyond threshold should fail
            just_beyond = fixed_now - 61
            with self.assertRaises(ValueError):
                self.validate_message_timestamp(just_beyond, max_drift_seconds=60)


class ErrorMessageFilteringTests(unittest.TestCase):
    """Test error message safety and information filtering"""

    def safe_error_response(self, error, context):
        """Mock of createSafeErrorResponse from background.js"""
        error_map = {
            'ENOENT': 'File not found',
            'EACCES': 'Permission denied',
            'ETIMEDOUT': 'Request timed out',
            'ECONNREFUSED': 'Service unavailable'
        }
        
        # Generic message for users
        user_message = error_map.get(getattr(error, 'code', None), 'An error occurred')
        
        return {
            'status': 'error',
            'error': user_message,
            'code': getattr(error, 'code', None)
        }

    def test_filter_filesystem_paths(self):
        """Should not leak filesystem paths in error messages"""
        class MockError:
            code = 'ENOENT'
            message = '/home/user/.clamfox_quarantine/malware.exe not found'
        
        response = self.safe_error_response(MockError(), 'file_scan')
        self.assertEqual(response['error'], 'File not found')
        self.assertNotIn('/home/user', response['error'])

    def test_filter_python_stack_traces(self):
        """Should not leak Python stack traces"""
        class MockError:
            code = None
            message = 'Traceback (most recent call last):\n  File "clamav_engine.py" line 123\nNameError: undefined'
        
        response = self.safe_error_response(MockError(), 'scan')
        self.assertEqual(response['error'], 'An error occurred')
        self.assertNotIn('Traceback', response['error'])
        self.assertNotIn('NameError', response['error'])

    def test_filter_internal_state(self):
        """Should not leak internal program state"""
        class MockError:
            code = None
            message = 'SESSION_HOST_SECRET mismatch detected'
        
        response = self.safe_error_response(MockError(), 'auth')
        self.assertNotIn('SESSION_HOST_SECRET', response['error'])
        self.assertNotIn('secret', response['error'].lower())

    def test_preserve_useful_error_codes(self):
        """Should preserve helpful error codes"""
        class MockError:
            code = 'ETIMEDOUT'
        
        response = self.safe_error_response(MockError(), 'network')
        self.assertEqual(response['code'], 'ETIMEDOUT')
        self.assertEqual(response['error'], 'Request timed out')


class IntegrationTests(unittest.TestCase):
    """Integration tests combining multiple security functions"""

    def test_yara_then_timestamp_validation(self):
        """Should validate both YARA rules and timestamps"""
        # This would test the full flow: receive rule, validate timestamp, sanitize rule
        pass

    def test_error_handling_consistency(self):
        """Error messages should be consistent across different code paths"""
        pass


class NativeMessageFuzzTests(unittest.TestCase):
    """Fuzz-style tests for malformed native message payloads."""

    def validate_native_response(self, action, response):
        """Minimal schema validation similar to background.js logic."""
        if not isinstance(response, dict):
            raise ValueError("Invalid response format")

        if action in ["scan", "scan_request"] and response.get("status") == "malicious":
            threat = response.get("threat")
            if not isinstance(threat, str) or len(threat) > 256:
                raise ValueError("Invalid threat identifier")

        return True

    def test_reject_malformed_native_responses(self):
        malformed_responses = [
            None,
            "not-an-object",
            ["array-is-invalid"],
            {"status": "malicious", "threat": "x" * 300},
            {"status": "malicious", "threat": 123},
        ]

        for response in malformed_responses:
            with self.assertRaises(ValueError):
                self.validate_native_response("scan", response)

    def test_replay_window_rejects_stale_timestamp(self):
        now = time.time()
        stale = now - 300  # 5 minutes ago

        def validate_message_timestamp(timestamp, max_drift_seconds=60):
            drift = abs(time.time() - timestamp)
            if drift > max_drift_seconds:
                raise ValueError("Message timestamp invalid")
            return True

        with self.assertRaises(ValueError):
            validate_message_timestamp(stale, max_drift_seconds=60)


class ProcessPoolRecoveryTests(unittest.TestCase):
    """Tests for timeout cancellation and process-pool recovery behavior."""

    def test_timeout_cancels_pending_future(self):
        class FakeFuture:
            def __init__(self):
                self.cancelled = False

            def result(self, timeout=None):
                raise concurrent.futures.TimeoutError()

            def cancel(self):
                self.cancelled = True

            def done(self):
                return False

        future = FakeFuture()
        futures = [future]

        for f in futures:
            try:
                f.result(timeout=1)
            except concurrent.futures.TimeoutError:
                f.cancel()

        self.assertTrue(future.cancelled)

    def test_broken_pool_triggers_recreation(self):
        class FakePool:
            def __init__(self, broken=False):
                self._broken = broken

        state = {"pool": FakePool(broken=True), "recreated": False}

        def get_pool():
            if getattr(state["pool"], "_broken", False):
                state["pool"] = FakePool(broken=False)
                state["recreated"] = True
            return state["pool"]

        pool = get_pool()
        self.assertTrue(state["recreated"])
        self.assertFalse(pool._broken)


class CVERegressionCatalogTests(unittest.TestCase):
    """Validate CVE catalog quality and execute mapped regression checks."""

    CATALOG_FILE = os.path.join(os.path.dirname(__file__), "cve_catalog.json")

    def _reject_non_object_native_response(self, response):
        if not isinstance(response, dict):
            raise ValueError("Invalid response format")
        return True

    def _url_scan_should_skip(self, has_temp_bypass, is_user_whitelisted):
        # Mirrors hardened logic in background.js: cookie-name presence is not trusted.
        return bool(has_temp_bypass or is_user_whitelisted)

    def _reject_malformed_stream_payload(self, response):
        if not isinstance(response, dict):
            raise ValueError("Invalid response format")
        if response.get("status") == "malicious":
            threat = response.get("threat")
            if not isinstance(threat, str) or len(threat) > 256:
                raise ValueError("Invalid threat identifier")
        return True

    def _cve_test_registry(self):
        return {
            "test_cve_2025_1234": lambda: self.assertRaises(ValueError, self._reject_non_object_native_response, []),
            "test_cve_local_2026_0001": lambda: self.assertFalse(
                self._url_scan_should_skip(has_temp_bypass=False, is_user_whitelisted=False)
            ),
            "test_cve_local_2026_0002": lambda: self.assertRaises(
                ValueError,
                self._reject_malformed_stream_payload,
                {"status": "malicious", "threat": "x" * 300},
            ),
        }

    def _load_catalog(self):
        with open(self.CATALOG_FILE, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def test_catalog_has_required_fields(self):
        catalog = self._load_catalog()
        self.assertIsInstance(catalog, list)
        self.assertGreater(len(catalog), 0)

        for entry in catalog:
            self.assertIsInstance(entry, dict)
            self.assertIn("id", entry)
            self.assertIn("description", entry)
            self.assertIn("test_fn", entry)
            self.assertIsInstance(entry["id"], str)
            self.assertTrue(entry["id"].strip())
            self.assertIsInstance(entry["description"], str)
            self.assertTrue(entry["description"].strip())
            self.assertIsInstance(entry["test_fn"], str)
            self.assertTrue(entry["test_fn"].strip())

    def test_catalog_references_implemented_checks(self):
        catalog = self._load_catalog()
        registry = self._cve_test_registry()

        for entry in catalog:
            self.assertIn(
                entry["test_fn"],
                registry,
                f"Missing regression implementation for {entry['id']} -> {entry['test_fn']}",
            )

    def test_all_catalog_checks_pass(self):
        catalog = self._load_catalog()
        registry = self._cve_test_registry()

        for entry in catalog:
            fn = registry[entry["test_fn"]]
            fn()


class DefinitionUpdatePolicyTests(unittest.TestCase):
    """Validate integrity and freshness controls for updated threat definitions."""

    def _verify_feed_integrity_policy(self, content_bytes, expected_digest, algo="sha256"):
        if algo.lower() != "sha256":
            return False
        digest = hashlib.sha256(content_bytes).hexdigest()
        return digest == expected_digest

    def _parse_time_lock_header(self, header_line):
        # Expected format: # CLAMFOX-TIME-LOCK: <timestamp> <signature_hex>
        parts = header_line.strip().split()
        if len(parts) != 4:
            raise ValueError("Invalid header format")
        if parts[0] != "#" or parts[1] != "CLAMFOX-TIME-LOCK:":
            raise ValueError("Invalid header marker")
        ts = int(parts[2])
        sig_hex = parts[3]
        bytes.fromhex(sig_hex)  # validate hex encoding
        return ts, sig_hex

    def _is_stale(self, timestamp, max_age_hours=96, now=None):
        if now is None:
            now = int(time.time())
        max_age_seconds = max_age_hours * 3600
        return (now - timestamp) > max_age_seconds

    def test_reject_weak_checksum_algorithm(self):
        content = b"test-definition"
        bad_md5 = hashlib.md5(content).hexdigest()  # nosec - intentional negative test
        self.assertFalse(self._verify_feed_integrity_policy(content, bad_md5, algo="md5"))

    def test_accept_sha256_when_digest_matches(self):
        content = b"safe-feed-content"
        digest = hashlib.sha256(content).hexdigest()
        self.assertTrue(self._verify_feed_integrity_policy(content, digest, algo="sha256"))

    def test_reject_sha256_mismatch(self):
        content = b"safe-feed-content"
        self.assertFalse(self._verify_feed_integrity_policy(content, "0" * 64, algo="sha256"))

    def test_time_lock_header_parsing_valid(self):
        header = "# CLAMFOX-TIME-LOCK: 1760000000 aabbccddeeff"
        ts, sig = self._parse_time_lock_header(header)
        self.assertEqual(ts, 1760000000)
        self.assertEqual(sig, "aabbccddeeff")

    def test_time_lock_header_rejects_malformed(self):
        with self.assertRaises(ValueError):
            self._parse_time_lock_header("# INVALID-HEADER 1760000000 deadbeef")

    def test_stale_definition_detection(self):
        now = 1_800_000_000
        self.assertFalse(self._is_stale(now - (24 * 3600), max_age_hours=96, now=now))
        self.assertTrue(self._is_stale(now - (120 * 3600), max_age_hours=96, now=now))


class UrlReputationDomainFallbackTests(unittest.TestCase):
    """Regression checks for URLhaus domain-level fallback behavior."""

    def _should_block_domain_match(self, domain_in_cache, globally_trusted):
        # Mirrors the current host policy: skip blanket domain blocking for
        # globally trusted/shared domains, require exact URL hits there.
        if not domain_in_cache:
            return False
        if globally_trusted:
            return False
        return True

    def test_skip_domain_fallback_for_globally_trusted_domain(self):
        self.assertFalse(self._should_block_domain_match(domain_in_cache=True, globally_trusted=True))

    def test_keep_domain_fallback_for_untrusted_domain(self):
        self.assertTrue(self._should_block_domain_match(domain_in_cache=True, globally_trusted=False))

    def test_no_domain_fallback_when_not_in_cache(self):
        self.assertFalse(self._should_block_domain_match(domain_in_cache=False, globally_trusted=False))


def run_tests():
    """Run all security tests"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(YaraValidationTests))
    suite.addTests(loader.loadTestsFromTestCase(TimestampValidationTests))
    suite.addTests(loader.loadTestsFromTestCase(ErrorMessageFilteringTests))
    suite.addTests(loader.loadTestsFromTestCase(IntegrationTests))
    suite.addTests(loader.loadTestsFromTestCase(NativeMessageFuzzTests))
    suite.addTests(loader.loadTestsFromTestCase(ProcessPoolRecoveryTests))
    suite.addTests(loader.loadTestsFromTestCase(CVERegressionCatalogTests))
    suite.addTests(loader.loadTestsFromTestCase(DefinitionUpdatePolicyTests))
    suite.addTests(loader.loadTestsFromTestCase(UrlReputationDomainFallbackTests))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_tests()
    exit(0 if success else 1)
