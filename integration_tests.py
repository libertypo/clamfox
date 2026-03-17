#!/usr/bin/env python3
"""Cross-file integration checks for release/CI security gates."""

from pathlib import Path
import json
import re
import unittest


ROOT = Path(__file__).resolve().parent


class IntegrationSecurityHarness(unittest.TestCase):
    def test_mandatory_suite_files_exist(self) -> None:
        for rel in ["test_security_suite.py", "test_security_suite.js", "integration_tests.py"]:
            self.assertTrue((ROOT / rel).is_file(), f"missing required suite file: {rel}")

    def test_mandatory_suite_files_not_gitignored(self) -> None:
        gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertNotIn("\nintegration_tests.py\n", f"\n{gitignore}\n")
        self.assertNotIn("\ntest_security_suite.js\n", f"\n{gitignore}\n")
        self.assertNotIn("\ntest_security_suite.py\n", f"\n{gitignore}\n")

    def test_manifest_versions_are_in_sync(self) -> None:
        manifest = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
        manifest_amo = json.loads((ROOT / "manifest_amo.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest.get("version"), manifest_amo.get("version"), "manifest versions diverged")

    def test_manifest_csp_is_aligned(self) -> None:
        manifest = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
        manifest_amo = json.loads((ROOT / "manifest_amo.json").read_text(encoding="utf-8"))
        csp_main = manifest.get("content_security_policy", {}).get("extension_pages", "")
        csp_amo = manifest_amo.get("content_security_policy", {}).get("extension_pages", "")
        self.assertIn("frame-src 'none'", csp_main)
        self.assertIn("frame-src 'none'", csp_amo)

    def test_security_workflow_runs_hard_gate_steps(self) -> None:
        wf = (ROOT / ".github/workflows/security-tests.yml").read_text(encoding="utf-8")

        self.assertIn("critical-invariants:", wf)
        self.assertIn("extended-regression:", wf)
        self.assertIn("needs: critical-invariants", wf)

        crit_step = wf.find("- name: Run Critical Invariants Gate")
        js_step = wf.find("- name: Run JS Security Suite")
        py_step = wf.find("- name: Run Python Security Suite")
        int_step = wf.find("- name: Run CVE Catalog Regression Harness")

        self.assertGreaterEqual(crit_step, 0, "missing critical invariants step")
        self.assertGreaterEqual(js_step, 0, "missing JS suite step")
        self.assertGreaterEqual(py_step, 0, "missing Python suite step")
        self.assertGreaterEqual(int_step, 0, "missing integration suite step")
        self.assertLess(crit_step, js_step, "critical invariants should run before JS suite in critical job")
        self.assertLess(py_step, int_step, "workflow order changed: Python should run before integration")

        self.assertIn("run: ./scripts/critical_invariants.sh", wf)
        self.assertIn("run: node test_security_suite.js", wf)
        self.assertIn("run: python test_security_suite.py", wf)
        self.assertIn("run: python integration_tests.py", wf)
        self.assertNotIn("hashFiles(", wf)

    def test_security_workflow_has_least_privilege_and_timeout(self) -> None:
        wf = (ROOT / ".github/workflows/security-tests.yml").read_text(encoding="utf-8")
        self.assertIn("permissions:\n  contents: read", wf)
        self.assertIn("timeout-minutes: 15", wf)

    def test_workflow_actions_are_sha_pinned(self) -> None:
        workflows = [
            ROOT / ".github/workflows/security-tests.yml",
            ROOT / ".github/workflows/codeql.yml",
            ROOT / ".github/workflows/release.yml",
        ]
        uses_re = re.compile(r"^\s*uses:\s*([^\s#]+)", re.MULTILINE)
        sha_pinned_re = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")

        for wf_path in workflows:
            wf = wf_path.read_text(encoding="utf-8")
            uses_values = uses_re.findall(wf)
            self.assertGreater(len(uses_values), 0, f"no uses entries found in {wf_path.name}")
            for value in uses_values:
                self.assertRegex(
                    value,
                    sha_pinned_re,
                    f"workflow action not SHA pinned in {wf_path.name}: {value}",
                )

    def test_release_workflow_publishes_checksums(self) -> None:
        wf = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertIn("Generate SHA256 Checksums", wf)
        self.assertIn("SHA256SUMS.txt", wf)
        self.assertIn("Release Preflight", wf)
        self.assertIn("./scripts/critical_invariants.sh", wf)
        self.assertIn("./scripts/local_hygiene.sh", wf)
        self.assertIn("git status --porcelain", wf)

    def test_docs_include_downloads_safe_zone_warning(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        privacy = (ROOT / "PRIVACY_SUMMARY.txt").read_text(encoding="utf-8")
        self.assertIn("DOWNLOAD POLICY WARNING", readme)
        self.assertIn("`DOWNLOADS` FOLDER", readme)
        self.assertIn("ClamFox enforces protected download", privacy)
        self.assertIn("Downloads", privacy)

    def test_install_script_no_source_signature_deletion(self) -> None:
        install = (ROOT / "host/install.sh").read_text(encoding="utf-8")
        self.assertNotIn('rm -f "$DIR/signatures/"*.hdb "$DIR/signatures/"*.ndb', install)
        self.assertIn('find "$INSTALL_DIR/signatures" -maxdepth 1 -type f', install)

    def test_install_script_fsverity_targets_live_host_entrypoint(self) -> None:
        install = (ROOT / "host/install.sh").read_text(encoding="utf-8")
        self.assertIn('for f in "$INSTALL_DIR/clamav_host.py" "$INSTALL_DIR/tpm_provider.py" "$INSTALL_DIR/yara_sanitizer.py"; do', install)
        self.assertNotIn('for f in "$INSTALL_DIR/clamav_engine.py" "$INSTALL_DIR/tpm_provider.py" "$INSTALL_DIR/yara_sanitizer.py"; do', install)

    def test_install_script_merges_firefox_policy(self) -> None:
        install = (ROOT / "host/install.sh").read_text(encoding="utf-8")
        self.assertIn('POLICY_FILE="$POLICY_DIR/policies.json"', install)
        self.assertIn('CLAMFOX_POLICY_FILE="$POLICY_FILE" CLAMFOX_USER_HOME="$USER_HOME" python3 - <<\'PYEOF\'', install)
        self.assertIn('data = json.load', install)
        self.assertIn('download_dir = os.path.join(user_home, "Downloads")', install)
        self.assertIn('os.replace(tmp, path)', install)
        self.assertNotIn('cat <<EOF > "$POLICY_DIR/policies.json"', install)
        self.assertIn('prefs["browser.download.useDownloadDir"] = {"Value": True, "Status": "locked"}', install)
        self.assertIn('prefs["browser.download.folderList"] = {"Value": 2, "Status": "locked"}', install)
        self.assertIn('prefs["browser.download.dir"] = {"Value": download_dir, "Status": "locked"}', install)

    def test_amo_review_notes_cover_potential_blockers(self) -> None:
        notes = (ROOT / "AMO_REVIEW_NOTES.md").read_text(encoding="utf-8")
        self.assertIn("Potential AMO Blocker 1: `nativeMessaging` Permission", notes)
        self.assertIn("Potential AMO Blocker 2: `webRequestBlocking` + Broad Host Permissions", notes)
        self.assertIn("Potential AMO Blocker 3: In-Page Hooking of `eval` / `Function` / `document.write`", notes)
        self.assertIn("Potential AMO Blocker 4: Host Dependency / Degraded Mode", notes)
        self.assertIn("Potential AMO Blocker 5: Network/Privacy Claims", notes)
        self.assertIn("Potential AMO Blocker 6: Stale Generated `build_amo` Artifacts", notes)

    def test_build_amo_manifest_matches_if_present(self) -> None:
        generated = ROOT / "build_amo" / "manifest_amo.json"
        if not generated.exists():
            return
        active = json.loads((ROOT / "manifest_amo.json").read_text(encoding="utf-8"))
        built = json.loads(generated.read_text(encoding="utf-8"))
        self.assertEqual(active, built, "stale build_amo/manifest_amo.json diverges from manifest_amo.json")

    def test_host_manifest_uses_hardened_install_path(self) -> None:
        host_manifest = json.loads((ROOT / "host/clamav_host.json").read_text(encoding="utf-8"))
        self.assertEqual(host_manifest.get("path"), "/opt/clamfox/clamav_host.py")

    def test_release_quarantine_runs_document_sanitization(self) -> None:
        host = (ROOT / "host/clamav_engine.py").read_text(encoding="utf-8")
        release_idx = host.find('elif action == "release_quarantine":')
        self.assertGreaterEqual(release_idx, 0, "release_quarantine handler missing")
        release_slice = host[release_idx: release_idx + 2400]
        self.assertIn("sanitize_document_before_release(target)", release_slice)

    def test_ooxml_sanitizer_uses_real_regex_tokens(self) -> None:
        host = (ROOT / "host/clamav_engine.py").read_text(encoding="utf-8")
        self.assertIn(r"<Relationship\b", host)
        self.assertIn(r'\sTargetMode="External"', host)
        self.assertIn(r"<script:event-listener\b", host)
        self.assertNotIn(r"<Relationship\\b", host)
        self.assertNotIn(r'\\sTargetMode="External"', host)

    def test_safe_path_does_not_allow_full_home_scope(self) -> None:
        host = (ROOT / "host/clamav_engine.py").read_text(encoding="utf-8")
        self.assertNotIn("if is_safe_user_home_path(filepath):", host)

    def test_scan_action_rejects_unsafe_file_targets_without_autostage(self) -> None:
        host = (ROOT / "host/clamav_engine.py").read_text(encoding="utf-8")
        scan_idx = host.find('elif action == "scan":')
        self.assertGreaterEqual(scan_idx, 0, "scan action handler missing")
        scan_slice = host[scan_idx: scan_idx + 1800]
        self.assertIn('if target_type != "url" and not is_safe_path(target):', scan_slice)
        self.assertNotIn("is_safe_staging_source(target)", scan_slice)

    def test_stage_metadata_is_authenticated_before_release(self) -> None:
        host = (ROOT / "host/clamav_engine.py").read_text(encoding="utf-8")
        self.assertIn("def _stage_metadata_mac", host)
        self.assertIn('meta["mac"] = mac', host)
        self.assertIn("hmac.compare_digest", host)

    def test_lock_file_is_fail_closed_no_read(self) -> None:
        host = (ROOT / "host/clamav_engine.py").read_text(encoding="utf-8")
        lock_idx = host.find("def lock_file(filepath):")
        self.assertGreaterEqual(lock_idx, 0, "lock_file function missing")
        lock_slice = host[lock_idx: lock_idx + 380]
        self.assertIn("os.chmod(filepath, 0o000)", lock_slice)

    def test_host_bridge_signing_is_fail_closed(self) -> None:
        host = (ROOT / "host/clamav_engine.py").read_text(encoding="utf-8")
        self.assertIn("Response signing failed (fail-closed)", host)
        self.assertNotIn("Response signing failed (continuing anyway)", host)

    def test_machine_key_fallback_file_is_hardened(self) -> None:
        host = (ROOT / "host/clamav_engine.py").read_text(encoding="utf-8")
        self.assertIn("os.lstat(fallback_path)", host)
        self.assertIn("stat.S_ISLNK", host)
        self.assertIn("st.st_uid != os.getuid()", host)
        self.assertIn("os.O_NOFOLLOW", host)
        self.assertIn("os.replace(tmp_path, fallback_path)", host)

    def test_host_strict_signing_gate_fails_fast_on_missing_key(self) -> None:
        host = (ROOT / "host/clamav_engine.py").read_text(encoding="utf-8")
        self.assertIn("if not get_or_create_machine_key():", host)
        self.assertIn("Machine signing key unavailable in strict mode", host)

    def test_install_script_urldb_permission_flow_is_explicit(self) -> None:
        install = (ROOT / "host/install.sh").read_text(encoding="utf-8")
        self.assertIn('if ! chmod 644 "$INSTALL_DIR/urldb.txt" 2>/dev/null; then', install)
        self.assertIn('touch "$INSTALL_DIR/urldb.txt"', install)
        self.assertNotIn('chmod 644 "$INSTALL_DIR/urldb.txt" 2>/dev/null || touch "$INSTALL_DIR/urldb.txt" && chmod 644 "$INSTALL_DIR/urldb.txt"', install)

    def test_local_hygiene_script_has_git_safety_guards(self) -> None:
        script = (ROOT / "scripts" / "local_hygiene.sh").read_text(encoding="utf-8")
        self.assertIn('git ls-files --error-unmatch -- "$p"', script)
        self.assertIn('git check-ignore -q -- "$p"', script)
        self.assertIn('Use --force to override safety checks', script)
        self.assertIn('--force', script)

    def test_critical_invariants_script_exists(self) -> None:
        script_path = ROOT / "scripts" / "critical_invariants.sh"
        self.assertTrue(script_path.is_file(), "scripts/critical_invariants.sh is missing")
        script = script_path.read_text(encoding="utf-8")
        self.assertIn('Response signing failed \\(continuing anyway\\)', script)
        self.assertIn('shell=True|os\\.system\\(|subprocess\\.Popen\\(', script)

    def test_host_observability_error_codes_present(self) -> None:
        host = (ROOT / "host/clamav_engine.py").read_text(encoding="utf-8")
        self.assertIn('"error_code": "CFX-E-REQ-001"', host)
        self.assertIn('"error_code": "CFX-E-RATE-001"', host)
        self.assertIn('"error_code": "CFX-E-AUTH-001"', host)

    def test_config_lock_is_rlock_for_reentrant_mutations(self) -> None:
        """MEDIUM: _config_lock must be RLock so check action can hold the lock
        across save_config calls without self-deadlocking."""
        host = (ROOT / "host/clamav_engine.py").read_text(encoding="utf-8")
        self.assertIn("threading.RLock()", host, "_config_lock must be RLock to allow reentrant acquisition in check action")
        self.assertNotIn("_config_lock = threading.Lock()", host)

    def test_check_action_config_mutations_are_under_lock(self) -> None:
        """MEDIUM: all config dict mutations in the check action must occur inside _config_lock."""
        host = (ROOT / "host/clamav_engine.py").read_text(encoding="utf-8")
        self.assertIn("with _config_lock:", host, "check action must hold _config_lock during config mutations")
        # Confirm dead _secret_issued code was removed
        self.assertNotIn("global _secret_issued", host)
        self.assertNotIn("_secret_issued = True", host)

    def test_list_quarantine_filters_meta_json_sidecars(self) -> None:
        """LOW: list_quarantine must exclude .meta.json sidecar files from the listing."""
        host = (ROOT / "host/clamav_engine.py").read_text(encoding="utf-8")
        # Both the filter expression and the action context must be present
        self.assertIn('.endswith(".meta.json")', host)
        # Verify the filter appears inside the list_quarantine handler (heuristic: nearby context)
        idx_action = host.find('action == "list_quarantine"')
        idx_filter = host.find('.endswith(".meta.json")')
        self.assertGreater(idx_filter, idx_action, ".meta.json filter must be inside list_quarantine handler")

    def test_burn_ledger_uses_explicit_file_permissions(self) -> None:
        """INFO: community burn ledger must be written with 0o600 to prevent IOC exposure."""
        host = (ROOT / "host/clamav_engine.py").read_text(encoding="utf-8")
        self.assertIn("os.O_CREAT | os.O_TRUNC, 0o600", host, "burn ledger must use os.open with 0o600")
        self.assertNotIn('open(burn_ledger, "w")', host, "burn ledger must not use plain open() without setting perms")

    def test_report_threat_validates_threat_type(self) -> None:
        """INFO: report_threat action must validate threat_type is a string."""
        host = (ROOT / "host/clamav_engine.py").read_text(encoding="utf-8")
        # Find the report_threat handler and verify isinstance check is nearby
        idx = host.find('action == "report_threat"')
        snippet = host[idx:idx + 500]
        self.assertIn("isinstance(threat_type, str)", snippet)


if __name__ == "__main__":
    unittest.main(verbosity=2)
