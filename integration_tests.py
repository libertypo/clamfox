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

        py_step = wf.find("- name: Run Python Security Suite")
        js_step = wf.find("- name: Run JS Security Suite")
        int_step = wf.find("- name: Run CVE Catalog Regression Harness")

        self.assertGreaterEqual(py_step, 0, "missing Python suite step")
        self.assertGreaterEqual(js_step, 0, "missing JS suite step")
        self.assertGreaterEqual(int_step, 0, "missing integration suite step")
        self.assertLess(py_step, js_step, "workflow order changed: Python should run before JS")
        self.assertLess(js_step, int_step, "workflow order changed: JS should run before integration")

        self.assertIn("run: python test_security_suite.py", wf)
        self.assertIn("run: node test_security_suite.js", wf)
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
        self.assertIn('data = json.load', install)
        self.assertIn('os.replace(tmp, path)', install)
        self.assertNotIn('cat <<EOF > "$POLICY_DIR/policies.json"', install)

    def test_host_manifest_uses_hardened_install_path(self) -> None:
        host_manifest = json.loads((ROOT / "host/clamav_host.json").read_text(encoding="utf-8"))
        self.assertEqual(host_manifest.get("path"), "/opt/clamfox/clamav_host.py")


if __name__ == "__main__":
    unittest.main(verbosity=2)
