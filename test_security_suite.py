#!/usr/bin/env python3
"""Mandatory Python security regression checks for ClamFox.

These tests validate behavioral security invariants so CI fails if
high-risk protections are weakened or moved out of critical control flow.
"""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parent
BACKGROUND = ROOT / "background.js"


class SecuritySuitePython(unittest.TestCase):
    def setUp(self) -> None:
        self.bg = BACKGROUND.read_text(encoding="utf-8")

    def _section(self, start_marker: str, end_marker: str) -> str:
        start = self.bg.find(start_marker)
        self.assertNotEqual(start, -1, f"missing start marker: {start_marker}")
        end = self.bg.find(end_marker, start)
        self.assertNotEqual(end, -1, f"missing end marker: {end_marker}")
        return self.bg[start:end]

    def test_download_stage_must_precede_scan(self) -> None:
        download_handler = self._section(
            "browser.downloads.onChanged.addListener(async (delta) => {",
            "class ScanRateLimiter {",
        )
        stage_idx = download_handler.find('action: "stage_quarantine"')
        scan_idx = download_handler.find(
            'performScan(scanTarget, "file", item.id, null, stagedBeforeScan);'
        )
        self.assertGreaterEqual(stage_idx, 0, "stage_quarantine action missing in download handler")
        self.assertGreaterEqual(scan_idx, 0, "performScan call missing in download handler")
        self.assertLess(stage_idx, scan_idx, "performScan happens before staging")

    def test_staging_failure_is_fail_closed(self) -> None:
        download_handler = self._section(
            "browser.downloads.onChanged.addListener(async (delta) => {",
            "class ScanRateLimiter {",
        )
        catch_idx = download_handler.find("} catch (e) {")
        self.assertGreaterEqual(catch_idx, 0, "staging failure catch block missing")

        failure_slice = download_handler[catch_idx:]
        cancel_idx = failure_slice.find("await browser.downloads.cancel(delta.id);")
        remove_idx = failure_slice.find("await browser.downloads.removeFile(delta.id);")
        erase_idx = failure_slice.find("await browser.downloads.erase({ id: delta.id });")

        self.assertGreaterEqual(cancel_idx, 0, "cancel missing in lock-failure path")
        self.assertGreaterEqual(remove_idx, 0, "removeFile missing in lock-failure path")
        self.assertGreaterEqual(erase_idx, 0, "erase missing in lock-failure path")
        self.assertLess(cancel_idx, remove_idx, "removeFile should follow cancel")
        self.assertLess(remove_idx, erase_idx, "erase should follow removeFile")
        self.assertNotIn('performScan(scanTarget, "file", item.id, null, false);', failure_slice)
        self.assertIn('downloadsFolderOnlyWarning', failure_slice)
        self.assertIn('title: "🛑 DOWNLOAD BLOCKED"', failure_slice)
        self.assertIn("return;", failure_slice)

    def test_locked_file_recovery_paths_exist(self) -> None:
        perform_scan = self._section(
            "async function performScan(target, type, downloadId = null, tabId = null, lockedBeforeScan = false) {",
            "MAIN_MESSAGE_LISTENER_READY = true;",
        )
        self.assertIn('const recoverLockedFile = async (reason = "") => {', perform_scan)
        for reason in [
            "signature verification failure",
            "response schema validation failure",
            "tamper/auth drift during scan",
            "clean verdict release failure",
            "native messaging exception",
        ]:
            self.assertIn(f'await recoverLockedFile("{reason}");', perform_scan)

        self.assertIn('recoverLockedFile("port disconnect before final verdict")', perform_scan)

    def test_clean_release_requires_live_secret(self) -> None:
        perform_scan = self._section(
            "async function performScan(target, type, downloadId = null, tabId = null, lockedBeforeScan = false) {",
            "MAIN_MESSAGE_LISTENER_READY = true;",
        )

        clean_branch_start = perform_scan.find('} else if (response.status === "clean") {')
        self.assertGreaterEqual(clean_branch_start, 0, "clean branch missing")
        clean_slice = perform_scan[clean_branch_start:]

        guard_idx = clean_slice.find("if (!secret || !HOST_AVAILABLE) {")
        release_idx = clean_slice.find('action: "release_quarantine"')
        recovery_idx = clean_slice.find('await recoverLockedFile("clean verdict release failure");')

        self.assertGreaterEqual(guard_idx, 0, "missing live-secret guard before release")
        self.assertGreaterEqual(release_idx, 0, "release_quarantine action missing")
        self.assertGreaterEqual(recovery_idx, 0, "missing clean release recovery")
        self.assertLess(guard_idx, release_idx, "release invoked before guard")


if __name__ == "__main__":
    unittest.main(verbosity=2)
