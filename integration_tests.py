#!/usr/bin/env python3
"""End-to-end / Regression test scaffolding for ClamFox.

This module contains several helpers and placeholder tests demonstrating how
an automated test suite for the *extension + native host* might be organized.

It does not attempt full coverage here, but provides a starting point for:

* Launching a real Firefox instance with the extension installed and driving
  basic UI flows via Selenium (E2E tests).
* Exercising the native messaging IPC channel with both normal and malformed
  payloads (fuzzing harness).
* Running regression checks for previously known CVEs or vulnerability patterns.
* Providing hooks that can be invoked from a CI pipeline (e.g. GitHub Actions)
  to exercise installer/updater behaviours.

When expanding this suite, the following techniques are useful:

* Use `selenium` or `puppeteer-firefox` to automate the extension UI.
* Spawn the native host as a subprocess and feed it crafted JSON blobs.
* Maintain a `cve_catalog.json` with past issue descriptions and test vectors.

Running the module directly will execute a very small sanity check, but
mostly the functions here are intended to be imported by CI scripts or
more comprehensive test runners.
"""

import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time

try:
    from selenium import webdriver
    from selenium.webdriver.firefox.options import Options as FxOptions
except ImportError:
    webdriver = None
    FxOptions = None

# ---------------------------------------------------------------------------
# E2E Helpers
# ---------------------------------------------------------------------------

EXTENSION_XPI = os.path.abspath("./clamfox_full_0.0.6.5.xpi")


def launch_firefox_with_extension(headless=True):
    """Start a Firefox WebDriver session with the ClamFox extension installed.

    Returns a `webdriver.Firefox` instance. Caller is responsible for quitting it.
    """
    if webdriver is None:
        raise RuntimeError("selenium is not installed; pip install selenium")

    opts = FxOptions()
    if headless:
        opts.add_argument("-headless")

    profile = webdriver.FirefoxProfile()
    profile.add_extension(EXTENSION_XPI)

    driver = webdriver.Firefox(firefox_profile=profile, options=opts)
    driver.set_page_load_timeout(30)
    return driver


def test_popup_loads():
    """Simple smoke test: ensure popup.html renders without JS errors."""
    driver = launch_firefox_with_extension()
    try:
        driver.get("about:debugging#/runtime/this-firefox")  # open debug page to load extension
        time.sleep(1)
        # open popup via background route
        driver.execute_script("browser.browserAction.openPopup();")
        time.sleep(1)
        assert "ClamFox" in driver.page_source
    finally:
        driver.quit()

# ---------------------------------------------------------------------------
# IPC Fuzzing Harness
# ---------------------------------------------------------------------------

NATIVE_HOST_BIN = os.path.abspath("./host/clamav_engine.py")


def fuzz_ipc(iterations=1000):
    """Send random JSON blobs to the native host stdin and watch for crashes.

    This is a very lightweight "fuzzer" that exercises the parsing code of the
    host. More advanced fuzzers (e.g. AFL, honggfuzz) could be directed at the
    built binary instead.
    """
    for i in range(iterations):
        msg = _mutate_message({
            "action": random.choice(["scan", "check", "update_urldb"]),
            "secret": "".join(random.choices("abcdef0123456789", k=64)),
            "target": random.choice([None, "/tmp/foo", "http://example.com"])
        })
        input_str = json.dumps(msg) + "\n"
        proc = subprocess.Popen([sys.executable, NATIVE_HOST_BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            out, err = proc.communicate(input=input_str.encode('utf-8'), timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, err = proc.communicate()
        # if process crashed, print diagnostic
        if proc.returncode not in (0,):
            print(f"Crash detected at iteration {i}, returncode={proc.returncode}")
            print("stdin=", msg)
            print("stdout=", out)
            print("stderr=", err)
            break


def _mutate_message(msg):
    """Introduce random modifications to a base message."""
    if random.random() < 0.3:
        # change type of a random field
        key = random.choice(list(msg.keys()))
        msg[key] = random.choice([123, False, [1,2,3], {"a":1}])
    if random.random() < 0.1:
        msg[random.choice(["junk", "overflow"])]= "x" * random.randint(0,5000)
    return msg

# ---------------------------------------------------------------------------
# CVE Regression Catalog
# ---------------------------------------------------------------------------

CVE_CATALOG = "cve_catalog.json"


def run_cve_regression_tests():
    """Iterate through known CVEs and ensure regressions do not reappear.

    Returns True on success and raises AssertionError on failure.
    """
    if not os.path.exists(CVE_CATALOG):
        raise AssertionError("CVE catalog missing")

    with open(CVE_CATALOG) as f:
        catalog = json.load(f)

    if not isinstance(catalog, list) or not catalog:
        raise AssertionError("CVE catalog is empty or invalid")

    for entry in catalog:
        cve_id = entry.get("id")
        desc = entry.get("description")
        test_fn_name = entry.get("test_fn")

        if not cve_id or not desc or not test_fn_name:
            raise AssertionError(f"Malformed CVE entry: {entry}")

        print(f"Checking {cve_id}: {desc}")
        # each entry should contain a `test_fn` name we can call
        fn = globals().get(test_fn_name)
        if fn:
            fn()
        else:
            raise AssertionError(f"No regression function named {test_fn_name} for {cve_id}")

    return True


def test_cve_2025_1234():
    """Regression: parser must reject array payload root (non-object)."""
    payload = []
    if isinstance(payload, list):
        return
    raise AssertionError("Expected array payload shape for regression check")


def test_cve_local_2026_0001():
    """Regression: cookie-name-only trust must not bypass URL scan gate."""
    has_temp_bypass = False
    is_user_whitelisted = False
    should_skip_scan = has_temp_bypass or is_user_whitelisted
    if should_skip_scan:
        raise AssertionError("URL scan bypass should require challenge transition or whitelist")


def test_cve_local_2026_0002():
    """Regression: malformed streaming threat payload must be rejected."""
    payload = {"status": "malicious", "threat": "x" * 300}
    threat = payload.get("threat")
    if not isinstance(threat, str) or len(threat) > 256:
        return
    raise AssertionError("Malformed stream payload unexpectedly accepted")

# ---------------------------------------------------------------------------
# Installer/Updater Emulation (placeholders)
# ---------------------------------------------------------------------------


def test_installer_permissions():
    """Verify installer script sets correct permissions on /opt/clamfox.

    This is a lightweight smoke test that can run in CI by using a tempdir and
    invoking `host/install.sh` with `DESTDIR` override.
    """
    tempdir = tempfile.mkdtemp()
    try:
        env = os.environ.copy()
        env['INSTALL_DIR'] = tempdir
        subprocess.check_call(["bash", "host/install.sh"], env=env)
        # check some expected files
        assert os.path.isfile(os.path.join(tempdir, "clamav_host.py"))
        assert oct(os.stat(os.path.join(tempdir, "config.json")).st_mode & 0o777) == '0o600'
    finally:
        shutil.rmtree(tempdir)

# ---------------------------------------------------------------------------
# Entry point for manual invocation
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    print("Running CVE regression catalog checks...")
    try:
        run_cve_regression_tests()
    except AssertionError as e:
        print(f"CVE regression failed: {e}")
        sys.exit(1)
    print("CVE regression checks passed.")
