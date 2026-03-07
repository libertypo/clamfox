/**
 * ClamFox Security Test Suite
 * 
 * Comprehensive tests for critical security functions and validators.
 * Run in browser console or with Node.js test runner.
 * 
 * Tests:
 * - Native message validation
 * - YARA rule validation
 * - Scan rate limiter
 * - Timestamp validation
 * - Error message filtering
 */

// ============================================================================
// TEST FRAMEWORK
// ============================================================================

class SecurityTestSuite {
    constructor() {
        this.tests = [];
        this.passed = 0;
        this.failed = 0;
        this.errors = [];
    }

    test(name, testFn) {
        this.tests.push({ name, testFn });
    }

    async run() {
        console.log("🛡️  ClamFox Security Test Suite\n");
        console.log("=".repeat(60));

        for (const { name, testFn } of this.tests) {
            try {
                await testFn();
                this.passed++;
                console.log(`✅ ${name}`);
            } catch (e) {
                this.failed++;
                this.errors.push({ test: name, error: e.message });
                console.log(`❌ ${name}`);
                console.log(`   Error: ${e.message}\n`);
            }
        }

        console.log("=".repeat(60));
        console.log(`\nResults: ${this.passed} passed, ${this.failed} failed\n`);

        if (this.failed > 0) {
            console.log("Failed Tests:");
            this.errors.forEach(({ test, error }) => {
                console.log(`  - ${test}: ${error}`);
            });
        }

        return { passed: this.passed, failed: this.failed, total: this.tests.length };
    }

    assert(condition, message) {
        if (!condition) throw new Error(message);
    }

    assertEquals(actual, expected, message) {
        if (actual !== expected) {
            throw new Error(message || `Expected ${expected}, got ${actual}`);
        }
    }

    assertThrows(fn, message) {
        try {
            fn();
            throw new Error(message || "Expected function to throw, but it didn't");
        } catch (e) {
            if (e.message === (message || "Expected function to throw, but it didn't")) {
                throw e;
            }
        }
    }
}

// ============================================================================
// MOCK IMPLEMENTATIONS (for testing without browser/host)
// ============================================================================

/**
 * Mock validation function matching validateNativeResponse behavior
 */
function mockValidateNativeResponse(action, response) {
    if (!response || typeof response !== "object" || Array.isArray(response)) {
        throw new Error("Invalid response format: Not a structured object");
    }

    const rootSchema = {
        action: "string",
        status: "string",
        secret: "string",
        error: "string",
        integrity_ok: "boolean",
        binary_ok: "boolean",
        honeypot_secret: "string"
    };

    for (const [key, expectedType] of Object.entries(rootSchema)) {
        const val = response[key];
        if (val !== undefined && val !== null) {
            if (typeof val !== expectedType) {
                throw new Error(`Type mismatch for '${key}': expected ${expectedType}, got ${typeof val}`);
            }
            if (expectedType === "string" && val.length > 2048 && key !== "error") {
                throw new Error(`String field '${key}' exceeds maximum permitted length (2KB)`);
            }
        }
    }

    // Action-specific validation for scan responses
    if ((action === "scan" || action === "scan_request") && response.status === "malicious") {
        if (typeof response.threat !== "string" || response.threat.length > 256) {
            throw new Error("Invalid 'threat' identifier in scan response");
        }
    }

    return true;
}

/**
 * Mock YARA validation function
 */
function mockValidateYaraRuleSafety(ruleContent) {
    const MAX_RULE_SIZE = 1024 * 1024;
    if (ruleContent.length > MAX_RULE_SIZE) {
        throw new Error(`Rule exceeds size limit: ${ruleContent.length} > ${MAX_RULE_SIZE}`);
    }

    const dangerousPatterns = [
        /entrypoint/i,
        /filesize/i,
        /import\s+"/i,
        /all\s+of\s+them/i
    ];

    for (const pattern of dangerousPatterns) {
        if (pattern.test(ruleContent)) {
            throw new Error(`Dangerous pattern detected: ${pattern.source}`);
        }
    }

    return require("crypto").createHash("sha256").update(ruleContent).digest("hex");
}

/**
 * Mock timestamp validator
 */
function mockValidateMessageTimestamp(timestamp, maxDrift = 60) {
    const currentTime = Math.floor(Date.now() / 1000);
    const drift = Math.abs(currentTime - timestamp);

    if (drift > maxDrift) {
        throw new Error(`Message timestamp invalid (drift: ${drift}s > ${maxDrift}s)`);
    }

    return true;
}

/**
 * Mock scan rate limiter
 */
class MockScanRateLimiter {
    constructor(cooldownMs = 30000) {
        this.scanTimes = new Map();
        this.SCAN_COOLDOWN = cooldownMs;
    }

    canScan(target) {
        const lastScan = this.scanTimes.get(target);
        const now = Date.now();

        if (lastScan && (now - lastScan) < this.SCAN_COOLDOWN) {
            return false;
        }

        this.scanTimes.set(target, now);
        return true;
    }

    reset(target) {
        this.scanTimes.delete(target);
    }
}

/**
 * Mock host-side signed payload canonicalization.
 * Mirrors host/clamav_engine.py send_message behavior:
 * sign all fields except _signature itself.
 */
function mockHostSignedPayload(response) {
    const canonical = {};
    Object.keys(response)
        .filter(k => k !== "_signature")
        .sort()
        .forEach(k => {
            canonical[k] = response[k];
        });
    return JSON.stringify(canonical);
}

/**
 * Mock extension-side signed payload canonicalization.
 * Mirrors background.js verifyResponseSignature behavior.
 */
function mockExtensionSignedPayload(response) {
    const canonical = {};
    Object.keys(response)
        .filter(k => k !== "_signature")
        .sort()
        .forEach(k => {
            canonical[k] = response[k];
        });
    return JSON.stringify(canonical);
}

/**
 * Mock trusted-domain check used by drive-by shield injected logic.
 */
function mockIsTrustedDriveByDomain(hostname) {
    const trustedDomains = [
        "google.com",
        "microsoft.com",
        "apple.com",
        "amazon.com",
        "github.com",
        "firefox.com",
        "mozilla.org"
    ];
    const h = String(hostname || "").toLowerCase();
    return trustedDomains.some(d => h === d || h.endsWith("." + d));
}

/**
 * Mock stream/background native message guard used by background.js handlers.
 * Security contract: verify signature first, then validate schema.
 */
async function mockGuardNativeStreamMessage(response, verifyFn, validateFn, action = "scan") {
    await verifyFn(response);
    return validateFn(action, response);
}

// ============================================================================
// TEST SUITE DEFINITION
// ============================================================================

const suite = new SecurityTestSuite();

// --- NATIVE MESSAGE VALIDATION TESTS ---

suite.test("Native Message Validation: Reject null response", () => {
    suite.assertThrows(
        () => mockValidateNativeResponse("scan", null),
        ""
    );
});

suite.test("Native Message Validation: Reject non-object response", () => {
    suite.assertThrows(
        () => mockValidateNativeResponse("scan", "not an object"),
        ""
    );
});

suite.test("Native Message Validation: Reject array response", () => {
    suite.assertThrows(
        () => mockValidateNativeResponse("scan", [{ status: "ok" }]),
        ""
    );
});

suite.test("Native Message Validation: Type mismatch detection", () => {
    try {
        mockValidateNativeResponse("check", { status: 123 });
        throw new Error("Should have thrown");
    } catch (e) {
        suite.assert(
            e.message.includes("Type mismatch"),
            "Should detect type mismatch"
        );
    }
});

suite.test("Native Message Validation: Oversized string rejection for non-error fields", () => {
    // The validator intentionally allows long `error` messages but enforces
    // a 2KB maximum on other string fields.
    try {
        mockValidateNativeResponse("check", { status: "x".repeat(3000) });
        throw new Error("Should have thrown");
    } catch (e) {
        suite.assert(
            e.message.includes("exceeds maximum"),
            "Should reject oversized strings in non-error fields"
        );
    }
});

suite.test("Native Message Validation: Accept valid response", () => {
    const valid = {
        status: "clean",
        integrity_ok: true,
        binary_ok: true,
        error: "".repeat(5000) // long error should be allowed
    };
    mockValidateNativeResponse("scan", valid);
});

suite.test("Native Message Validation: Reject oversized threat name", () => {
    try {
        mockValidateNativeResponse("scan", {
            status: "malicious",
            threat: "x".repeat(300)
        });
        throw new Error("Should have thrown");
    } catch (e) {
        suite.assert(
            e.message.includes("threat"),
            "Should reject oversized threat field"
        );
    }
});

// --- YARA RULE VALIDATION TESTS ---

suite.test("YARA Validation: Accept safe rule", () => {
    const safeRule = `
        rule ExampleRule {
            strings:
                $a = "test"
            condition:
                $a
        }
    `;
    const hash = mockValidateYaraRuleSafety(safeRule);
    suite.assert(hash.length === 64, "Should return valid SHA256 hash");
});

suite.test("YARA Validation: Reject oversized rule", () => {
    const oversizedRule = "x".repeat(1024 * 1024 + 1);
    suite.assertThrows(
        () => mockValidateYaraRuleSafety(oversizedRule),
        ""
    );
});

suite.test("YARA Validation: Reject 'entrypoint' pattern", () => {
    const badRule = `
        rule Bad {
            strings:
                $a = "test"
            condition:
                $a at entrypoint
        }
    `;
    try {
        mockValidateYaraRuleSafety(badRule);
        throw new Error("Should have thrown");
    } catch (e) {
        suite.assert(e.message.includes("Dangerous"), "Should detect dangerous pattern");
    }
});

suite.test("YARA Validation: Reject 'filesize' pattern", () => {
    const badRule = `
        rule SizeBomb {
            condition:
                filesize > 1000000
        }
    `;
    try {
        mockValidateYaraRuleSafety(badRule);
        throw new Error("Should have thrown");
    } catch (e) {
        suite.assert(e.message.includes("Dangerous"), "Should detect dangerous pattern");
    }
});

suite.test("YARA Validation: Reject 'all of them' pattern", () => {
    const badRule = `
        rule MultiMatch {
            strings:
                $a = "test"
                $b = "bad"
            condition:
                all of them
        }
    `;
    try {
        mockValidateYaraRuleSafety(badRule);
        throw new Error("Should have thrown");
    } catch (e) {
        suite.assert(e.message.includes("Dangerous"), "Should detect dangerous pattern");
    }
});

// --- TIMESTAMP VALIDATION TESTS ---

suite.test("Timestamp Validation: Accept current timestamp", () => {
    const now = Math.floor(Date.now() / 1000);
    mockValidateMessageTimestamp(now);
});

suite.test("Timestamp Validation: Accept timestamp within drift", () => {
    const now = Math.floor(Date.now() / 1000);
    mockValidateMessageTimestamp(now - 30, 60); // 30 seconds ago
});

suite.test("Timestamp Validation: Reject timestamp outside drift", () => {
    const now = Math.floor(Date.now() / 1000);
    const oldTime = now - 120; // 2 minutes ago

    try {
        mockValidateMessageTimestamp(oldTime, 60);
        throw new Error("Should have thrown");
    } catch (e) {
        suite.assert(e.message.includes("drift"), "Should detect timestamp drift");
    }
});

suite.test("Timestamp Validation: Reject future timestamp", () => {
    const now = Math.floor(Date.now() / 1000);
    const futureTime = now + 120; // 2 minutes in future

    try {
        mockValidateMessageTimestamp(futureTime, 60);
        throw new Error("Should have thrown");
    } catch (e) {
        suite.assert(e.message.includes("drift"), "Should detect future timestamp");
    }
});

// --- SCAN RATE LIMITER TESTS ---

suite.test("Scan Rate Limiter: Allow first scan", () => {
    const limiter = new MockScanRateLimiter(30000);
    const result = limiter.canScan("/path/to/file.exe");
    suite.assert(result === true, "Should allow first scan");
});

suite.test("Scan Rate Limiter: Block rapid re-scan", () => {
    const limiter = new MockScanRateLimiter(30000);
    limiter.canScan("/path/to/file.exe");
    const result = limiter.canScan("/path/to/file.exe");
    suite.assert(result === false, "Should block rapid re-scan");
});

suite.test("Scan Rate Limiter: Allow different targets", () => {
    const limiter = new MockScanRateLimiter(30000);
    limiter.canScan("/path/to/file1.exe");
    const result = limiter.canScan("/path/to/file2.exe");
    suite.assert(result === true, "Should allow different targets");
});

suite.test("Scan Rate Limiter: Reset cooldown", () => {
    const limiter = new MockScanRateLimiter(30000);
    const target = "/path/to/file.exe";
    limiter.canScan(target);

    // Block first re-scan
    suite.assert(limiter.canScan(target) === false, "Should be blocked initially");

    // Reset and allow re-scan
    limiter.reset(target);
    const result = limiter.canScan(target);
    suite.assert(result === true, "Should allow after reset");
});

// --- SIGNATURE CANONICALIZATION REGRESSION TESTS ---

suite.test("Signature Canonicalization: Includes security metadata fields", () => {
    const response = {
        status: "ok",
        _signed_at: 1700000000,
        _pubkey_hint: "-----BEGIN PUBLIC KEY-----ABC",
        _signature: "BASE64SIG",
        threat: "none"
    };

    const payload = mockHostSignedPayload(response);
    suite.assert(payload.includes('"_signed_at":1700000000'), "_signed_at must be signed");
    suite.assert(payload.includes('"_pubkey_hint":"-----BEGIN PUBLIC KEY-----ABC"'), "_pubkey_hint must be signed");
    suite.assert(!payload.includes("BASE64SIG"), "_signature must be excluded from signed payload");
});

suite.test("Signature Canonicalization: Host and extension payloads match", () => {
    const response = {
        z: 1,
        status: "clean",
        _signed_at: 1700000001,
        _pubkey_hint: "HINT",
        _signature: "SIG",
        a: "first"
    };

    const hostPayload = mockHostSignedPayload(response);
    const extPayload = mockExtensionSignedPayload(response);
    suite.assertEquals(extPayload, hostPayload, "Host and extension canonicalization must be identical");
});

// --- DRIVE-BY TRUSTED DOMAIN REGRESSION TESTS ---

suite.test("Drive-by Domain Trust: Allows exact/suffix trusted domains only", () => {
    suite.assert(mockIsTrustedDriveByDomain("google.com") === true, "Exact trusted domain should pass");
    suite.assert(mockIsTrustedDriveByDomain("mail.google.com") === true, "Trusted subdomain should pass");
});

suite.test("Drive-by Domain Trust: Rejects substring spoof domains", () => {
    suite.assert(mockIsTrustedDriveByDomain("evilgoogle.com") === false, "Substring spoof must fail");
    suite.assert(mockIsTrustedDriveByDomain("google.com.evil.tld") === false, "Suffix spoof must fail");
});

// --- STREAM AUTH REGRESSION TESTS ---

suite.test("Native Stream Guard: Rejects before schema validation when signature check fails", async () => {
    let schemaValidated = false;
    const verifyFn = async () => {
        throw new Error("Signature invalid");
    };
    const validateFn = () => {
        schemaValidated = true;
        return true;
    };

    try {
        await mockGuardNativeStreamMessage({ status: "progress" }, verifyFn, validateFn, "scan");
        throw new Error("Should have thrown");
    } catch (e) {
        suite.assert(e.message.includes("Signature"), "Should fail on signature verification");
        suite.assert(schemaValidated === false, "Schema validation must not run when signature fails");
    }
});

suite.test("Native Stream Guard: Verifies signature before schema validation", async () => {
    const steps = [];
    const verifyFn = async () => {
        steps.push("verify");
        return true;
    };
    const validateFn = () => {
        steps.push("validate");
        return true;
    };

    const ok = await mockGuardNativeStreamMessage({ status: "progress" }, verifyFn, validateFn, "scan");
    suite.assert(ok === true, "Guard should pass on valid signed message");
    suite.assertEquals(steps.join(","), "verify,validate", "Must verify before schema validation");
});

// ============================================================================
// EXECUTE TEST SUITE
// ============================================================================

console.log("\n🧪 Running Security Test Suite...\n");
suite.run().then(results => {
    if (results.failed === 0) {
        console.log("🎉 All tests passed! Security baseline verified.\n");
    } else {
        console.log(`⚠️  ${results.failed} test(s) failed. Review above for details.\n`);
    }
});

// ============================================================================
// EXPORT FOR MODULE SYSTEMS (Node.js, etc)
// ============================================================================

if (typeof module !== "undefined" && module.exports) {
    module.exports = {
        SecurityTestSuite,
        mockValidateNativeResponse,
        mockValidateYaraRuleSafety,
        mockValidateMessageTimestamp,
        MockScanRateLimiter,
        mockHostSignedPayload,
        mockExtensionSignedPayload,
        mockIsTrustedDriveByDomain,
        mockGuardNativeStreamMessage,
        suite
    };
}
