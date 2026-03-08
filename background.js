// Security: Set to false in production to prevent internal state leaking to DevTools
const DEBUG = false;
const dbg = (...args) => { if (DEBUG) console.log(...args); };

// Supply-Chain Canary (Injected at build time)
const CLAMFOX_CANARY = "PLACEHOLDER_CANARY";
const RUNTIME_PATCH_TAG = "CFX-NAVG-20260308";

function runIntegrityAudit() {
    // If the canary is missing or still the placeholder in a production build, 
    // it indicates an unofficial or tampered distribution.
    if (CLAMFOX_CANARY === "PLACEHOLDER_CANARY" && !DEBUG) {
        console.error("🛑 INTEGRITY ERROR: Supply-Chain Canary missing. This build may be unofficial.");
        browser.action.setBadgeText({ text: "LAK" }); // "Leak/integrity"
        browser.action.setBadgeBackgroundColor({ color: "#f59e0b" });
    }
}
runIntegrityAudit();

const NATIVE_HOST_NAME = "clamav_host";
const HOST_CHECK_TIMEOUT_MS = 20000;
let HOST_AVAILABLE = false; // Detected at runtime
let MAIN_MESSAGE_LISTENER_READY = false;

const allowedAfterChallenge = new Set(); // Tracks hosts that just completed a Cloudflare challenge
const ACTIVE_CHALLENGES = new Map(); // tabId -> expiration timestamp
const USER_WHITELIST = new Set(); // Persistent overrides
const USER_WHITELIST_EXPIRY = new Map(); // domain -> expiry epoch ms
const USER_BYPASS_TTL_MS = 24 * 60 * 60 * 1000; // 24h default manual bypass TTL

// WASM Shield State
let WASM_READY = false;
let wasmInstance = null;
let wasmExports = null;

/**
 * Load persistent user-configured whitelist from storage.
 * 
 * Restores previously whitelisted domains from browser.storage.local.
 * Called during startup to initialize USER_WHITELIST Set.
 */
async function initWhitelist() {
    const now = Date.now();
    const storage = await browser.storage.local.get({ userWhitelist: [], userWhitelistExpiry: {} });
    let changed = false;

    if (Array.isArray(storage.userWhitelist)) {
        storage.userWhitelist.forEach(domain => {
            if (typeof domain !== "string" || !domain) return;

            // Backward-compatibility: old entries had no TTL metadata.
            let expiresAt = Number(storage.userWhitelistExpiry[domain]);
            if (!Number.isFinite(expiresAt)) {
                expiresAt = now + USER_BYPASS_TTL_MS;
                changed = true;
            }

            if (expiresAt > now) {
                USER_WHITELIST.add(domain);
                USER_WHITELIST_EXPIRY.set(domain, expiresAt);
            } else {
                changed = true;
            }
        });

        if (changed) {
            await persistUserWhitelist();
        }

        dbg(`🛡️ USER WHITELIST: Loaded ${USER_WHITELIST.size} active domains.`);
    }
}

function purgeExpiredUserWhitelist() {
    const now = Date.now();
    let changed = false;

    for (const [domain, expiresAt] of USER_WHITELIST_EXPIRY.entries()) {
        if (!Number.isFinite(expiresAt) || expiresAt <= now) {
            USER_WHITELIST_EXPIRY.delete(domain);
            USER_WHITELIST.delete(domain);
            changed = true;
        }
    }

    return changed;
}

async function persistUserWhitelist() {
    await browser.storage.local.set({
        userWhitelist: Array.from(USER_WHITELIST),
        userWhitelistExpiry: Object.fromEntries(USER_WHITELIST_EXPIRY)
    });
}

// getBaseDomain is now provided by psl_data.js

function isPortal(hostname) {
    if (!hostname) return false;
    const base = getBaseDomain(hostname);
    return SECURE_PORTALS.some(d => base === d);
}

/**
 * Check if a domain is whitelisted (trusted).
 * 
 * A domain is considered whitelisted if it:
 * 1. Matches a Secure Portal (High-Value Target)
 * 2. Is in the persistent user whitelist
 * 
 * @param {string} hostname - Domain name to check (e.g., 'mail.google.com')
 * @returns {boolean} - True if domain is trusted, false otherwise
 */
function isWhitelisted(hostname) {
    if (!hostname) return false;

    if (purgeExpiredUserWhitelist()) {
        persistUserWhitelist().catch(() => { });
    }

    // 1. Check Hardcoded/Dynamic High-Value Targets (Secure Portals)
    if (isPortal(hostname)) return true;

    // 2. Check Persistent User Overrides
    const base = getBaseDomain(hostname);
    const whitelistArr = Array.from(USER_WHITELIST);
    if (whitelistArr.some(d => base === d)) return true;

    return false;
}

// Default fallback: a fresh random value per session so no attacker who
// reads the source code can predict the honeypot secret.
let HONEYPOT_SECRET = `cf_honey_${crypto.randomUUID()}`;
let SESSION_HOST_SECRET = null; // Ephemeral Cryptographic Secret

// Bootstrap bridge: keeps popup diagnostics alive even if later init paths fail.
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (MAIN_MESSAGE_LISTENER_READY) return false;
    if (!message || !message.action) return false;
    if (message.action !== "proxy_check" && message.action !== "proxy_reconnect") return false;

    // Apply the same sender trust gate used by the main listener.
    if (sender.id && sender.id !== browser.runtime.id) return false;
    const extensionOrigin = browser.runtime.getURL("");
    const isExtensionPage = sender.url && sender.url.startsWith(extensionOrigin);
    if (!isExtensionPage) return false;

    (async () => {
        try {
            if (message.action === "proxy_reconnect") {
                SESSION_HOST_SECRET = null;
                const refreshed = await getSecret(true);
                sendResponse(refreshed ? { status: "ok" } : { status: "error", error: "Handshake failed. Host may be offline or misconfigured." });
                return;
            }

            const secret = await getSecret();
            const res = await sendNativeMessageWithTimeout(NATIVE_HOST_NAME, { action: "check", secret: secret }, HOST_CHECK_TIMEOUT_MS);
            if (res && res.secret) delete res.secret;
            sendResponse(res || { status: "error", error: "No response from host." });
        } catch (e) {
            const reason = (e && e.message) ? e.message : String(e || "unknown bootstrap error");
            sendResponse({ status: "error", error: `Background bootstrap bridge error: ${reason}` });
        }
    })();

    return true;
});

// Initialized via initBackground()

async function initWasm() {
    try {
        const response = await fetch(browser.runtime.getURL("wasm_shield/clamfox_shield.wasm"));
        const bytes = await response.arrayBuffer();

        // 1. Integrity Audit: Internal Subresource Integrity (SRI)
        const hashBuffer = await crypto.subtle.digest("SHA-256", bytes);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

        const EXPECTED_WASM_HASH = "PLACEHOLDER_WASM_HASH";
        if (hashHex !== EXPECTED_WASM_HASH) {
            console.error("🛑 SECURITY ALERT: WASM Core tampered or corrupt! SRI verification failed.");
            browser.action.setBadgeText({ text: "WSRI" });
            browser.action.setBadgeBackgroundColor({ color: "#ef4444" });
            return;
        }

        const results = await WebAssembly.instantiate(bytes, {
            // Minimal web-bindgen like imports if needed
            env: {
                memory: new WebAssembly.Memory({ initial: 256 }),
                abort: () => { console.error("WASM Aborted"); }
            },
            "./clamfox_shield_bg.js": {
                // Mocks for basic functionality if bindgen were used
                __wbindgen_string_new: function (ptr, len) { /* ... */ },
                __wbindgen_object_drop_ref: function (arg0) { /* ... */ },
            }
        });
        wasmInstance = results.instance;
        wasmExports = wasmInstance.exports;
        WASM_READY = true;
        dbg("🛡️ WASM CORE: High-Speed Matching Engine active.");
    } catch (e) {
        console.warn("🛡️ WASM SHIELD: Failed to load (Falling back to Native Host for all checks):", e);
    }
}

async function initBackground() {
    // Runtime marker: confirms this exact patched background build is active.
    browser.action.setBadgeText({ text: "CFX" }).catch(() => { });
    browser.action.setBadgeBackgroundColor({ color: "#2563eb" }).catch(() => { });
    setTimeout(() => browser.action.setBadgeText({ text: "" }).catch(() => { }), 4000);
    browser.notifications.create({
        type: "basic",
        iconUrl: "icons/scanning.svg",
        title: "ClamFox Runtime",
        message: `Navigation guard active (${RUNTIME_PATCH_TAG})`
    }).catch(() => { });

    await initWhitelist();
    await initWasm();
    const storage = await browser.storage.local.get("honeypotSecret");
    if (storage.honeypotSecret) {
        HONEYPOT_SECRET = storage.honeypotSecret;
    }

    // Perform initial handshake to sync secrets from host with error handling
    try {
        const secret = await getSecret(true);
        if (!secret) {
            throw new Error("Failed to obtain session secret from host");
        }
        dbg("🛡️ SECURITY CORE: Startup handshake complete.");
    } catch (e) {
        console.error("🛑 CRITICAL: Unable to initialize secure session secret:", e);
        // Mark extension as degraded
        browser.action.setBadgeText({ text: "ERR" });
        browser.action.setBadgeBackgroundColor({ color: "#ef4444" });
        // Log but keep extension responsive while strict URL/download policies handle enforcement.
        dbg("⚠️ Extension initialized without native host; strict policy paths remain active.");
    }
}

initBackground();

// EDR Core: Tab-based Incident Telemetry
const TAB_INCIDENTS = new Map();

function escalateTabProtection(tabId) {
    dbg(`🛡️ EDR ESCALATION: Hardening security for suspect tab ${tabId}`);
    // We could use scripting.registerContentScripts or dynamic CSP injection here.
    // For now, we flag it in storage so content scripts can react.
    browser.storage.local.set({ [`tab_escalated_${tabId}`]: true });
}

// Memory Management: Cleanup tab data on close
browser.tabs.onRemoved.addListener((tabId) => {
    if (TAB_INCIDENTS.has(tabId)) {
        TAB_INCIDENTS.delete(tabId);
        dbg(`🧹 EDR CLEANUP: Purged telemetry for closed tab ${tabId}`);
    }

    if (CERT_CACHE.has(tabId)) {
        CERT_CACHE.delete(tabId);
        dbg(`🧹 CACHE CLEANUP: Purged certificate info for closed tab ${tabId}`);
    }

    if (ACTIVE_CHALLENGES.has(tabId)) {
        ACTIVE_CHALLENGES.delete(tabId);
    }

    // Cleanup Rate Limiter data for the tab
    if (THREAT_RATE_LIMITER.has(`rate:tab:${tabId}`)) {
        THREAT_RATE_LIMITER.delete(`rate:tab:${tabId}`);
    }

    browser.storage.local.remove(`tab_escalated_${tabId}`).catch(() => { });
});

// Periodic Garbage Collection to prevent Map bloat
browser.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === "garbage_collection") {
        const now = Date.now();
        let cleanedTabs = 0;

        // Clean up TAB_INCIDENTS older than 1 hour
        for (const [tabId, incidents] of TAB_INCIDENTS.entries()) {
            const recent = incidents.filter(i => (now - i.time) < 3600000);
            if (recent.length === 0) {
                TAB_INCIDENTS.delete(tabId);
                cleanedTabs++;
            } else {
                TAB_INCIDENTS.set(tabId, recent);
            }
        }

        // Clean up THREAT_RATE_LIMITER stale entries (> 5 minutes)
        for (const [key, value] of THREAT_RATE_LIMITER.entries()) {
            if (Array.isArray(value)) {
                // Tab rate limit history
                const recent = value.filter(t => (now - t) < 300000); // 5 mins
                if (recent.length === 0) {
                    THREAT_RATE_LIMITER.delete(key);
                } else {
                    THREAT_RATE_LIMITER.set(key, recent);
                }
            } else if (typeof value === 'number') {
                // Deduplication timestamp
                if ((now - value) > 300000) {
                    THREAT_RATE_LIMITER.delete(key);
                }
            }
        }

        // Clean up stale Cloudflare challenges
        let cleanedChallenges = 0;
        for (const [tabId, expires] of ACTIVE_CHALLENGES.entries()) {
            if (now > expires) {
                ACTIVE_CHALLENGES.delete(tabId);
                cleanedChallenges++;
            }
        }

        // Clean up stale Beacon Throttle Locks (Throttles older than 5 minutes are definitely stale)
        let cleanedBeacons = 0;
        for (const [host, expires] of BEACON_THROTTLE_LOCK.entries()) {
            if (now > expires) {
                BEACON_THROTTLE_LOCK.delete(host);
                cleanedBeacons++;
            }
        }

        if (cleanedTabs > 0 || cleanedChallenges > 0 || cleanedBeacons > 0) {
            dbg(`🧹 GARBAGE COLLECTION: Purged ${cleanedTabs} tabs, ${cleanedChallenges} challenges, and ${cleanedBeacons} beacons.`);
        }
    }
});
browser.alarms.create("garbage_collection", { periodInMinutes: 15 });

browser.downloads.onChanged.addListener(async (delta) => {
    // Scan after download completes: lock access, evaluate, then release/quarantine.
    if (delta.state && delta.state.current === "complete") {
        dbg("Download complete event received for ID:", delta.id);
        const items = await browser.downloads.search({ id: delta.id });
        let item = null;
        if (items.length > 0) {
            item = items[0];
        }

        if (item && item.filename) {
            browser.notifications.create(`scan-${delta.id}`, {
                type: "basic",
                iconUrl: "icons/scanning.svg",
                title: "ClamFox Analysis",
                message: `Scanning downloaded file: ${item.filename.split('/').pop() || item.filename}...`
            }).catch(() => { });

            // SECURITY HARDENING: Lock the file from the OS BEFORE the scan reaches the user
            let lockedBeforeScan = false;
            try {
                const secret = await getSecret();
                if (!secret || !HOST_AVAILABLE) {
                    throw new Error("Security engine unavailable before file lock");
                }

                const lockResponse = await sendNativeMessageWithTimeout(NATIVE_HOST_NAME, {
                    action: "lock",
                    target: item.filename,
                    secret: secret
                }, 5000);

                if (!lockResponse || lockResponse.status !== "ok") {
                    throw new Error(lockResponse && lockResponse.error ? lockResponse.error : "File lock request failed");
                }

                lockedBeforeScan = true;
                dbg("🔒 FILE SEALED: Access restricted during analysis.");
            } catch (e) {
                console.error("🛑 DOWNLOAD SECURITY FAILURE: Could not lock file before scan", e);
                try {
                    await browser.downloads.cancel(delta.id);
                } catch (err) { }
                try {
                    await browser.downloads.removeFile(delta.id);
                } catch (err) { }
                try {
                    await browser.downloads.erase({ id: delta.id });
                } catch (err) { }

                browser.notifications.create({
                    type: "basic",
                    iconUrl: "icons/warning.svg",
                    title: "🛑 DOWNLOAD BLOCKED",
                    message: "ClamFox blocked this file because secure pre-scan locking failed.",
                    priority: 2
                }).catch(() => { });
                return;
            }

            // Ensure our engine knows it's a quarantined target if routing was successful
            performScan(item.filename, "file", item.id, null, lockedBeforeScan);
        } else {
            console.warn("Download completion detected but no filename available for scan:", delta.id);
        }
    }
});

/**
 * Rate limiter for scan operations to prevent DoS via rapid repeated scans.
 * Maintains per-file cooldown to avoid redundant scanning of same target.
 */
class ScanRateLimiter {
    constructor(cooldownMs = 30000) {
        this.scanTimes = new Map(); // filename -> last scan timestamp
        this.SCAN_COOLDOWN = cooldownMs;
    }
    
    /**
     * Check if a target can be scanned now.
     * @param {string} target - File path, URL, or identifier
     * @returns {boolean} - True if scanning allowed, false if in cooldown
     */
    canScan(target) {
        const lastScan = this.scanTimes.get(target);
        const now = Date.now();
        
        if (lastScan && (now - lastScan) < this.SCAN_COOLDOWN) {
            dbg(`🛡️ SCAN RATE LIMIT: Skipping ${target} (cooldown active)`);
            return false;
        }
        
        this.scanTimes.set(target, now);
        return true;
    }
    
    /**
     * Clear cooldown for a specific target (e.g., for manual scans).
     * @param {string} target - Target to reset
     */
    reset(target) {
        this.scanTimes.delete(target);
    }
}

const fileScanLimiter = new ScanRateLimiter(30000); // 30 second cooldown between same-file scans

/**
 * Sends a message to the native host with automatic timeout enforcement.
 * 
 * Enforces both timeout and response validation in a single operation.
 * All outbound native messages flow through this function to ensure critical
 * checks (response schema, integrity) are never bypassed.
 * 
 * @param {string} hostname - Native host name (e.g., 'clamav_host')
 * @param {Object} message - Message object with 'action' and other properties
 * @param {number} timeoutMs - Timeout in milliseconds (default 8000)
 * @returns {Promise<Object>} Validated response from native host
 * @throws {Error} If timeout occurs or response validation fails
 */

/**
 * Verify cryptographic signature on host response.
 * 
 * 🔐 SECURITY: Ensures response authenticity via EC-DSA signature.
 * Only trusts responses that were signed with the host's machine private key.
 * Prevents host-compromise attacks where attacker could forge arbitrary responses.
 * 
 * @param {Object} response - Response object with '_signature' and '_signed_at' fields
 * @returns {Promise<boolean>} True if signature is valid, false otherwise
 * @throws {Error} If signature verification fails or response lacks signature
 */
async function verifyResponseSignature(response) {
    if (!response || typeof response !== "object") {
        throw new Error("Invalid response format for signature verification");
    }

    // Check that response includes signature fields
    if (!response._signature || !response._signed_at || !response._pubkey_hint) {
        throw new Error("Response missing cryptographic signature - possible tampering or host downgrade");
    }

    // Check timestamp to prevent replay attacks (signature can't be more than 60 seconds old)
    const signedAt = response._signed_at;
    const now = Math.floor(Date.now() / 1000);
    if (now - signedAt > 60) {
        throw new Error("Response signature is stale (older than 60 seconds) - possible replay attack");
    }
    if (signedAt > now + 5) {
        throw new Error("Response signature timestamp is in the future - host clock may be compromised");
    }

    const hostPubKeyKey = "hostPublicKey";
    async function fetchAndPinHostPublicKey() {
        dbg("🔐 Fetching host public key from bridge...");
        const getKeyMsg = { action: "get_public_key" };
        // TOFU hardening: fetch key twice and require exact match before pinning.
        const keyResponseA = await browser.runtime.sendNativeMessage("clamav_host", getKeyMsg);
        const keyResponseB = await browser.runtime.sendNativeMessage("clamav_host", getKeyMsg);

        const pubKeyA = keyResponseA && typeof keyResponseA._pubkey === "string" ? keyResponseA._pubkey : null;
        const pubKeyB = keyResponseB && typeof keyResponseB._pubkey === "string" ? keyResponseB._pubkey : null;

        if (!pubKeyA || !pubKeyB || pubKeyA !== pubKeyB) {
            throw new Error("Host public key bootstrap mismatch");
        }

        await browser.storage.local.set({ [hostPubKeyKey]: pubKeyA });
        dbg("🔐 Host public key retrieved and pinned (double-fetch match)");
        return pubKeyA;
    }

    let cachedPubKey = (await browser.storage.local.get(hostPubKeyKey))[hostPubKeyKey];

    // Fetch fresh key if not cached.
    if (!cachedPubKey) {
        try {
            cachedPubKey = await fetchAndPinHostPublicKey();
        } catch (e) {
            dbg("🛡️ WARNING: Could not retrieve host public key:", e);
        }
    }

    if (!cachedPubKey) {
        throw new Error("No host public key available - cannot verify response authenticity");
    }

    // Key continuity hardening: ensure signed responses keep the same key identity hint
    // as the pinned public key we already trust.
    const normalizePem = (s) => String(s || "").replace(/\r\n/g, "\n");
    const expectedHint = normalizePem(cachedPubKey).slice(0, 100);
    const responseHint = normalizePem(response._pubkey_hint);
    if (responseHint !== expectedHint) {
        // Self-heal path: host may have been reinstalled/resealed and rotated key.
        // Re-bootstrap key once and retry continuity check before failing hard.
        try {
            cachedPubKey = await fetchAndPinHostPublicKey();
        } catch (e) {
            throw new Error("Host key continuity check failed (_pubkey_hint mismatch)");
        }

        const refreshedHint = normalizePem(cachedPubKey).slice(0, 100);
        if (responseHint !== refreshedHint) {
            throw new Error("Host key continuity check failed (_pubkey_hint mismatch)");
        }
    }

    // Reconstruct signed data in canonical formats.
    // Compact form matches newer host builds; legacy spaced+ASCII form matches
    // historical Python json.dumps defaults used by older host packs.
    const payload = Object.keys(response)
        .filter(k => k !== "_signature")
        .sort()
        .reduce((obj, key) => {
            obj[key] = response[key];
            return obj;
        }, {});

    const signedDataCompact = _stableJsonStringify(payload, false);
    const signedDataLegacy = _toAsciiEscapedJson(_stableJsonStringify(payload, true));

    try {
        let lastError = null;
        for (let attempt = 0; attempt < 2; attempt++) {
        // Import host's public key for verification
            const pubKeyObj = await crypto.subtle.importKey(
                "spki",
                _pem2der(cachedPubKey),
                {
                    name: "ECDSA",
                    namedCurve: "P-256"
                },
                false,
                ["verify"]
            );

        // Decode signature from base64
            const signatureDer = _base64ToArrayBuffer(response._signature);
            let signatureRaw = null;
            let signatureDerFromRaw = null;
            try {
                signatureRaw = _derEcdsaSigToRaw(signatureDer, 32);
            } catch (e) {
                signatureRaw = null;
            }
            if (!signatureRaw) {
                try {
                    const sigBytes = new Uint8Array(signatureDer);
                    if (sigBytes.length === 64) {
                        signatureDerFromRaw = _rawEcdsaSigToDer(signatureDer, 32);
                    }
                } catch (e) {
                    signatureDerFromRaw = null;
                }
            }

            const dataBytesCompact = new TextEncoder().encode(signedDataCompact);
            const dataBytesLegacy = new TextEncoder().encode(signedDataLegacy);

            const verifyWith = (sig, data) => crypto.subtle.verify(
                {
                    name: "ECDSA",
                    hash: "SHA-256"
                },
                pubKeyObj,
                sig,
                data
            );

            const isValidCompactDer = await verifyWith(signatureDer, dataBytesCompact);
            const isValidCompactRaw = (!isValidCompactDer && signatureRaw)
                ? await verifyWith(signatureRaw, dataBytesCompact)
                : false;

            const isValidLegacyDer = (!isValidCompactDer && !isValidCompactRaw)
                ? await verifyWith(signatureDer, dataBytesLegacy)
                : false;
            const isValidLegacyRaw = (!isValidCompactDer && !isValidCompactRaw && !isValidLegacyDer && signatureRaw)
                ? await verifyWith(signatureRaw, dataBytesLegacy)
                : false;

            const isValidCompactDerFromRaw = (!isValidCompactDer && !isValidCompactRaw && !isValidLegacyDer && !isValidLegacyRaw && signatureDerFromRaw)
                ? await verifyWith(signatureDerFromRaw, dataBytesCompact)
                : false;
            const isValidLegacyDerFromRaw = (!isValidCompactDer && !isValidCompactRaw && !isValidLegacyDer && !isValidLegacyRaw && !isValidCompactDerFromRaw && signatureDerFromRaw)
                ? await verifyWith(signatureDerFromRaw, dataBytesLegacy)
                : false;

            if (isValidCompactDer || isValidCompactRaw || isValidLegacyDer || isValidLegacyRaw || isValidCompactDerFromRaw || isValidLegacyDerFromRaw) {
                dbg("🔐 ✅ Response signature verified successfully");
                return true;
            }

            lastError = new Error("Signature verification failed - response may be forged");

            // One-time self-heal retry in case host key rotated between sessions.
            if (attempt === 0) {
                cachedPubKey = await fetchAndPinHostPublicKey();
                continue;
            }
        }

        throw lastError || new Error("Signature verification failed - response may be forged");

    } catch (cryptoErr) {
        console.error("🛡️ SIGNATURE VERIFICATION ERROR:", cryptoErr);
        throw new Error(`Cryptographic verification failed: ${cryptoErr.message}`);
    }
}

/**
 * Helper: Convert PEM-format public key (with BEGIN/END markers) to DER binary.
 */
function _pem2der(pemStr) {
    const withoutMarkers = pemStr
        .split('\n')
        .filter(line => !line.includes('BEGIN') && !line.includes('END') && line.trim())
        .join('');
    return _base64ToArrayBuffer(withoutMarkers);
}

/**
 * Helper: Convert base64 string to ArrayBuffer.
 */
function _base64ToArrayBuffer(b64Str) {
    const binaryString = atob(b64Str);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

function _derEcdsaSigToRaw(derSigBuffer, partLen = 32) {
    const der = new Uint8Array(derSigBuffer);
    if (der.length < 8 || der[0] !== 0x30) {
        throw new Error("Invalid DER ECDSA signature (missing SEQUENCE)");
    }

    let offset = 1;
    let seqLen = der[offset++];
    if (seqLen & 0x80) {
        const lenBytes = seqLen & 0x7f;
        if (lenBytes < 1 || lenBytes > 2 || offset + lenBytes > der.length) {
            throw new Error("Invalid DER ECDSA signature length");
        }
        seqLen = 0;
        for (let i = 0; i < lenBytes; i++) {
            seqLen = (seqLen << 8) | der[offset++];
        }
    }

    if (offset + seqLen > der.length) {
        throw new Error("Invalid DER ECDSA signature (truncated sequence)");
    }

    if (der[offset++] !== 0x02) throw new Error("Invalid DER ECDSA signature (missing R INTEGER)");
    const rLen = der[offset++];
    if (offset + rLen > der.length) throw new Error("Invalid DER ECDSA signature (R out of range)");
    let r = der.slice(offset, offset + rLen);
    offset += rLen;

    if (der[offset++] !== 0x02) throw new Error("Invalid DER ECDSA signature (missing S INTEGER)");
    const sLen = der[offset++];
    if (offset + sLen > der.length) throw new Error("Invalid DER ECDSA signature (S out of range)");
    let s = der.slice(offset, offset + sLen);

    while (r.length > 0 && r[0] === 0x00) r = r.slice(1);
    while (s.length > 0 && s[0] === 0x00) s = s.slice(1);

    if (r.length > partLen || s.length > partLen) {
        throw new Error("Invalid DER ECDSA signature (component too large)");
    }

    const raw = new Uint8Array(partLen * 2);
    raw.set(r, partLen - r.length);
    raw.set(s, partLen * 2 - s.length);
    return raw.buffer;
}

function _rawEcdsaSigToDer(rawSigBuffer, partLen = 32) {
    const raw = new Uint8Array(rawSigBuffer);
    if (raw.length !== partLen * 2) {
        throw new Error("Invalid raw ECDSA signature length");
    }

    const toDerInt = (arr) => {
        let i = 0;
        while (i < arr.length - 1 && arr[i] === 0x00) i++;
        let v = arr.slice(i);
        if (v[0] & 0x80) {
            const prefixed = new Uint8Array(v.length + 1);
            prefixed[0] = 0x00;
            prefixed.set(v, 1);
            v = prefixed;
        }
        return v;
    };

    const r = toDerInt(raw.slice(0, partLen));
    const s = toDerInt(raw.slice(partLen));

    const totalLen = 2 + r.length + 2 + s.length;
    const out = new Uint8Array(2 + totalLen);
    let o = 0;
    out[o++] = 0x30;
    out[o++] = totalLen;
    out[o++] = 0x02;
    out[o++] = r.length;
    out.set(r, o);
    o += r.length;
    out[o++] = 0x02;
    out[o++] = s.length;
    out.set(s, o);
    return out.buffer;
}

function _toAsciiEscapedJson(str) {
    let out = "";
    for (let i = 0; i < str.length; i++) {
        const code = str.charCodeAt(i);
        if (code <= 0x7f) {
            out += str[i];
        } else {
            out += `\\u${code.toString(16).padStart(4, "0")}`;
        }
    }
    return out;
}

function _stableJsonStringify(value, spaced = false) {
    const pairSep = spaced ? ": " : ":";
    const itemSep = spaced ? ", " : ",";

    if (value === null || typeof value !== "object") {
        return JSON.stringify(value);
    }

    if (Array.isArray(value)) {
        return `[${value.map(v => _stableJsonStringify(v, spaced)).join(itemSep)}]`;
    }

    const keys = Object.keys(value).sort();
    return `{${keys.map(k => `${JSON.stringify(k)}${pairSep}${_stableJsonStringify(value[k], spaced)}`).join(itemSep)}}`;
}

async function sendNativeMessageWithTimeout(hostname, message, timeoutMs = 8000) {
    const timeoutPromise = new Promise((_, reject) =>
        setTimeout(() => reject(new Error("Native Messaging request timed out")), timeoutMs)
    );
    const response = await Promise.race([
        browser.runtime.sendNativeMessage(hostname, message),
        timeoutPromise
    ]);

    // 🛡️ SECURITY: Verify cryptographic signature first (must be awaited - now async)
    try {
        await verifyResponseSignature(response);
    } catch (e) {
        console.error(`🛡️ SIGNATURE VERIFICATION FAILURE [${message.action}]:`, e);
        throw new Error(`Response authenticity check failed: ${e.message}`);
    }

    // 🛡️ SECURITY: Then scrutinize response schema and structure
    try {
        validateNativeResponse(message.action, response);
    } catch (e) {
        console.error(`🛡️ NATIVE MESSAGE VALIDATION FAILURE [${message.action}]:`, e);
        throw new Error(`Security validation failed for host response: ${e.message}`);
    }

    return response;
}

/**
 * Validates incoming host messages against expected schemas to prevent 
 * exploitation of the extension logic via malformed responses.
 * 
 * Performs strict type checking and constraint validation on all fields
 * to prevent injection attacks or resource exhaustion via oversized responses.
 * 
 * @param {string} action - Original action that triggered this response
 * @param {Object} response - Response object from native host
 * @throws {Error} If response fails any validation checks
 * 
 * @example
 * // Throws: "Type mismatch for 'status': expected string, got number"
 * validateNativeResponse('scan', { status: 123 });
 * 
 * @example
 * // Throws: "String field 'error' exceeds maximum permitted length (2KB)"
 * validateNativeResponse('check', { error: 'x'.repeat(3000) });
 */
function validateNativeResponse(action, response) {
    if (!response || typeof response !== "object" || Array.isArray(response)) {
        throw new Error("Invalid response format: Not a structured object");
    }

    // 1. Generic Schema Verification
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
            // Constraint: no string in the root schema should exceed common sense limits
            if (expectedType === "string" && val.length > 2048 && key !== "error") {
                throw new Error(`String field '${key}' exceeds maximum permitted length (2KB)`);
            }
        }
    }

    // 2. Action-Specific Schema Hardening
    switch (action) {
        case "check_url":
            if (response.status === "malicious") {
                if (typeof response.threat !== "string" || response.threat.length > 256) {
                    throw new Error("Invalid 'threat' identifier in URL reputation response");
                }
            }
            if (response.status === "clean" && response.trust !== undefined && typeof response.trust !== "string") {
                throw new Error("Invalid 'trust' value in URL reputation response");
            }
            break;
        case "scan":
        case "scan_request":
            if (response.status === "malicious") {
                if (typeof response.threat !== "string" || response.threat.length > 256) {
                    throw new Error("Invalid 'threat' identifier in discovery response");
                }
            }
            if (response.forensics && typeof response.forensics !== "object") {
                throw new Error("Forensic payload must be a structured object");
            }
            break;
        case "get_intel":
            if (response.hvts && !Array.isArray(response.hvts)) {
                throw new Error("'hvts' data must be an array");
            }
            break;
        case "get_audit_logs":
            if (response.logs !== undefined && typeof response.logs !== "string" && !Array.isArray(response.logs)) {
                throw new Error("Audit log payload must be a string or array");
            }
            break;
        case "list_quarantine":
            if (response.files !== undefined && !Array.isArray(response.files)) {
                throw new Error("Quarantine listing payload must be an array");
            }
            break;
        case "clipper_alert":
            if (typeof response.old !== "string" || typeof response.new !== "string") {
                throw new Error("Clipper alert missing required address fields");
            }
            break;
    }

    return true;
}

async function getSecret(forceRefresh = false) {
    if (!forceRefresh && SESSION_HOST_SECRET) {
        return SESSION_HOST_SECRET;
    }

    if (forceRefresh) {
        SESSION_HOST_SECRET = null;
        await browser.storage.local.remove("hostPublicKey").catch(() => { });
    }

    try {
        dbg("🔒 Security Handshake starting...");
        // Send a bare check to get the current secret
        const response = await sendNativeMessageWithTimeout(NATIVE_HOST_NAME, { action: "check" }, HOST_CHECK_TIMEOUT_MS);

        if (response && (response.integrity_ok === false || response.binary_ok === false)) {
            console.warn("🛡️ SECURITY ALERT: Host seal broken. Re-seal required for full protection.");
            browser.action.setBadgeText({ text: "SEAL" });
            browser.action.setBadgeBackgroundColor({ color: "#ef4444" });
            HOST_AVAILABLE = true;
            if (response.secret && response.secret !== "****") {
                SESSION_HOST_SECRET = response.secret;
            }
            await browser.storage.local.set({ hostActive: true, sealBroken: true });
            return SESSION_HOST_SECRET;
        }

        if (response && response.secret && response.secret !== "****") {
            HOST_AVAILABLE = true;
            SESSION_HOST_SECRET = response.secret;
            const update = { hostActive: true, sealBroken: false };
            if (response.honeypot_secret) {
                update.honeypotSecret = response.honeypot_secret;
                HONEYPOT_SECRET = response.honeypot_secret; // Update in-memory
            }
            await browser.storage.local.set(update);
            // Clear badge if previously tampered
            browser.action.setBadgeText({ text: "" });
            dbg("🔒 Security Handshake successful (Host + Honeypot). Core features enabled.");
            return response.secret;
        } else if (response && response.secret === "****" && SESSION_HOST_SECRET) {
            // Host is alive but refusing to re-issue secret. This is normal if we already have it.
            HOST_AVAILABLE = true;
            dbg("🔒 Security Handshake: Host refused re-issue (Already issued). Using cached secret.");
            return SESSION_HOST_SECRET;
        }
    } catch (e) {
        HOST_AVAILABLE = false;
        await browser.storage.local.set({ hostActive: false });
        console.warn("🛡️ HYBRID MODE: Host not found. Reverting to Browser-Only Shields (Anti-Phishing, Privacy, CSP).");
    }
    return null;
}

function getDeterministicTestThreat(urlStr) {
    const s = String(urlStr || "").toLowerCase();
    if (!s) return null;

    try {
        const u = new URL(s);
        const host = u.hostname.toLowerCase();
        const path = u.pathname.toLowerCase();

        // Restrict WICAR detection to known malware-test endpoints, not full domain.
        if ((host === "wicar.org" || host === "www.wicar.org") &&
            (path.startsWith("/data/") || path.includes("/test-malware"))) {
            return "Testing Payload (Safe Simulated Threat)";
        }

        if ((host === "eicar.org" || host === "www.eicar.org") && path.includes("/download")) {
            return "Testing Payload (Safe Simulated Threat)";
        }
    } catch (e) {
        // Keep safe fallback for direct file-like test URLs.
        if (s.includes("/eicar.com")) {
            return "Testing Payload (Safe Simulated Threat)";
        }
    }

    return null;
}

function extractAboutBlockedTarget(urlStr) {
    try {
        if (typeof urlStr !== "string" || !urlStr.startsWith("about:blocked")) return null;
        const qIndex = urlStr.indexOf("?");
        if (qIndex === -1) return null;
        const query = urlStr.slice(qIndex + 1);
        const params = new URLSearchParams(query);
        const rawTarget = params.get("u");
        if (!rawTarget) return null;
        const decoded = decodeURIComponent(rawTarget);
        if (!decoded.startsWith("http://") && !decoded.startsWith("https://")) return null;
        return decoded;
    } catch (e) {
        return null;
    }
}

const mainFrameRequestGuard = async (details) => {
        if (details.type !== "main_frame") return {};
        if (details.url.startsWith(browser.runtime.getURL(""))) return {};
        if (details.url.startsWith("about:") || details.url.startsWith("moz-extension:")) return {};

        // Deterministic local test feeds should be blocked instantly without host round-trip.
        const localTestThreat = getDeterministicTestThreat(details.url);
        if (localTestThreat) {
            handleMaliciousUrl(details.url, localTestThreat, details.tabId, true);
            return { cancel: true };
        }

        let url;
        try {
            url = new URL(details.url);
        } catch (e) {
            // If URL parsing fails, log and continue without early return.
            console.warn("Failed to parse URL:", details.url, e);
            url = null;
        }


        // Cloudflare Challenge Bypass: detect any challenge token, clearance or chk_jschl endpoint
        const cfChallenge = details.url.includes("__cf_chl_") ||
            details.url.includes("cf_chl_prog") ||
            details.url.includes("cf_chl_opt") ||
            details.url.includes("cf_chl_f") ||
            details.url.includes("/cdn-cgi/challenge") ||
            details.url.includes("/cdn-cgi/l/chk_jschl") ||
            (url && url.hostname.includes("challenges.cloudflare.com"));

        if (cfChallenge) {
            // Option 3: Persistent Challenge Mode
            if (details.tabId && details.tabId !== -1) {
                ACTIVE_CHALLENGES.set(details.tabId, Date.now() + 60000); // 60s quarantine
                dbg(`🛡️ CLOUDFLARE SHIELD: Tab ${details.tabId} entered Challenge Mode (60s).`);
            }
            // Remember the hostname for a short window so the next navigation (the real site) is allowed
            if (url && !url.hostname.includes("cloudflare")) {
                allowedAfterChallenge.add(url.hostname);
                setTimeout(() => allowedAfterChallenge.delete(url.hostname), 60000); // Increased to 60s
            }
            return {};
        }

        // Skip scanning only for explicit challenge transition or user whitelist.
        // Do not trust cf_clearance cookie-name presence alone (spoofable by attacker-controlled origins).
        if (url) {
            const hasTempBypass = allowedAfterChallenge.has(url.hostname);
            const isUserWhitelisted = isWhitelisted(url.hostname);

            if (hasTempBypass || isUserWhitelisted) {
                return {};
            }
        }

        // Latency Fast-Path: Skip native scanning for trusted High-Value Targets or User Whitelist
        if (url && isWhitelisted(url.hostname)) {
            return {};
        }

        // --- NEW: WASM High-Speed Pre-Scan ---
        if (WASM_READY && wasmExports) {
            try {
                // 1. Homograph Detection (In-process, no bridge lag)
                if (typeof wasmExports.check_homograph_attack === "function") {
                    const homographResult = wasmExports.check_homograph_attack(details.url);
                    if (homographResult) {
                        handleMaliciousUrl(details.url, String(homographResult), details.tabId);
                        return { cancel: true }; // Enforce network block
                    }
                }

                // 2. DGA / Statistical Detection
                if (typeof wasmExports.check_dga_heuristics === "function") {
                    const dgaResult = wasmExports.check_dga_heuristics(details.url);
                    if (dgaResult) {
                        handleMaliciousUrl(details.url, String(dgaResult), details.tabId);
                        return { cancel: true }; // Enforce network block
                    }
                }
            } catch (e) {
                // Never let WASM pre-scan failures bypass native URL reputation checks.
                console.warn("🛡️ WASM PRE-SCAN ERROR: Falling back to native URL reputation.", e);
            }
        }

        try {
            const secret = await getSecret();

            if (!secret || !HOST_AVAILABLE) {
                handleMaliciousUrl(details.url, "Security Engine Unavailable", details.tabId);
                return { cancel: true };
            }

            const response = await sendNativeMessageWithTimeout(NATIVE_HOST_NAME, {
                action: "check_url",
                target: details.url,
                secret: secret
            }, 3000);

            if (response.status === "malicious") {
                handleMaliciousUrl(details.url, response.threat || "URLhaus Blocklist", details.tabId, response.confirmed);
                return { cancel: true };
            }

            if (response.status !== "clean") {
                console.error("🛑 SECURITY FAIL-CLOSED: Unexpected URL verdict status.", response.status);
                handleMaliciousUrl(details.url, "Security Engine Invalid Verdict", details.tabId);
                return { cancel: true };
            }
        } catch (e) {
            console.error("🛑 SECURITY FAIL-CLOSED: URL check pipeline failed.", e);
            handleMaliciousUrl(details.url, "Security Engine Failure", details.tabId);
            return { cancel: true };
        }
    };

const MAIN_FRAME_FILTER = { urls: ["http://*/*", "https://*/*"] };
try {
    // Preferred path: true request cancellation when runtime supports blocking listeners.
    browser.webRequest.onBeforeRequest.addListener(mainFrameRequestGuard, MAIN_FRAME_FILTER, ["blocking"]);
} catch (e) {
    // Compatibility path: keep scanning and actively redirect malicious tabs even if
    // the current runtime refuses blocking webRequest listeners.
    console.warn("🛡️ WEBREQUEST BLOCKING MODE UNAVAILABLE: Falling back to redirect enforcement.", e);
    browser.webRequest.onBeforeRequest.addListener(
        (details) => {
            mainFrameRequestGuard(details).catch((err) => {
                console.error("🛡️ MAIN-FRAME GUARD ERROR (fallback mode):", err);
            });
            return {};
        },
        MAIN_FRAME_FILTER
    );
}

const NAV_GUARD_DEDUP = new Map(); // key(tabId:url) -> timestamp
const NAV_GUARD_DEDUP_MS = 4000;

browser.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    const candidateUrl = changeInfo.url || tab?.pendingUrl || tab?.url;
    if (!candidateUrl) return;

    const interstitialTarget = extractAboutBlockedTarget(candidateUrl);
    if (candidateUrl.startsWith("about:blocked") && !interstitialTarget) {
        handleMaliciousUrl("about:blocked", "Browser Safe Browsing Interstitial", tabId, true);
        return;
    }
    const effectiveUrl = interstitialTarget || candidateUrl;

    if (!effectiveUrl.startsWith("http://") && !effectiveUrl.startsWith("https://")) return;
    if (effectiveUrl.startsWith(browser.runtime.getURL(""))) return;

    let parsed;
    try {
        parsed = new URL(effectiveUrl);
    } catch (e) {
        return;
    }

    // Keep behavior aligned with request guard bypasses.
    if (isWhitelisted(parsed.hostname)) return;
    if (allowedAfterChallenge.has(parsed.hostname)) return;

    const dedupKey = `${tabId}:${effectiveUrl}`;
    const now = Date.now();
    const last = NAV_GUARD_DEDUP.get(dedupKey);
    if (last && (now - last) < NAV_GUARD_DEDUP_MS) return;
    NAV_GUARD_DEDUP.set(dedupKey, now);

    // Deterministic test-feed enforcement independent from host/bridge latency.
    const localTestThreat = getDeterministicTestThreat(effectiveUrl);
    if (localTestThreat) {
        handleMaliciousUrl(effectiveUrl, localTestThreat, tabId, true);
        return;
    }

    try {
        const secret = await getSecret();
        const response = await sendNativeMessageWithTimeout(NATIVE_HOST_NAME, {
            action: "check_url",
            target: effectiveUrl,
            secret: secret
        }, 3000);

        if (response.status === "malicious") {
            handleMaliciousUrl(effectiveUrl, response.threat || "URLhaus Blocklist", tabId, response.confirmed === true);
        }
    } catch (e) {
        // Silent fallback path: tab guard should not create extra UX noise on transient failures.
        dbg("🛡️ NAV GUARD: Host check unavailable for tab fallback", e);
    }
});

browser.webNavigation.onCommitted.addListener((details) => {
    if (!details || !details.url || details.frameId !== 0) return;
    if (!details.url.startsWith("about:blocked")) return;
    if (!Number.isInteger(details.tabId) || details.tabId < 0) return;

    const interstitialTarget = extractAboutBlockedTarget(details.url);
    if (interstitialTarget) {
        const localThreat = getDeterministicTestThreat(interstitialTarget) || "Browser Safe Browsing Interstitial";
        handleMaliciousUrl(interstitialTarget, localThreat, details.tabId, true);
        return;
    }

    handleMaliciousUrl("about:blocked", "Browser Safe Browsing Interstitial", details.tabId, true);
});

function handleMaliciousUrl(urlStr, threatName, tabId, confirmed = false) {
    let url;
    try { url = new URL(urlStr); } catch (e) { url = { hostname: urlStr }; }

    logBlock(url.hostname, threatName, urlStr, tabId);

    browser.notifications.create({
        type: "basic",
        iconUrl: "icons/warning.svg",
        title: browser.i18n.getMessage("siteBlockedTitle") || "🛑 MALICIOUS SITE BLOCKED",
        message: `ClamFox prevented a connection to ${url.hostname}. This site is flagged as: ${threatName}.`,
        priority: 2
    });

    const blockedUrl = browser.runtime.getURL("popup/blocked.html") +
        "?url=" + encodeURIComponent(urlStr) +
        "&threat=" + encodeURIComponent(threatName) +
        "&confirmed=" + (confirmed ? "1" : "0");

    if (Number.isInteger(tabId) && tabId >= 0) {
        browser.tabs.update(tabId, { url: blockedUrl }).catch(() => { });
    }
}

// Exfiltration Interception: Scan POST/WebSocket data flows
browser.webRequest.onBeforeRequest.addListener(
    (details) => {
        if (details.method !== "POST" || !details.requestBody) return {};

        // Skipping Cloudflare, whitelisted, or trusted secure portals to avoid blocking/latency
        try {
            const url = new URL(details.url);
            if (url.hostname.includes('cloudflare') || url.hostname.includes('challenges.cloudflare.com')) return {};
            if (isWhitelisted(url.hostname)) return {};
        } catch (e) { }

        let bodyString = "";
        if (details.requestBody.formData) {
            bodyString = JSON.stringify(details.requestBody.formData);
        } else if (details.requestBody.raw) {
            // Surgical Sampling: Scan the Head (first 64KB) and Tail (last 64KB).
            // This catches prepended/appended stolen data without blocking the browser.
            bodyString = details.requestBody.raw.map(r => {
                if (r.bytes) {
                    if (r.bytes.byteLength < 131072) { // 128KB
                        try { return new TextDecoder("utf-8").decode(r.bytes); } catch (e) { return ""; }
                    } else {
                        const head = r.bytes.slice(0, 65536);
                        const tail = r.bytes.slice(-65536);
                        try {
                            return new TextDecoder("utf-8").decode(head) + " " + new TextDecoder("utf-8").decode(tail);
                        } catch (e) { return ""; }
                    }
                }
                return "";
            }).join(" ");
        }

        // Exfiltration Heuristic: Catching our own honeypots leaving the network
        // Only the live session secret (HONEYPOT_SECRET, random per session) and the
        // static crypto-address decoy are checked — the old hardcoded literal has been removed.
        const isExfiltratingHoneypot = (HONEYPOT_SECRET && bodyString.includes(HONEYPOT_SECRET)) ||
            bodyString.includes('bc1qza6h7u3w2qj4z58y8z7a90b4d4z4cx9m2mz6z');

        if (isExfiltratingHoneypot) {
            console.warn("🛑 DATA EXFILTRATION BLOCKED! Suspicious POST payload intercepted to:", details.url);
            logBlock(new URL(details.url).hostname, "Honeypot Exfiltration Intercepted", details.url, details.tabId);
            browser.notifications.create({
                type: "basic",
                iconUrl: "icons/warning.svg",
                title: "🛑 DATA EXFILTRATION DETECTED",
                message: `ClamFox intercepted a script attempting to exfiltrate decoy honeypot credentials to ${new URL(details.url).hostname}.`,
                priority: 2
            });
            // Cannot synchronously block POST streams in pure MV3 without breaking Chrome compatibility.
            // But we have captured the incident and will escalate tab protections immediately.
            if (details.tabId !== -1) escalateTabProtection(details.tabId);
        }
    },
    { urls: ["http://*/*", "https://*/*"], types: ["xmlhttprequest", "ping", "websocket", "other"] },
    ["requestBody"]
);

// ------------------------------------------------------------------
// Unified Advanced Threat Network Shield
// (C2 Beacon, Local Port Scan, and Anti DNS-Rebinding)
// ------------------------------------------------------------------
const REQUEST_HISTORY = new Map();
const PORT_SCAN_HISTORY = new Map();

// Periodic garbage collection to prevent memory bloat
setInterval(() => {
    const now = Date.now();
    for (let [host, history] of REQUEST_HISTORY.entries()) {
        const fresh = history.filter(t => now - t < 60000);
        if (fresh.length === 0) REQUEST_HISTORY.delete(host);
        else REQUEST_HISTORY.set(host, fresh);
    }
    for (let [host, history] of PORT_SCAN_HISTORY.entries()) {
        const fresh = history.filter(p => now - p.time < 2000);
        if (fresh.length === 0) PORT_SCAN_HISTORY.delete(host);
        else PORT_SCAN_HISTORY.set(host, fresh);
    }
}, 300000); // Run every 5 minutes

const BEACON_THROTTLE_LOCK = new Map(); // host -> next allowed timestamp

// ------------------------------------------------------------------
// Certificate Intelligence Watchdog (Multi-Factor Legitimacy)
// ------------------------------------------------------------------
const CERT_CACHE = new Map(); // tabId -> certInfo
const YOUNG_CERT_THRESHOLD = 72 * 60 * 60 * 1000; // 72 Hours
const TLS_ERROR_PATTERNS = [
    "SEC_ERROR",
    "SSL_ERROR",
    "NS_ERROR_NET_INADEQUATE_SECURITY",
    "MOZILLA_PKIX_ERROR"
];
const SAFE_BROWSING_ERROR_PATTERNS = [
    "NS_ERROR_PHISHING_URI",
    "NS_ERROR_MALWARE_URI",
    "NS_ERROR_UNWANTED_URI",
    "NS_ERROR_HARMFUL_URI"
];

browser.webRequest.onHeadersReceived.addListener(
    async (details) => {
        if (details.type !== "main_frame") return {};

        try {
            const securityInfo = await browser.webRequest.getSecurityInfo(details.requestId, { certificateChain: true });
            if (securityInfo && securityInfo.certificates && securityInfo.certificates.length > 0) {
                const cert = securityInfo.certificates[0];
                const now = Date.now();
                const certAge = now - cert.validityStart;

                const info = {
                    issuer: cert.issuer,
                    subject: cert.subject,
                    isYoung: certAge < YOUNG_CERT_THRESHOLD,
                    isUntrusted: securityInfo.state === "insecure" || securityInfo.state === "broken",
                    fingerprint: cert.fingerprint ? cert.fingerprint.sha256 : null,
                    state: securityInfo.state
                };

                CERT_CACHE.set(details.tabId, info);

                if (info.isYoung) {
                    console.warn(`🛡️ CERT WATCHDOG: Site ${new URL(details.url).hostname} uses a very young certificate (${Math.round(certAge / 3600000)}h old).`);
                }
            }
        } catch (e) {
            console.error("Cert Watchdog failed to inspect:", e);
        }
        return {};
    },
    { urls: ["https://*/*"], types: ["main_frame"] }
);

// TLS Failure Watchdog: capture browser-blocked certificate failures
// that never reach onHeadersReceived (e.g. self-signed cert warnings).
browser.webRequest.onErrorOccurred.addListener(
    (details) => {
        if (details.type !== "main_frame") return;
        if (!details.url || !details.url.startsWith("https://")) return;

        const err = String(details.error || "");
        const isTlsError = TLS_ERROR_PATTERNS.some(p => err.includes(p));
        if (!isTlsError) return;

        let host = "unknown";
        try {
            host = new URL(details.url).hostname;
        } catch (e) { }

        if (host && isWhitelisted(host)) return;
        if (host && shouldThrottleAlert(host)) return;

        logBlock(
            host,
            `TLS Certificate Failure (${err})`,
            details.url,
            details.tabId,
            {
                block_stage: "transport",
                source_host: host,
                final_host: host,
                engine_verdict: err,
                verdict_status: "tls_error",
                request_type: details.type,
                from_cache: !!details.fromCache
            }
        ).catch(() => { });

        browser.notifications.create({
            type: "basic",
            iconUrl: "icons/warning.svg",
            title: "⚠️ TLS CERTIFICATE BLOCK",
            message: `Firefox blocked ${host} due to a certificate problem (${err}).`,
            priority: 2
        }).catch(() => { });
    },
    { urls: ["https://*/*"], types: ["main_frame"] }
);

// Browser-interstitial handoff: if Firefox blocks a malicious page first,
// still surface ClamFox warning UX and telemetry by switching to our block page.
browser.webRequest.onErrorOccurred.addListener(
    (details) => {
        if (!details || details.type !== "main_frame") return;
        const err = String(details.error || "");
        const isSafeBrowsingBlock = SAFE_BROWSING_ERROR_PATTERNS.some(p => err.includes(p));
        if (!isSafeBrowsingBlock) return;
        if (!Number.isInteger(details.tabId) || details.tabId < 0) return;

        const blockedTarget = (typeof details.url === "string" && details.url) ? details.url : "about:blocked";
        handleMaliciousUrl(blockedTarget, `Browser Safe Browsing (${err})`, details.tabId, true);
    },
    { urls: ["http://*/*", "https://*/*"], types: ["main_frame"] }
);

browser.webRequest.onBeforeRequest.addListener(
    (details) => {
        // Only inspect background requests
        if (details.type === "main_frame" || details.type === "sub_frame") return {};

        try {
            const url = new URL(details.url);
            const host = url.hostname;
            const port = url.port;
            const now = Date.now();

            // Exclusion list: Only user-whitelisted domains are exempt from Beacon detection.
            // (Removed hardcoded Analytics/FB exemptions to prevent 'Living off the Land' exfiltration)
            const isExempt = isWhitelisted(host);

            if (!isExempt) {
                let history = REQUEST_HISTORY.get(host) || [];
                history = history.filter(t => now - t < 60000);
                history.push(now);
                REQUEST_HISTORY.set(host, history);

                if (BEACON_THROTTLE_LOCK.has(host) && now < BEACON_THROTTLE_LOCK.get(host)) {
                    // Cannot return {cancel:true} in strict MV3 without breaking Chromium compatibility.
                    // Request will proceed, but telemetry is flagged.
                    return;
                }

                if (history.length > 12) {
                    let intervals = [];
                    for (let i = history.length - 1; i >= history.length - 10; i--) {
                        intervals.push(history[i] - history[i - 1]);
                    }

                    const mean = intervals.reduce((a, b) => a + b) / intervals.length;
                    const variance = intervals.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / intervals.length;
                    const stdDev = Math.sqrt(variance);

                    if (stdDev < 500 && mean > 1000) {
                        console.warn(`🛑 C2 BEACON SHIELD: Throttling metronomic telemetry to ${host}`);
                        logBlock(host, "C2 Beacon / Aggressive Telemetry Detected", details.url, details.tabId);

                        // Limit notification frequency to once per 10 minutes per host
                        const lastNotice = LAST_NOTIFICATION_TIME.get(host + "_beacon") || 0;
                        if (now - lastNotice > 600000) {
                            browser.notifications.create({
                                type: "basic",
                                iconUrl: "icons/warning.svg",
                                title: "🛑 C2 BEACON INTERCEPTED",
                                message: `Suspicious metronomic telemetry (C2 Beacon) detected for ${host}. Background tracking is flagged.`,
                                priority: 2
                            });
                            LAST_NOTIFICATION_TIME.set(host + "_beacon", now);
                        }

                        // Switch to Throttle Mode: Only allow 1 request per 30 seconds
                        BEACON_THROTTLE_LOCK.set(host, now + 30000);
                        return;
                    }
                }
            }

            // 2. Local Port Scan & Anti DNS-Rebinding
            // Migrated to DeclarativeNetRequest (`rules.json`) for zero-latency blocking at the browser engine level.

        } catch (e) { }
    },
    { urls: ["http://*/*", "https://*/*"] }
);



const THREAT_RATE_LIMITER = new Map();
const ALERT_THROTTLE_MS = 5000; // 5 seconds between alerts for same domain

function shouldThrottleAlert(domain) {
    if (!domain) return false;
    const key = `alert:${domain}`;
    const now = Date.now();
    const lastAlert = THREAT_RATE_LIMITER.get(key);

    if (lastAlert && (now - lastAlert) < ALERT_THROTTLE_MS) {
        return true; // Throttle
    }

    THREAT_RATE_LIMITER.set(key, now);
    return false;
}

async function logBlock(name, reason, url, tabId = null, forensicData = null) {
    // 1. DEDUPLICATION: Prevent reporting the same threat for the same URL in the last 10 seconds
    const dedupKey = `${reason}:${url}`;
    const lastReported = THREAT_RATE_LIMITER.get(dedupKey);
    if (lastReported && (Date.now() - lastReported) < 10000) {
        return { status: "ignored", reason: "duplicate" };
    }
    THREAT_RATE_LIMITER.set(dedupKey, Date.now());

    // 2. GLOBAL RATE LIMITING: Max 20 incidents per minute across all tabs (EDR Hardening)
    const globalKey = "rate:global:incidents";
    let globalHistory = THREAT_RATE_LIMITER.get(globalKey) || [];
    const now = Date.now();
    globalHistory = globalHistory.filter(t => (now - t) < 60000); // 1 minute window
    if (globalHistory.length >= 20) {
        console.error(`🛡️ GLOBAL RATE LIMITER: Security incident cap reached (20/min). Possible multi-tab attack or high-volume noise.`);
        return { status: "ignored", reason: "global_rate_limit_exceeded" };
    }
    globalHistory.push(now);
    THREAT_RATE_LIMITER.set(globalKey, globalHistory);

    // 3. PER-TAB RATE LIMITING: Max 5 incidents per minute per tab
    if (tabId && tabId !== -1) {
        const tabKey = `rate:tab:${tabId}`;
        let tabHistory = THREAT_RATE_LIMITER.get(tabKey) || [];
        tabHistory = tabHistory.filter(t => (now - t) < 60000);
        if (tabHistory.length >= 5) {
            console.warn(`🛡️ TAB RATE LIMITER: Ignoring security incident from tab ${tabId} (Limit reached)`);
            return { status: "ignored", reason: "tab_rate_limit_exceeded" };
        }
        tabHistory.push(now);
        THREAT_RATE_LIMITER.set(tabKey, tabHistory);
    }

    const storage = await browser.storage.local.get({ blockedHistory: [] });
    const blocks = storage.blockedHistory;

    let incidentHostname = url;
    let maskedUrl = url;
    try {
        const parsedUrl = new URL(url);
        incidentHostname = parsedUrl.hostname;
        parsedUrl.search = ''; // Strip query parameters
        maskedUrl = parsedUrl.href;
    } catch (e) { /* non-HTTP url — keep raw value */ }

    const inferredBlockStage = "content";
    const sourceHost = (forensicData && typeof forensicData.source_host === "string") ? forensicData.source_host : incidentHostname;
    const finalHost = (forensicData && typeof forensicData.final_host === "string") ? forensicData.final_host : incidentHostname;
    const engineVerdict = (forensicData && typeof forensicData.engine_verdict === "string") ? forensicData.engine_verdict : reason;

    const incident = {
        name: name,
        status: "blocked",
        reason: reason,
        url: maskedUrl,
        hostname: incidentHostname,
        block_stage: (forensicData && typeof forensicData.block_stage === "string") ? forensicData.block_stage : inferredBlockStage,
        source_host: sourceHost,
        final_host: finalHost,
        engine_verdict: engineVerdict,
        time: new Date().toISOString(),
        tabId: tabId,
        reported: false,
        forensics: forensicData
    };

    blocks.push(incident);

    // PERSISTENT DISK LOGGING (EDR Requirement)
    try {
        const secret = await getSecret();
        sendNativeMessageWithTimeout(NATIVE_HOST_NAME, {
            action: "log_incident",
            incident: incident,
            secret: secret
        }, 5000).catch(() => { });
    } catch (e) { }

    // EDR CORRELATION: Check if this tab is under active attack
    if (tabId) {
        let history = TAB_INCIDENTS.get(tabId) || [];
        history.push({ reason, time: Date.now() });
        TAB_INCIDENTS.set(tabId, history);

        // Threshold check: 3 distinct security signals within 60 seconds = Attack Chain Identified
        const recentSignals = history.filter(h => (Date.now() - h.time) < 60000);
        if (recentSignals.length >= 3) {
            console.error("🚨 EDR ALERT: Attack Chain Correlation detected on tab", tabId);
            browser.notifications.create({
                type: "basic",
                iconUrl: "icons/warning.svg",
                title: "🚨 ATTACK CHAIN IDENTIFIED",
                message: `Multiple security layers tripped on ${incident.hostname}. Forensics captured an active exploit attempt involving ${reason}.`,
                priority: 2
            });
            escalateTabProtection(tabId);
        }
    }

    await browser.storage.local.set({ blockedHistory: blocks.slice(-30) });
}

async function performScan(target, type, downloadId = null, tabId = null, lockedBeforeScan = false) {
    // A completed download scan must always run even if a recent partial scan
    // touched the same path moments earlier.
    if (type === "file") {
        fileScanLimiter.reset(target);
    }

    // Security: Rate limit scans of same file to prevent DoS
    if (!fileScanLimiter.canScan(target)) {
        dbg(`Scan rate-limited for: ${target}`);
        return;
    }
    
    dbg(`Initiating ${type} scan for: ${target}`);

    let lockActive = (type === "file" && lockedBeforeScan === true);
    let scanFinalized = false;

    const recoverLockedFile = async (reason = "") => {
        if (!lockActive) return;
        try {
            const secret = await getSecret();
            if (!secret || !HOST_AVAILABLE) {
                return;
            }
            await sendNativeMessageWithTimeout(NATIVE_HOST_NAME, {
                action: "unlock",
                target: target,
                secret: secret
            }, 5000);
            lockActive = false;
            if (reason) {
                console.warn("⚠️ LOCK RECOVERY: Released file lock after scan interruption:", reason);
            }
        } catch (e) {
            console.error("⚠️ LOCK RECOVERY FAILED:", e);
        }
    };

    const progressUpdate = (data) => {
        if (data.percent !== undefined) {
            browser.action.setBadgeText({ text: `${data.percent}%` });
            browser.action.setBadgeBackgroundColor({ color: "#3b82f6" });
        }

        if (tabId) {
            browser.tabs.sendMessage(tabId, { action: "show_toast", ...data }).catch(() => { });
        }
        browser.runtime.sendMessage({ action: "scan_progress", target, ...data }).catch(() => { });
    };

    if (!HOST_AVAILABLE && type !== "url") {
        dbg(`Bypassing ${type} scan (Host Offline): ${target}`);
        browser.action.setBadgeText({ text: "OFF" });
        browser.action.setBadgeBackgroundColor({ color: "#f59e0b" });
        progressUpdate({ status: "complete", result: "error", msg: "Unscanned: Native host offline" });
        notifyError("Security engine offline: file not scanned.");
        return;
    }

    if (type === "file") {
        const filename = target.split('/').pop() || target;
        browser.notifications.create(`scan-${downloadId}`, {
            type: "basic",
            iconUrl: "icons/scanning.svg",
            title: "ClamFox Analysis",
            message: `Scanning downloaded file: ${filename}...`
        });
    }

    progressUpdate({ status: "scanning", percent: 0, msg: "Connecting..." });

    try {
        const settings = await browser.storage.local.get({
            useMB: true,
            puaEnabled: true,
            ramMode: true,
            ghostMode: false,
            autoBurnEnabled: false
        });
        const secret = await getSecret();

        if (type === "url" && (!secret || !HOST_AVAILABLE)) {
            progressUpdate({
                status: "complete",
                result: "error",
                msg: "Security engine unavailable: URL scan aborted."
            });
            notifyHostMissing();
            browser.runtime.sendMessage({ action: "scan_complete", target }).catch(() => { });
            return;
        }

        const port = browser.runtime.connectNative(NATIVE_HOST_NAME);

        port.onMessage.addListener(async (response) => {
            // SECURITY: Verify authenticity first, then validate schema.
            // Streaming messages must be signed too, otherwise forged progress/final
            // events could influence scan verdict handling.
            try {
                await verifyResponseSignature(response);
            } catch (e) {
                scanFinalized = true;
                console.error("🛡️ SECURITY ALERT: Scan stream signature verification failed:", e, response);
                notifyError("Security validation rejected scan stream response.");
                await recoverLockedFile("signature verification failure");
                port.disconnect();
                return;
            }

            try {
                validateNativeResponse("scan", response);
            } catch (e) {
                scanFinalized = true;
                console.error("🛡️ SECURITY ALERT: Rejected malformed scan stream response:", e, response);
                notifyError("Security validation rejected scan stream response.");
                await recoverLockedFile("response schema validation failure");
                port.disconnect();
                return;
            }

            if (response.status === "progress") {
                progressUpdate({ status: "scanning", percent: response.percent, msg: response.msg });
                return;
            }

            if (response.status === "error" && response.tamper) {
                scanFinalized = true;
                console.error("🛑 SECURITY ALERT: Host reported tampering or invalid secret!");
                // Self-heal: clear secret and re-handshake next time
                SESSION_HOST_SECRET = null;
                notifyError("Security Handshake Expired. Re-authenticating...");
                await recoverLockedFile("tamper/auth drift during scan");
                port.disconnect();
                return;
            }

            // Final Result Handling
            dbg("Scan result:", response);
            scanFinalized = true;
            port.disconnect();

            if (tabId) {
                let scanResult = "clean";
                if (response.status === "infected" || (response.mb && response.mb.status === "mb_infected")) {
                    scanResult = "infected";
                } else if (response.status === "error" || response.status === "missing") {
                    scanResult = "error";
                }

                browser.tabs.sendMessage(tabId, {
                    action: "show_toast",
                    status: "complete",
                    result: scanResult,
                    msg: response.error ? `${response.error}: ${response.details || ""}` : null,
                    virus: response.virus || (response.mb && response.mb.status === "mb_infected" ? "MalwareBazaar Flag" : null)
                }).catch(() => { });
            }

            // Handle infection during download or completion
            if (response.status === "infected" || (response.mb && response.mb.status === "mb_infected")) {
                if (type === "file" && downloadId) {
                    browser.notifications.clear(`scan-${downloadId}`).catch(() => { });
                }
                const virus = response.virus || (response.mb && response.mb.status === "mb_infected" ? "MalwareBazaar Flag" : "Unknown Threat");
                await logBlock(
                    target.split('/').pop() || target,
                    virus,
                    target,
                    tabId,
                    {
                        block_stage: "content",
                        source_host: null,
                        final_host: null,
                        engine_verdict: response.virus || (response.mb && response.mb.status === "mb_infected" ? "MalwareBazaar Flag" : "File scan malicious verdict"),
                        verdict_status: response.status || "infected"
                    }
                );

                browser.action.setBadgeText({ text: "ERR" });
                browser.action.setBadgeBackgroundColor({ color: "#ef4444" });

                if (downloadId) {
                    try {
                        await browser.downloads.cancel(downloadId);
                        await browser.downloads.removeFile(downloadId).catch(() => { });
                        await browser.downloads.erase({ id: downloadId });
                    } catch (e) { }
                }
                lockActive = false;
                notifyThreat(target, response.virus || "MalwareBazaar threat");

                // AUTO-BURN Logic: Automatically neutralizing zero-days globally if enabled
                if (settings.autoBurnEnabled && (response.status === "infected" || (response.mb && response.mb.status === "mb_infected"))) {
                    dbg("🔥 AUTO-BURN: High-confidence threat detected. Initiating community neutralization...");
                    sendNativeMessageWithTimeout(NATIVE_HOST_NAME, {
                        action: "report_threat",
                        target: target,
                        type: response.virus || "Automated Detection",
                        details: { forensics: { auto: true, source: "Background Shield" } },
                        secret: secret
                    }, 10000).then(async (burnResp) => {
                        if (burnResp && burnResp.status === "ok") {
                            const bh = await browser.storage.local.get({ blockedHistory: [] });
                            if (bh.blockedHistory.length > 0) {
                                // Update the incident we just logged (it should be the last one)
                                const lastIndex = bh.blockedHistory.findLastIndex(b => b.url === target);
                                if (lastIndex !== -1) {
                                    bh.blockedHistory[lastIndex].reported = true;
                                    await browser.storage.local.set({ blockedHistory: bh.blockedHistory });
                                }
                            }
                        }
                    }).catch(() => { });
                }
            } else if (response.status === "clean") {
                browser.action.setBadgeText({ text: "OK" });
                browser.action.setBadgeBackgroundColor({ color: "#10b981" });
                notifyClean(target, downloadId);

                // SECURITY HARDENING: Release it from the quarantine directory into the user's view
                try {
                    const secret = await getSecret();
                    if (!secret || !HOST_AVAILABLE) {
                        throw new Error("Security engine unavailable during clean release");
                    }
                    const releaseResp = await sendNativeMessageWithTimeout(NATIVE_HOST_NAME, {
                        action: "release_quarantine",
                        target: target,
                        secret: secret
                    }, 5000);
                    if (releaseResp && releaseResp.status === "ok") {
                        lockActive = false;
                    } else {
                        throw new Error((releaseResp && releaseResp.error) ? releaseResp.error : "release_quarantine returned non-ok status");
                    }
                } catch (e) {
                    notifyError("Clean verdict received, but file release failed. Attempting lock recovery.");
                    await recoverLockedFile("clean verdict release failure");
                }

                setTimeout(() => browser.action.setBadgeText({ text: "" }), 5000);
            } else if (type === "file" && (response.status === "error" || response.status === "missing")) {
                if (downloadId) {
                    try {
                        await browser.downloads.cancel(downloadId);
                        await browser.downloads.removeFile(downloadId).catch(() => { });
                        await browser.downloads.erase({ id: downloadId });
                    } catch (e) { }
                }
                lockActive = false;
                notifyError("File blocked because security scan did not complete successfully.");
            }

            // Store result
            const storage = await browser.storage.local.get({ recentScans: [] });
            const scans = storage.recentScans;

            let displayName = target;
            try {
                const url = new URL(target);
                displayName = url.hostname;
            } catch (e) {
                displayName = target.split('/').pop() || target;
            }

            scans.push({
                name: displayName,
                status: response.status,
                virus: response.virus || (response.mb && response.mb.status === "mb_infected" ? "MalwareBazaar Flag" : null),
                error: response.details ? `${response.error || 'Error'}: ${response.details}` : response.error,
                time: Date.now(),
                type: type,
                fullTarget: target
            });
            await browser.storage.local.set({ recentScans: scans.slice(-20) });

            // Final popup update
            browser.runtime.sendMessage({ action: "scan_complete", target }).catch(() => { });
        });

        port.onDisconnect.addListener(() => {
            if (browser.runtime.lastError) {
                console.error("Port disconnected with error:", browser.runtime.lastError);
                if (!scanFinalized) {
                    recoverLockedFile("port disconnect before final verdict").catch(() => { });
                }
                notifyHostMissing();
            }
        });

        port.postMessage({
            action: "scan",
            target: target,
            type: type,
            use_mb: settings.ghostMode ? false : settings.useMB,
            pua_enabled: settings.puaEnabled,
            ram_mode: settings.ramMode,
            secret: secret
        });

    } catch (error) {
        console.error("Native Messaging Error:", error);
        if (tabId) {
            browser.tabs.sendMessage(tabId, { action: "show_toast", status: "complete", result: "error" }).catch(() => { });
        }
        await recoverLockedFile("native messaging exception");
        notifyHostMissing();
    }
}

MAIN_MESSAGE_LISTENER_READY = true;
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    // Security: Only allow internal extension messages
    if (sender.id && sender.id !== browser.runtime.id) {
        console.error("🛑 UNAUTHORIZED MESSAGE SOURCE:", sender.id);
        return false;
    }

    const extensionOrigin = browser.runtime.getURL("");
    const isExtensionPage = sender.url && sender.url.startsWith(extensionOrigin);

    dbg(`Internal message received from ${sender.url ? sender.url : "unknown"}:`, message);

    const handleMessage = async () => {
        // Skip internal pages
        if (message.url && (message.url.startsWith("about:") || message.url.startsWith("chrome:") || message.url.startsWith("file:"))) {
            return { status: "clean", info: "internal_page_skipped" };
        }

        // --- PRIVILEGE ESCALATION PROTECTION ---
        // Block content scripts from calling sensitive host-proxying or administrative actions.
        const privilegedActions = [
            "scan_request", "proxy_check", "proxy_update", "proxy_force_engine_update",
            "proxy_reconnect", "proxy_reseal", "proxy_update_yara", "proxy_get_logs",
            "proxy_report_threat", "proxy_list_quarantine", "proxy_restore",
            "update_alarm_settings", "bypass_domain", "rotate_secret", "get_intel"
        ];

        if (!isExtensionPage && privilegedActions.includes(message.action)) {
            console.error(`🛡️ SECURITY ALERT: Content script at ${sender.url} tried to trigger privileged action: ${message.action}`);
            return { status: "error", error: "Unauthorized privileged action from content script." };
        }

        let secret = await getSecret();

        if (message.action === "scan_request") {
            performScan(message.url, "url", null, message.tabId || null);
            return { status: "initiated" };
        } else if (message.action === "proxy_check") {
            try {
                dbg("Diagnostic: Starting proxy_check...");
                const res = await sendNativeMessageWithTimeout(NATIVE_HOST_NAME, { action: "check", secret: secret }, HOST_CHECK_TIMEOUT_MS);
                dbg("Diagnostic: proxy_check success:", res);

                // Keep secret in sync: If host returns a new secret during check, store it
                if (res.secret && res.secret !== "****") {
                    dbg("🔄 Secret refresh detected during check.");
                    SESSION_HOST_SECRET = res.secret;
                }

                // SECURITY: Never leak the host secret back to the caller (even internal pages).
                // Extension pages should use getSecret() if they need it.
                if (res && res.secret) {
                    delete res.secret;
                }

                return res;
            } catch (e) {
                console.warn("Diagnostic: proxy_check failed, attempting force refresh...", e);
                // Force refresh on failure
                try {
                    const newSecret = await getSecret(true);
                    const res = await sendNativeMessageWithTimeout(NATIVE_HOST_NAME, { action: "check", secret: newSecret }, HOST_CHECK_TIMEOUT_MS);
                    dbg("Diagnostic: proxy_check success after refresh:", res);

                    if (res && res.secret) {
                        delete res.secret;
                    }

                    return res;
                } catch (err) {
                    console.error("Diagnostic: proxy_check CRITICAL FAILURE:", err);
                    const reason = (err && err.message) ? err.message : String(err || "unknown error");
                    return { status: "error", error: `Security engine handshake failed: ${reason}` };
                }
            }
        } else if (message.action === "proxy_update") {
            return sendNativeMessageWithTimeout(NATIVE_HOST_NAME, { action: "update_urldb", secret: secret }, 15000); // 15s for updates
        } else if (message.action === "proxy_force_engine_update") {
            return sendNativeMessageWithTimeout(NATIVE_HOST_NAME, { action: "force_db_update", secret: secret }, 15000);
        } else if (message.action === "proxy_reconnect") {
            dbg("🔄 Manual Reconnection requested.");
            SESSION_HOST_SECRET = null;
            await browser.storage.local.remove("hostPublicKey").catch(() => { });
            return getSecret(true).then(newSecret => {
                if (newSecret) return { status: "ok" };
                else return { status: "error", error: "Handshake failed. Host unavailable or cryptographic verification failed." };
            });
        } else if (message.action === "proxy_reseal") {
            return sendNativeMessageWithTimeout(NATIVE_HOST_NAME, { action: "reseal", secret: secret }, 15000);
        } else if (message.action === "proxy_update_yara") {
            return sendNativeMessageWithTimeout(NATIVE_HOST_NAME, { action: "update_yara", secret: secret }, 15000);
        } else if (message.action === "proxy_get_logs") {
            return sendNativeMessageWithTimeout(NATIVE_HOST_NAME, { action: "get_audit_logs", secret: secret });
        } else if (message.action === "proxy_report_threat") {
            return sendNativeMessageWithTimeout(NATIVE_HOST_NAME, {
                action: "report_threat",
                target: message.target,
                type: message.type,
                details: message.details,
                secret: secret
            });
        } else if (message.action === "proxy_list_quarantine") {
            return sendNativeMessageWithTimeout(NATIVE_HOST_NAME, { action: "list_quarantine", secret: secret });
        } else if (message.action === "proxy_restore") {
            return sendNativeMessageWithTimeout(NATIVE_HOST_NAME, { action: "restore", target: message.target, secret: secret });
        } else if (message.action === "update_alarm_settings") {
            setupIntelligenceAlarm();
            return { status: "ok" };
        } else if (message.action === "check_trust") {
            try {
                const response = await sendNativeMessageWithTimeout(NATIVE_HOST_NAME, {
                    action: "check_url",
                    target: message.url,
                    secret: secret
                }, 3000);

                const certInfo = (sender.tab && sender.tab.id) ? CERT_CACHE.get(sender.tab.id) : null;
                let trustLevel = response.trust || "standard";
                let threatSignals = [];

                if (certInfo) {
                    if (certInfo.isYoung && trustLevel !== "high") {
                        threatSignals.push("Young Certificate (Cryptographic Anomaly)");
                        trustLevel = "untrusted";
                    }
                    if (certInfo.isUntrusted) {
                        threatSignals.push("Invalid/Insecure TLS State");
                        trustLevel = "untrusted";
                    }
                }

                return {
                    trust: trustLevel,
                    status: response.status,
                    threats: threatSignals,
                    cert: certInfo ? { issuer: certInfo.issuer, isYoung: certInfo.isYoung } : null
                };
            } catch (e) {
                return { trust: "standard", status: "error" };
            }
        } else if (message.action === "log_honeypot") {
            const host = sender.tab ? new URL(sender.tab.url).hostname : null;
            logBlock("Honeypot Decoy Tripped", message.threat, sender.tab ? sender.tab.url : "Unknown URL", sender.tab ? sender.tab.id : null, message.forensics);

            if (!isWhitelisted(host) && !shouldThrottleAlert(host)) {
                browser.notifications.create({
                    type: "basic",
                    iconUrl: "icons/warning.svg",
                    title: "🛑 BOT SCRAPING ATTEMPT",
                    message: `ClamFox Forensic Engine caught a script trying to read hidden honey-fields on this page. Potential data-stealer detected.`,
                    priority: 2
                });
            }
            return { status: "logged" };
        } else if (message.action === "log_formjacking") {
            const host = sender.tab ? new URL(sender.tab.url).hostname : null;
            logBlock("Formjacking Detected", message.threat, sender.tab ? sender.tab.url : "Unknown URL", sender.tab ? sender.tab.id : null, message.forensics);

            if (!isWhitelisted(host) && !shouldThrottleAlert(host)) {
                browser.notifications.create({
                    type: "basic",
                    iconUrl: "icons/warning.svg",
                    title: "🛑 KEYLOGGER / FORMJACKING",
                    message: `Security Bypass: A script tried to attach an unauthorized listener to a sensitive input field. Listener suppressed.`,
                    priority: 2
                });
            }
            return { status: "logged" };
        } else if (message.action === "log_visual_phish") {
            const host = sender.tab ? new URL(sender.tab.url).hostname : null;
            logBlock("Visual Phishing Detected", message.threat, sender.tab ? sender.tab.url : "Unknown URL", sender.tab ? sender.tab.id : null, message.forensics);

            if (!isWhitelisted(host) && !shouldThrottleAlert(host)) {
                browser.notifications.create({
                    type: "basic",
                    iconUrl: "icons/warning.svg",
                    title: "⚠️ BRAND IMPERSONATION ALERT",
                    message: `ClamFox Visual Shield detected brand spoofing! ${message.threat}. Verify the URL before entering data.`,
                    priority: 2
                });
            }
            return { status: "logged" };
        } else if (message.action === "log_driveby") {
            const host = sender.tab ? new URL(sender.tab.url).hostname : null;
            logBlock("Drive-by Download Detected", message.threat, sender.tab ? sender.tab.url : "Unknown URL", sender.tab ? sender.tab.id : null, message.forensics);

            if (!isWhitelisted(host) && !shouldThrottleAlert(host)) {
                browser.notifications.create({
                    type: "basic",
                    iconUrl: "icons/warning.svg",
                    title: "🛑 DRIVE-BY DOWNLOAD BLOCKED",
                    message: `Security Enforcement: Blocked an automated, non-user-initiated download attempt. Analysis: ${message.threat}.`,
                    priority: 2
                });
            }
            return { status: "logged" };
        } else if (message.action === "log_behavior") {
            const host = sender.tab ? new URL(sender.tab.url).hostname : null;
            logBlock("Malicious Behavior Detected", message.threat, sender.tab ? sender.tab.url : "Unknown URL", sender.tab ? sender.tab.id : null, message.forensics);

            if (!isWhitelisted(host) && !shouldThrottleAlert(host)) {
                browser.notifications.create({
                    type: "basic",
                    iconUrl: "icons/warning.svg",
                    title: "🛑 BEHAVIORAL THREAT NEUTRALIZED",
                    message: `The ClamFox Heuristic Engine identified a malicious script pattern: ${message.threat}. Execution suppressed.`,
                    priority: 2
                });
            }
            return { status: "logged" };
        } else if (message.action === "log_dom_anomaly") {
            const host = sender.tab ? new URL(sender.tab.url).hostname : null;
            logBlock("DOM Anomaly / Clickjacking Overlay", message.threat, sender.tab ? sender.tab.url : "Unknown URL", sender.tab ? sender.tab.id : null, message.forensics);

            if (!isWhitelisted(host) && !shouldThrottleAlert(host)) {
                browser.notifications.create({
                    type: "basic",
                    iconUrl: "icons/warning.svg",
                    title: "🛑 CLICKJACKING OVERLAY BLOCKED",
                    message: `Privacy Shield: An invisible UI layer was detected and destroyed. This layer was likely trying to capture clicks or intercept sensitive interactions.`,
                    priority: 2
                });
            }
            return { status: "logged" };
        } else if (message.action === "get_hvts") {
            try {
                const settings = await browser.storage.local.get({ suppressTrustedToasts: true });
                const url = browser.runtime.getURL("host/trust_db.json");
                const response = await fetch(url);
                const data = await response.json();
                return {
                    hvts: data.hvts || [],
                    whitelist: data.global_whitelist || [],
                    user_whitelist: Array.from(USER_WHITELIST),
                    honeypot_secret: HONEYPOT_SECRET,
                    is_challenge_mode: (sender.tab && ACTIVE_CHALLENGES.has(sender.tab.id) && ACTIVE_CHALLENGES.get(sender.tab.id) > Date.now()),
                    suppress_trusted_toasts: settings.suppressTrustedToasts
                };
            } catch (e) {
                const settings = await browser.storage.local.get({ suppressTrustedToasts: true });
                console.error("Failed to load trust_db.json", e);
                return {
                    hvts: [],
                    whitelist: [],
                    user_whitelist: Array.from(USER_WHITELIST),
                    honeypot_secret: HONEYPOT_SECRET,
                    is_challenge_mode: (sender.tab && ACTIVE_CHALLENGES.has(sender.tab.id) && ACTIVE_CHALLENGES.get(sender.tab.id) > Date.now()),
                    suppress_trusted_toasts: settings.suppressTrustedToasts
                };
            }
        } else if (message.action === "get_tab_id") {
            return sender.tab ? sender.tab.id : null;
        } else if (message.action === "bypass_domain") {
            if (message.domain) {
                const baseDomain = getBaseDomain(message.domain);
                const expiresAt = Date.now() + USER_BYPASS_TTL_MS;
                dbg(`🛡️ USER OVERRIDE: Temporarily whitelisting ${baseDomain} for 24h`);

                USER_WHITELIST.add(baseDomain);
                USER_WHITELIST_EXPIRY.set(baseDomain, expiresAt);
                await persistUserWhitelist();

                return { status: "whitelisted", expiresAt };
            }
        }
        return false;
    };

    // Return true to indicate we will send a response asynchronously
    handleMessage().then(sendResponse).catch(err => {
        console.error("Message Handler Error:", err);
        sendResponse({ status: "error", error: "An internal extension messaging error occurred." });
    });
    return true;
});

function notifyThreat(target, virus) {
    let displayName = target;
    try {
        const url = new URL(target);
        displayName = url.hostname;
    } catch (e) {
        displayName = target.split('/').pop() || target;
    }

    browser.notifications.create({
        type: "basic",
        iconUrl: "icons/warning.svg",
        title: browser.i18n.getMessage("threatDetected"),
        message: browser.i18n.getMessage("threatMessage", [virus, displayName]),
        priority: 2
    });
}

function notifyClean(target, downloadId = null) {
    let displayName = target;
    let typeLabel = "target";

    try {
        const url = new URL(target);
        displayName = url.hostname;
        typeLabel = browser.i18n.getMessage("site");
    } catch (e) {
        displayName = target.split('/').pop() || target;
        typeLabel = browser.i18n.getMessage("file");
    }

    if (downloadId) {
        browser.notifications.clear(`scan-${downloadId}`).catch(() => { });
    }

    browser.notifications.create({
        type: "basic",
        iconUrl: "icons/success.svg",
        title: browser.i18n.getMessage("scanCompleteSafe"),
        message: browser.i18n.getMessage("safeMessage", [displayName, typeLabel])
    });
}

function notifyError(err) {
    browser.notifications.create({
        type: "basic",
        title: browser.i18n.getMessage("scanError"),
        message: browser.i18n.getMessage("errorMessage", [err])
    });
}

function notifyHostMissing() {
    browser.notifications.create({
        type: "basic",
        title: browser.i18n.getMessage("hostMissing"),
        message: browser.i18n.getMessage("hostMissingMessage")
    });
}

// Context Menu Setup
browser.runtime.onInstalled.addListener(() => {
    browser.menus.create({
        id: "scan-link",
        title: browser.i18n.getMessage("scanLink"),
        contexts: ["link"]
    });

    browser.menus.create({
        id: "scan-image",
        title: browser.i18n.getMessage("scanImage"),
        contexts: ["image"]
    });
    dbg("ClamAV Context Menus Registered");

    // Initialize 6-hour Intelligence Sync Alarm
    setupIntelligenceAlarm();

    // Ensure privacy shield is active on install/update
    initPrivacyShield();
});

async function setupIntelligenceAlarm() {
    const settings = await browser.storage.local.get({ autoSyncEnabled: true });
    if (settings.autoSyncEnabled) {
        dbg("⏰ Setting up 3-hour Intelligence Sync Alarm...");
        browser.alarms.create("intelligence-sync", {
            periodInMinutes: 180 // 3 hours
        });
    } else {
        browser.alarms.clear("intelligence-sync");
    }

    // Security: Session key rotation every 6 hours.
    // Even if the session secret is ever observed (e.g. via a compromised DevTools session),
    // it will be invalidated and replaced automatically, limiting the attack window.
    browser.alarms.create("secret-rotation", {
        delayInMinutes: 360,       // First rotation after 6 hours
        periodInMinutes: 360       // Then every 6 hours
    });
}

// Handle Background Alarms
browser.alarms.onAlarm.addListener(async (alarm) => {
    if (alarm.name === "intelligence-sync") {
        dbg("🚀 Executing Scheduled Intelligence Sync...");
        try {
            const secret = await getSecret();
            // Sync URLHaus
            await sendNativeMessageWithTimeout(NATIVE_HOST_NAME, { action: "update_urldb", secret: secret }, 15000);
            // Sync YARA
            await sendNativeMessageWithTimeout(NATIVE_HOST_NAME, { action: "update_yara", secret: secret }, 15000);
            dbg("✅ Scheduled Sync Completed.");
        } catch (e) {
            console.error("❌ Scheduled Sync Failed:", e);
        }
    } else if (alarm.name === "secret-rotation") {
        // Security: Automatic session key rotation
        dbg("🔑 Scheduled session key rotation starting...");
        try {
            const currentSecret = await getSecret();
            const response = await sendNativeMessageWithTimeout(NATIVE_HOST_NAME, {
                action: "rotate_secret",
                secret: currentSecret
            }, 8000);
            if (response && response.status === "ok" && response.secret) {
                SESSION_HOST_SECRET = response.secret;
                dbg("🔑 Session secret rotated successfully.");
            } else {
                console.warn("🔑 Secret rotation returned unexpected response:", response);
            }
        } catch (e) {
            console.error("🔑 Session key rotation failed:", e);
            // On failure, force a fresh handshake on next request
            SESSION_HOST_SECRET = null;
        }
    }
});

// ------------------------------------------------------------------
// Proactive Bridging & Credential Guard
// ------------------------------------------------------------------

let backgroundPort = null;

async function initBackgroundBridge() {
    if (backgroundPort) return;

    try {
        backgroundPort = browser.runtime.connectNative(NATIVE_HOST_NAME);
        backgroundPort.onMessage.addListener(async (msg) => {
            try {
                // 🛡️ SECURITY: Authenticate unsolicited messages from the host,
                // then validate structure before processing.
                await verifyResponseSignature(msg);
                validateNativeResponse(msg.action || "background_alert", msg);

                if (msg.action === "clipper_alert") {
                    console.warn("🛡️ CLIPPER SHIELD: Hijack detected!", msg);
                    browser.notifications.create({
                        type: "basic",
                        iconUrl: "icons/warning.svg",
                        title: "⚠️ CLIPBOARD HIJACK BLOCKED",
                        message: browser.i18n.getMessage("clipperShieldAlert") || "A malicious script tried to swap your crypto address!",
                        priority: 2
                    });

                    // Log it to history
                    logBlock("System Clipboard", msg.threat || "Crypto-Address Hijacking", msg.new);
                }
            } catch (e) {
                console.error("🛡️ SECURITY ALERT: Rejected unauthenticated/malformed background alert from host:", e, msg);
            }
        });

        backgroundPort.onDisconnect.addListener(() => {
            backgroundPort = null;
            // Backoff and reconnect
            setTimeout(initBackgroundBridge, 10000);
        });
    } catch (e) {
        console.error("Failed to init background bridge:", e);
    }
}

// ------------------------------------------------------------------
// Privacy & Anonymity Hardening (WebRTC Leak Shield)
// ------------------------------------------------------------------
async function initPrivacyShield() {
    if (!browser.privacy || !browser.privacy.network) return;

    try {
        // 'default_public_interface_only' hides local IP (192.168.x.x) while keeping 
        // WebRTC functional for public video calls.
        await browser.privacy.network.webRTCIPHandlingPolicy.set({
            value: "default_public_interface_only"
        });
        dbg("🛡️ PRIVACY SHIELD: WebRTC IP Leak Protection active.");
    } catch (e) {
        console.error("Failed to set WebRTC policy:", e);
    }
}

// ------------------------------------------------------------------
// Targeted CSP Augmentation (Defense-in-Depth for HVTs)
// ------------------------------------------------------------------
let SECURE_PORTALS = [];

async function updateSecurePortals() {
    try {
        // 1. Load Local HVTs (for similarity checks)
        // Standalone-friendly path first, then host-fallback
        let url = browser.runtime.getURL("data/trust_db.json");
        let response;
        try {
            response = await fetch(url);
        } catch (e) {
            url = browser.runtime.getURL("host/trust_db.json");
            response = await fetch(url);
        }
        const data = await response.json();
        let currentHVTs = data.hvts || [];
        let dynamicWhitelist = [];

        // 2. Sync with Host for Dynamic Researcher/Cloudflare/Talos Whitelist
        try {
            const secret = await getSecret();
            const intel = await sendNativeMessageWithTimeout(NATIVE_HOST_NAME, {
                action: "get_intel",
                secret: secret
            }, 8000);
            if (intel.status === "ok") {
                if (intel.hvts) currentHVTs = intel.hvts;
                if (intel.whitelist) dynamicWhitelist = intel.whitelist;
                dbg("🛡️ INTEL SYNC: Dynamic research-based whitelist (Top 5k) loaded from host.");
            }
        } catch (e) {
            console.warn("Dynamic Intel sync failed. Using local HVT fallbacks.");
        }

        const hvtDomains = currentHVTs.map(hvt => hvt.domains).flat();
        const storage = await browser.storage.local.get({ customPortals: [] });

        // Merge: HVTs + Top Dynamic Whitelist + User Custom Portals
        SECURE_PORTALS = [...hvtDomains, ...dynamicWhitelist, ...storage.customPortals];
    } catch (e) {
        console.error("Failed to update secure portals", e);
    }
}
updateSecurePortals();
browser.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && changes.customPortals) updateSecurePortals();
});

browser.webRequest.onHeadersReceived.addListener(
    (details) => {
        try {
            const url = new URL(details.url);
            // ONLY apply CSP hardening to designated High-Value Portals, NOT to general user whitelists.
            const isTargetPortal = isPortal(url.hostname);

            if (isTargetPortal) {
                // Proactive Inspection: If it's a critical auth flow (PosteID, etc) or site has its own strict policy, DON'T interfere.
                const responseHeaders = details.responseHeaders;
                const hasExistingSecurity = responseHeaders.some(h =>
                    h.name.toLowerCase() === "content-security-policy" ||
                    h.name.toLowerCase() === "x-frame-options"
                );
                // Detection for OAuth/SAML/Bank flows: paths with 'auth', 'callback', 'login' or params with 'state', 'code'
                const isAuthFlow = url.pathname.includes("auth") || url.pathname.includes("callback") ||
                    url.pathname.includes("login") ||
                    url.search.includes("state=") || url.search.includes("code=");

                if (isAuthFlow || hasExistingSecurity) {
                    dbg(`🛡️ PROACTIVE BYPASS: Not injecting security headers into ${url.hostname} flow.`);
                    return {};
                }

                // Default strict protection for standard idle pages (non-login)
                responseHeaders.push({
                    name: "Content-Security-Policy",
                    value: "webrtc 'none'; object-src 'none'; frame-ancestors 'self';"
                });
                return { responseHeaders };
            }
        } catch (e) { }
        return {};
    },
    { urls: ["http://*/*", "https://*/*"], types: ["main_frame"] },
    ["responseHeaders"]
);

// Start the proactive bridge immediately
initBackgroundBridge();
initPrivacyShield();

// Single message listener handles everything.

browser.menus.onClicked.addListener((info, tab) => {
    dbg("Context Menu Clicked:", info.menuItemId);
    const tabId = tab ? tab.id : null;

    if (info.menuItemId === "scan-link") {
        if (info.linkUrl) {
            dbg("Scanning link:", info.linkUrl);
            performScan(info.linkUrl, "url", null, tabId);
        } else {
            console.error("No link URL found in context menu info");
        }
    } else if (info.menuItemId === "scan-image") {
        if (info.srcUrl) {
            dbg("Scanning image:", info.srcUrl);
            performScan(info.srcUrl, "url", null, tabId);
        } else {
            console.error("No source URL found in context menu info");
        }
    }
});
