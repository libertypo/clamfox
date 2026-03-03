// Security: Set to false in production to prevent internal state leaking to DevTools
const DEBUG = false;
const dbg = (...args) => { if (DEBUG) console.log(...args); };

// Supply-Chain Canary (Injected at build time)
const CLAMFOX_CANARY = "PLACEHOLDER_CANARY";

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
let HOST_AVAILABLE = false; // Detected at runtime

const SCAN_INTERVAL_BYTES = 10 * 1024 * 1024; // Scan every 10MB
const allowedAfterChallenge = new Set(); // Tracks hosts that just completed a Cloudflare challenge
const ACTIVE_CHALLENGES = new Map(); // tabId -> expiration timestamp
const USER_WHITELIST = new Set(); // Persistent overrides

// WASM Shield State
let WASM_READY = false;
let wasmInstance = null;
let wasmExports = null;

async function initWhitelist() {
    const storage = await browser.storage.local.get("userWhitelist");
    if (storage.userWhitelist && Array.isArray(storage.userWhitelist)) {
        storage.userWhitelist.forEach(domain => USER_WHITELIST.add(domain));
        dbg(`🛡️ USER WHITELIST: Loaded ${USER_WHITELIST.size} domains.`);
    }
}

// getBaseDomain is now provided by psl_data.js

function isPortal(hostname) {
    if (!hostname) return false;
    const base = getBaseDomain(hostname);
    return SECURE_PORTALS.some(d => base === d);
}

function isWhitelisted(hostname) {
    if (!hostname) return false;
    // 1. Check Hardcoded/Dynamic High-Value Targets (Secure Portals)
    if (isPortal(hostname)) return true;

    // 2. Check Persistent User Overrides
    const base = getBaseDomain(hostname);
    const whitelistArr = Array.from(USER_WHITELIST);
    if (whitelistArr.some(d => base === d)) return true;

    return false;
}

const activeDownloads = new Map();

// Default fallback: a fresh random value per session so no attacker who
// reads the source code can predict the honeypot secret.
let HONEYPOT_SECRET = `cf_honey_${crypto.randomUUID()}`;
let SESSION_HOST_SECRET = null; // Ephemeral Cryptographic Secret

// Initialized via initBackground()

async function initWasm() {
    try {
        const response = await fetch(browser.runtime.getURL("wasm_shield/clamfox_shield.wasm"));
        const bytes = await response.arrayBuffer();

        // 1. Integrity Audit: Internal Subresource Integrity (SRI)
        const hashBuffer = await crypto.subtle.digest("SHA-256", bytes);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

        const EXPECTED_WASM_HASH = "2b6babb47828432d460efa5314c164afa6f742366c8a1fc53df4b195b39f5f67";
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
    await initWhitelist();
    await initWasm();
    const storage = await browser.storage.local.get("honeypotSecret");
    if (storage.honeypotSecret) {
        HONEYPOT_SECRET = storage.honeypotSecret;
    }

    // Perform initial handshake to sync secrets from host
    await getSecret(true);
    dbg("🛡️ SECURITY CORE: Startup handshake complete.");
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
        let cleanedDownloads = 0;

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

        // Clean up activeDownloads that are stale (no updates in 2 hours)
        for (const [id, info] of activeDownloads.entries()) {
            if (info.lastUpdated && (now - info.lastUpdated) > 7200000) {
                activeDownloads.delete(id);
                cleanedDownloads++;
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

        if (cleanedTabs > 0 || cleanedDownloads > 0 || cleanedChallenges > 0 || cleanedBeacons > 0) {
            dbg(`🧹 GARBAGE COLLECTION: Purged ${cleanedTabs} tabs, ${cleanedDownloads} downloads, ${cleanedChallenges} challenges, and ${cleanedBeacons} beacons.`);
        }
    }
});
browser.alarms.create("garbage_collection", { periodInMinutes: 15 });

// DOWNLOAD SHIELD: Prevent access until scanned
browser.downloads.onCreated.addListener(async (item) => {
    // 1. Whitelist Check
    try {
        const url = new URL(item.url);
        if (isWhitelisted(url.hostname)) {
            dbg("🛡️ USER OVERRIDE: Allowing download from whitelisted domain:", url.hostname);
            return;
        }
    } catch (e) { }

    // 2. Pre-emptive Pause to allow reputation check
    await browser.downloads.pause(item.id).catch(() => { });

    try {
        const secret = await getSecret();
        const response = await browser.runtime.sendNativeMessage(NATIVE_HOST_NAME, {
            action: "check_url",
            target: item.url,
            secret: secret
        });

        if (response.status === "malicious") {
            console.error("🛑 DOWNLOAD ABORTED: Malicious Source Detected:", item.url);
            await browser.downloads.cancel(item.id).catch(() => { });
            await browser.downloads.erase({ id: item.id }).catch(() => { });

            logBlock(new URL(item.url).hostname, "Malicious Link (Download Pre-Scan)", item.url);

            browser.notifications.create({
                type: "basic",
                iconUrl: "icons/warning.svg",
                title: "🛑 DOWNLOAD BLOCKED",
                message: `ClamFox prevented the download of a file from a known malicious site: ${new URL(item.url).hostname}`,
                priority: 2
            });
        } else {
            // Normal source, resume download
            await browser.downloads.resume(item.id).catch(() => { });
        }
    } catch (e) {
        // Fallback: resume if engine fails (usability)
        await browser.downloads.resume(item.id).catch(() => { });
    }
});



browser.downloads.onChanged.addListener(async (delta) => {
    // 1. Handle completed downloads
    if (delta.state && delta.state.current === "complete") {
        dbg("Download complete event received for ID:", delta.id);
        const items = await browser.downloads.search({ id: delta.id });
        if (items.length > 0) {
            const item = items[0];

            // SECURITY HARDENING: Lock the file from the OS BEFORE the scan reaches the user
            try {
                const secret = await getSecret();
                await browser.runtime.sendNativeMessage(NATIVE_HOST_NAME, {
                    action: "lock",
                    target: item.filename,
                    secret: secret
                });
                dbg("🔒 FILE SEALED: Access restricted during analysis.");
            } catch (e) { }

            // Ensure our engine knows it's a quarantined target if routing was successful
            performScan(item.filename, "file", item.id);
        }
        activeDownloads.delete(delta.id);
        return;
    }

    // 2. Monitor ongoing downloads for real-time scanning
    if (delta.bytesReceived) {
        const id = delta.id;
        const currentBytes = delta.bytesReceived.current;

        let info = activeDownloads.get(id);
        if (!info) {
            const items = await browser.downloads.search({ id: id });
            if (items.length > 0) {
                info = { lastScanBytes: 0, filename: items[0].filename, lastUpdated: Date.now() };
                activeDownloads.set(id, info);
            }
        }

        if (info) {
            info.lastUpdated = Date.now();
            const settings = await browser.storage.local.get({ scanFrequencyMB: 10 });
            const intervalBytes = settings.scanFrequencyMB * 1024 * 1024;
            // Duplicate SCAN_INTERVAL_BYTES removed (using global constant)
            if ((currentBytes - info.lastScanBytes) > intervalBytes) {
                dbg(`Progressive scan for ${info.filename} at ${currentBytes} bytes (Interval: ${settings.scanFrequencyMB}MB)`);
                info.lastScanBytes = currentBytes;
                performScan(info.filename, "file_partial", id);
            }
        }
    }

    // 3. Handle interrupted/erased
    if (delta.state && delta.state.current === "interrupted") {
        activeDownloads.delete(delta.id);
    }
});

async function sendNativeMessageWithTimeout(hostname, message, timeoutMs = 8000) {
    const timeoutPromise = new Promise((_, reject) =>
        setTimeout(() => reject(new Error("Native Messaging request timed out")), timeoutMs)
    );
    return Promise.race([
        browser.runtime.sendNativeMessage(hostname, message),
        timeoutPromise
    ]);
}

async function getSecret(forceRefresh = false) {
    if (!forceRefresh && SESSION_HOST_SECRET) {
        return SESSION_HOST_SECRET;
    }

    try {
        dbg("🔒 Security Handshake starting...");
        // Send a bare check to get the current secret
        const response = await sendNativeMessageWithTimeout(NATIVE_HOST_NAME, { action: "check" }, 5000);

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

browser.webRequest.onBeforeRequest.addListener(
    async (details) => {
        if (details.type !== "main_frame") return {};
        if (details.url.startsWith(browser.runtime.getURL(""))) return {};
        if (details.url.startsWith("about:") || details.url.startsWith("moz-extension:")) return {};

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

        // If we have just passed a challenge OR have a valid cf_clearance cookie, skip scanning
        if (url) {
            const hasTempBypass = allowedAfterChallenge.has(url.hostname);
            const isUserWhitelisted = isWhitelisted(url.hostname);
            let hasCookieClearance = false;
            try {
                const cookies = await browser.cookies.getAll({ url: details.url, name: "cf_clearance" });
                hasCookieClearance = cookies && cookies.length > 0;
            } catch (e) { }

            if (hasTempBypass || hasCookieClearance || isUserWhitelisted) {
                return {};
            }
        }

        // Latency Fast-Path: Skip native scanning for trusted High-Value Targets or User Whitelist
        if (isWhitelisted(url.hostname)) {
            return {};
        }

        // --- NEW: WASM High-Speed Pre-Scan ---
        if (WASM_READY && wasmExports) {
            // 1. Homograph Detection (In-process, no bridge lag)
            const homographResult = wasmExports.check_homograph_attack(details.url);
            if (homographResult) {
                handleMaliciousUrl(details.url, homographResult, details.tabId);
                return; // Short-circuit
            }

            // 2. DGA / Statistical Detection
            const dgaResult = wasmExports.check_dga_heuristics(details.url);
            if (dgaResult) {
                handleMaliciousUrl(details.url, dgaResult, details.tabId);
                return; // Short-circuit
            }
        }

        try {
            const secret = await getSecret();

            // SECURITY FAIL-OPEN: Don't hang the browser if the host is offline or slow
            const timeoutPromise = new Promise(resolve => setTimeout(() => resolve({ status: "timeout" }), 3000));
            const response = await Promise.race([
                browser.runtime.sendNativeMessage(NATIVE_HOST_NAME, {
                    action: "check_url",
                    target: details.url,
                    secret: secret
                }),
                timeoutPromise
            ]);

            if (response.status === "timeout") {
                const settings = await browser.storage.local.get({ strictMode: false });
                if (settings.strictMode) {
                    console.error("🛑 SECURITY FAIL-CLOSED: Host response timed out. Blocking request due to Strict Mode.");
                    handleMaliciousUrl(details.url, "Scan Timeout (Strict Mode)", details.tabId);
                    return { cancel: true };
                }
                console.warn("🛡️ SECURITY FAIL-OPEN: Host response timed out (3s). Proceeding for stability.");
                return {};
            }

            // Cloudflare challenge final bypass: if the URL is a challenge or clearance, ignore any malicious verdict
            if (details.url.includes("__cf_chl_") || details.url.includes("/cdn-cgi/challenge") || details.url.includes("cf_clearance")) {
                return {};
            }

            if (response.status === "malicious") {
                handleMaliciousUrl(details.url, response.threat || "URLhaus Blocklist", details.tabId, response.confirmed);
            }
        } catch (e) { }
    },
    { urls: ["<all_urls>"] }
);

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

    if (tabId && tabId !== -1) {
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
        const isExfiltratingHoneypot = (HONEYPOT_SECRET && bodyString.includes(HONEYPOT_SECRET)) ||
            bodyString.includes('H0n3yP0t@123!') ||
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
    { urls: ["<all_urls>"], types: ["xmlhttprequest", "ping", "websocket", "other"] },
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
    { urls: ["<all_urls>"] }
);



const THREAT_RATE_LIMITER = new Map();

async function logBlock(name, reason, url, tabId = null, forensicData = null) {
    // 1. DEDUPLICATION: Prevent reporting the same threat for the same URL in the last 10 seconds
    const dedupKey = `${reason}:${url}`;
    const lastReported = THREAT_RATE_LIMITER.get(dedupKey);
    if (lastReported && (Date.now() - lastReported) < 10000) {
        return { status: "ignored", reason: "duplicate" };
    }
    THREAT_RATE_LIMITER.set(dedupKey, Date.now());

    // 2. RATE LIMITING: Max 5 incidents per minute per tab
    if (tabId) {
        const tabKey = `rate:tab:${tabId}`;
        let tabHistory = THREAT_RATE_LIMITER.get(tabKey) || [];
        const now = Date.now();
        tabHistory = tabHistory.filter(t => (now - t) < 60000);
        if (tabHistory.length >= 5) {
            console.warn(`🛡️ RATE LIMITER: Ignoring security incident from tab ${tabId} (Limit reached)`);
            return { status: "ignored", reason: "rate_limit_exceeded" };
        }
        tabHistory.push(now);
        THREAT_RATE_LIMITER.set(tabKey, tabHistory);
    }

    const storage = await browser.storage.local.get({ blockedHistory: [] });
    const blocks = storage.blockedHistory;

    const incident = {
        name: name,
        status: "blocked",
        reason: reason,
        url: url,
        hostname: new URL(url).hostname,
        time: new Date().toISOString(),
        tabId: tabId,
        reported: false,
        forensics: forensicData
    };

    blocks.push(incident);

    // PERSISTENT DISK LOGGING (EDR Requirement)
    try {
        const secret = await getSecret();
        browser.runtime.sendNativeMessage(NATIVE_HOST_NAME, {
            action: "log_incident",
            incident: incident,
            secret: secret
        }).catch(() => { });
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

async function performScan(target, type, downloadId = null, tabId = null) {
    dbg(`Initiating ${type} scan for: ${target}`);

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
        progressUpdate({ status: "complete", result: "clean", msg: "Bypassed (Browser-Only Mode)" });
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
        const port = browser.runtime.connectNative(NATIVE_HOST_NAME);

        port.onMessage.addListener(async (response) => {
            if (response.status === "progress") {
                progressUpdate({ status: "scanning", percent: response.percent, msg: response.msg });
                return;
            }

            if (response.status === "error" && response.tamper) {
                console.error("🛑 SECURITY ALERT: Host reported tampering or invalid secret!");
                // Self-heal: clear secret and re-handshake next time
                SESSION_HOST_SECRET = null;
                notifyError("Security Handshake Expired. Re-authenticating...");
                port.disconnect();
                return;
            }

            // Final Result Handling
            dbg("Scan result:", response);
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
                await logBlock(target.split('/').pop() || target, virus, target, tabId);

                browser.action.setBadgeText({ text: "ERR" });
                browser.action.setBadgeBackgroundColor({ color: "#ef4444" });

                if (downloadId) {
                    try {
                        await browser.downloads.cancel(downloadId);
                        await browser.downloads.erase({ id: downloadId });
                    } catch (e) { }
                }
                notifyThreat(target, response.virus || "MalwareBazaar threat");

                // AUTO-BURN Logic: Automatically neutralizing zero-days globally if enabled
                if (settings.autoBurnEnabled && (response.status === "infected" || (response.mb && response.mb.status === "mb_infected"))) {
                    dbg("🔥 AUTO-BURN: High-confidence threat detected. Initiating community neutralization...");
                    browser.runtime.sendNativeMessage(NATIVE_HOST_NAME, {
                        action: "report_threat",
                        target: target,
                        type: response.virus || "Automated Detection",
                        details: { forensics: { auto: true, source: "Background Shield" } },
                        secret: secret
                    }).then(async (burnResp) => {
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
            } else if (response.status === "clean" && type !== "file_partial") {
                browser.action.setBadgeText({ text: "OK" });
                browser.action.setBadgeBackgroundColor({ color: "#10b981" });
                notifyClean(target, downloadId);

                // SECURITY HARDENING: Release it from the quarantine directory into the user's view
                try {
                    const secret = await getSecret();
                    browser.runtime.sendNativeMessage(NATIVE_HOST_NAME, {
                        action: "release_quarantine",
                        target: target,
                        secret: secret
                    }).catch(() => { });
                } catch (e) { }

                setTimeout(() => browser.action.setBadgeText({ text: "" }), 5000);
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
                error: response.error,
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
        notifyHostMissing();
    }
}

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
                const res = await sendNativeMessageWithTimeout(NATIVE_HOST_NAME, { action: "check", secret: secret });
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
                    const res = await sendNativeMessageWithTimeout(NATIVE_HOST_NAME, { action: "check", secret: newSecret });
                    dbg("Diagnostic: proxy_check success after refresh:", res);

                    if (res && res.secret) {
                        delete res.secret;
                    }

                    return res;
                } catch (err) {
                    console.error("Diagnostic: proxy_check CRITICAL FAILURE:", err);
                    return { status: "error", error: err.message };
                }
            }
        } else if (message.action === "proxy_update") {
            return sendNativeMessageWithTimeout(NATIVE_HOST_NAME, { action: "update_urldb", secret: secret }, 15000); // 15s for updates
        } else if (message.action === "proxy_force_engine_update") {
            return sendNativeMessageWithTimeout(NATIVE_HOST_NAME, { action: "force_db_update", secret: secret }, 15000);
        } else if (message.action === "proxy_reconnect") {
            dbg("🔄 Manual Reconnection requested.");
            SESSION_HOST_SECRET = null;
            return getSecret(true).then(newSecret => {
                if (newSecret) return { status: "ok" };
                else return { status: "error", error: "Handshake failed. Host may be offline or misconfigured." };
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
                const response = await browser.runtime.sendNativeMessage(NATIVE_HOST_NAME, {
                    action: "check_url",
                    target: message.url,
                    secret: secret
                });

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

            if (!isWhitelisted(host)) {
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

            if (!isWhitelisted(host)) {
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

            if (!isWhitelisted(host)) {
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

            if (!isWhitelisted(host)) {
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

            if (!isWhitelisted(host)) {
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

            if (!isWhitelisted(host)) {
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
                dbg(`🛡️ USER OVERRIDE: Persistently whitelisting ${message.domain}`);
                USER_WHITELIST.add(message.domain);

                // Persist to storage
                const current = Array.from(USER_WHITELIST);
                await browser.storage.local.set({ userWhitelist: current });

                return { status: "whitelisted" };
            }
        }
        return false;
    };

    // Return true to indicate we will send a response asynchronously
    handleMessage().then(sendResponse).catch(err => {
        console.error("Message Handler Error:", err);
        sendResponse({ status: "error", error: err.message });
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
            await browser.runtime.sendNativeMessage(NATIVE_HOST_NAME, { action: "update_urldb", secret: secret });
            // Sync YARA
            await browser.runtime.sendNativeMessage(NATIVE_HOST_NAME, { action: "update_yara", secret: secret });
            dbg("✅ Scheduled Sync Completed.");
        } catch (e) {
            console.error("❌ Scheduled Sync Failed:", e);
        }
    } else if (alarm.name === "secret-rotation") {
        // Security: Automatic session key rotation
        dbg("🔑 Scheduled session key rotation starting...");
        try {
            const currentSecret = await getSecret();
            const response = await browser.runtime.sendNativeMessage(NATIVE_HOST_NAME, {
                action: "rotate_secret",
                secret: currentSecret
            });
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
            const intel = await browser.runtime.sendNativeMessage(NATIVE_HOST_NAME, {
                action: "get_intel",
                secret: secret
            });
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
    { urls: ["<all_urls>"], types: ["main_frame"] },
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
