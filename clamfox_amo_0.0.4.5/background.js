const NATIVE_HOST_NAME = "clamav_host";

const SCAN_INTERVAL_BYTES = 10 * 1024 * 1024; // Scan every 10MB
const activeDownloads = new Map();

let HONEYPOT_SECRET = "H0n3yP0t@123!"; // Default fallback

async function initHoneypot() {
    const storage = await browser.storage.local.get("honeypotSecret");
    if (storage.honeypotSecret) {
        HONEYPOT_SECRET = storage.honeypotSecret;
    } else {
        const arr = new Uint32Array(4);
        crypto.getRandomValues(arr);
        HONEYPOT_SECRET = "cf_honey_" + Array.from(arr, dec => dec.toString(36)).join('');
        await browser.storage.local.set({ honeypotSecret: HONEYPOT_SECRET });
    }
    console.log("🍯 HONEYPOT SHIELD: Dynamic secret established.");
}

initHoneypot();

// EDR Core: Tab-based Incident Telemetry
const TAB_INCIDENTS = new Map();

function escalateTabProtection(tabId) {
    console.log(`🛡️ EDR ESCALATION: Hardening security for suspect tab ${tabId}`);
    // We could use scripting.registerContentScripts or dynamic CSP injection here.
    // For now, we flag it in storage so content scripts can react.
    browser.storage.local.set({ [`tab_escalated_${tabId}`]: true });
}

// DOWNLOAD SHIELD: Prevent access until scanned
browser.downloads.onCreated.addListener(async (item) => {
    // 1. Pre-emptive Pause to allow reputation check
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
        console.log("Download complete event received for ID:", delta.id);
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
                console.log("🔒 FILE SEALED: Access restricted during analysis.");
            } catch (e) { }

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
                info = { lastScanBytes: 0, filename: items[0].filename };
                activeDownloads.set(id, info);
            }
        }

        if (info) {
            const settings = await browser.storage.local.get({ scanFrequencyMB: 10 });
            const intervalBytes = settings.scanFrequencyMB * 1024 * 1024;

            if ((currentBytes - info.lastScanBytes) > intervalBytes) {
                console.log(`Progressive scan for ${info.filename} at ${currentBytes} bytes (Interval: ${settings.scanFrequencyMB}MB)`);
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

async function getSecret(forceRefresh = false) {
    if (!forceRefresh) {
        const storage = await browser.storage.local.get("hostSecret");
        if (storage.hostSecret) return storage.hostSecret;
    }

    try {
        console.log("🔒 Security Handshake starting...");
        // Send a bare check to get the current secret
        const response = await browser.runtime.sendNativeMessage(NATIVE_HOST_NAME, { action: "check" });
        if (response && response.secret && response.secret !== "****") {
            await browser.storage.local.set({ hostSecret: response.secret });
            console.log("🔒 Security Handshake successful.");
            return response.secret;
        }
    } catch (e) {
        console.warn("Handshake failed, host might be offline:", e);
    }
    return null;
}

browser.webRequest.onBeforeRequest.addListener(
    async (details) => {
        if (details.type !== "main_frame") return {};
        if (details.url.startsWith(browser.runtime.getURL(""))) return {};
        if (details.url.startsWith("about:") || details.url.startsWith("moz-extension:")) return {};

        // Latency Fast-Path: Skip native scanning for trusted High-Value Targets
        try {
            const url = new URL(details.url);
            if (SECURE_PORTALS.some(d => url.hostname === d || url.hostname.endsWith("." + d))) {
                return {};
            }
        } catch (e) { }

        try {
            const secret = await getSecret();
            const response = await browser.runtime.sendNativeMessage(NATIVE_HOST_NAME, {
                action: "check_url",
                target: details.url,
                secret: secret
            });

            if (response.status === "malicious") {
                logBlock(new URL(details.url).hostname, response.threat || "URLhaus Blocklist", details.url, details.tabId);

                browser.notifications.create({
                    type: "basic",
                    iconUrl: "icons/warning.svg",
                    title: browser.i18n.getMessage("siteBlockedTitle") || "🛑 MALICIOUS SITE BLOCKED",
                    message: `ClamFox prevented a connection to ${new URL(details.url).hostname}. This site is flagged as: ${response.threat || "Malicious"}.`,
                    priority: 2
                });

                const blockedUrl = browser.runtime.getURL("popup/blocked.html") +
                    "?url=" + encodeURIComponent(details.url) +
                    "&threat=" + encodeURIComponent(response.threat || "URLhaus Blocklist");

                return { redirectUrl: blockedUrl };
            }
        } catch (e) { }

        return {};
    },
    { urls: ["<all_urls>"] },
    ["blocking"]
);

// Exfiltration Interception: Scan POST/WebSocket data flows
browser.webRequest.onBeforeRequest.addListener(
    (details) => {
        if (details.method !== "POST" || !details.requestBody) return {};

        // Skip large payloads, Cloudflare, or trusted secure portals to avoid blocking/latency
        try {
            const url = new URL(details.url);
            if (url.hostname.includes('cloudflare') || url.hostname.includes('challenges.cloudflare.com')) return {};
            if (SECURE_PORTALS.some(d => url.hostname === d || url.hostname.endsWith("." + d))) return {};
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
                title: "🛑 DATA EXFILTRATION BLOCKED",
                message: `ClamFox intercepted a script attempting to exfiltrate decoy honeypot credentials to ${new URL(details.url).hostname}. Connection terminated.`,
                priority: 2
            });
            return { cancel: true }; // Kill the connection
        }

        return {};
    },
    { urls: ["<all_urls>"], types: ["xmlhttprequest", "ping", "websocket", "other"] },
    ["blocking", "requestBody"]
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

browser.webRequest.onBeforeRequest.addListener(
    (details) => {
        // Only inspect background requests
        if (details.type === "main_frame" || details.type === "sub_frame") return {};

        try {
            const url = new URL(details.url);
            const host = url.hostname;
            const port = url.port;
            const now = Date.now();

            // Exclusion list for known high-frequency legitimate telemetry/API hosts
            const isExempt = host.includes('google-analytics') || host.includes('doubleclick') ||
                host.includes('facebook') || host.includes('cloudflare') ||
                host.includes('cloudfront') || host.includes('amazonaws') ||
                host.includes('skype.com') || host.includes('microsoft.com') ||
                SECURE_PORTALS.some(d => host === d || host.endsWith("." + d));

            if (!isExempt) {
                let history = REQUEST_HISTORY.get(host) || [];
                history = history.filter(t => now - t < 60000);
                history.push(now);
                REQUEST_HISTORY.set(host, history);

                if (history.length > 12) {
                    let intervals = [];
                    for (let i = history.length - 1; i >= history.length - 10; i--) {
                        intervals.push(history[i] - history[i - 1]);
                    }

                    const mean = intervals.reduce((a, b) => a + b) / intervals.length;
                    const variance = intervals.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / intervals.length;
                    const stdDev = Math.sqrt(variance);

                    if (stdDev < 500 && mean > 1000) {
                        console.warn(`🛑 C2 BEACON SHIELD: Blocked metronomic telemetry to ${host}`);
                        logBlock(host, "C2 Beacon / Aggressive Telemetry Blocked", details.url, details.tabId);
                        browser.notifications.create({
                            type: "basic",
                            iconUrl: "icons/warning.svg",
                            title: "🛑 C2 BEACON INTERCEPTED",
                            message: `Suspicious metronomic telemetry (C2 Beacon) detected and suppressed for ${host}. Background tracking is now throttled.`,
                            priority: 2
                        });

                        const futureBan = [];
                        for (let i = 0; i < 50; i++) futureBan.push(now + 300000);
                        REQUEST_HISTORY.set(host, futureBan);

                        return { cancel: true };
                    }
                }
            }

            // 2. Local Port Scan & Anti DNS-Rebinding Detection
            const isLocalIP = /^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|0\.0\.0\.0|localhost)/.test(host);

            if (isLocalIP && details.originUrl) {
                const originHost = new URL(details.originUrl).hostname;
                const isOriginLocal = /^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|0\.0\.0\.0|localhost)/.test(originHost);

                if (!isOriginLocal && originHost) {
                    if (port) {
                        // Check if it's a port scan
                        let history = PORT_SCAN_HISTORY.get(originHost) || [];
                        history = history.filter(p => now - p.time < 2000); // 2 seconds window
                        history.push({ port: parseInt(port), time: now });
                        PORT_SCAN_HISTORY.set(originHost, history);

                        const uniquePorts = new Set(history.map(p => p.port)).size;

                        if (uniquePorts >= 5) {
                            console.warn(`🛑 PORT SCAN SHIELD: Blocked public site ${originHost} from scanning local ports!`);
                            logBlock(originHost, "WebSocket/Local Port Scan Blocked", details.url, details.tabId);
                            browser.notifications.create({
                                type: "basic",
                                iconUrl: "icons/warning.svg",
                                title: "🛑 LOCAL NETWORK SCAN BLOCKED",
                                message: `Security Alert: ${originHost} was caught performing a port scan on your local network. This is a common reconnaissance technique for internal exploits.`,
                                priority: 2
                            });
                            return { cancel: true };
                        }
                    } else {
                        // Standard DNS Rebinding Catch
                        console.warn(`🛑 DNS-REBINDING SHIELD: Blocked public site ${originHost} from scanning local IP: ${host}`);
                        logBlock(originHost, "DNS Rebinding / Local Scan Blocked", details.url, details.tabId);
                        browser.notifications.create({
                            type: "basic",
                            iconUrl: "icons/warning.svg",
                            title: "🛑 INTRANET LEAK PREVENTED",
                            message: `Proactive Shield: Blocked ${originHost} from resolving or interacting with private local addresses (DNS Rebinding protection).`,
                            priority: 2
                        });
                        return { cancel: true };
                    }
                }
            }
        } catch (e) { }

        return {};
    },
    { urls: ["<all_urls>"] },
    ["blocking"]
);

browser.downloads.onCreated.addListener(async (item) => {
    try { await browser.downloads.pause(item.id); } catch (e) { }

    try {
        const secret = await getSecret();
        const response = await browser.runtime.sendNativeMessage(NATIVE_HOST_NAME, {
            action: "check_url",
            target: item.url,
            secret: secret
        });

        if (response.status === "malicious") {
            await browser.downloads.cancel(item.id);
            await browser.downloads.erase({ id: item.id });

            browser.notifications.create({
                type: "basic",
                iconUrl: "icons/warning.svg",
                title: "🛑 DOWNLOAD BLOCKED",
                message: `Malicious URL detected and blocked: ${item.url}`,
                priority: 2
            });

            logBlock(item.filename.split('/').pop() || "Blocked Download", `URLhaus: ${response.threat}`, item.url);
        } else {
            await browser.downloads.resume(item.id);
        }
    } catch (error) {
        try { await browser.downloads.resume(item.id); } catch (e) { }
    }
});

async function logBlock(name, reason, url, tabId = null, forensicData = null) {
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
    console.log(`Initiating ${type} scan for: ${target}`);

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
                await browser.storage.local.remove("hostSecret");
                notifyError("Security Handshake Expired. Re-authenticating...");
                port.disconnect();
                return;
            }

            // Final Result Handling
            console.log("Scan result:", response);
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
                const virus = response.virus || (response.mb && response.mb.status === "mb_infected" ? "MalwareBazaar Flag" : "Unknown Threat");
                logBlock(target.split('/').pop() || target, virus, target, tabId);

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
                    console.log("🔥 AUTO-BURN: High-confidence threat detected. Initiating community neutralization...");
                    browser.runtime.sendNativeMessage(NATIVE_HOST_NAME, {
                        action: "report_threat",
                        target: target,
                        type: response.virus || "Automated Detection",
                        details: { forensics: { auto: true, source: "Background Shield" } },
                        secret: secret
                    }).catch(() => { });
                }
            } else if (response.status === "clean" && type !== "file_partial") {
                browser.action.setBadgeText({ text: "OK" });
                browser.action.setBadgeBackgroundColor({ color: "#10b981" });
                notifyClean(target);

                // SECURITY HARDENING: Re-enable access only after verified clean
                try {
                    const secret = await getSecret();
                    browser.runtime.sendNativeMessage(NATIVE_HOST_NAME, {
                        action: "unlock",
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

    console.log("Internal message received:", message);

    const handleMessage = async () => {
        // Skip internal pages
        if (message.url && (message.url.startsWith("about:") || message.url.startsWith("chrome:") || message.url.startsWith("file:"))) {
            return { status: "clean", info: "internal_page_skipped" };
        }

        let secret = await getSecret();

        if (message.action === "scan_request") {
            performScan(message.url, "url", null, message.tabId || null);
            return { status: "initiated" };
        } else if (message.action === "proxy_check") {
            try {
                console.log("Diagnostic: Starting proxy_check...");
                const res = await browser.runtime.sendNativeMessage(NATIVE_HOST_NAME, { action: "check", secret: secret });
                console.log("Diagnostic: proxy_check success:", res);

                // Keep secret in sync: If host returns a new secret during check, store it
                if (res.secret && res.secret !== "****") {
                    console.log("🔄 Secret refresh detected during check.");
                    await browser.storage.local.set({ hostSecret: res.secret });
                }

                return res;
            } catch (e) {
                console.warn("Diagnostic: proxy_check failed, attempting force refresh...", e);
                // Force refresh on failure
                try {
                    const newSecret = await getSecret(true);
                    const res = await browser.runtime.sendNativeMessage(NATIVE_HOST_NAME, { action: "check", secret: newSecret });
                    console.log("Diagnostic: proxy_check success after refresh:", res);
                    return res;
                } catch (err) {
                    console.error("Diagnostic: proxy_check CRITICAL FAILURE:", err);
                    return { status: "error", error: err.message };
                }
            }
        } else if (message.action === "proxy_update") {
            return browser.runtime.sendNativeMessage(NATIVE_HOST_NAME, { action: "update_urldb", secret: secret });
        } else if (message.action === "proxy_force_engine_update") {
            return browser.runtime.sendNativeMessage(NATIVE_HOST_NAME, { action: "force_db_update", secret: secret });
        } else if (message.action === "proxy_reseal") {
            return browser.runtime.sendNativeMessage(NATIVE_HOST_NAME, { action: "reseal", secret: secret });
        } else if (message.action === "proxy_update_yara") {
            return browser.runtime.sendNativeMessage(NATIVE_HOST_NAME, { action: "update_yara", secret: secret });
        } else if (message.action === "proxy_get_logs") {
            return browser.runtime.sendNativeMessage(NATIVE_HOST_NAME, { action: "get_audit_logs", secret: secret });
        } else if (message.action === "proxy_report_threat") {
            return browser.runtime.sendNativeMessage(NATIVE_HOST_NAME, {
                action: "report_threat",
                target: message.target,
                type: message.type,
                details: message.details,
                secret: secret
            });
        } else if (message.action === "proxy_list_quarantine") {
            return browser.runtime.sendNativeMessage(NATIVE_HOST_NAME, { action: "list_quarantine", secret: secret });
        } else if (message.action === "proxy_restore") {
            return browser.runtime.sendNativeMessage(NATIVE_HOST_NAME, { action: "restore", target: message.target, secret: secret });
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
                return { trust: response.trust || "standard", status: response.status };
            } catch (e) {
                return { trust: "standard", status: "error" };
            }
        } else if (message.action === "log_honeypot") {
            logBlock("Honeypot Decoy Tripped", message.threat, sender.tab ? sender.tab.url : "Unknown URL", sender.tab ? sender.tab.id : null, message.forensics);
            browser.notifications.create({
                type: "basic",
                iconUrl: "icons/warning.svg",
                title: "🛑 BOT SCRAPING ATTEMPT",
                message: `ClamFox Forensic Engine caught a script trying to read hidden honey-fields on this page. Potential data-stealer detected.`,
                priority: 2
            });
            return { status: "logged" };
        } else if (message.action === "log_formjacking") {
            logBlock("Formjacking Detected", message.threat, sender.tab ? sender.tab.url : "Unknown URL", sender.tab ? sender.tab.id : null, message.forensics);
            browser.notifications.create({
                type: "basic",
                iconUrl: "icons/warning.svg",
                title: "🛑 KEYLOGGER / FORMJACKING",
                message: `Security Bypass: A script tried to attach an unauthorized listener to a sensitive input field. Listener suppressed.`,
                priority: 2
            });
            return { status: "logged" };
        } else if (message.action === "log_visual_phish") {
            logBlock("Visual Phishing Detected", message.threat, sender.tab ? sender.tab.url : "Unknown URL", sender.tab ? sender.tab.id : null, message.forensics);
            browser.notifications.create({
                type: "basic",
                iconUrl: "icons/warning.svg",
                title: "⚠️ BRAND IMPERSONATION ALERT",
                message: `ClamFox Visual Shield detected brand spoofing! ${message.threat}. Verify the URL before entering data.`,
                priority: 2
            });
            return { status: "logged" };
        } else if (message.action === "log_driveby") {
            logBlock("Drive-by Download Detected", message.threat, sender.tab ? sender.tab.url : "Unknown URL", sender.tab ? sender.tab.id : null, message.forensics);
            browser.notifications.create({
                type: "basic",
                iconUrl: "icons/warning.svg",
                title: "🛑 DRIVE-BY DOWNLOAD BLOCKED",
                message: `Security Enforcement: Blocked an automated, non-user-initiated download attempt. Analysis: ${message.threat}.`,
                priority: 2
            });
            return { status: "logged" };
        } else if (message.action === "log_behavior") {
            logBlock("Malicious Behavior Detected", message.threat, sender.tab ? sender.tab.url : "Unknown URL", sender.tab ? sender.tab.id : null, message.forensics);
            browser.notifications.create({
                type: "basic",
                iconUrl: "icons/warning.svg",
                title: "🛑 BEHAVIORAL THREAT NEUTRALIZED",
                message: `The ClamFox Heuristic Engine identified a malicious script pattern: ${message.threat}. Execution suppressed.`,
                priority: 2
            });
            return { status: "logged" };
        } else if (message.action === "log_dom_anomaly") {
            logBlock("DOM Anomaly / Clickjacking Overlay", message.threat, sender.tab ? sender.tab.url : "Unknown URL", sender.tab ? sender.tab.id : null, message.forensics);
            browser.notifications.create({
                type: "basic",
                iconUrl: "icons/warning.svg",
                title: "🛑 CLICKJACKING OVERLAY BLOCKED",
                message: `Privacy Shield: An invisible UI layer was detected and destroyed. This layer was likely trying to capture clicks or intercept sensitive interactions.`,
                priority: 2
            });
            return { status: "logged" };
        } else if (message.action === "get_hvts") {
            try {
                const url = browser.runtime.getURL("host/trust_db.json");
                const response = await fetch(url);
                const data = await response.json();
                return {
                    hvts: data.hvts || [],
                    whitelist: data.global_whitelist || [],
                    honeypot_secret: HONEYPOT_SECRET
                };
            } catch (e) {
                console.error("Failed to load trust_db.json", e);
                return { hvts: [], whitelist: [], honeypot_secret: HONEYPOT_SECRET };
            }
        } else if (message.action === "get_tab_id") {
            return sender.tab ? sender.tab.id : null;
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

function notifyClean(target) {
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
    console.log("ClamAV Context Menus Registered");

    // Initialize 6-hour Intelligence Sync Alarm
    setupIntelligenceAlarm();

    // Ensure privacy shield is active on install/update
    initPrivacyShield();
});

async function setupIntelligenceAlarm() {
    const settings = await browser.storage.local.get({ autoSyncEnabled: true });
    if (settings.autoSyncEnabled) {
        console.log("⏰ Setting up 3-hour Intelligence Sync Alarm...");
        browser.alarms.create("intelligence-sync", {
            periodInMinutes: 180 // 3 hours
        });
    } else {
        browser.alarms.clear("intelligence-sync");
    }
}

// Handle Background Alarms
browser.alarms.onAlarm.addListener(async (alarm) => {
    if (alarm.name === "intelligence-sync") {
        console.log("🚀 Executing Scheduled Intelligence Sync...");
        try {
            const secret = await getSecret();
            // Sync URLHaus
            await browser.runtime.sendNativeMessage(NATIVE_HOST_NAME, { action: "update_urldb", secret: secret });
            // Sync YARA
            await browser.runtime.sendNativeMessage(NATIVE_HOST_NAME, { action: "update_yara", secret: secret });
            console.log("✅ Scheduled Sync Completed.");
        } catch (e) {
            console.error("❌ Scheduled Sync Failed:", e);
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
        console.log("🛡️ PRIVACY SHIELD: WebRTC IP Leak Protection active.");
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
        const url = browser.runtime.getURL("host/trust_db.json");
        const response = await fetch(url);
        const data = await response.json();
        const defaultPortals = (data.hvts || []).map(hvt => hvt.domains).flat();
        const globalWhitelist = data.global_whitelist || [];

        const storage = await browser.storage.local.get({ customPortals: [] });
        SECURE_PORTALS = [...defaultPortals, ...globalWhitelist, ...storage.customPortals];
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
            const isSecurePortal = SECURE_PORTALS.some(d => url.hostname === d || url.hostname.endsWith("." + d));

            if (isSecurePortal) {
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
                    console.log(`🛡️ PROACTIVE BYPASS: Not injecting security headers into ${url.hostname} flow.`);
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
    ["blocking", "responseHeaders"]
);

// Start the proactive bridge immediately
initBackgroundBridge();
initPrivacyShield();

// Single message listener handles everything.

browser.menus.onClicked.addListener((info, tab) => {
    console.log("Context Menu Clicked:", info.menuItemId);
    const tabId = tab ? tab.id : null;

    if (info.menuItemId === "scan-link") {
        if (info.linkUrl) {
            console.log("Scanning link:", info.linkUrl);
            performScan(info.linkUrl, "url", null, tabId);
        } else {
            console.error("No link URL found in context menu info");
        }
    } else if (info.menuItemId === "scan-image") {
        if (info.srcUrl) {
            console.log("Scanning image:", info.srcUrl);
            performScan(info.srcUrl, "url", null, tabId);
        } else {
            console.error("No source URL found in context menu info");
        }
    }
});
