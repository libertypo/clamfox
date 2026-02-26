const NATIVE_HOST_NAME = "clamav_host";

document.addEventListener('DOMContentLoaded', async () => {
    translatePage();
    await checkEngine();
    await renderLogs();
    await renderBlockHistory();
    await initSettings();
    initTheme();
    initExports();

    document.getElementById('scan-page-btn').addEventListener('click', scanCurrentTab);
    document.getElementById('refresh-url-db').addEventListener('click', forceUpdateUrlDb);
    document.getElementById('refresh-engine-db').addEventListener('click', forceUpdateEngineDb);
    document.getElementById('refresh-yara-db').addEventListener('click', forceUpdateYaraDb);
    document.getElementById('view-audit-logs').addEventListener('click', showAuditLogs);
    document.getElementById('close-forensic').addEventListener('click', () => {
        document.getElementById('forensic-overlay').style.display = 'none';
    });
    document.getElementById('report-threat-btn').addEventListener('click', communityBurn);
    document.getElementById('clear-blocks').addEventListener('click', clearBlockHistory);
    document.getElementById('clear-scans').addEventListener('click', clearScanHistory);

    // View Switching Logic
    const dashboardView = document.getElementById('view-dashboard');
    const settingsView = document.getElementById('view-settings');
    const navSettings = document.getElementById('nav-settings');
    const navBack = document.getElementById('nav-back');

    if (navSettings && navBack) {
        navSettings.addEventListener('click', () => {
            dashboardView.classList.remove('active');
            settingsView.classList.add('active');
        });

        navBack.addEventListener('click', () => {
            settingsView.classList.remove('active');
            dashboardView.classList.add('active');
        });
    }

    // Listen for progress updates
    browser.runtime.onMessage.addListener((message) => {
        if (message.action === "scan_progress") {
            const btn = document.getElementById('scan-page-btn');
            if (btn && btn.disabled) {
                btn.textContent = browser.i18n.getMessage("scanningWithPercent", [message.percent]);
            }
        } else if (message.action === "scan_complete") {
            const btn = document.getElementById('scan-page-btn');
            if (btn) {
                btn.textContent = browser.i18n.getMessage("scanTab");
                btn.disabled = false;
                renderLogs();
                renderBlockHistory();
            }
        }
    });
});

async function forceUpdateUrlDb() {
    const btn = document.getElementById('refresh-url-db');
    const text = document.getElementById('url-db-status-text');

    btn.disabled = true;
    text.textContent = browser.i18n.getMessage("updating");
    text.style.color = "var(--primary)";

    try {
        await browser.runtime.sendMessage({ action: "proxy_update" });
        checkEngine();
    } catch (error) {
        text.textContent = browser.i18n.getMessage("updateFailed");
        text.style.color = "var(--danger)";
    } finally {
        btn.disabled = false;
    }
}

async function forceUpdateEngineDb() {
    const btn = document.getElementById('refresh-engine-db');
    const text = document.getElementById('db-status-text');

    btn.disabled = true;
    text.textContent = browser.i18n.getMessage("updating");
    text.style.color = "var(--primary)";

    try {
        const response = await browser.runtime.sendMessage({ action: "proxy_force_engine_update" });
        if (response.status === "ok") {
            text.textContent = browser.i18n.getMessage("engineUpdated");
            setTimeout(() => checkEngine(), 1500);
        } else {
            text.textContent = browser.i18n.getMessage("updateFailed");
            text.style.color = "var(--danger)";
        }
    } catch (error) {
        text.textContent = browser.i18n.getMessage("hostError");
        text.style.color = "var(--danger)";
    } finally {
        btn.disabled = false;
    }
}

async function forceUpdateYaraDb() {
    const btn = document.getElementById('refresh-yara-db');
    const text = document.getElementById('yara-status-text');

    btn.disabled = true;
    text.textContent = "Syncing YARA...";
    text.style.color = "var(--primary)";

    try {
        const response = await browser.runtime.sendMessage({ action: "proxy_update_yara" });
        if (response.status === "ok") {
            text.textContent = "Signatures Unified";
            text.style.color = "var(--success)";
            setTimeout(() => {
                text.textContent = "Community Rules";
                text.style.color = "";
            }, 3000);
        } else {
            text.textContent = "Sync Failed";
            text.style.color = "var(--danger)";
            console.error(response.error);
        }
    } catch (error) {
        text.textContent = "Host Error";
        text.style.color = "var(--danger)";
    } finally {
        btn.disabled = false;
    }
}

async function initSettings() {
    const freqSlider = document.getElementById('scan-freq-slider');
    const freqValue = document.getElementById('freq-value');
    const mbToggle = document.getElementById('mb-toggle');
    const puaToggle = document.getElementById('pua-toggle');
    const ramToggle = document.getElementById('ram-toggle');

    // Load saved settings
    const settings = await browser.storage.local.get({
        scanFrequencyMB: 10,
        useMB: true,
        puaEnabled: true,
        ramMode: true,
        ghostMode: false,
        remindersEnabled: true,
        autoSyncEnabled: true,
        autoBurnEnabled: false,
        promptInjectionShieldEnabled: true,
        suppressTrustedToasts: true
    });

    freqSlider.value = settings.scanFrequencyMB;
    freqValue.textContent = settings.scanFrequencyMB;
    mbToggle.checked = settings.useMB;
    puaToggle.checked = settings.puaEnabled;
    ramToggle.checked = settings.ramMode;

    const reminderToggle = document.getElementById('reminder-toggle');
    if (reminderToggle) {
        reminderToggle.checked = settings.remindersEnabled;
        reminderToggle.addEventListener('change', () => {
            browser.storage.local.set({ remindersEnabled: reminderToggle.checked });
        });
    }

    // Save on change
    freqSlider.addEventListener('input', () => {
        freqValue.textContent = freqSlider.value;
        const hint = document.querySelector('[data-i18n="frequencyHint"]');
        if (hint) hint.textContent = browser.i18n.getMessage("frequencyHint", [freqSlider.value]);
        browser.storage.local.set({ scanFrequencyMB: parseInt(freqSlider.value) });
    });

    mbToggle.addEventListener('change', () => {
        browser.storage.local.set({ useMB: mbToggle.checked });
    });

    puaToggle.addEventListener('change', () => {
        browser.storage.local.set({ puaEnabled: puaToggle.checked });
    });

    ramToggle.addEventListener('change', () => {
        browser.storage.local.set({ ramMode: ramToggle.checked });
    });

    const ghostToggle = document.getElementById('ghost-toggle');
    if (ghostToggle) {
        ghostToggle.checked = settings.ghostMode;
        ghostToggle.addEventListener('change', () => {
            browser.storage.local.set({ ghostMode: ghostToggle.checked });
        });
    }

    const promptInjectionShieldToggle = document.getElementById('prompt-injection-shield-toggle');
    if (promptInjectionShieldToggle) {
        promptInjectionShieldToggle.checked = settings.promptInjectionShieldEnabled;
        promptInjectionShieldToggle.addEventListener('change', () => {
            browser.storage.local.set({ promptInjectionShieldEnabled: promptInjectionShieldToggle.checked });
        });
    }

    const suppressToastsToggle = document.getElementById('suppress-toasts-toggle');
    if (suppressToastsToggle) {
        suppressToastsToggle.checked = settings.suppressTrustedToasts || false;
        suppressToastsToggle.addEventListener('change', () => {
            browser.storage.local.set({ suppressTrustedToasts: suppressToastsToggle.checked });
        });
    }

    const autoSyncToggle = document.getElementById('auto-sync-toggle');
    if (autoSyncToggle) {
        autoSyncToggle.checked = settings.autoSyncEnabled;
        autoSyncToggle.addEventListener('change', () => {
            browser.storage.local.set({ autoSyncEnabled: autoSyncToggle.checked });
            browser.runtime.sendMessage({ action: "update_alarm_settings" }).catch(() => { });
        });
    }

    const autoBurnToggle = document.getElementById('auto-burn-toggle');
    if (autoBurnToggle) {
        autoBurnToggle.checked = settings.autoBurnEnabled;
        autoBurnToggle.addEventListener('change', () => {
            browser.storage.local.set({ autoBurnEnabled: autoBurnToggle.checked });
        });
    }

    initCustomPortals();
}

async function initCustomPortals() {
    const input = document.getElementById('new-portal-input');
    const addBtn = document.getElementById('add-portal-btn');
    const list = document.getElementById('custom-portals-list');

    const render = async () => {
        const data = await browser.storage.local.get({ customPortals: [] });
        list.textContent = '';
        if (data.customPortals.length === 0) {
            const emptyHint = document.createElement('span');
            emptyHint.style.fontSize = "0.75rem";
            emptyHint.style.color = "var(--text-dim)";
            emptyHint.textContent = browser.i18n.getMessage("noCustomPortals") || "No custom portals added";
            list.appendChild(emptyHint);
            return;
        }

        data.customPortals.forEach(domain => {
            const tag = document.createElement('div');
            tag.className = 'portal-tag';

            const nameSpan = document.createElement('span');
            nameSpan.textContent = domain;

            const removeBtn = document.createElement('span');
            removeBtn.className = 'remove-portal';
            removeBtn.dataset.domain = domain;
            removeBtn.textContent = '×';

            removeBtn.addEventListener('click', async () => {
                const current = await browser.storage.local.get({ customPortals: [] });
                const updated = current.customPortals.filter(d => d !== domain);
                await browser.storage.local.set({ customPortals: updated });
                render();
            });

            tag.appendChild(nameSpan);
            tag.appendChild(removeBtn);
            list.appendChild(tag);
        });
    };

    addBtn.addEventListener('click', async () => {
        const domain = input.value.trim().toLowerCase();
        if (!domain || !domain.includes('.')) return;

        const current = await browser.storage.local.get({ customPortals: [] });
        if (!current.customPortals.includes(domain)) {
            current.customPortals.push(domain);
            await browser.storage.local.set({ customPortals: current.customPortals });
            input.value = '';
            render();
        }
    });

    render();
}

async function initTheme() {
    const pills = document.querySelectorAll('.theme-pill');
    const storage = await browser.storage.local.get({ theme: 'auto' });

    const setTheme = (theme) => {
        document.body.className = '';

        let effectiveTheme = theme;
        if (theme === 'auto') {
            effectiveTheme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
        }

        if (effectiveTheme === 'light') document.body.classList.add('light-mode');
        if (effectiveTheme === 'glass') document.body.classList.add('glass-mode');

        pills.forEach(p => {
            p.classList.toggle('active', p.dataset.theme === theme);
        });
    };

    // Listen for system theme changes
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', async () => {
        const current = await browser.storage.local.get({ theme: 'auto' });
        if (current.theme === 'auto') setTheme('auto');
    });

    setTheme(storage.theme);

    pills.forEach(pill => {
        pill.addEventListener('click', () => {
            const theme = pill.dataset.theme;
            setTheme(theme);
            browser.storage.local.set({ theme });
        });
    });
}

function initExports() {
    const exportScans = document.getElementById('export-scans');
    const exportBlocks = document.getElementById('export-blocks');

    if (exportScans) {
        exportScans.addEventListener('click', async () => {
            const storage = await browser.storage.local.get({ recentScans: [] });
            exportJson(storage.recentScans, 'clamfox_scans_report.json');
        });
    }

    if (exportBlocks) {
        exportBlocks.addEventListener('click', async () => {
            const storage = await browser.storage.local.get({ blockedHistory: [] });
            exportJson(storage.blockedHistory, 'clamfox_blocks_report.json');
        });
    }
}

function exportJson(data, filename) {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
}

async function checkEngine() {
    const dot = document.getElementById('engine-dot');
    const text = document.getElementById('engine-text');
    const warning = document.getElementById('missing-warning');
    const btn = document.getElementById('scan-page-btn');
    const badge = document.getElementById('protection-badge');

    let isHealthy = false;
    let response = null;

    try {
        response = await browser.runtime.sendMessage({ action: "proxy_check" });
        console.log("ClamFox Diagnostic: Received engine status:", response);

        if (response && response.status === "ok") {
            const isTampered = (response.integrity_ok === false || response.binary_ok === false);
            isHealthy = !isTampered;

            dot.className = isHealthy ? "dot online" : (isTampered ? "dot offline" : "dot warning");
            text.textContent = isHealthy ? "ClamAV Active" : (isTampered ? "Integrity Breach!" : "ClamAV Warning");

            // Handle On-Access & Anonymity UI
            if (response.on_access) {
                const onAccess = document.getElementById('on-access-status');
                if (onAccess) {
                    onAccess.textContent = response.on_access === "active" ? "Active" : "Standby";
                    onAccess.style.color = response.on_access === "active" ? "var(--primary)" : "var(--text-dim)";
                }
            }

            if (response.privacy) {
                const tunnelStatus = document.getElementById('tunnel-status');
                const tunnelDot = document.getElementById('tunnel-dot');
                const ghostToggle = document.getElementById('ghost-toggle');
                const isTunneled = !!(response.privacy.tor || response.privacy.vpn);

                if (tunnelStatus) tunnelStatus.textContent = response.privacy.tor ? "Tor Active" : (response.privacy.vpn || "Local");
                if (tunnelDot) tunnelDot.className = isTunneled ? "dot online" : "dot offline";

                if (ghostToggle && isTunneled) {
                    ghostToggle.checked = false;
                    ghostToggle.disabled = true;
                    browser.storage.local.set({ ghostMode: false });
                    const ghostHint = document.querySelector('[data-i18n="ghostHint"]');
                    if (ghostHint) ghostHint.textContent = "Ghost Mode disabled: VPN/Tor Protection Active";
                } else if (ghostToggle) {
                    ghostToggle.disabled = false;
                    const ghostHint = document.querySelector('[data-i18n="ghostHint"]');
                    if (ghostHint) ghostHint.textContent = browser.i18n.getMessage("ghostHint");
                }
            }

            // CRITICAL: Integrity Breach Handling
            if (isTampered) {
                warning.innerHTML = ""; // Clear existing template
                warning.style.display = "block";

                const title = document.createElement("strong");
                title.textContent = response.integrity_ok === false ? "CRITICAL: Host Script Tampered!" : "ALERT: Extension Engine Changed!";
                warning.appendChild(title);
                warning.appendChild(document.createElement("br"));

                const desc = document.createElement("span");
                desc.textContent = response.integrity_ok === false
                    ? "The security seal has been broken. Unauthorized changes detected."
                    : "The ClamAV binary was updated. This must be re-verified.";
                warning.appendChild(desc);
                warning.appendChild(document.createElement("br"));

                const authBtn = document.createElement("button");
                authBtn.textContent = "Authorize & Reseal";
                authBtn.className = "primary-btn";
                authBtn.style.marginTop = "12px";
                authBtn.style.width = "100%";
                authBtn.onclick = async () => {
                    authBtn.disabled = true;
                    authBtn.textContent = "Sealing...";
                    try {
                        const res = await browser.runtime.sendMessage({ action: "proxy_reseal" });
                        if (res.status === "ok") window.location.reload();
                        else alert("Seal failed: " + res.error);
                    } catch (e) { alert("Communication Error"); }
                    authBtn.disabled = false;
                };
                warning.appendChild(authBtn);
            }

            // Intelligence & Database Health Metrics
            let dbDiffHours = 0;
            const hasClamDB = !!response.db_last_update;
            const hasUrlIntel = !!response.url_db_last_update;
            const hasPhishIntel = !!response.phish_db_last_update;

            if (hasClamDB) {
                dbDiffHours = Math.floor((new Date() - new Date(response.db_last_update * 1000)) / (1000 * 60 * 60));
            }

            // A build is 'healthy' ONLY if tamper-free AND has basic virus signatures
            isHealthy = !isTampered && hasClamDB && dbDiffHours <= 72 && (hasUrlIntel || hasPhishIntel);

            // UI WARNING BOX DISPATCHER (Exclusive Priority)
            if (isTampered) {
                // Handled in existing block above (line 375), preserving it
            } else if (!hasClamDB || dbDiffHours > 72 || !hasUrlIntel || !hasPhishIntel) {
                warning.innerHTML = "";
                warning.style.display = "block";

                const title = document.createElement("strong");
                title.textContent = "PROTECTION WEAKENED";
                warning.appendChild(title);
                warning.appendChild(document.createElement("br"));

                const desc = document.createElement("span");
                let reason = "Security feeds are syncing in the background.";
                if (!hasClamDB) reason = "Virus signatures are missing. Protection is limited.";
                else if (dbDiffHours > 72) reason = `Virus signatures are outdated (${Math.floor(dbDiffHours / 24)}d old).`;
                else if (!hasUrlIntel || !hasPhishIntel) reason = "Reputation intelligence is missing or incomplete.";

                desc.textContent = reason;
                warning.appendChild(desc);
                warning.appendChild(document.createElement("br"));

                const syncBtn = document.createElement("button");
                syncBtn.textContent = "Update Intelligence Now";
                syncBtn.className = "primary-btn";
                syncBtn.style.marginTop = "12px";
                syncBtn.style.width = "100%";
                syncBtn.onclick = async () => {
                    syncBtn.disabled = true;
                    syncBtn.textContent = "Syncing...";
                    // Trigger refresh of all intelligence feeds
                    await browser.runtime.sendMessage({ action: "proxy_update" });
                    await browser.runtime.sendMessage({ action: "proxy_update_yara" });
                    window.location.reload();
                };
                warning.appendChild(syncBtn);
            } else if (response.engine && response.engine.includes("Standard") && response.optimize_cmd) {
                const optCode = warning.querySelector('code');
                if (optCode) {
                    optCode.textContent = response.optimize_cmd;
                    warning.style.display = "block";
                } else {
                    warning.style.display = "none";
                }
            } else {
                warning.style.display = "none";
            }

            btn.disabled = isTampered;

            // Update Intelligence Status Texts in Settings View
            const urlStatus = document.getElementById('url-db-status-text');
            const yaraStatus = document.getElementById('yara-status-text');
            const urlDashboard = document.getElementById('url-dashboard-status');

            if (urlStatus && response.url_db_last_update) {
                const date = new Date(response.url_db_last_update * 1000);
                const timeStr = date.toLocaleDateString() + " " + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                urlStatus.textContent = `Last sync: ${timeStr}`;
                if (urlDashboard) urlDashboard.textContent = `Synced: ${timeStr}`;
            }

            if (yaraStatus && response.yara_last_update) {
                const date = new Date(response.yara_last_update * 1000);
                const timeStr = date.toLocaleDateString() + " " + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                yaraStatus.textContent = `Active: ${timeStr}`;
                const yaraDashboard = document.getElementById('yara-dashboard-status');
                if (yaraDashboard) yaraDashboard.textContent = `Active: ${timeStr}`;
            }

            const dbStatusText = document.getElementById('db-status-text');
            if (dbStatusText && response.db_last_update) {
                const date = new Date(response.db_last_update * 1000);
                const timeStr = date.toLocaleDateString() + " " + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                dbStatusText.textContent = `Synced: ${timeStr}`;
            }
        }
    } catch (e) {
        console.error("ClamFox Diagnostic: Engine Health Check Failed:", e);
        response = { status: "error", error: e.message };
    }

    // Badge & Warning Box Finalization (Terminal Dispatcher)
    if (!response || response.status === "error") {
        // CASE: TOTAL DISCONNECT / HOST ERROR
        badge.textContent = "Offline / Connection Error";
        badge.className = "protection-status status-danger";

        warning.innerHTML = "";
        warning.style.display = "block";
        const title = document.createElement("strong");
        title.textContent = "SECURITY ENGINE DISCONNECTED";
        warning.appendChild(title);
        warning.appendChild(document.createElement("br"));

        const desc = document.createElement("span");
        const errMsg = (response && response.error) ? response.error : "The background scanner is not responding. Ensure the host is installed and Firefox has been restarted.";
        desc.textContent = errMsg;
        warning.appendChild(desc);
        warning.appendChild(document.createElement("br"));

        const retryBtn = document.createElement("button");
        retryBtn.textContent = "Verify & Reconnect";
        retryBtn.className = "primary-btn";
        retryBtn.style.marginTop = "12px";
        retryBtn.style.width = "100%";
        retryBtn.onclick = () => window.location.reload();
        warning.appendChild(retryBtn);

    } else if (response.status === "missing") {
        isHealthy = false;
        dot.className = "dot offline";
        text.textContent = "Scanner Missing";
        warning.style.display = "block";
        badge.textContent = "Scanner Missing";
        badge.className = "protection-status status-danger";
    } else {
        const tampered = (response.integrity_ok === false || response.binary_ok === false);

        if (tampered) {
            badge.textContent = "CRITICAL: Tampered";
            badge.className = "protection-status status-danger";
            // Warning box already handled in the success block for tamper
        } else if (isHealthy) {
            badge.textContent = "Protection Active";
            badge.className = "protection-status status-secured";
            warning.style.display = "none";
        } else {
            badge.textContent = "Warning / Weakened";
            badge.className = "protection-status status-warning";
            // Warning box already handled in the success block for weakened
        }
    }
}


async function renderBlockHistory() {
    const container = document.getElementById('block-container');
    const storage = await browser.storage.local.get({ blockedHistory: [] });
    const blocks = storage.blockedHistory;

    container.textContent = '';
    if (blocks.length > 0) {
        // Limit to 5 most recent
        blocks.slice(-5).reverse().forEach(block => {
            const item = document.createElement('div');
            item.className = 'log-item';
            item.style.borderLeft = "3px solid #ef4444";

            const info = document.createElement('div');
            info.className = 'log-info';

            const name = document.createElement('div');
            name.className = 'log-name';
            name.style.color = "#ef4444";
            name.textContent = `${browser.i18n.getMessage("blockedLabel") || "Blocked"}: ${block.name}`;

            const meta = document.createElement('div');
            meta.className = 'log-meta';
            const timeStr = new Date(block.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
            let metaText = `${timeStr} • ${block.reason}`;
            if (block.reported) {
                metaText += " • 🔥 BURNED";
            }
            meta.textContent = metaText;

            info.appendChild(name);
            info.appendChild(meta);
            item.appendChild(info);

            // Click to view forensics
            item.style.cursor = 'pointer';
            item.addEventListener('click', () => {
                showForensics(block);
            });

            container.appendChild(item);
        });
    } else {
        const empty = document.createElement('div');
        empty.style.textAlign = "center";
        empty.style.color = "var(--text-dim)";
        empty.style.padding = "20px";
        empty.style.fontSize = "0.85rem";
        empty.textContent = browser.i18n.getMessage("cleanHistory") || "Clean history";
        container.appendChild(empty);
    }
}

async function renderLogs() {
    const container = document.getElementById('log-container');
    const storage = await browser.storage.local.get({ recentScans: [] });
    const scans = storage.recentScans;

    container.textContent = '';
    if (scans.length > 0) {
        // Limit to 5 most recent
        scans.slice(-5).reverse().forEach(scan => {
            const item = document.createElement('div');
            item.className = 'log-item';

            const statusIndicator = document.createElement('div');
            statusIndicator.className = `log-status ${scan.status}`;

            const info = document.createElement('div');
            info.className = 'log-info';

            const name = document.createElement('div');
            name.className = 'log-name';
            name.textContent = scan.name;

            const meta = document.createElement('div');
            meta.className = 'log-meta';
            const timeStr = new Date(scan.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

            let statusText = "";
            if (scan.status === 'clean') {
                statusText = "Safe: Secure to access";
            } else if (scan.status === 'infected') {
                statusText = `Threat: ${scan.virus || 'Malicious Payload'}`;
            } else if (scan.status === 'progress') {
                statusText = "Scanning...";
            } else {
                statusText = "Error: System processing failure";
            }

            meta.textContent = `${timeStr} • ${statusText}`;

            info.appendChild(name);
            info.appendChild(meta);
            item.appendChild(statusIndicator);
            item.appendChild(info);
            container.appendChild(item);
        });
    } else {
        const empty = document.createElement('div');
        empty.style.textAlign = "center";
        empty.style.color = "var(--text-dim)";
        empty.style.padding = "20px";
        empty.style.fontSize = "0.85rem";
        empty.textContent = browser.i18n.getMessage("noScans") || "No scans recorded";
        container.appendChild(empty);
    }
}

async function scanCurrentTab() {
    const btn = document.getElementById('scan-page-btn');
    const originalText = btn.textContent;
    btn.textContent = "Scanning...";
    btn.disabled = true;

    try {
        const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
        if (!tab) return;

        await browser.runtime.sendMessage({
            action: "scan_request",
            url: tab.url,
            tabId: tab.id
        });
    } catch (error) {
        alert("Scan request failed.");
        btn.textContent = originalText;
        btn.disabled = false;
    }
}

function showForensics(block) {
    const overlay = document.getElementById('forensic-overlay');
    const body = document.getElementById('forensic-body');
    const title = document.getElementById('forensic-title');
    const reportBtn = document.getElementById('report-threat-btn');

    title.textContent = `Forensic Audit: ${block.hostname || 'Unknown'}`;

    let content = `[TIME] ${block.time}\n`;
    content += `[THREAT] ${block.reason}\n`;
    content += `[TARGET URL] ${block.url}\n`;

    if (block.forensics) {
        content += `\n[DOM SNAPSHOT]\n${JSON.stringify(block.forensics, null, 2)}`;
    } else {
        content += `\nNo DOM forensics captured for this incident.`;
    }

    body.textContent = content;
    overlay.style.display = 'flex';

    if (block.reported) {
        reportBtn.textContent = "🔥 ALREADY BURNED";
        reportBtn.disabled = true;
        reportBtn.style.color = "var(--success)";
        reportBtn.style.borderColor = "var(--success)";
    } else {
        reportBtn.textContent = "🔥 Community Burn";
        reportBtn.disabled = false;
        reportBtn.style.color = "var(--danger)";
        reportBtn.style.borderColor = "var(--danger)";
    }

    // Store metadata for report
    reportBtn.dataset.url = block.url;
    reportBtn.dataset.reason = block.reason;
    reportBtn.dataset.time = block.time;
    reportBtn.dataset.forensics = JSON.stringify(block.forensics || {});
}

async function showAuditLogs() {
    try {
        const response = await browser.runtime.sendMessage({ action: "proxy_get_logs" });
        if (response.status === "ok") {
            const overlay = document.getElementById('forensic-overlay');
            const body = document.getElementById('forensic-body');
            const title = document.getElementById('forensic-title');

            title.textContent = "System EDR Audit Logs (alert_log.txt)";
            body.textContent = response.logs || "No logs found on disk.";
            overlay.style.display = 'flex';
        }
    } catch (e) {
        alert("Failed to retrieve system logs.");
    }
}

async function communityBurn() {
    const btn = document.getElementById('report-threat-btn');
    const url = btn.dataset.url;
    const reason = btn.dataset.reason;
    const forensics = JSON.parse(btn.dataset.forensics || "{}");

    if (!url) return;

    btn.disabled = true;
    const originalText = btn.textContent;
    btn.textContent = "Burning...";

    try {
        const response = await browser.runtime.sendMessage({
            action: "proxy_report_threat",
            target: url,
            type: reason,
            details: { forensics: forensics }
        });

        if (response.status === "ok") {
            btn.textContent = "🔥 COMMUNITY NEUTRALIZED";
            btn.style.color = "var(--success)";
            btn.style.borderColor = "var(--success)";
            btn.disabled = true;

            // Update storage
            const data = await browser.storage.local.get({ blockedHistory: [] });
            const blocks = data.blockedHistory;
            const incidentIndex = blocks.findIndex(b => b.url === url && b.time === btn.dataset.time);
            if (incidentIndex !== -1) {
                blocks[incidentIndex].reported = true;
                await browser.storage.local.set({ blockedHistory: blocks });
            }

            setTimeout(() => {
                renderBlockHistory();
            }, 2000);
        } else {
            alert("Burn failed: " + response.error);
            btn.textContent = originalText;
            btn.disabled = false;
        }
    } catch (e) {
        alert("Communication Error with Host");
        btn.textContent = originalText;
        btn.disabled = false;
    }
}

function translatePage() {
    document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.getAttribute('data-i18n');
        const count = el.getAttribute('data-i18n-count');
        const translated = count ? browser.i18n.getMessage(key, [count]) : browser.i18n.getMessage(key);
        if (translated) {
            el.textContent = translated;
        }
    });

    document.querySelectorAll('[data-i18n-title]').forEach(el => {
        const translated = browser.i18n.getMessage(el.getAttribute('data-i18n-title'));
        if (translated) {
            el.title = translated;
        }
    });
}

async function clearBlockHistory() {
    if (confirm(browser.i18n.getMessage("confirmClearHistory") || "Clear blocked sites history?")) {
        await browser.storage.local.set({ blockedHistory: [] });
        renderBlockHistory();
    }
}

async function clearScanHistory() {
    if (confirm(browser.i18n.getMessage("confirmClearHistory") || "Clear scan history?")) {
        await browser.storage.local.set({ recentScans: [] });
        renderLogs();
    }
}
