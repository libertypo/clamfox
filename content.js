// Content script loaded.
const array = new Uint32Array(4);
crypto.getRandomValues(array);
const SYS_SECRET_TOKEN = Array.from(array, dec => dec.toString(36)).join('');
let lastClickedElement = null;
let GLOBAL_HVT_DATA = null;
const ACTIVE_TOASTS = new Set();
let TRUSTED_BYPASS = false;

// Track which element was right-clicked
document.addEventListener("contextmenu", (event) => {
    lastClickedElement = event.target;
}, true);

function isSiteTrusted() {
    if (!GLOBAL_HVT_DATA) return false;
    const hostname = window.location.hostname.toLowerCase();
    const hvts = GLOBAL_HVT_DATA.hvts || [];
    const whitelist = GLOBAL_HVT_DATA.whitelist || [];
    const userWhitelist = GLOBAL_HVT_DATA.user_whitelist || [];

    const isHVT = hvts.some(hvt => hvt.domains.some(d => hostname === d || hostname.endsWith('.' + d)));
    const isWhitelisted = whitelist.some(d => hostname === d || hostname.endsWith('.' + d));
    const isUserWhitelisted = userWhitelist.some(d => hostname === d || hostname.endsWith('.' + d));

    return isHVT || isWhitelisted || isUserWhitelisted;
}

// Utility: Parse color and check alpha transparency numerically
function isActuallyTransparent(style) {
    const bg = style.backgroundColor;
    const opacity = parseFloat(style.opacity);

    if (opacity < 0.1) return true;
    if (bg === 'transparent' || bg === 'rgba(0, 0, 0, 0)') return true;

    // Handle rgba(r, g, b, a) or hsla(h, s, l, a)
    const match = bg.match(/rgba?\(.*,\s*([\d.]+)\)/) || bg.match(/hsla?\(.*,\s*([\d.]+)\)/);
    if (match && parseFloat(match[1]) < 0.1) return true;

    return false;
}

// Initialize container
function getContainer() {
    let container = document.getElementById('sys-alert-layer');
    if (!container) {
        container = document.createElement('div');
        container.id = 'sys-alert-layer';
        document.body.appendChild(container);
    }
    return container;
}

// EDR Utility: Capture DOM context for forensics
function captureForensicSnapshot(node = null) {
    const snapshot = {
        timestamp: new Date().toISOString(),
        url: window.location.href,
        userAgent: navigator.userAgent
    };
    if (node && node.outerHTML) {
        // Truncate to avoid massive payloads
        snapshot.offendingNode = node.outerHTML.substring(0, 1000);
        snapshot.parentContext = node.parentElement ? node.parentElement.tagName : "N/A";
    }
    return snapshot;
}

// Show "Safe Browsing" reminder on load (with frequency cap)
async function showSafeBrowsingReminder() {
    const settings = await browser.storage.local.get({
        remindersEnabled: true
    });

    if (!settings.remindersEnabled) {
        return;
    }

    const lastReminder = localStorage.getItem('sys_last_reminder');
    const now = Date.now();

    // Only show once every 15 minutes
    if (lastReminder && (now - parseInt(lastReminder)) < 15 * 60 * 1000) {
        return;
    }

    const reminder = document.createElement("div");
    reminder.className = "sys-toast sys-reminder";

    const icon = document.createElement("span");
    icon.className = "sys-toast-icon sys-icon-clean";
    icon.style.color = "var(--primary)";

    const text = document.createElement("span");
    const boldTitle = document.createElement("b");
    boldTitle.textContent = browser.i18n.getMessage("safeBrowsing");
    text.appendChild(boldTitle);
    text.appendChild(document.createTextNode(": " + browser.i18n.getMessage("safeBrowsingHint")));

    reminder.appendChild(icon);
    reminder.appendChild(text);

    getContainer().appendChild(reminder);
    localStorage.setItem('sys_last_reminder', now.toString());

    // Auto-remove after 6 seconds
    setTimeout(() => {
        reminder.style.animation = "sys-slide-out-right 0.5s forwards";
        setTimeout(() => reminder.remove(), 500);
    }, 6000);
}

// Prompt Injection Shield: Defense against command-based attacks and Prompt Injection
// Prompt Injection Shield: Defense against command-based attacks and Prompt Injection
async function runPromptInjectionShield(hvtData) {
    const settings = await browser.storage.local.get({ promptInjectionShieldEnabled: true });
    if (!settings.promptInjectionShieldEnabled) return;

    const currentDomain = window.location.hostname.toLowerCase();

    // Skip heavy DOM traversal on Cloudflare
    if (currentDomain.includes('cloudflare') || currentDomain.includes('challenges')) return;

    // 1. Detect "Hidden Commands" (Indirect Prompt Injection)
    const injectionKeywords = [
        "ignore previous instructions", "system prompt", "you are now",
        "act as a", "output the following", "new directive"
    ];

    const fetchedHvts = hvtData.hvts || [];
    const userWhitelist = hvtData.user_whitelist || [];
    const isHVT = fetchedHvts.some(hvt => hvt.domains.some(d => currentDomain === d || currentDomain.endsWith('.' + d)));
    const isUserWhitelisted = userWhitelist.some(d => currentDomain === d || currentDomain.endsWith('.' + d));

    if (isUserWhitelisted || hvtData.is_challenge_mode) return; // User allowed or Cloudflare challenge active

    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_ELEMENT, null, false);
    let node;

    while (node = walker.nextNode()) {
        const style = window.getComputedStyle(node);

        // Robust Accessibility Check (Still used for false-positive prevention)
        const isAccessibilityElement =
            (node.classList && (
                node.classList.contains("sr-only") ||
                node.classList.contains("visually-hidden") ||
                node.classList.contains("screen-reader-only")
            )) ||
            node.hasAttribute("aria-label") ||
            node.hasAttribute("aria-hidden") ||
            node.hasAttribute("role");

        const isHidden = style.display === 'none' ||
            style.visibility === 'hidden' ||
            parseFloat(style.opacity) < 0.1 ||
            parseInt(style.fontSize) < 2 ||
            (style.position === 'absolute' && (parseInt(style.left) < -5000 || parseInt(style.top) < -5000));

        if (isHidden) {
            // PROACTIVE BYPASS: If we are on a Bank/HVT or whitelisted site, Prompt Injection risk is near-zero.
            if (isHVT || isUserWhitelisted) continue;

            // Skip scanning if it's explicitly an accessibility element (Prevents False Positives)
            if (isAccessibilityElement) continue;

            const textContent = node.textContent.toLowerCase();
            if (injectionKeywords.some(kw => textContent.includes(kw))) {
                console.warn("🛡️ PROMPT INJECTION SHIELD: Detected potential hidden prompt injection!");
                const forensics = captureForensicSnapshot(node);
                showToast("complete", "infected", browser.i18n.getMessage("promptInjectionRisk"), browser.i18n.getMessage("promptInjectionMessage"));
                browser.runtime.sendMessage({
                    action: "log_behavior",
                    threat: "Hidden Prompt Injection / Command Injection Attempt",
                    forensics: forensics
                }).catch(() => { });
                return; // One warning per page is enough
            }
        }
    }

    // 2. Monitoring: Detect unauthorized interaction on sensitive portals
    const monitoredPortals = ["chat.example.com"];

    if (monitoredPortals.some(p => currentDomain.includes(p))) {
        console.log("🛡️ PROMPT INJECTION SHIELD: Monitored Portal active. Enabling Scuttle-Block.");
        // Monitor for background scripts trying to modify the input area
        const inputs = document.querySelectorAll('textarea, [contenteditable="true"]');
        inputs.forEach(input => {
            input.addEventListener('input', (e) => {
                if (!e.isTrusted) {
                    console.warn("🛡️ PROMPT INJECTION SHIELD: Non-trusted input detected! Potential field hijacking.");
                    showToast("complete", "infected", browser.i18n.getMessage("inputHijackBlocked"), browser.i18n.getMessage("inputHijackMessage"));
                }
            });
        });
    }
}

// Hacker Honeypots & Decoys
// ------------------------------------------------------------------
async function deployHoneypots(hvtData) {
    const userWhitelist = hvtData.user_whitelist || [];
    const currentDomain = window.location.hostname.toLowerCase();

    if (userWhitelist.some(d => currentDomain === d || currentDomain.endsWith("." + d)) || hvtData.is_challenge_mode) {
        return; // Don't deploy decoys on trusted sites or during challenges
    }

    // We only inject on HTTP/HTTPS
    if (!window.location.protocol.startsWith('http')) return;

    const trapDiv = document.createElement('div');
    trapDiv.style.position = 'absolute';
    trapDiv.style.left = '-10000px';
    trapDiv.style.top = '-10000px';
    trapDiv.style.opacity = '0';
    trapDiv.style.pointerEvents = 'none';
    trapDiv.setAttribute('aria-hidden', 'true');
    trapDiv.id = 'sys-honey-trap';

    const fakeBtc = document.createElement('div');
    fakeBtc.className = 'bitcoin-address btc-wallet eth-wallet crypto-address';
    fakeBtc.textContent = 'bc1qza6h7u3w2qj4z58y8z7a90b4d4z4cx9m2mz6z';

    const fakePass = document.createElement('input');
    fakePass.type = 'password';
    fakePass.name = 'password';
    fakePass.value = hvtData.honeypot_secret || 'H0n3yP0t@123!';

    trapDiv.appendChild(fakeBtc);
    trapDiv.appendChild(fakePass);
    document.body.appendChild(trapDiv);

    let tripped = false;

    function triggerAlert(type) {
        if (tripped) return;
        tripped = true;
        const forensics = captureForensicSnapshot(fakeBtc);
        console.warn(`🛡️ HONEYPOT TRIPPED: Scraping of ${type} detected!`);
        showWarningToast("🛑 SCRAPING DETECTED", `A script attempted to steal hidden ${type} from this page!`);
        browser.runtime.sendMessage({
            action: "log_honeypot",
            threat: `Honeypot Tripped: Scraper checking for ${type}`,
            forensics: forensics
        }).catch(() => { });
    }

    // Attach traps to the elements using defineProperty
    const origTextContent = Object.getOwnPropertyDescriptor(Node.prototype, 'textContent');
    if (origTextContent) {
        Object.defineProperty(fakeBtc, 'textContent', {
            get() { triggerAlert("Crypto Wallets"); return origTextContent.get.call(this); },
            set(val) { origTextContent.set.call(this, val); }
        });
    }

    const origInnerHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
    if (origInnerHTML) {
        Object.defineProperty(fakeBtc, 'innerHTML', {
            get() { triggerAlert("Crypto Wallets"); return origInnerHTML.get.call(this); },
            set(val) { origInnerHTML.set.call(this, val); }
        });
    }

    const origValue = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
    if (origValue) {
        Object.defineProperty(fakePass, 'value', {
            get() { triggerAlert("Passwords"); return origValue.get.call(this); },
            set(val) { origValue.set.call(this, val); }
        });
    }
}

// ------------------------------------------------------------------
// Formjacking & Keylogger Shield
// ------------------------------------------------------------------
function deployFormjackingShield() {
    // Inject script into the main page context to hook EventTarget.prototype.addEventListener
    const script = document.createElement('script');
    script.textContent = `
        (function() {
            const origAddEventListener = EventTarget.prototype.addEventListener;
            EventTarget.prototype.addEventListener = function(type, listener, options) {
                const isKeyLoggingEvent = ['keydown', 'keyup', 'keypress', 'input', 'change'].includes(type);
                if (isKeyLoggingEvent && this instanceof HTMLInputElement) {
                    const isSensitive = this.type === 'password' || 
                                        (this.name && this.name.toLowerCase().includes('card')) || 
                                        (this.id && this.id.toLowerCase().includes('cc-'));
                    if (isSensitive) {
                        try {
                            const funcStr = listener.toString().toLowerCase();
                            // Whitelist WCAG/Accessibility tools (e.g. screen readers, live regions)
                            const isWCAG = funcStr.includes('aria-') || funcStr.includes('role=') || 
                                           funcStr.includes('speak') || funcStr.includes('live-region') ||
                                           funcStr.includes('accessibility');
                                           
                            // Whitelist common UI elements: Password strength meters, toggles
                            const isUIHelper = funcStr.includes('strength') || funcStr.includes('meter') || 
                                               funcStr.includes('score') || funcStr.includes('zxcvbn') ||
                                               funcStr.includes('toggle') || funcStr.includes('showpass');

                            if (!isWCAG && !isUIHelper) {
                                document.dispatchEvent(new CustomEvent('${SYS_SECRET_TOKEN}', { detail: {
                                    __sys_form_event: true, 
                                    threat: 'Keylogger listener detected on sensitive field',
                                    target: this.name || this.type 
                                }}));
                            }
                        } catch(e) { /* Ignore native code serialization errors */ }
                    }
                }
                return origAddEventListener.call(this, type, listener, options);
            };
            EventTarget.prototype.addEventListener.toString = function() { return "function addEventListener() { [native code] }"; };
        })();
    `;
    (document.head || document.documentElement).appendChild(script);
    script.remove();

    // Listen for alerts from the injected script
    document.addEventListener(SYS_SECRET_TOKEN, (event) => {
        if (event.detail && event.detail.__sys_form_event) {
            console.warn("🛡️ FORMJACKING SHIELD:", event.detail.threat);
            if (!window._sysFormEventAlerted) {
                window._sysFormEventAlerted = true;
                const forensics = captureForensicSnapshot(document.activeElement);
                showWarningToast("🛑 KEYLOGGER / FORMJACKING", `Suspicious listener attached to ${event.detail.target} input!`);
                browser.runtime.sendMessage({
                    action: "log_formjacking",
                    threat: event.detail.threat + " - " + event.detail.target,
                    forensics: forensics
                }).catch(() => { });
            }
        }
    });
}

// ------------------------------------------------------------------
// Visual Anti-Phishing Shield
// ------------------------------------------------------------------
async function deployVisualAntiPhishing(hvtData) {
    const currentHost = window.location.hostname.toLowerCase();
    const storage = await browser.storage.local.get({ customPortals: [] });

    const fetchedHvts = hvtData.hvts || [];
    const whitelist = hvtData.whitelist || [];
    const userWhitelist = hvtData.user_whitelist || [];

    if (whitelist.some(d => currentHost === d || currentHost.endsWith('.' + d)) ||
        userWhitelist.some(d => currentHost === d || currentHost.endsWith('.' + d))) {
        return; // Whitelisted - safe domains or user overrides
    }

    if (fetchedHvts.length === 0) return;

    // Merge custom portals (ignoring dupes)
    const hvts = [...fetchedHvts];
    storage.customPortals.forEach(domain => {
        const brand = domain.split('.')[0];
        if (!hvts.find(h => h.domains.includes(domain))) {
            hvts.push({ brand: brand, domains: [domain] });
        }
    });

    const isAuthenticHVT = hvts.find(hvt =>
        hvt.domains.some(d => currentHost === d || currentHost.endsWith('.' + d))
    );

    if (isAuthenticHVT) return; // Genuine HVT site

    // Check 1: Favicon Spoofing
    const iconLinks = document.querySelectorAll("link[rel*='icon']");
    for (let link of iconLinks) {
        const iconUrl = link.href.toLowerCase();
        for (let hvt of hvts) {
            if (hvt.domains.some(d => iconUrl.includes(d))) {
                console.warn("🛡️ VISUAL SHIELD: Favicon spoofing detected!", iconUrl);
                triggerVisualPhishAlert("Favicon stealing (" + hvt.brand + ")");
                return;
            }
        }
    }

    // Check 2: Title Spoofing
    const pageTitle = document.title.toLowerCase();
    for (let hvt of hvts) {
        if (pageTitle.includes(hvt.brand) && !pageTitle.includes("how to") && !pageTitle.includes("review") && !pageTitle.includes("vs ") && !pageTitle.includes("vs.")) {
            console.warn("🛡️ VISUAL SHIELD: Title spoofing detected!", pageTitle);
            triggerVisualPhishAlert("Brand impersonation in title (" + hvt.brand + ")");
            return;
        }
    }
}

function triggerVisualPhishAlert(threatDetails) {
    if (window._sysVisualAlerted) return;
    window._sysVisualAlerted = true;
    window._sysVisualPhishDetected = true;
    window._sysVisualPhishReason = threatDetails;

    const forensics = captureForensicSnapshot(document.body);
    showWarningToast("⚠️ SUSPECTED PHISHING", "This page visually impersonates a major brand but is hosted on an unofficial domain.");
    browser.runtime.sendMessage({
        action: "log_visual_phish",
        threat: "Visual Phishing Detection: " + threatDetails,
        forensics: forensics
    }).catch(() => { });
}

// ------------------------------------------------------------------
// Drive-by Download Shield
// ------------------------------------------------------------------
function deployDriveByDownloadShield() {
    const script = document.createElement('script');
    script.textContent = `
        (function() {
            // Hook programmatic anchor clicks
            const origClick = HTMLAnchorElement.prototype.click;
            HTMLAnchorElement.prototype.click = function() {
                // If it has a download attribute or seems to point to an executable/archive
                const isSuspectFile = this.href && this.href.match(/\\.(exe|scr|msi|vbs|bat|cmd|js|ps1|zip|rar|7z|iso|img)$/i);
                
                if (this.hasAttribute('download') || isSuspectFile) {
                    document.dispatchEvent(new CustomEvent('${SYS_SECRET_TOKEN}', { detail: { 
                        __sys_driveby_threat: true, 
                        threat: 'Programmatic hidden download initiated: ' + (this.href || 'Blob') 
                    }}));
                }
                return origClick.apply(this, arguments);
            };
            HTMLAnchorElement.prototype.click.toString = function() { return "function click() { [native code] }"; };

            // Hook programmatic window.open which are often used for pop-under downloads
            const origWindowOpen = window.open;
            window.open = function(url, target, features) {
                if (url && typeof url === 'string') {
                    const isSuspectFile = url.match(/\\.(exe|scr|msi|vbs|bat|cmd|js|ps1|zip|rar|7z|iso|img)$/i);
                    if (isSuspectFile) {
                        document.dispatchEvent(new CustomEvent('${SYS_SECRET_TOKEN}', { detail: { 
                            __sys_driveby_threat: true, 
                            threat: 'Programmatic window.open download initiated: ' + url
                        }}));
                    }
                }
                return origWindowOpen.apply(this, arguments);
            };
            window.open.toString = function() { return "function open() { [native code] }"; };
        })();
    `;
    (document.head || document.documentElement).appendChild(script);
    script.remove();

    document.addEventListener(SYS_SECRET_TOKEN, (event) => {
        if (event.detail && event.detail.__sys_driveby_threat) {
            console.warn("🛡️ DRIVE-BY DOWNLOAD SHIELD: ", event.detail.threat);
            if (!window._sysDriveByAlerted) {
                window._sysDriveByAlerted = true;
                showWarningToast("🛑 AUTOMATED DOWNLOAD", "A script tried to download a file without your permission.");
                browser.runtime.sendMessage({
                    action: "log_driveby",
                    threat: "Drive-by Download Detection: " + event.detail.threat
                }).catch(() => { });
            }
        }
    });
}

// ------------------------------------------------------------------
// Behavioral Fingerprinting Shield
// ------------------------------------------------------------------
function deployBehavioralFingerprintShield() {
    const script = document.createElement('script');
    script.textContent = `
        (function () {
            // YARA-like signatures for JS Memory Space
            const signatures = [
                { name: "CryptoMiner (CoinHive/Monero variants)", regex: /(?:cryptonight|coinhive|monerominer|stratum\+tcp)/i },
                { name: "Aggressive JS Obfuscation / Exploit Kit", regex: /(?:eval|document\.write)\s*\(\s*unescape\s*\(/i },
                { name: "Inline HTML Smuggling / Dropper", regex: /data:application\/(?:x-msdownload|octet-stream);base64,[A-Za-z0-9+/]{200,}/i }
            ];

    function scanPayload(payload) {
        if (!payload || typeof payload !== 'string') return;
        for (let sig of signatures) {
            if (sig.regex.test(payload)) {
                document.dispatchEvent(new CustomEvent('${SYS_SECRET_TOKEN}', {
                    detail: {
                        __sys_behavior_threat: true,
                        threat: sig.name
                    }
                }));
                return true;
            }
        }
        return false;
    }

    // Hook dynamic JS evaluation points
    const origEval = window.eval;
    window.eval = function (code) {
        scanPayload(code);
        return origEval.apply(this, arguments);
    };
    window.eval.toString = function () { return "function eval() { [native code] }"; };

    const origFunction = window.Function;
    window.Function = function (...args) {
        if (args.length > 0) scanPayload(args[args.length - 1]);
        return origFunction.apply(this, arguments);
    };
    window.Function.toString = function () { return "function Function() { [native code] }"; };

    const origDocWrite = document.write;
    document.write = function (markup) {
        scanPayload(markup);
        return origDocWrite.apply(this, arguments);
    };
    document.write.toString = function () { return "function write() { [native code] }"; };
})();
    `;
    (document.head || document.documentElement).appendChild(script);
    script.remove();

    document.addEventListener(SYS_SECRET_TOKEN, (event) => {
        if (event.detail && event.detail.__sys_behavior_threat) {
            console.warn("🛡️ BEHAVIORAL SHIELD: ", event.detail.threat);
            if (!window._sysBehaviorAlerted) {
                window._sysBehaviorAlerted = true;
                const forensics = captureForensicSnapshot(document.activeElement);
                showWarningToast("🛑 MALICIOUS BEHAVIOR", "This page is attempting to execute a known malicious script sequence.");
                browser.runtime.sendMessage({
                    action: "log_behavior",
                    threat: "Behavioral Signature Match: " + event.detail.threat,
                    forensics: forensics
                }).catch(() => { });
            }
        }
    });
}

// ------------------------------------------------------------------
// Canvas & WebGL Anti-Fingerprinting Shield
// ------------------------------------------------------------------
async function deployFingerprintPoisoningShield(hvtData) {
    const fetchedHvts = hvtData.hvts || [];
    const whitelist = hvtData.whitelist || [];
    const userWhitelist = hvtData.user_whitelist || [];
    const currentHost = window.location.hostname.toLowerCase();

    const isHVT = fetchedHvts.some(hvt =>
        hvt.domains.some(d => currentHost === d || currentHost.endsWith('.' + d))
    );
    const isWhitelisted = whitelist.some(d => currentHost === d || currentHost.endsWith('.' + d));
    const isUserWhitelisted = userWhitelist.some(d => currentHost === d || currentHost.endsWith('.' + d));

    if (isHVT || isWhitelisted || isUserWhitelisted || hvtData.is_challenge_mode || currentHost.includes('cloudflare') || currentHost.includes('challenges')) {
        console.log("🛡️ PRIVACY SHIELD: Skipping fingerprint poisoning for trusted portal to maintain anti-fraud integrity.");
        return;
    }

    const script = document.createElement('script');
    script.textContent = `
    (function () {
        // Poison Canvas API
        const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
        HTMLCanvasElement.prototype.toDataURL = function () {
            const ctx = this.getContext('2d');
            if (ctx) {
                const width = this.width || 1;
                const height = this.height || 1;
                const r = new Uint32Array(5);
                crypto.getRandomValues(r);
                const x = r[0] % width;
                const y = r[1] % height;
                const origStyle = ctx.fillStyle;
                try {
                    ctx.fillStyle = \`rgba(\${r[2] % 256}, \${r[3] % 256}, \${r[4] % 256}, 0.01)\`;
                        ctx.fillRect(x, y, 1, 1);
                    } finally {
                        ctx.fillStyle = origStyle;
                    }
                }
                return origToDataURL.apply(this, arguments);
            };
            HTMLCanvasElement.prototype.toDataURL.toString = function() { return "function toDataURL() { [native code] }"; };

            const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
            CanvasRenderingContext2D.prototype.getImageData = function() {
                let imageData;
                try {
                    imageData = origGetImageData.apply(this, arguments);
                } catch(e) { /* ignore and throw naturally if valid */ return origGetImageData.apply(this, arguments); }
                
                if (imageData && imageData.data && imageData.data.length > 0) {
                    const r = new Uint32Array(1);
                    crypto.getRandomValues(r);
                    const index = (r[0] % Math.floor(imageData.data.length / 4)) * 4;
                    imageData.data[index] = imageData.data[index] ^ 1; // Flip LSB
                }
                return imageData;
            };
            CanvasRenderingContext2D.prototype.getImageData.toString = function() { return "function getImageData() { [native code] }"; };

            // Poison WebGL API
            const origReadPixels = WebGLRenderingContext.prototype ? WebGLRenderingContext.prototype.readPixels : null;
            if (origReadPixels) {
                WebGLRenderingContext.prototype.readPixels = function() {
                    const res = origReadPixels.apply(this, arguments);
                    const pixels = arguments[6];
                    if (pixels && pixels.length > 0) {
                        const r = new Uint32Array(1);
                        crypto.getRandomValues(r);
                        const index = r[0] % pixels.length;
                        pixels[index] = pixels[index] ^ 1; // Flip LSB
                    }
                    return res;
                };
                WebGLRenderingContext.prototype.readPixels.toString = function() { return "function readPixels() { [native code] }"; };
            }
        })();
    `;
    (document.head || document.documentElement).appendChild(script);
    script.remove();
}

// ------------------------------------------------------------------
// DOM Anomaly & Overlay Shield (Banking Trojans)
// ------------------------------------------------------------------
// DOM Anomaly & Overlay Shield (Clickjacking / Banking Trojans)
// ------------------------------------------------------------------
async function deployDOMAnomalyShield(hvtData) {
    const fetchedHvts = hvtData?.hvts || [];
    const whitelist = hvtData?.whitelist || [];
    const userWhitelist = hvtData?.user_whitelist || [];
    const currentHost = window.location.hostname.toLowerCase();

    // Skip shields during active security challenges (Option 3)
    if (hvtData.is_challenge_mode) {
        console.log("🛡️ CLOUDFLARE SHIELD: Tab in Challenge Mode. DOM monitoring suppressed.");
        return;
    }

    // Skip Cloudflare challenges as they use heavy legitimate overlays
    if (currentHost.includes('cloudflare') || currentHost.includes('challenges')) return;

    const isWhitelistedDynamic = () => {
        const hostname = window.location.hostname.toLowerCase();
        const base = hostname.split('.').slice(-2).join('.'); // newsblur.com from www.newsblur.com

        // Check HVTs and Global Whitelist
        const inStatic = fetchedHvts.some(hvt => hvt.domains.some(d => hostname === d || hostname.endsWith('.' + d))) ||
            whitelist.some(d => hostname === d || hostname.endsWith('.' + d));
        if (inStatic) return true;

        // Check Live User Whitelist
        const inUser = userWhitelist.some(d =>
            hostname === d ||
            hostname.endsWith('.' + d) ||
            d.endsWith('.' + hostname) ||
            d === base
        );
        return inUser;
    };

    // Option 1: Active Intercept Strategy
    const SUSPECT_OVERLAYS = new WeakSet();

    window.addEventListener("click", (e) => {
        if (window.__CLAMFOX_BYPASS || isWhitelistedDynamic()) return;

        const target = e.target;
        const style = window.getComputedStyle(target);

        // Check if this specific element was already pre-flagged as suspect
        let isConfirmedThreat = SUSPECT_OVERLAYS.has(target);

        // SURGICAL ANALYSIS: Check stack depth at click point if top element is ghostly
        if (!isConfirmedThreat && isActuallyTransparent(style)) {
            const elements = document.elementsFromPoint(e.clientX, e.clientY);
            if (elements.length > 1) {
                // Find what's directly beneath our ghostly target
                const secondElement = elements[1];
                if (secondElement) {
                    const secondStyle = window.getComputedStyle(secondElement);
                    const tag = secondElement.tagName.toLowerCase();

                    // Broadened High Value Target Detection
                    const isSemanticHVT = ['a', 'button', 'input', 'select', 'textarea'].includes(tag);
                    const isCustomHVT = secondElement.getAttribute('onclick') ||
                        secondElement.getAttribute('role') === 'button' ||
                        secondStyle.cursor === 'pointer';

                    const isInteractive = isSemanticHVT || isCustomHVT;

                    // Verify stacking: Interceptor must be above target
                    const targetZ = parseInt(secondStyle.zIndex) || 0;
                    const interceptorZ = parseInt(style.zIndex) || 0;

                    if (isInteractive && interceptorZ >= targetZ) {
                        isConfirmedThreat = true;
                        console.warn(`🛡️ SURGICAL SHIELD: Intercepted stealthy overlay covering interactive <${tag}>!`);
                    }
                }
            }
        }

        if (isConfirmedThreat) {
            e.preventDefault();
            e.stopPropagation();

            console.warn("🛡️ CLICKJACKING INTERCEPT: Blocked interaction with suspicious overlay layer.");

            showWarningToast(
                "🛑 CLICK INTERCEPTED",
                "We blocked this click because it was hitting a hidden invisible layer covering a page button.",
                "Allow Anyway",
                () => {
                    window.__CLAMFOX_BYPASS = true;
                    target.click(); // Proceed with original intent
                    browser.runtime.sendMessage({
                        action: "bypass_domain",
                        domain: window.location.hostname
                    });
                }
            );
        }
    }, true);

    // Keep whitelist updated across tabs
    browser.storage.onChanged.addListener((changes, area) => {
        if (area === "local" && (changes.userWhitelist || changes.hostActive)) {
            browser.runtime.sendMessage({ action: "get_hvts" }).then(newData => {
                if (newData.user_whitelist) {
                    userWhitelist.length = 0;
                    userWhitelist.push(...newData.user_whitelist);
                }
            }).catch(() => { });
        }
    });

    const checkElement = (node) => {
        if (node.nodeType !== Node.ELEMENT_NODE) return;

        // Skip common App Roots and Containers (SPAs like Tailscale)
        const id = node.id?.toLowerCase() || "";
        const cls = typeof node.className === 'string' ? node.className.toLowerCase() : "";
        if (id.includes('app') || id.includes('root') || id.includes('mount') ||
            cls.includes('app-root') || id === 'main' || id === 'wrapper') return;

        const style = window.getComputedStyle(node);
        const position = style.position;

        // Clickjacking overlays almost always use absolute or fixed positioning
        if (position !== 'absolute' && position !== 'fixed' && position !== 'sticky') return;

        const opacity = parseFloat(style.opacity);
        const bg = style.backgroundColor;
        const pointerEvents = style.pointerEvents;

        const takesClicks = pointerEvents !== 'none';

        if (isActuallyTransparent(style) && takesClicks) {
            const rect = node.getBoundingClientRect();
            const vWidth = window.innerWidth;
            const vHeight = window.innerHeight;

            if (vWidth === 0 || vHeight === 0) return;

            // Coverage Threshold: 10% of viewport for pre-flagging (More sensitive)
            const area = rect.width * rect.height;
            const isSignificant = area > (vWidth * vHeight * 0.10);

            if (isSignificant) {
                if (isWhitelistedDynamic() || window.__CLAMFOX_BYPASS) return;

                console.log("🛡️ SUSPECT OVERLAY DETECTED: Monitoring for click interception.");
                SUSPECT_OVERLAYS.add(node);

                // Log context but don't block interaction yet
                const forensics = captureForensicSnapshot(node);
                browser.runtime.sendMessage({
                    action: "log_dom_anomaly",
                    threat: "Potential Clickjacking Layer Detected (Active Monitoring)",
                    forensics: forensics
                }).catch(() => { });
            }
        }
    };

    // 1. Initial Scan (Catch elements already in HTML or added before script)
    const initialElements = document.querySelectorAll('div, a, iframe, button, section, main');
    initialElements.forEach(checkElement);

    // 2. Mutation Monitor (Added nodes + Attribute changes)
    let mutationThrottleTimer = null;
    let nodesProcessed = 0;

    const observer = new MutationObserver((mutations) => {
        // Denial of Service protection: Reset counter every 500ms
        if (!mutationThrottleTimer) {
            mutationThrottleTimer = setTimeout(() => {
                nodesProcessed = 0;
                mutationThrottleTimer = null;
            }, 500);
        }

        for (let mutation of mutations) {
            if (nodesProcessed > 500) {
                console.warn("🛡️ CLICKJACKING SHIELD: DOM flooding detected! Dropping mutations to prevent lockup.");
                return; // Abort processing to save main thread
            }

            if (mutation.type === 'childList') {
                mutation.addedNodes.forEach(node => {
                    nodesProcessed++;
                    checkElement(node);
                });
            } else if (mutation.type === 'attributes') {
                nodesProcessed++;
                checkElement(mutation.target);
            }
        }
    });

    observer.observe(document.body, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ['style', 'class']
    });
}

// Keep settings updated in real-time
browser.storage.onChanged.addListener((changes, area) => {
    if (area === "local") {
        if (changes.suppressTrustedToasts || changes.userWhitelist || changes.hostActive) {
            browser.runtime.sendMessage({ action: "get_hvts" }).then(newData => {
                GLOBAL_HVT_DATA = newData;
                if (newData.suppress_trusted_toasts && isSiteTrusted()) {
                    TRUSTED_BYPASS = true;
                } else {
                    TRUSTED_BYPASS = false;
                }
            }).catch(() => { });
        }
    }
});

// Initialize
(async () => {
    // Perform HVT Check once as early as possible
    const hvtData = await browser.runtime.sendMessage({ action: "get_hvts" }).catch(() => ({}));
    GLOBAL_HVT_DATA = hvtData;

    // Determine if we should bypass alerts for this trusted site
    if (hvtData.suppress_trusted_toasts && isSiteTrusted()) {
        TRUSTED_BYPASS = true;
    }

    // Start passive shields immediately
    deployDOMAnomalyShield(hvtData);
    deployFormjackingShield();
    deployBehavioralFingerprintShield();

    // Start heavier logic once DOM is interactive
    const initFull = async () => {
        showSafeBrowsingReminder();
        runPromptInjectionShield(hvtData);
        deployHoneypots(hvtData);
        await deployVisualAntiPhishing(hvtData);
        deployDriveByDownloadShield();
        await deployFingerprintPoisoningShield(hvtData);
        await monitorDOMTampering(hvtData);

        // Perform final Comprehensive Legitimacy Check (Hard Block)
        const trustCheck = await browser.runtime.sendMessage({ action: "check_trust", url: window.location.href });
        if (window._sysVisualPhishDetected && trustCheck.trust === "untrusted") {
            const reason = `Multi-Factor Phishing Identified: [Visual: ${window._sysVisualPhishReason}] + [Trust: ${trustCheck.trust}] + [Signals: ${trustCheck.threats ? trustCheck.threats.join(", ") : "None"}]`;
            console.error("🛑 LEGITIMACY ENGINE BLOCK:", reason);
            window.location.href = browser.runtime.getURL("popup/blocked.html?url=" + encodeURIComponent(window.location.href) + "&reason=" + encodeURIComponent(reason));
        }
    };

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", initFull);
    } else {
        initFull();
    }
})();

// Listen for scan results from background.js
browser.runtime.onMessage.addListener((message) => {
    if (message.action === "show_toast") {
        showToast(message.status, message.result, message.virus, message.msg);
    }
});

function showToast(status, result, virus, msg) {
    // 1. Identify or Create the Scan Toast
    let toast = document.getElementById('sys-scan-toast');

    // If it's a new scan starting (status "scanning") and there's no toast, OR
    // if there's an old non-scanning toast, refresh it
    if (status === "scanning" && (!toast || !toast.classList.contains('scanning'))) {
        if (toast) toast.remove();
        toast = document.createElement("div");
        toast.id = 'sys-scan-toast';
        toast.className = "sys-toast scanning";
        toast.textContent = '';
        const iconSpan = document.createElement("span");
        iconSpan.className = "sys-toast-icon sys-icon-scanning";

        const txtContainer = document.createElement("span");
        txtContainer.className = "sys-text-container";
        const bAlert = document.createElement("b");
        bAlert.textContent = "Alert";
        const txtMsg = document.createElement("span");
        txtMsg.className = "sys-msg";
        txtMsg.textContent = "Scanning...";
        txtContainer.appendChild(bAlert);
        txtContainer.appendChild(document.createTextNode(": "));
        txtContainer.appendChild(txtMsg);

        toast.appendChild(iconSpan);
        toast.appendChild(txtContainer);
        getContainer().appendChild(toast);
    } else if (!toast) {
        // Results toast (for things like blocking) - create if doesn't exist
        toast = document.createElement("div");
        toast.id = 'sys-scan-toast';
        toast.className = "sys-toast";

        const iconSpan = document.createElement("span");
        iconSpan.className = "sys-toast-icon";

        const txtContainer = document.createElement("span");
        txtContainer.className = "sys-text-container";
        const bAlert = document.createElement("b");
        bAlert.className = "sys-toast-title";
        bAlert.textContent = "Alert";
        const txtMsg = document.createElement("span");
        txtMsg.className = "sys-msg";
        txtContainer.appendChild(bAlert);
        txtContainer.appendChild(document.createTextNode(": "));
        txtContainer.appendChild(txtMsg);

        toast.appendChild(iconSpan);
        toast.appendChild(txtContainer);
        getContainer().appendChild(toast);
    }

    // 2. Identify inner elements for surgical updates
    const icon = toast.querySelector('.sys-toast-icon');
    const titleElement = toast.querySelector('.sys-toast-title');
    const msgElement = toast.querySelector('.sys-msg');

    // 3. Update State & Content
    let stateClass = "";
    let iconClass = "";
    let text = "";

    if (status === "scanning") {
        stateClass = "scanning";
        iconClass = "sys-icon-scanning";
        text = msg || "Scanning Target...";
    } else if (result === "clean") {
        stateClass = "clean";
        iconClass = "sys-icon-clean";
        text = msg || "Verified: Secure to access";
    } else if (result === "infected") {
        stateClass = "infected";
        iconClass = "sys-icon-infected";
        text = msg || `THREAT: ${virus}`;
    } else {
        stateClass = "error";
        iconClass = "sys-icon-error";
        text = "Scan Error";
    }

    if (titleElement) {
        titleElement.textContent = virus || "Alert";
    }

    // Only update Class/Animation if state actually changed
    if (!toast.classList.contains(stateClass)) {
        toast.classList.remove('scanning', 'clean', 'infected', 'error');
        toast.classList.add(stateClass);

        // Trigger entrance animation for state transitions
        toast.style.animation = "none";
        void toast.offsetWidth;
        toast.style.animation = "sys-slide-in-right 0.6s cubic-bezier(0.19, 1, 0.22, 1)";
    }

    // Surgical content update (Prevent Flickering)
    if (icon.className !== `sys-toast-icon ${iconClass}`) {
        icon.className = `sys-toast-icon ${iconClass}`;
    }
    if (msgElement.textContent !== text) {
        msgElement.textContent = text;
    }

    // 4. Persistence Management
    if (status !== "scanning") {
        if (window.toastTimeout) clearTimeout(window.toastTimeout);
        window.toastTimeout = setTimeout(() => {
            if (toast && toast.parentNode) {
                toast.style.animation = "sys-slide-out-right 0.5s forwards";
                setTimeout(() => toast.remove(), 500);
            }
        }, 4000);
    }
}
// ------------------------------------------------------------------
// Vicious Credential Guard & Smuggling Block
// ------------------------------------------------------------------

let trustVerified = false;

async function checkCredentialGuard(event) {
    if (trustVerified) return;

    // Only trigger once per page load to avoid annoyance
    trustVerified = true;

    const response = await browser.runtime.sendMessage({
        action: "check_trust",
        url: window.location.href
    });

    if (response.trust !== "high" && response.status === "clean") {
        let warningTitle = browser.i18n.getMessage("credentialGuardTitle") || "⚠️ UNTRUSTED PORTAL";
        let warningMsg = browser.i18n.getMessage("credentialGuardMessage") || "This site is not a verified brand. Use caution before entering passwords.";

        // Comprehensive Block Check: If Visual Shield flagged it AND identity check fails
        if (window._sysVisualPhishDetected && response.trust === "untrusted") {
            const reason = `Credential Guard: [Visual: ${window._sysVisualPhishReason}] + [Trust: ${response.trust}]`;
            window.location.href = browser.runtime.getURL("popup/blocked.html?url=" + encodeURIComponent(window.location.href) + "&reason=" + encodeURIComponent(reason));
            return;
        }

        if (response.trust === "untrusted" && response.threats && response.threats.length > 0) {
            warningTitle = "🛑 CRYPTO-SIGNAL ALERT";
            warningMsg = `ClamFox detected ${response.threats[0]}. This is often used for short-lived phishing sites.`;
        } else if (response.cert && response.cert.isYoung) {
            warningTitle = "⚠️ SUSPICIOUS CERTIFICATE";
            warningMsg = "This site uses a very new certificate (issued < 72h ago). Verify the identity before entering credentials.";
        }

        console.warn("🛡️ CREDENTIAL GUARD: Untrusted Portal. Shielding User.", response);
        showWarningToast(warningTitle, warningMsg);
    }
}

async function showWarningToast(title, msg, btnLabel = null, onBtnClick = null) {
    if (TRUSTED_BYPASS) {
        console.log("🛡️ SHIELD SILENCED: Toast suppressed on trusted site per user settings.", title, msg);
        return;
    }

    if (ACTIVE_TOASTS.has(msg)) return;
    ACTIVE_TOASTS.add(msg);

    // EDR REACTIVE HARDENING
    const tabId = await browser.runtime.sendMessage({ action: "get_tab_id" });
    const escalationKey = `tab_escalated_${tabId}`;
    const storage = await browser.storage.local.get(escalationKey);
    const isEscalated = storage[escalationKey] === true;

    const reminder = document.createElement("div");
    reminder.className = "sys-toast sys-reminder";
    reminder.style.backgroundColor = isEscalated ? "#000" : "var(--danger)";
    reminder.style.borderLeft = isEscalated ? "6px solid var(--danger)" : "4px solid white";
    if (isEscalated) {
        reminder.style.boxShadow = "0 0 20px rgba(239, 68, 68, 0.5)";
    }

    const icon = document.createElement("span");
    icon.className = isEscalated ? "sys-toast-icon sys-icon-scanning" : "sys-toast-icon sys-icon-infected";
    icon.style.color = isEscalated ? "var(--danger)" : "white";

    const text = document.createElement("span");
    text.style.color = "white";
    const boldTitle = document.createElement("b");
    boldTitle.textContent = title;
    text.appendChild(boldTitle);
    text.appendChild(document.createTextNode(": " + msg));

    reminder.appendChild(icon);
    reminder.appendChild(text);

    if (btnLabel && onBtnClick) {
        const btn = document.createElement("button");
        btn.textContent = btnLabel;
        btn.style.marginLeft = "12px";
        btn.style.background = "white";
        btn.style.color = "var(--danger)";
        btn.style.border = "none";
        btn.style.borderRadius = "4px";
        btn.style.padding = "4px 8px";
        btn.style.fontSize = "12px";
        btn.style.fontWeight = "bold";
        btn.style.cursor = "pointer";
        btn.onclick = () => {
            window.__CLAMFOX_BYPASS = true; // Immediate local bypass for this page
            onBtnClick();
            reminder.remove();
            ACTIVE_TOASTS.delete(msg);
        };
        reminder.appendChild(btn);
    }

    getContainer().appendChild(reminder);

    // Auto-remove after 10 seconds (longer for interactive warning)
    setTimeout(() => {
        if (reminder && reminder.parentNode) {
            reminder.style.animation = "sys-slide-out-right 0.5s forwards";
            setTimeout(() => {
                reminder.remove();
                ACTIVE_TOASTS.delete(msg);
            }, 500);
        } else {
            ACTIVE_TOASTS.delete(msg);
        }
    }, 10000);
}

// 1. Monitor for Password focus
document.addEventListener('focusin', (e) => {
    if (e.target.type === 'password') {
        checkCredentialGuard(e);
    }
});

// 2. Smuggling Block: Intercept dynamic link smuggling
document.addEventListener('click', (e) => {
    const link = e.target.closest('a');
    if (link && (link.href.startsWith('blob:') || link.href.startsWith('data:'))) {
        // If it was a programmatic click (no isTrusted) or has a download attribute, it's suspect
        if (!e.isTrusted || link.hasAttribute('download')) {
            console.error("🛡️ SMUGGLING BLOCK: Intercepted suspicious memory-download!");
            e.preventDefault();
            showWarningToast(
                "🛑 SMUGGLING BLOCK",
                "System blocked an automated memory-download common in malware attacks."
            );
        }
    }
}, true);

// ------------------------------------------------------------------
// High-Value Target (HVT) DOM Tampering Shield
// ------------------------------------------------------------------

async function monitorDOMTampering(hvtData) {
    const currentDomain = window.location.hostname.toLowerCase();

    const hvts = hvtData.hvts || [];
    const whitelist = hvtData.whitelist || [];
    const userWhitelist = hvtData.user_whitelist || [];

    if (hvtData.is_challenge_mode) {
        return; // Cloudflare challenge active
    }

    if (hvts.length === 0) return;

    // We flatten domains to match the old logic
    const bankingTargets = hvts.map(hvt => hvt.domains).flat();

    const isHVT = bankingTargets.some(b => currentDomain === b || currentDomain.endsWith("." + b));
    const isWhitelisted = whitelist.some(d => currentDomain === d || currentDomain.endsWith("." + d)) ||
        userWhitelist.some(d => currentDomain === d || currentDomain.endsWith("." + d));

    if (!isHVT && !isWhitelisted) return;

    console.log("🛡️ DOM SHIELD: Monitoring active for trusted/monitored target.");

    let domThrottleTimer = null;
    let domNodesProcessed = 0;

    const observer = new MutationObserver((mutations) => {
        // Denial of Service protection: Reset counter every 500ms
        if (!domThrottleTimer) {
            domThrottleTimer = setTimeout(() => {
                domNodesProcessed = 0;
                domThrottleTimer = null;
            }, 500);
        }

        for (let mutation of mutations) {
            if (domNodesProcessed > 500) {
                console.warn("🛡️ DOM SHIELD: DOM flooding detected! Dropping mutations to prevent UI lockup.");
                return;
            }

            if (mutation.type === 'childList') {
                mutation.addedNodes.forEach(node => {
                    domNodesProcessed++;
                    // Detect unexpected script injections or overlays (WebInjects)
                    if (node.tagName === 'SCRIPT') {
                        // Check if script is sourced from an external, non-standard domain
                        if (node.src && !node.src.includes(currentDomain) && !node.src.includes("google") && !node.src.includes("cdn") && !node.src.includes("gstatic")) {
                            console.warn("🛡️ DOM SHIELD ALERT: Suspicious cross-origin script injected!", node.src);
                            const forensics = captureForensicSnapshot(node);
                            showWarningToast(
                                "⚠️ TAMPER WARNING",
                                "A suspicious external script was just injected into this banking page."
                            );
                            browser.runtime.sendMessage({
                                action: "log_behavior",
                                threat: "Suspicious Cross-Origin Script Injection: " + node.src,
                                forensics: forensics
                            }).catch(() => { });
                        }
                    } else if (node.tagName === 'IFRAME') {
                        // Invisible iframes are classic credential stealers
                        const style = window.getComputedStyle(node);
                        if (style.opacity === "0" || style.display === "none" || style.visibility === "hidden" || parseInt(style.width) < 5) {

                            // Smart Whitelisting: Ignore common legitimate invisible frames (Google Auth, OneTap, etc.)
                            const src = node.src || "";
                            if (src.includes("google.com/gsi/") || src.includes("accounts.google.com") || src.includes("gstatic.com")) {
                                return;
                            }

                            console.warn("🛡️ DOM SHIELD ALERT: Hidden IFrame injected!");
                            const forensics = captureForensicSnapshot(node);
                            showWarningToast(
                                "⚠️ TAMPER WARNING",
                                "An invisible tracking frame tried to load on this secure page."
                            );
                            browser.runtime.sendMessage({
                                action: "log_behavior",
                                threat: "Hidden IFrame Injection (Stealer/Sniffer)",
                                forensics: forensics
                            }).catch(() => { });
                        }
                    }
                });
            }
        }
    });

    // Monitor the entire body for structural changes
    observer.observe(document.body, { childList: true, subtree: true });
}
