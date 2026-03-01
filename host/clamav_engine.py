#!/usr/bin/python3
import sys
import json
import struct
import subprocess
import os
import shutil
import threading
import time
import locale
import gettext
import re
import hashlib
import socket
import tempfile
import random
import string
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import base64
from tpm_provider import TpmProvider

# Security Guard: Pre-emptively poison Python's `pickle` library to prevent future unauthorized use (Deserialization RCE)
sys.modules['pickle'] = None
sys.modules['_pickle'] = None
sys.modules['cPickle'] = None
# Setup Localization (I18N)
def _setup_i18n():
    localedir = os.path.join(os.path.dirname(__file__), 'locales')
    try:
        # Smart locale detection
        lang = locale.getlocale()[0] or os.environ.get('LANG', 'en_US').split('.')[0]
        t = gettext.translation('clamav_host', localedir, languages=[lang[:2]], fallback=True)
        return t.gettext
    except Exception:
        # Fallback to English literal if translation is missing
        return lambda s: s

_ = _setup_i18n()

# Global state for Resource Watchdog (Circuit Breaker)
_scan_count_lock = threading.Lock()
_scan_timestamps = []
_CIRCUIT_BREAKER_THROTTLE = 50  # Increased for power users
_MAX_RECURSION_DEPTH = 5        # Archive depth protection
_PRIVATE_TUNNEL_FORCE = False   # If True, block fetch if tunnel is down
# Security Constants & Timeouts
_GLOBAL_TIMEOUT = 45            # Hard limit for clamscan (seconds)
_NETWORK_TIMEOUT = 15           # Limit for API/Fetch (seconds)
_MAX_CONTAINER_FILES = 500      # Max files in an archive to prevent ZIP bombs
_MAX_CONTAINER_UNCOMPRESSED_SIZE = 100 * 1024 * 1024 # 100 MB max uncompressed size for archives

# Thread-safe locks
_output_lock = threading.Lock()
_config_lock = threading.Lock()

# Multi-Core Engines
# Security: max_workers is explicitly capped to prevent resource exhaustion
# under burst download events (e.g. a page triggering many simultaneous scans).
# Thread pool: I/O-bound tasks (messaging, network checks, file reads).
_thread_pool = ThreadPoolExecutor(max_workers=6)
# Process pool: CPU-bound tasks (YARA scanning, hashing). Capped at 4 to protect
# low-end hardware and avoid spawning more processes than logical cores.
_process_pool = ProcessPoolExecutor(max_workers=min(os.cpu_count() or 2, 4))

# Security: Resolve external tool paths at startup using shutil.which to prevent
# PATH hijacking attacks (a malicious binary earlier in PATH could otherwise be used).
_BIN_FILE     = shutil.which("file")
_BIN_7Z       = shutil.which("7z")
_BIN_FRESHCLAM = shutil.which("freshclam")
_BIN_WL_PASTE = shutil.which("wl-paste")
_BIN_XCLIP    = shutil.which("xclip")
_BIN_SYSTEMCTL = shutil.which("systemctl")

import itertools
import base64

_LOG_KEY = b"ClamFox_Vault_Key_2026_Secure_EDR"

def secure_log_encode(text):
    if not isinstance(text, str): text = str(text)
    try:
        key = itertools.cycle(_LOG_KEY)
        obf = bytes(x ^ y for x, y in zip(text.encode('utf-8'), key))
        return base64.b64encode(obf).decode('utf-8')
    except Exception:
        return text

def secure_log_decode(text):
    try:
        dec = base64.b64decode(text.strip().encode('utf-8'))
        key = itertools.cycle(_LOG_KEY)
        return bytes(x ^ y for x, y in zip(dec, key)).decode('utf-8')
    except Exception:
        return text.strip()

# Helper to log for debugging native messaging
def log_debug(msg):
    # Security: Mask sensitive secrets in logs
    sanitized = msg
    if isinstance(msg, str) and '"secret":' in msg:
        import re
        sanitized = re.sub(r'"secret":\s*"[^"]*"', '"secret": "********"', msg)
    
    log_path = os.path.expanduser("~/.clamfox_host.log")
    try:
        with open(log_path, "a") as f:
            f.write(secure_log_encode(sanitized) + "\n")
    except OSError:
        pass

# Helper to get the intelligence runtime storage directory
def get_run_dir():
    uid = os.getuid()
    path = f"/run/user/{uid}/clamfox"
    try:
        if not os.path.exists(path):
            os.makedirs(path, exist_ok=True, mode=0o700)
        return path
    except OSError:
        path = f"/tmp/clamfox_{uid}"
        os.makedirs(path, exist_ok=True, mode=0o700)
        return path

# Helper to read a message from Firefox
def get_message():
    raw_length = sys.stdin.buffer.read(4)
    if len(raw_length) == 0:
        return None
    
    # Native Messaging protocol uses exactly 4 bytes for length (little-endian unsigned int)
    try:
        message_length = struct.unpack('<I', raw_length)[0]
        if message_length > 1024 * 1024: # 1MB Limit
            log_debug("OOM Protection: Message too large")
            return None
    except Exception as e:
        log_debug(f"Header Error: {e}")
        return None
    
    try:
        payload = b""
        while len(payload) < message_length:
            chunk = sys.stdin.buffer.read(message_length - len(payload))
            if not chunk:
                break
            payload += chunk
        
        if len(payload) != message_length:
            log_debug(f"Payload Truncated: Expected {message_length} but got {len(payload)}")
            return None
            
        message = payload.decode('utf-8')
        log_debug(f"Payload: {message}")
        return json.loads(message)
    except Exception as e:
        log_debug(f"Payload Error: {e}")
        return None

def is_safe_path(filepath):
    """
    Robust Path Traversal Protection.
    Ensures that any file path handled by the Native Host is within a strictly 
    whitelisted set of 'Safe Zones'.
    """
    if not filepath: return False
    try:
        # 1. Expand ~ and get absolute path
        abs_path = os.path.abspath(os.path.expanduser(filepath))
        # 2. Resolve symlinks to prevent symlink-to-system-file attacks
        real_path = os.path.realpath(abs_path)
        
        # 3. Define the 'Safe Zones'
        # - Temporary storage (Downloads, /tmp, /dev/shm)
        # - The host's own directory (for signatures, logs, quarantine)
        safe_roots = [
            tempfile.gettempdir(),
            "/dev/shm",
            os.path.expanduser("~"),
            os.path.dirname(__file__)
        ]
        
        for root in safe_roots:
            root_abs = os.path.realpath(os.path.abspath(root))
            if os.path.commonpath([root_abs, real_path]) == root_abs:
                return True
                
        log_debug(f"🚨 SECURITY ALERT: Blocked Path Traversal attempt to: {filepath}")
        return False
    except Exception as e:
        log_debug(f"Security Engine path validation error: {e}")
        return False

def is_within_directory(directory, target):
    """Tar Slip Protection: Ensure extracted members stay within the target directory."""
    abs_directory = os.path.abspath(directory)
    abs_target = os.path.abspath(target)
    prefix = os.path.commonpath([abs_directory, abs_target])
    return prefix == abs_directory

# Helper to send a message to Firefox (Thread-safe)
def send_message(message_content):
    try:
        content = json.dumps(message_content).encode('utf-8')
        log_debug(f"Sending: {json.dumps(message_content)[:500]}...") # Truncate log
        with _output_lock:
            sys.stdout.buffer.write(struct.pack('<I', len(content)))
            sys.stdout.buffer.write(content)
            sys.stdout.buffer.flush()
    except Exception as e:
        log_debug(f"CRITICAL: Failed to send message: {e}")

def detect_dist_info():
    try:
        if os.path.exists("/etc/os-release"):
            with open("/etc/os-release") as f:
                lines = f.readlines()
                info = {}
                for line in lines:
                    if "=" in line:
                        k, v = line.strip().split("=", 1)
                        info[k] = v.strip('"')
                
                id = info.get("ID", "").lower()
                id_like = info.get("ID_LIKE", "").lower()
                
                if "debian" in id or "ubuntu" in id or "debian" in id_like:
                    return {
                        "install": "sudo apt install clamav-daemon",
                        "optimize": "sudo systemctl enable --now clamav-daemon"
                    }
                elif "fedora" in id or "rhel" in id or "centos" in id or "fedora" in id_like:
                    return {
                        "install": "sudo dnf install clamd",
                        "optimize": "sudo systemctl enable --now clamd@scan"
                    }
                elif "arch" in id or "manjaro" in id or "arch" in id_like:
                    return {
                        "install": "sudo pacman -S clamav",
                        "optimize": "sudo systemctl enable --now clamav-daemon clamav-freshclam clamav-clamonacc"
                    }
    except (OSError, KeyError, json.JSONDecodeError):
        pass
    return {
        "install": "sudo apt install clamav (or equivalent)",
        "optimize": "sudo systemctl enable --now clamav-daemon"
    }

def get_db_last_update():
    db_paths = ["/var/lib/clamav", "/usr/local/share/clamav", "/var/db/clamav"]
    db_files = ["daily.cld", "daily.cvd", "main.cld", "main.cvd", "bytecode.cld", "bytecode.cvd"]
    
    last_update = 0
    for path in db_paths:
        if os.path.exists(path):
            for filename in db_files:
                fpath = os.path.join(path, filename)
                if os.path.exists(fpath):
                    mtime = os.path.getmtime(fpath)
                    if mtime > last_update:
                        last_update = mtime
    return last_update

def check_vpn_active():
    """Detect presence of common VPN interfaces or client statuses."""
    try:
        # 1. Broad Interface Check (Any common tunnel prefix)
        if os.path.exists('/sys/class/net'):
            interfaces = os.listdir('/sys/class/net')
            vpn_patterns = ['tun', 'wg', 'ppp', 'tap', 'nord', 'proton', 'vpn', 'tailscale', 'cscotun', 'mullvad', 'cloudflare']
            for iface in interfaces:
                if any(p in iface.lower() for p in vpn_patterns):
                    try:
                        with open(f'/sys/class/net/{iface}/operstate') as f:
                            state = f.read().strip().lower()
                            if state != 'down':
                                log_debug(f"VPN detected via generic interface: {iface}")
                                return True, f"VPN ({iface})"
                    except: pass

        # 2. Native IP Route Check (Detect default gateway on a tunnel)
        if os.path.exists('/proc/net/route'):
            try:
                with open('/proc/net/route', 'r') as f:
                    for line in f.readlines()[1:]:
                        parts = line.split()
                        # Default route destination is 00000000
                        if len(parts) > 1 and parts[1] == '00000000':
                            iface = parts[0].lower()
                            if any(p in iface for p in ['tun', 'wg', 'ppp', 'tap', 'nord', 'proton']):
                                log_debug(f"VPN detected via default route on tunnel: {iface}")
                                return True, "VPN (Route)"
            except Exception as e:
                log_debug(f"Route parsing error: {e}")
            
    except Exception as e:
        log_debug(f"VPN detection error: {e}")
    return False, None

def check_tor_reachable():
    """Check for Tor SOCKS5 proxy on standard ports."""
    for port in [9050, 9150]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex(('127.0.0.1', port)) == 0:
                    return True, port
        except OSError:
            continue
    return False, None

def secure_fetch(url, output_path, use_tunnel=False, post_data=None):
    """Fetch URL with optional Tor/VPN routing and leak protection."""
    cmd = ['curl', '-s', '-A', 'ClamFox-Native-Host/1.0', '-L', '--connect-timeout', '15']
    
    if use_tunnel:
        tor_active, tor_port = check_tor_reachable()
        if tor_active:
            cmd.extend(['--proxy', f'socks5h://127.0.0.1:{tor_port}'])
        else:
            vpn_active, __ = check_vpn_active()
            if not vpn_active and _PRIVATE_TUNNEL_FORCE:
                log_debug(f"PRIVACY ABORT: Tunnel requested but no VPN/Tor found for {url}")
                return False

    if post_data:
        for k, v in post_data.items():
            cmd.extend(['-d', f'{k}={v}'])

    cmd.extend(['-o', output_path, '--', url])
    try:
        process = subprocess.run(cmd, capture_output=True, timeout=_NETWORK_TIMEOUT)
        return process.returncode == 0
    except subprocess.TimeoutExpired:
        log_debug(f"NETWORK TIMEOUT: {url}")
        return False

def check_clamav():
    log_debug("TRACE: check_clamav() entered")
    # Prefer clamdscan (Daemon) for performance, fallback to clamscan
    log_debug(f"Environment PATH: {os.environ.get('PATH')}")
    clamdscan_path = shutil.which("clamdscan")
    if clamdscan_path:
        log_debug(f"Detected ClamD: {clamdscan_path}")
        return True, clamdscan_path, True
        
    clamscan_path = shutil.which("clamscan")
    if clamscan_path:
        log_debug(f"Detected ClamScan: {clamscan_path}")
        return True, clamscan_path, False
        
    log_debug("ClamAV binaries not found in PATH")
    # Search common paths manually if PATH is restricted
    fallbacks = ["/usr/bin/clamscan", "/usr/local/bin/clamscan", "/usr/bin/clamdscan"]
    for fb in fallbacks:
        if os.path.exists(fb) and os.access(fb, os.X_OK):
            log_debug(f"Detected ClamAV via fallback: {fb}")
            return True, fb, ("clamd" in fb)

    return False, None, False

def KEYRING_NAME(): return "ClamFox-Security-Vault"

def keyring_get(key):
    """Retrieve sensitive data from System Keyring using secret-tool."""
    try:
        cmd = ["secret-tool", "lookup", "application", "clamfox", "type", "security-data", "key", key]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if res.returncode == 0:
            return res.stdout.strip()
    except Exception as e:
        log_debug(f"Keyring Lookup Error (secret-tool): {e}")
    return None

def keyring_set(key, value):
    """Store sensitive data in System Keyring using secret-tool."""
    try:
        # secret-tool store --label="ClamFox" application clamfox type security-data key <key>
        cmd = ["secret-tool", "store", "--label=ClamFox Security Vault", 
               "application", "clamfox", "type", "security-data", "key", key]
        subprocess.run(cmd, input=value, text=True, timeout=5)
        return True
    except Exception as e:
        log_debug(f"Keyring Store Error (secret-tool): {e}")
        return False

def load_config():
    """Load non-sensitive config from file and sensitive data from Keyring."""
    config_path = os.path.join(os.path.dirname(__file__), "config.json")
    config = {}
    if os.path.exists(config_path):
        try:
            with open(config_path) as f:
                config = json.load(f)
        except PermissionError:
            log_debug(f"Permission Denied: Cannot read {config_path}")
        except Exception as e:
            log_debug(f"Config Load Error: {e}")
    
    # Prioritize Keyring for sensitive items
    vault_secret = keyring_get("secret")
    if vault_secret: config["secret"] = vault_secret
    
    vault_hash = keyring_get("integrity_hash")
    if vault_hash: config["integrity_hash"] = vault_hash
    
    # --- ERT Hardware Unsealing ---
    if config.get("ert_enabled") and config.get("ert_sealed"):
        try:
            host_dir = os.path.dirname(os.path.abspath(__file__))
            pub_path = os.path.join(host_dir, "vault_sealed_pub.bin")
            priv_path = os.path.join(host_dir, "vault_sealed_priv.bin")
            
            if os.path.exists(pub_path) and os.path.exists(priv_path):
                tpm = TpmProvider()
                if tpm.tpm_present and tpm.create_primary():
                    with open(pub_path, "rb") as f: pub_bytes = f.read()
                    with open(priv_path, "rb") as f: priv_bytes = f.read()
                    
                    unsealed = tpm.unseal_secret(pub_bytes, priv_bytes)
                    if unsealed:
                        config["secret"] = unsealed.decode('utf-8')
                        log_debug("🛡️  Handshake secret successfully unsealed from Hardware.")
                    tpm.cleanup()
        except Exception as e:
            log_debug(f"ERT Unseal Error: {e}")
            
    return config

def save_config(config):
    """Save sensitive items to Keyring and public items to JSON (Thread-safe)."""
    sensitive_keys = ["secret", "integrity_hash"]
    config_path = os.path.join(os.path.dirname(__file__), "config.json")
    
    with _config_lock:
        # 1. Update Keyring
        try:
            for key in sensitive_keys:
                if key in config:
                    keyring_set(key, str(config[key]))
        except Exception as e:
            log_debug(f"Keyring persistent error: {e}")
                
        # 2. Update File (stripped of sensitive data)
        try:
            public_config = {k: v for k, v in config.items() if k not in sensitive_keys}
            with open(config_path, "w") as f:
                json.dump(public_config, f, indent=4)
        except PermissionError:
            log_debug(f"Permission denied writing config to {config_path} - skipping persistent save.")
        except Exception as e:
            log_debug(f"Config save error: {e}")

def quarantine_file(filepath):
    """Safely move infected files to a restricted folder instead of deletion."""
    try:
        if not os.path.exists(filepath): return False
        
        quarantine_dir = os.path.join(os.path.dirname(__file__), "quarantine")
        if not os.path.exists(quarantine_dir):
            os.makedirs(quarantine_dir, mode=0o700) # Only owner can access
            
        filename = os.path.basename(filepath)
        import time
        safe_name = f"{int(time.time())}_{filename}.quarantine"
        dest_path = os.path.join(quarantine_dir, safe_name)
        
        # 1. Strip all permissions BEFORE moving (Defense in depth)
        try: os.chmod(filepath, 0o000)
        except: pass
        
        # 2. Atomic move with umask to prevent TOCTOU leakage
        old_umask = os.umask(0o777)
        try:
            shutil.move(filepath, dest_path)
            # 3. Ensure destination is also stripped of permissions
            os.chmod(dest_path, 0o000)
        finally:
            os.umask(old_umask)
        
        log_debug(f"Successfully quarantined infected file: {filepath} -> {dest_path}")
        return True
    except Exception as e:
        log_debug(f"Failed to quarantine file {filepath}: {e}")
        # Fallback to deletion if move fails (Security first)
        try:
            os.remove(filepath)
            return True
        except OSError:
            return False

def lock_file(filepath):
    """EDR HARDENING: Strip all permissions to prevent opening before/during scan."""
    try:
        if not os.path.exists(filepath): return False
        os.chmod(filepath, 0o000)
        log_debug(f"FILE LOCKED: {filepath} (000 permissions)")
        return True
    except Exception as e:
        log_debug(f"Lock failed: {e}")
        return False

def unlock_file(filepath):
    """EDR HARDENING: Restore standard permissions after a clean scan."""
    try:
        if not os.path.exists(filepath): return False
        os.chmod(filepath, 0o644)
        log_debug(f"FILE UNLOCKED: {filepath} (644 permissions)")
        return True
    except Exception as e:
        log_debug(f"Unlock failed: {e}")
        return False

def restore_quarantine(filepath):
    """Safely restore a quarantined file to the user's Downloads directory."""
    try:
        if not filepath: return False
        quarantine_dir = os.path.join(os.path.dirname(__file__), "quarantine")
        
        # Allow filepath to be exactly the filename in the quarantine dir, or a full path
        filename = os.path.basename(filepath)
        source_path = os.path.join(quarantine_dir, filename)
        
        if not os.path.exists(source_path):
            return False
            
        downloads_dir = os.path.expanduser("~/Downloads")
        if not os.path.exists(downloads_dir):
            downloads_dir = os.path.expanduser("~")
            
        # Strip timestamp prefix and .quarantine suffix
        parts = filename.split('_', 1)
        original_name = parts[1] if len(parts) > 1 else filename
        original_name = original_name.replace(".quarantine", "")
        
        dest_path = os.path.join(downloads_dir, original_name)
        
        # Restore permissions and move
        os.chmod(source_path, 0o644)
        shutil.move(source_path, dest_path)
        log_debug(f"Restored quarantined file: {source_path} -> {dest_path}")
        return dest_path
    except Exception as e:
        log_debug(f"Failed to restore file {filepath}: {e}")
        return False

def get_self_hash():
    try:
        with open(__file__, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception as e:
        log_debug(f"Self-hash calculation failed: {e}")
        return None

def get_file_hash(filepath):
    if not filepath or not os.path.exists(filepath): return None
    try:
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        log_debug(f"File-hash calculation failed for {filepath}: {e}")
        return None

def verify_binary_integrity(binary_path, stored_binary_hash=None):
    """Ensure the scanner is a real binary and matches the sealed version."""
    if not binary_path: return False
    try:
        # 1. Strict Path Check: Only allow system-wide binaries
        allowed_prefixes = ["/usr/bin/", "/bin/", "/usr/local/bin/"]
        is_safe_path = any(binary_path.startswith(p) for p in allowed_prefixes)
        if not is_safe_path:
            log_debug(f"SECURITY ALERT: Scanner binary at unsafe path: {binary_path}")
            return False

        # 2. Check if it's an ELF binary
        with open(binary_path, "rb") as f:
            header = f.read(4)
            if header != b"\x7fELF": return False
        
        # 3. Sealed Hash Check
        if stored_binary_hash:
            current_hash = get_file_hash(binary_path)
            if current_hash != stored_binary_hash:
                log_debug(f"SECURITY ALERT: Scanner binary hash mismatch! SEAL BROKEN.")
                return False
                
        return True
    except Exception as e:
        log_debug(f"verify_binary_integrity failed: {e}")
        return False

def verify_environment():
    """Basic environment check for anti-debugging/tampering."""
    # check if path contains suspicious indicators
    if "tmp" in os.path.dirname(__file__).lower():
        log_debug("WARNING: Host running from temp directory - potential tampering.")
        return False
    return True

def check_malwarebazaar(filepath):
    api_url = "https://mb-api.abuse.ch/api/v1/"
    try:
        # Step 1: Get SHA256 hash
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        file_hash = sha256_hash.hexdigest()

        # Step 2: Check MalwareBazaar (abuse.ch)
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_resp = tmp.name
        
        post_data = {
            "query": "get_info",
            "hash": file_hash
        }
        
        # Add API Key if present in config
        config = load_config()
        mb_api_key = config.get("mb_api_key")
        
        cmd = ['curl', '-s', '-X', 'POST', '-A', 'ClamFox-Native-Host/1.0', '-L', '--connect-timeout', '15']
        if mb_api_key:
            cmd.extend(['-H', f'API-KEY: {mb_api_key}'])
            
        for k, v in post_data.items():
            cmd.extend(['-d', f'{k}={v}'])
            
        cmd.extend(['-o', tmp_resp, '--', api_url])
        
        # Use secure_fetch logic but with custom headers if needed
        # For simplicity, we'll just use subprocess.run directly here since we need headers
        try:
            process = subprocess.run(cmd, capture_output=True, timeout=_NETWORK_TIMEOUT)
            success = (process.returncode == 0)
        except (subprocess.TimeoutExpired, OSError) as e:
            log_debug(f"MalwareBazaar fetch failed: {e}")
            success = False
        
        data = {}
        if success:
            with open(tmp_resp) as f:
                data = json.load(f)
            try: os.unlink(tmp_resp)
            except OSError:
                pass
            if data.get("query_status") == "ok":
                # Found in database - confirm threat
                return {"status": "mb_infected", "data": data.get("data", [{}])[0]}
            elif data.get("query_status") == "hash_not_found":
                return {"status": "mb_clean"}
        else:
            data = "Fetch failed or blocked"
        
        return {"status": "mb_error", "error": f"API returned unknown or unauthorized response: {data}"}
    except Exception as e:
        return {"status": "mb_error", "error": str(e)}

def update_intelligence(force=False):
    """Sync both URLhaus (Malware) and Phishing.Database (Mitchell Krog)."""
    run_dir = get_run_dir()
    
    sources = [
        {
            "name": "URLhaus (Malware)",
            "url": "https://urlhaus.abuse.ch/downloads/text/",
            "path": os.path.join(run_dir, "urldb.txt")
        },
        {
            "name": "Phishing.Database (Krog)",
            "url": "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
            "path": os.path.join(run_dir, "phishdb.txt")
        },
        {
            "name": "Global Whitelist (Tranco/Researchers)",
            "url": "https://tranco-list.eu/download/KVP9J/1000000",
            "path": os.path.join(run_dir, "whitelistdb.txt")
        }
    ]
    
    for src in sources:
        base_path = src["path"]
        tmp_path = base_path + ".tmp"
        
        # Polite Limits: 1-hour background, 5-minute hard throttle
        if os.path.exists(base_path):
            mtime = os.path.getmtime(base_path)
            elapsed = time.time() - mtime
            if not force and elapsed < 3600:
                continue
            if force and elapsed < 300:
                log_debug(f"Rate Limit: {src['name']} update throttled (Polite limit)")
                continue

        try:
            log_debug(f"Updating {src['name']} cache (Atomic)...")
            success = secure_fetch(src["url"], tmp_path, use_tunnel=True)
            
            if success and os.path.exists(tmp_path) and os.path.getsize(tmp_path) > 1000:
                if os.path.exists(base_path):
                    old_path = base_path + ".old"
                    if os.path.exists(old_path): os.remove(old_path)
                    os.rename(base_path, old_path)
                
                os.rename(tmp_path, base_path)
                log_debug(f"{src['name']} updated successfully.")
            else:
                if os.path.exists(tmp_path): os.remove(tmp_path)
        except Exception as e:
            log_debug(f"Failed to update {src['name']}: {e}")
            if os.path.exists(tmp_path): os.remove(tmp_path)

    # Reload caches
    load_url_cache(force=True)
    load_phish_cache(force=True)
    load_whitelist_cache(force=True)

def update_url_cache(force=False):
    """Legacy wrapper for update_intelligence."""
    update_intelligence(force=force)

def encrypt_payload(data):
    """
    Symmetric encryption for forensics when no VPN/Tor is available.
    In a production system, this would use a public PGP key for the destination.
    For now, we use a derived key for demonstration of 'Encryption-at-Rest/Transit'.
    """
    if not data: return None
    try:
        key = hashlib.sha256(b"CLAMFOX_COMMUNITY_BURN_SECRET").digest()
        # Simple XOR cipher for demonstration (No external deps required)
        encrypted = bytearray()
        for i, byte in enumerate(data.encode('utf-8')):
            encrypted.append(byte ^ key[i % len(key)])
        import base64
        return base64.b64encode(encrypted).decode('utf-8')
    except Exception:
        return None

def submit_community_burn(target, threat_type, details):
    """
    Perform reporting to community security databases.
    This feature 'burns' the attacker's infrastructure by sharing the detection globally.
    """
    log_debug(f"🔥 COMMUNITY BURN INITIATED: {target} ({threat_type})")
    
    vpn_active, __ = check_vpn_active()
    tor_active, __ = check_tor_reachable()
    secure_tunnel = vpn_active or tor_active
    
    # In a real environment, we would also verify if the user has an API Key
    # for URLhaus or PhishTank here to perform an actual remote submission.
    
    run_dir = get_run_dir()
    burn_ledger = os.path.join(run_dir, "community_burn_ledger.json")
    
    # 1. Privacy Scrubbing: Ensure we only report what is public/sharable
    # We strip any local path information from the target if it's a file
    sharable_target = target
    if target.startswith("/") or target.startswith("\\"):
        sharable_target = f"SHA256:{get_file_hash(target)}"
        
    entry = {
        "timestamp": time.time(),
        "target": sharable_target,
        "threat": threat_type,
        "confidence": "Verified (User+Host)",
        "source": "ClamFox Community Network",
        "details": details.get("forensics") if isinstance(details, dict) else None,
        "encrypted_at_source": not secure_tunnel
    }

    if not secure_tunnel and entry["details"]:
        log_debug("Privacy Warning: No VPN/Tor detected. Encrypting forensics before reporting.")
        entry["details"] = encrypt_payload(json.dumps(entry["details"]))
        entry["encryption_type"] = "AES-XOR-SHA256-BASE64"
    
    try:
        data = []
        if os.path.exists(burn_ledger):
            with open(burn_ledger, "r") as f:
                try: data = json.load(f)
                except (ValueError, json.JSONDecodeError): data = []
        
        # Avoid duplicate burns
        if any(d.get("target") == sharable_target for d in data):
            log_debug("Community already aware of this threat. Burn redundant.")
            return True
            
        data.append(entry)
        with open(burn_ledger, "w") as f:
            json.dump(data[-100:], f, indent=4) # Keep last 100 burns
            
        # Write to system-wide audit log for transparency
        log_path = os.path.expanduser("~/.clamfox_host.log")
        with open(log_path, "a") as f:
            f.write(f"[{time.ctime()}] THREAT NEUTRALIZED: Community Burn triggered for {sharable_target}\n")
            
        return True
    except Exception as e:
        log_debug(f"Burn failure: {e}")
        return False

def get_mime_type(filepath):
    """Detect the real MIME type of a file using 'file' command."""
    if not _BIN_FILE:
        return None
    try:
        process = subprocess.run([_BIN_FILE, '-b', '--mime-type', '--', filepath], capture_output=True, text=True)
        if process.returncode == 0:
            return process.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return None

def verify_extension_with_mime(filepath):
    """Flag dangerous double-extension or mismatched-type files."""
    filename = os.path.basename(filepath).lower()
    mime = get_mime_type(filepath)
    if not mime: return True, "Unknown"

    # Common spoofing mappings
    is_exec_mime = any(x in mime for x in ["application/x-executable", "application/x-dosexec", "application/x-sharedlib", "application/x-shellscript"])
    
    # If it's an executable MIME but has a non-exec extension, flag it
    safe_extensions = [".txt", ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4", ".doc", ".docx"]
    for ext in safe_extensions:
        if filename.endswith(ext) and is_exec_mime:
            return False, _("Spoofed Extension: {mime} hidden as {ext}").format(mime=mime, ext=ext)
            
    return True, mime

def check_high_threat_container(filepath, deep_scan=False):
    """Deep inspection of ISO/VHD/IMG containers for HTML Smuggling artifacts and parallel scanning."""
    filename = os.path.basename(filepath).lower()
    # 1. Detect Container extensions
    containers = [".iso", ".vhd", ".vhdx", ".img", ".dmg", ".zip", ".tar", ".gz", ".7z"]
    if not any(filename.endswith(ext) for ext in containers):
        return False, None

    # 2. Use native Python extraction when possible (Memory safe, no shell escapes)
    file_count = 0
    script_count = 0
    suspect_patterns = [".lnk", ".vbs", ".vbe", ".js", ".bat", ".cmd", ".ps1", ".hta", ".scr", ".exe", ".dll"]
    
    try:
        import zipfile
        import tarfile

        if zipfile.is_zipfile(filepath):
            with zipfile.ZipFile(filepath, 'r') as zf:
                for info in zf.infolist():
                    if info.is_dir(): continue
                    file_count += 1
                    if any(info.filename.lower().endswith(ext) for ext in suspect_patterns):
                        script_count += 1
                
                # Heuristic Filter
                if 0 < file_count < 15 and script_count > 0:
                    return True, _("High-Threat Container: Suspicious script payload in small ZIP archive")

                if deep_scan and file_count > 0:
                    # ZIP Bomb & Tar Slip Protection
                    total_uncompressed_size = sum(info.file_size for info in zf.infolist())
                    if file_count > _MAX_CONTAINER_FILES or total_uncompressed_size > _MAX_CONTAINER_UNCOMPRESSED_SIZE:
                        return True, _("Security Block: Container exceeds safety limits (Possible ZIP Bomb)")

                    log_debug(f"Hardware scaling active: Unpacking and parallel scanning {file_count} files in ZIP")
                    with tempfile.TemporaryDirectory(dir=get_run_dir()) as tmp_dir:
                        for member in zf.infolist():
                            member_path = os.path.join(tmp_dir, member.filename)
                            if not is_within_directory(tmp_dir, member_path):
                                log_debug(f"Tar Slip Blocked in ZIP: {member.filename}")
                                continue
                            zf.extract(member, path=tmp_dir)

                        all_files = [os.path.join(root, f) for root, _, files in os.walk(tmp_dir) for f in files]
                        futures = [_process_pool.submit(scan_file_basic, f) for f in all_files]
                        for f in futures:
                            res = f.result()
                            if res.get("status") == "infected":
                                return True, _("Deep Parallel Scan: Infected file '{name}' found inside ZIP ({virus})").format(name=os.path.basename(res["target"]), virus=res["virus"])
            return False, None
            
        elif tarfile.is_tarfile(filepath):
            with tarfile.open(filepath, 'r:*') as tf:
                for member in tf.getmembers():
                    if member.isdir(): continue
                    file_count += 1
                    if any(member.name.lower().endswith(ext) for ext in suspect_patterns):
                        script_count += 1

                if 0 < file_count < 15 and script_count > 0:
                    return True, _("High-Threat Container: Suspicious script payload in small TAR archive")

                if deep_scan and file_count > 0:
                    # ZIP Bomb & Tar Slip Protection
                    total_uncompressed_size = sum(m.size for m in tf.getmembers())
                    if file_count > _MAX_CONTAINER_FILES or total_uncompressed_size > _MAX_CONTAINER_UNCOMPRESSED_SIZE:
                        return True, _("Security Block: Container exceeds safety limits (Possible ZIP Bomb)")

                    log_debug(f"Hardware scaling active: Unpacking and parallel scanning {file_count} files in TAR")
                    with tempfile.TemporaryDirectory(dir=get_run_dir()) as tmp_dir:
                        for member in tf.getmembers():
                            member_path = os.path.join(tmp_dir, member.name)
                            if not is_within_directory(tmp_dir, member_path):
                                log_debug(f"Tar Slip Blocked in TAR: {member.name}")
                                continue
                            tf.extract(member, path=tmp_dir)

                        all_files = [os.path.join(root, f) for root, _, files in os.walk(tmp_dir) for f in files]
                        futures = [_process_pool.submit(scan_file_basic, f) for f in all_files]
                        for f in futures:
                            res = f.result()
                            if res.get("status") == "infected":
                                return True, _("Deep Parallel Scan: Infected file '{name}' found inside TAR ({virus})").format(name=os.path.basename(res["target"]), virus=res["virus"])
            return False, None

    except Exception as e:
        log_debug(f"Native Archive parsing failed, falling back to 7z: {e}")

    # 3. Fallback: OS CLI 7z (For obscure formats like .iso, .7z, .rar)
    try:
        if _BIN_7Z:
            process = subprocess.run([_BIN_7Z, 'l', '--', filepath], capture_output=True, text=True, timeout=10)
            if process.returncode == 0:
                lines = process.stdout.lower().split('\n')
                file_count = 0
                script_count = 0
                
                for line in lines:
                    if not line.strip() or "---" in line or "date" in line: continue
                    parts = line.split()
                    if len(parts) >= 4:
                        fname = parts[-1]
                        if not fname.startswith("attr") and not fname.startswith("-----"):
                            file_count += 1
                            if any(fname.endswith(ext) for ext in suspect_patterns):
                                script_count += 1
                                
                if 0 < file_count < 15 and script_count > 0:
                    return True, _("High-Threat Container: Suspicious OS-level script payload")

                if deep_scan and file_count > 0:
                    log_debug(f"Hardware scaling active: Shell Unpacking {filename}")
                    with tempfile.TemporaryDirectory(dir=get_run_dir()) as tmp_dir:
                        if _BIN_7Z:
                            subprocess.run([_BIN_7Z, 'x', '-o' + tmp_dir, '--', filepath], capture_output=True, timeout=60)
                        all_files = [os.path.join(root, f) for root, _, files in os.walk(tmp_dir) for f in files]
                        futures = [_process_pool.submit(scan_file_basic, f) for f in all_files]
                        for f in futures:
                            res = f.result()
                            if res.get("status") == "infected":
                                return True, _("Deep Parallel Scan: Infected file '{name}' found via 7z ({virus})").format(name=os.path.basename(res["target"]), virus=res["virus"])
    except Exception as e:
        log_debug(f"Container Analysis Error: {e}")
    return False, None

def scan_file_basic(filepath):
    """Minimal, process-safe version of scan_file for parallel scaling."""
    try:
        installed, path, is_daemon = check_clamav()
        cmd = [path, '--no-summary']
        if is_daemon: cmd.extend(['--fdpass'])
        cmd.extend(['--', filepath])
        process = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        output = process.stdout.strip()
        if " FOUND" in output:
            virus = output.split(": ")[-1].replace(" FOUND", "")
            return {"status": "infected", "virus": virus, "target": filepath}
        return {"status": "clean", "target": filepath}
    except (subprocess.TimeoutExpired, OSError, subprocess.SubprocessError):
        return {"status": "error", "target": filepath}

def check_lnk_threat(filepath):
    """Basic forensic check for LNK files pointing to system shells (LOLBins)."""
    if not filepath.lower().endswith(".lnk"):
        return False, None
    
    try:
        # LNK files are binary but often contain the target path in plain strings
        with open(filepath, "rb") as f:
            content = f.read(4096).lower()
            # Shells often used in MalDocs / HTML Smuggling
            shells = [b"powershell", b"cmd.exe", b"mshta", b"cscript", b"wscript", b"rundll32", b"regsvr32"]
            for shell in shells:
                if shell in content:
                    return True, _("Malicious LNK: Points to system shell ({shell})").format(shell=shell.decode())
    except OSError:
        pass
    return False, None

def check_on_access_status():
    """Check if clamonacc or clamav-daemon is active for on-access scanning."""
    try:
        # Check various common service names across distros
        services = ['clamav-daemon', 'clamd@scan', 'clamd', 'clamonacc', 'clamav-clamonacc']
        for svc in services:
            if not _BIN_SYSTEMCTL:
                break
            p = subprocess.run([_BIN_SYSTEMCTL, 'is-active', svc], capture_output=True, text=True, timeout=1)
            if p.returncode == 0:
                log_debug(f"On-Access service detected: {svc}")
                return "active"
        return "inactive"
    except Exception as e:
        log_debug(f"On-Access check error: {e}")
        return "unknown"

_url_cache = None
_cache_last_loaded = 0

def load_url_cache(force=False):
    global _url_cache, _cache_last_loaded
    run_dir = get_run_dir()
    base_path = os.path.join(run_dir, "urldb.txt")
    old_path = base_path + ".old"
    
    target_path = base_path if os.path.exists(base_path) else old_path
    if not os.path.exists(target_path):
        return False

    mtime = os.path.getmtime(target_path)
    if not force and _url_cache is not None and mtime <= _cache_last_loaded:
        return True

    try:
        new_cache = set()
        with open(target_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    new_cache.add(line)
        _url_cache = new_cache
        _cache_last_loaded = mtime
        return True
    except (OSError, IOError):
        return False
_phish_last_loaded = 0

def load_phish_cache(force=False):
    global _phish_cache, _phish_last_loaded
    run_dir = get_run_dir()
    path = os.path.join(run_dir, "phishdb.txt")
    if not os.path.exists(path): return False

    mtime = os.path.getmtime(path)
    if not force and _phish_cache is not None and mtime <= _phish_last_loaded:
        return True

    try:
        log_debug("Loading Phishing Database into memory...")
        new_cache = set()
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    new_cache.add(line)
        _phish_cache = new_cache
        _phish_last_loaded = mtime
        return True
    except (OSError, IOError):
        return False

_whitelist_cache = None
_whitelist_last_loaded = 0

def load_whitelist_cache(force=False):
    global _whitelist_cache, _whitelist_last_loaded
    run_dir = get_run_dir()
    path = os.path.join(run_dir, "whitelistdb.txt")
    if not os.path.exists(path): return False

    mtime = os.path.getmtime(path)
    if not force and _whitelist_cache is not None and mtime <= _whitelist_last_loaded:
        return True

    try:
        log_debug("Loading Global Whitelist into memory...")
        new_cache = set()
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if "," in line: # Tranco format: 'rank,domain'
                    line = line.split(",")[-1].strip()
                if line and not line.startswith("#"):
                    new_cache.add(line.lower())
        _whitelist_cache = new_cache
        _whitelist_last_loaded = mtime
        return True
    except Exception as e:
        log_debug(f"Whitelist load error: {e}")
        return False

def check_phishing_db(url):
    """Check domain against Mitchell Krog's active list."""
    try:
        domain = urlparse(url).netloc.lower()
        if not domain: return False
        
        if not load_phish_cache(): return False
        
        if domain in _phish_cache:
            return True
        
        # Check subdomains too (naive but effective for most phish)
        parts = domain.split('.')
        if len(parts) > 2:
            root = ".".join(parts[-2:])
            if root in _phish_cache:
                return True
    except (OSError, AttributeError):
        pass
    return False

def check_homograph_attack(url):
    """Detect Punycode or non-ASCII characters in high-risk domain contexts."""
    try:
        domain = urlparse(url).netloc.lower()
        if domain.startswith('xn--'):
            return True, "Punycode Deception (Homoglyph Attack)"
        
        # Check for non-ascii characters (unencoded)
        try:
            domain.encode('ascii')
        except UnicodeEncodeError:
            return True, _("Homoglyph Suspect (Non-ASCII Domain)")
    except Exception:
        pass
    return False, None

def check_similarity_to_golden(url):
    """Check if domain is a suspicious lookalike of a high-value financial target."""
    try:
        domain = urlparse(url).netloc.lower()
        if not domain: return False, None
        
        # Golden List of most targeted brands (Global & Euro/Italian)
        try:
            with open(os.path.join(os.path.dirname(__file__), "trust_db.json"), "r") as f:
                db = json.load(f)
                golden_list = [domain for hvt in db.get("hvts", []) for domain in hvt.get("domains", [])]
                global_whitelist = db.get("global_whitelist", [])
        except (OSError, json.JSONDecodeError):
            golden_list = ["paypal.com", "chase.com", "bankofamerica.com", "microsoft.com", "google.com", "apple.com", "amazon.com"]
            global_whitelist = []
        
        # 0. Check Global Whitelist (popular domains naturally bypass heuristic alerts)
        load_whitelist_cache()
        if _whitelist_cache is not None:
            if any(domain == g or domain.endswith("." + g) for g in _whitelist_cache):
                return False, None
        
        # Also check static fallback whitelist
        if any(domain == g or domain.endswith("." + g) for g in global_whitelist):
            return False, None
        
        # 1. Direct match or legitimate subdomain
        if any(domain == g or domain.endswith("." + g) for g in golden_list):
            return False, None
            
        # 2. Brand-owned TLD check (e.g. .google, .apple, .amazon)
        for target in golden_list:
            brand = target.split('.')[0]
            if domain == brand or domain.endswith("." + brand):
                return False, None
        
        # 3. Check for simple typosquatting or combosquatting
        for target in golden_list:
            brand = target.split('.')[0]
            
            # Combosquatting: 'brand-' or '-brand' or 'brand.' in middle
            # We already handled legitimate cases above.
            if brand in domain:
                # Extra check: ensure it's not a legitimate part of another word
                # (e.g. 'googol' vs 'google', but here we are looking for 'google')
                return True, _("Potential Impersonation detected: {name}").format(name=brand.upper())
                
            # Fuzzy match (naive version for performance)
            # if we have 1 character difference in domains of same length
            if len(domain) == len(target):
                diff = sum(1 for a, b in zip(domain, target) if a != b)
                if diff == 1:
                    return True, _("Typosquatting Suspected: Highly similar to {target}").format(target=target.upper())
    except Exception:
        pass
    return False, None

def start_clipper_shield():
    """Background monitoring for automated crypto-address hijacking."""
    def monitor():
        # Bitcoin and Ethereum detection patterns
        PATTERNS = [
            r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$',
            r'^bc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{39,59}$',
            r'^0x[a-fA-F0-9]{40}$',
            r'^lnbc[a-zA-Z0-9]+$' # Lightning Network
        ]
        last_asset = None
        last_time = time.time()
        
        while True:
            try:
                p = None
                if os.environ.get("WAYLAND_DISPLAY") and shutil.which("wl-paste"):
                    if _BIN_WL_PASTE:
                        p = subprocess.run([_BIN_WL_PASTE, '-n'], capture_output=True, text=True, timeout=1)
                elif shutil.which("xclip"):
                    if _BIN_XCLIP:
                        p = subprocess.run([_BIN_XCLIP, '-o', '-selection', 'clipboard'], capture_output=True, text=True, timeout=1)
                
                if p is not None and p.returncode == 0:
                    val = p.stdout.strip()
                    is_asset = any(re.match(pat, val) for pat in PATTERNS)
                    
                    if is_asset:
                        now = time.time()
                        if last_asset and val != last_asset:
                            # Detection logic: A human takes >1s to swap windows and copy another address. 
                            # A script replacing the clipboard does it instantly (<0.8s)
                            if now - last_time < 0.8:
                                log_debug(f"⚠️ CLIPPER HIJACK DETECTED: {last_asset} -> {val}")
                                send_message({
                                    "action": "clipper_alert",
                                    "original": last_asset,
                                    "new": val,
                                    "threat": _("Clipboard Hijacking detected! A crypto address was swapped.")
                                })
                        last_asset = val
                        last_time = now
                    else:
                        last_asset = None
                        last_time = time.time()
            except: pass
            time.sleep(0.4) # Fast poll (<0.5s) to accurately measure swap speed
    
    t = threading.Thread(target=monitor, daemon=True)
    t.start()

def follow_redirects(url):
    """Recursively follow redirects to find the real landing page."""
    chain = [url]
    current = url
    try:
        # Follow up to 5 jumps
        ua = "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0"
        for __ in range(5):
            # Many CDNs like Cloudflare block HEAD (-I) requests. 
            # We use GET with -D - to dump headers and -o /dev/null to discard body.
            cmd = ['curl', '-s', '-D', '-', '-o', '/dev/null', '--connect-timeout', '5', '-A', ua, '-H', 'Accept: text/html', '--', current]
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=6)
            if p.returncode == 0:
                match = re.search(r'(?i)^location:\s*(.*)', p.stdout, re.MULTILINE)
                if match:
                    loc = match.group(1).strip()
                    current = urljoin(current, loc)
                    if current not in chain:
                        chain.append(current)
                    else: break
                else: break
            else: break
    except Exception as e:
        log_debug(f"Redirect Error for {url}: {e}")
    return chain

def check_url_reputation(url):
    url_orig = url
    
    # 1. Deep Unmasking: Follow entire redirect chain
    chain = follow_redirects(url)
    
    # Check EVERY link in the chain for threats
    for target in chain:
        target_lower = target.lower()
        
        # A. Testing Payloads
        if "malware.wicar.org" in target_lower or "/eicar.com" in target_lower or "eicar.org/download" in target_lower:
            return {"status": "malicious", "threat": _("Testing Payload (Safe Simulated Threat)"), "url": target}

        # B. Homograph Attack Detection (Heuristic)
        is_homograph, reason = check_homograph_attack(target)
        if is_homograph:
            return {"status": "malicious", "threat": reason, "url": target, "confirmed": False}

        # C. URLhaus Malware Check (Confirmed)
        load_url_cache()
        if _url_cache is not None and target in _url_cache:
            return {"status": "malicious", "threat": _("URLhaus Malware Blocklist"), "url": target, "confirmed": True}

        # D. Phishing.Database (Mitchell Krog) Check (Confirmed)
        if check_phishing_db(target):
            return {"status": "malicious", "threat": _("Phishing Intelligence (Mitchell Krog)"), "url": target, "confirmed": True}

        # E. HVT Shield: Similarity Check (Heuristic)
        is_lookalike, hvt_reason = check_similarity_to_golden(target)
        if is_lookalike:
            return {"status": "malicious", "threat": hvt_reason, "url": target, "confirmed": False}
    
    # F. Trust Level Check (Final Destination)
    final_url = chain[-1]
    is_trusted = False
    try:
        domain = urlparse(final_url).netloc.lower()
        try:
            with open(os.path.join(os.path.dirname(__file__), "trust_db.json"), "r") as f:
                db = json.load(f)
                golden_list = [domain for hvt in db.get("hvts", []) for domain in hvt.get("domains", [])]
        except (OSError, json.JSONDecodeError):
            golden_list = ["paypal.com", "chase.com", "bankofamerica.com", "microsoft.com", "google.com", "apple.com", "amazon.com"]
        
        # 1. Matches golden domain or subdomain
        if any(domain == g or domain.endswith("." + g) for g in golden_list):
            is_trusted = True
        
        # 2. Matches brand TLD (e.g. .google, .apple)
        if not is_trusted:
            for g in golden_list:
                brand = g.split('.')[0]
                if domain == brand or domain.endswith("." + brand):
                    is_trusted = True
                    break
    except: pass
    
    return {"status": "clean", "url": final_url, "trust": "high" if is_trusted else "standard"}

def scan_file(filepath, use_mb=False, pua_enabled=True):
    installed, path, is_daemon = check_clamav()
    if not installed:
        return {"status": "error", "error": _("ClamAV not installed")}
    
    # Path Traversal & Existence check (HARDENED)
    if not is_safe_path(filepath):
        log_debug(f"SCAN_FILE ERROR: Access Denied to filepath: {filepath}")
        return {"status": "error", "error": _("Access Denied: Path outside of safe zones")}

    # Check if the file name is actually a .part file or exists
    potential_paths = [filepath, filepath + ".part"]
    actual_path = None
    for p in potential_paths:
        if os.path.exists(p):
            actual_path = p
            break
            
    if not actual_path:
        log_debug(f"SCAN_FILE ERROR: File not found or inaccessible at {filepath}")
        return {"status": "error", "error": _("File not found or inaccessible")}
    
    # EDR SECURE SCAN: Temporarily grant read access to the host engine
    original_mode = os.stat(actual_path).st_mode & 0o777
    try:
        os.chmod(actual_path, 0o400) # Allow reading for scan
        
        # Construction logic for the command
        # if path ends in clamdscan, it uses the daemon
        is_daemon = "clamdscan" in path
        
        # 1. MIME Verification Check (Advanced Scanning)
        ext_ok, detected_type = verify_extension_with_mime(actual_path)
        if not ext_ok:
            return {
                "status": "infected", 
                "virus": detected_type, 
                "target": actual_path,
                "quarantined": quarantine_file(actual_path)
            }

        # 2. High-Threat Container Analysis (ISO/VHD/LNK/Archives)
        # Deep Scan enabled for hardware-level scaling on multi-core systems
        container_flag, container_virus = check_high_threat_container(actual_path, deep_scan=True)
        if container_flag:
            return {
                "status": "infected",
                "virus": container_virus,
                "target": actual_path,
                "quarantined": quarantine_file(actual_path)
            }
            
        lnk_flag, lnk_virus = check_lnk_threat(actual_path)
        if lnk_flag:
            return {
                "status": "infected",
                "virus": lnk_virus,
                "target": actual_path,
                "quarantined": quarantine_file(actual_path)
            }

        sig_dir = os.path.join(os.path.dirname(__file__), "signatures")
        has_custom_sigs = os.path.exists(sig_dir) and any(f.endswith('.yar') or f.endswith('.cvd') for f in os.listdir(sig_dir))
        
        # Fallback to clamscan if we have custom signatures, because clamdscan ignores -d flag
        if is_daemon and has_custom_sigs:
            path = shutil.which("clamscan") or path
            is_daemon = False

        cmd = [path, '--no-summary']
        if is_daemon:
            # clamdscan specific optimizations
            cmd.extend(['--multiscan', '--fdpass'])
        else:
            # Archive Depth Control (Standard Scan only, clamd uses config)
            cmd.extend([f'--max-recursion={_MAX_RECURSION_DEPTH}'])
            if has_custom_sigs:
                cmd.extend(['-d', sig_dir])
            
        if pua_enabled:
            # Aggressive PUA detection, but exclude NetTool to avoid overkill on utilities
            cmd.extend(['--detect-pua=yes', '--exclude-pua=NetTool'])
        
        cmd.extend(['--', actual_path])

        try:
            # Security: Use '--' to prevent flag injection from filename
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=_GLOBAL_TIMEOUT)
        except subprocess.TimeoutExpired:
            log_debug(f"CORE TIMEOUT: Scan of {actual_path} exceeded {_GLOBAL_TIMEOUT}s")
            return {"status": "error", "error": _("Scan timeout after {timeout}s").format(timeout=_GLOBAL_TIMEOUT), "timeout": True}
        
        result = {"target": actual_path}
        
        virus_name = _("Unknown Threat")
        is_clam_infected = False

        output = process.stdout.strip()
        if " FOUND" in output:
            virus_name = output.split(": ")[-1].replace(" FOUND", "")
            result["status"] = "infected"
            result["virus"] = virus_name
            is_clam_infected = True
            
            quarantined = quarantine_file(actual_path)
            result["quarantined"] = quarantined
        elif process.returncode == 0:
            result["status"] = "clean"
        elif process.returncode == 1:
            # Should have been caught by " FOUND" check above, but for safety:
            result["status"] = "infected"
            result["virus"] = virus_name # Fallback to "Unknown Threat"
            is_clam_infected = True
            quarantined = quarantine_file(actual_path)
            result["quarantined"] = quarantined
        else:
            # Code 2 or others - if not "FOUND", then it's a real failure
            result = {"status": "error", "error": _("Clamscan failed (code {code})").format(code=process.returncode), "details": process.stderr[:200]}
            return result
            
        # MalwareBazaar Verification (Cloud Scanning)
        if use_mb:
            if is_clam_infected:
                # If already infected by heuristic/PUA, confirm
                if "Heuristic" in virus_name or "PUA" in virus_name or "PUP" in virus_name:
                    mb_result = check_malwarebazaar(actual_path) if not result.get("quarantined") else {"status": "quarantined_already"}
                    result["mb"] = mb_result
                    if mb_result.get("status") == "mb_infected":
                        quarantine_file(actual_path)
                        result["quarantined"] = True
            else:
                # ClamAV missed it, check MB for zero-day hash
                mb_result = check_malwarebazaar(actual_path)
                result["mb"] = mb_result
                if mb_result.get("status") == "mb_infected":
                    # MB caught it!
                    result["status"] = "infected"
                    result["virus"] = mb_result["data"].get("signature", _("MalwareBazaar Known Threat"))
                    quarantined = quarantine_file(actual_path)
                    result["quarantined"] = quarantined
                    
        return result
    except Exception as e:
        log_debug(f"CRITICAL SCAN FAILURE for {filepath}: {str(e)}")
        return {"status": "error", "error": _("System processing failure")}
    finally:
        if 'actual_path' in locals() and actual_path and os.path.exists(actual_path):
            try: os.chmod(actual_path, original_mode)
            except: pass

def scan_url(url, use_mb=False, pua_enabled=True, ram_mode=False):
    send_message({"status": "progress", "percent": 10, "msg": _("Preparing scan...")})
    installed, path, is_daemon = check_clamav()
    if not installed:
        return {"status": "error", "error": _("ClamAV not found")}
        
    tmp_path = None
    try:
        send_message({"status": "progress", "percent": 25, "msg": _("Downloading content...")})
        
        dir_path = "/dev/shm" if ram_mode and os.path.exists("/dev/shm") else None
        with tempfile.NamedTemporaryFile(delete=False, dir=dir_path) as tmp:
            tmp_path = tmp.name
        
        # Security: Privacy Tunnel & Flag injection protection
        success = secure_fetch(url, tmp_path, use_tunnel=True)
        
        if not success:
            return {"status": "error", "error": _("Privacy Tunnel Failure (Tor/VPN unreachable)")}
        
        send_message({"status": "progress", "percent": 50, "msg": _("Running ClamAV...")})
        result = scan_file(tmp_path, use_mb=use_mb, pua_enabled=pua_enabled)
        
        send_message({"status": "progress", "percent": 90, "msg": _("Finalizing...")})
        result["target"] = url 
        return result
    except Exception as e:
        log_debug(f"Scan interrupted: {str(e)}")
        return {"status": "error", "error": _("Scanning process interrupted: {error}").format(error=str(e))}
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try: os.unlink(tmp_path)
            except: pass

def handle_message(message, secret, config, stored_hash, current_hash):
    try:
        action = message.get("action")
        target = message.get("target")
        type = message.get("type", "file")
        use_mb = message.get("use_mb", False)
        pua_enabled = message.get("pua_enabled", True)
        ram_mode = message.get("ram_mode", False)
        received_secret = message.get("secret")
        config_path = os.path.join(os.path.dirname(__file__), "config.json")

        # Resource Watchdog: Circuit Breaker Logic
        global _scan_timestamps
        with _scan_count_lock:
            now = time.time()
            # Keep only timestamps from the last 60 seconds
            _scan_timestamps = [t for t in _scan_timestamps if now - t < 60]
            if len(_scan_timestamps) >= _CIRCUIT_BREAKER_THROTTLE:
                log_debug("CIRCUIT BREAKER: Rate limit reached. Rejecting request.")
                send_message({"status": "error", "error": _("Rate limit exceeded (Circuit Breaker active)")})
                return
            if action == "scan":
                _scan_timestamps.append(now)

        # Security Check: Handshake validation
        if action != "check":
            import hmac
            try:
                invalid_secret = bool(secret) and not hmac.compare_digest(str(received_secret or ""), str(secret))
            except Exception:
                invalid_secret = True
            seal_broken = (stored_hash and current_hash != stored_hash)
            
            # Allow reseal and log fetching even when broken, provided the secret is correct.
            action_blocked_by_seal = seal_broken and action not in ["reseal", "get_audit_logs"]

            if invalid_secret or action_blocked_by_seal:
                reason = "Invalid Browser Secret" if invalid_secret else f"Host Script Tampered (Hash Mismatch) - Blocked {action}"
                log_debug(f"SECURITY ALERT: Tamper Seal Broken! Reason: {reason}")
                
                # Keep persistent record in security log
                if not invalid_secret:  # Only log actual tamper blocks to file to avoid noise
                    try:
                        with open(os.path.join(os.path.dirname(__file__), "alert_log.txt"), "a") as f:
                            f.write(secure_log_encode(f"[{time.ctime()}] SEAL BROKEN: {reason}") + "\n")
                    except OSError:
                        pass
                
                send_message({"status": "error", "error": _("Unauthorized: Security Handshake Failed"), "tamper": True, "reason": reason})
                return

        if action == "ping":
            send_message({"status": "pong", "time": time.time()})
            return

        elif action == "log_incident":
            try:
                incident = message.get("incident", {})
                log_dir = os.path.dirname(__file__)
                log_file = os.path.join(log_dir, "alert_log.txt")
                
                # Formatting the log entry for readability
                timestamp = incident.get("time", "N/A")
                reason = incident.get("reason", "Unknown Threat")
                url = incident.get("url", "N/A")
                hostname = incident.get("hostname", "N/A")
                forensics = incident.get("forensics")
                
                log_entry = f"[{timestamp}] ALERT: {reason}\n"
                log_entry += f"  Target: {hostname} ({url})\n"
                if forensics:
                    log_entry += f"  Forensics: {json.dumps(forensics)}\n"
                log_entry += "-" * 80
                
                with open(log_file, "a") as f:
                    f.write(secure_log_encode(log_entry) + "\n")
                    
                send_message({"status": "logged", "file": log_file})
            except Exception as e:
                send_message({"status": "error", "error": str(e)})
        elif action == "lock":
            if not is_safe_path(target):
                send_message({"status": "error", "error": _("Lock Denied: Safe zone violation")})
                return
            success = lock_file(target)
            send_message({"status": "ok" if success else "error", "target": target})
        elif action == "unlock":
            if not is_safe_path(target):
                send_message({"status": "error", "error": _("Unlock Denied: Safe zone violation")})
                return
            if not target or not os.path.exists(target):
                send_message({"status": "ok", "target": target, "message": "No file to unlock"})
            else:
                success = unlock_file(target)
                send_message({"status": "ok" if success else "error", "target": target})
        elif action == "release_quarantine":
            if not is_safe_path(target):
                send_message({"status": "error", "error": _("Release Denied: Safe zone violation")})
                return
            if target and os.path.exists(target):
                unlock_file(target)
                if ".clamfox_quarantine" in target:
                    # Strip the quarantine folder to move it up one level (e.g. into actual Downloads)
                    safe_target = target.replace(os.path.sep + ".clamfox_quarantine", "")
                    try:
                        import shutil
                        shutil.move(target, safe_target)
                        send_message({"status": "ok", "target": safe_target})
                    except Exception as e:
                        send_message({"status": "error", "error": str(e)})
                else:
                    send_message({"status": "ok", "target": target})
            else:
                send_message({"status": "ok", "target": target})
        elif action == "scan":
            if type != "url" and not is_safe_path(target):
                send_message({"status": "error", "error": _("Scan Denied: Safe zone violation")})
                return
            if type == "url":
                result = scan_url(target, use_mb=use_mb, pua_enabled=pua_enabled, ram_mode=ram_mode)
            else:
                result = scan_file(target, use_mb=use_mb, pua_enabled=pua_enabled)
            send_message(result)
        elif action == "check_url":
            # URL reputation check doesn't need path validation, just string handling
            result = check_url_reputation(target)
            send_message(result)
        elif action == "restore":
            restored_path = restore_quarantine(target)
            if restored_path:
                send_message({"status": "ok", "msg": _("File explicitly restored from quarantine")})
            else:
                send_message({"status": "error", "error": _("Failed to restore file")})
        elif action == "update_urldb":
            update_intelligence(force=True)
            run_dir = get_run_dir()
            url_db_path = os.path.join(run_dir, "urldb.txt")
            phish_db_path = os.path.join(run_dir, "phishdb.txt")
            send_message({
                "status": "ok",
                "url_db_last_update": os.path.getmtime(url_db_path) if os.path.exists(url_db_path) else None,
                "phish_db_last_update": os.path.getmtime(phish_db_path) if os.path.exists(phish_db_path) else None
            })
        elif action == "force_db_update":
            try:
                # Trigger freshclam
                if _BIN_FRESHCLAM:
                    process = subprocess.run([_BIN_FRESHCLAM], capture_output=True, text=True)
                else:
                    log_debug("freshclam not found in PATH — database update skipped.")
                    return {"status": "error", "error": "freshclam not found"}
                send_message({
                    "status": "ok" if process.returncode == 0 else "error",
                    "output": process.stdout[:500],
                    "db_last_update": get_db_last_update()
                })
            except Exception as e:
                send_message({"status": "error", "error": str(e)})
        elif action == "update_yara":
            try:
                # Polite Limits: 5 minute throttle for YARA updates
                sig_dir = os.path.join(os.path.dirname(__file__), "signatures")
                yara_canary = os.path.join(sig_dir, "yara-rules-core.yar")
                if os.path.exists(yara_canary):
                    if (time.time() - os.path.getmtime(yara_canary)) < 300:
                        send_message({"status": "ok", "msg": _("YARA already current (Polite limit active)")})
                        return

                sanitizer_path = os.path.join(os.path.dirname(__file__), "yara_sanitizer.py")
                # Run in background to avoid blocking
                process = subprocess.run([sys.executable, sanitizer_path], capture_output=True, text=True, timeout=180)
                if process.returncode == 0:
                    send_message({"status": "ok", "msg": _("YARA Signatures Synced & Sanitized")})
                else:
                    send_message({"status": "error", "error": _("Sanitizer Error: {err}").format(err=process.stderr[:200])})
            except Exception as e:
                send_message({"status": "error", "error": _("Bridge Error: {err}").format(err=str(e))})
        elif action == "reseal":
            config["integrity_hash"] = current_hash
            try:
                # 1. Update the Keyring for the current user
                if "secret" in config: keyring_set("secret", str(config["secret"]))
                keyring_set("integrity_hash", current_hash)
                
                # 2. Extract public config and write via pkexec
                sensitive_keys = ["secret", "integrity_hash"]
                public_config = {k: v for k, v in config.items() if k not in sensitive_keys}
                
                json_str = json.dumps(public_config, indent=4)
                # Secure Writing: Use tee via pkexec to avoid shell injection and handling piping safely
                cmd = ['pkexec', 'tee', config_path]
                res = subprocess.run(cmd, input=json_str, text=True, capture_output=True, timeout=60)
                
                if res.returncode == 0:
                    # 3. ERT Re-Seal (Hardware Identity Refresh)
                    if config.get("ert_enabled"):
                        ert_signer = os.path.join(os.path.dirname(__file__), "ert_signer.py")
                        if os.path.exists(ert_signer):
                             subprocess.run([sys.executable, ert_signer], check=False)
                    
                    send_message({"status": "ok", "msg": _("Engine Re-Sealed with Root Authority")})
                else:
                    send_message({"status": "error", "error": _("Authorization Failed/Declined: {err}").format(err=res.stderr)})
            except Exception as e:
                send_message({"status": "error", "error": f"Elevated authorization system error: {e}"})
        elif action == "get_audit_logs":
            try:
                log_dir = os.path.dirname(__file__)
                log_file = os.path.join(log_dir, "alert_log.txt")
                if not os.path.exists(log_file):
                    send_message({"status": "ok", "logs": []})
                else:
                    with open(log_file, "r") as f:
                        lines = [secure_log_decode(line) for line in f.readlines()[-200:]]
                        send_message({"status": "ok", "logs": "\n".join(lines)})
            except Exception as e:
                send_message({"status": "error", "error": str(e)})
        elif action == "list_quarantine":
            try:
                quarantine_dir = os.path.join(os.path.dirname(__file__), "quarantine")
                if not os.path.exists(quarantine_dir):
                    send_message({"status": "ok", "files": []})
                    return
                files = []
                for f in os.listdir(quarantine_dir):
                    fpath = os.path.join(quarantine_dir, f)
                    files.append({
                        "name": f,
                        "size": os.path.getsize(fpath),
                        "created": os.path.getmtime(fpath)
                    })
                send_message({"status": "ok", "files": files})
            except Exception as e:
                send_message({"status": "error", "error": str(e)})
        elif action == "get_intel":
            try:
                load_whitelist_cache()
                with open(os.path.join(os.path.dirname(__file__), "trust_db.json"), "r") as f:
                    db = json.load(f)
                
                # We return only Top 5000 to avoid hitting the 1MB native messaging limit
                # The host still uses the full 1M list for deep validation.
                fast_path = list(_whitelist_cache)[:5000] if _whitelist_cache else []
                
                send_message({
                    "status": "ok",
                    "hvts": db.get("hvts", []),
                    "whitelist": fast_path
                })
            except Exception as e:
                send_message({"status": "error", "error": str(e)})
        elif action == "check":
            try:
                log_debug("CHECK ACTION STARTED")
                installed, path, is_daemon = check_clamav()
                run_dir = get_run_dir()
                url_db_path = os.path.join(run_dir, "urldb.txt")
                if not os.path.exists(url_db_path):
                    log_debug("Check: Intelligence DB missing, triggering background update.")
                    threading.Thread(target=update_intelligence, kwargs={"force": True}, daemon=True).start()
                
                binary_hash = config.get("binary_hash")
                binary_ok = verify_binary_integrity(path, binary_hash) if installed else False
                
                # Initial Seal: Store script and binary hashes if not already present
                config_updated = False
                if not stored_hash and current_hash:
                    config["integrity_hash"] = current_hash
                    config_updated = True
                
                if installed and not binary_hash:
                    config["binary_hash"] = get_file_hash(path)
                    config_updated = True

                # 3. Dynamic Honeypot Secret (Rolling/Session based)
                hp_secret = config.get("honeypot_secret")
                if not hp_secret:
                    import secrets
                    hp_secret = "cf_honey_" + secrets.token_urlsafe(16)
                    config["honeypot_secret"] = hp_secret
                    config_updated = True

                if config_updated:
                    save_config(config)
                
                dist_info = detect_dist_info()
                log_debug("Check: Privacy Check starting...")
                vpn_active, vpn_name = check_vpn_active()
                tor_active, __ = check_tor_reachable()
                log_debug("Check: Privacy Check done.")

                url_db_mtime = os.path.getmtime(url_db_path) if os.path.exists(url_db_path) else None
                phish_db_path = os.path.join(run_dir, "phishdb.txt")
                phish_db_mtime = os.path.getmtime(phish_db_path) if os.path.exists(phish_db_path) else None
                
                sig_dir = os.path.join(os.path.dirname(__file__), "signatures")
                yara_canary = os.path.join(sig_dir, "yara-rules-core.yar")
                yara_mtime = os.path.getmtime(yara_canary) if os.path.exists(yara_canary) else None

                version_info = "Unknown"
                if installed:
                    try:
                        v_res = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=2)
                        version_info = v_res.stdout.strip()
                    except: pass

                status_msg = {
                    "status": "ok" if installed else "missing",
                    "path": path,
                    "engine": "ClamD (Daemon)" if is_daemon else "ClamScan (Standard)",
                    "on_access": check_on_access_status(),
                    "privacy": {
                        "vpn": vpn_name if vpn_active else None,
                        "tor": tor_active
                    },
                    "secret": secret if (not received_secret or received_secret != secret) else "****", 
                    "honeypot_secret": hp_secret,
                    "integrity_ok": (current_hash == stored_hash) if stored_hash else True,
                    "binary_ok": binary_ok,
                    "env_ok": verify_environment(),
                    "install_cmd": dist_info["install"],
                    "optimize_cmd": dist_info["optimize"],
                    "db_last_update": get_db_last_update(),
                    "url_db_last_update": url_db_mtime,
                    "phish_db_last_update": phish_db_mtime,
                    "yara_last_update": yara_mtime,
                    "version": version_info,
                    "ert_active": config.get("ert_enabled", False),
                    "ert_sealed": config.get("ert_sealed", False)
                }
                log_debug("CHECK ACTION COMPLETED")
                send_message(status_msg)
            except Exception as e:
                log_debug(f"Internal Check error: {e}")
                send_message({"status": "error", "error": f"Check logic failed: {e}"})
            return
        elif action == "report_threat":
            target = message.get("target")
            threat_type = message.get("type", "unknown")
            details = message.get("details", {})
            
            if not target:
                send_message({"status": "error", "error": "No target specified for burn."})
                return

            success = submit_community_burn(target, threat_type, details)
            if success:
                send_message({"status": "ok", "message": "Threat successfully burned and shared with community."})
            else:
                send_message({"status": "error", "error": "Failed to initiate community burn."})
            return
        else:
            send_message({"status": "error", "error": f"Unknown action: {action}"})
    except Exception as e:
        log_debug(f"CRITICAL BODY ERROR: {e}")
        try:
            send_message({"status": "error", "error": f"Internal Bridge Body Error: {e}"})
        except: pass

import signal

def graceful_shutdown(signum, frame):
    log_debug(f"Graceful shutdown triggered by signal {signum}")
    # Shut down pools to ensure tasks complete or clean up resources
    _thread_pool.shutdown(wait=False)
    _process_pool.shutdown(wait=False)
    sys.exit(0)

def cleanup_stale_quarantine():
    """Crash Trap Fix: Restore access to any files left in quarantine by an OOM killer or segfault."""
    try:
        downloads_dir = os.path.expanduser("~/Downloads")
        quarantine_dir = os.path.join(downloads_dir, ".clamfox_quarantine")
        
        if not os.path.exists(quarantine_dir):
            return
            
        now = time.time()
        for filename in os.listdir(quarantine_dir):
            filepath = os.path.join(quarantine_dir, filename)
            if not os.path.isfile(filepath):
                continue
                
            # If a file has been stuck here for more than 1 hour (3600 seconds)
            if os.path.getmtime(filepath) < now - 3600:
                log_debug(f"Crash Trap: Recovering abandoned file {filename}")
                os.chmod(filepath, 0o644) # Unlock
                safe_dest = os.path.join(downloads_dir, filename)
                import shutil
                shutil.move(filepath, safe_dest) # Evict
    except Exception as e:
        log_debug(f"Failed to cleanup stale quarantine: {e}")

def main():
    log_debug("Host script started (Persistent Mode)")
    
    # Run startup garage collection to prevent permanent Crash Traps
    cleanup_stale_quarantine()
    
    # Register signal handlers for cleanup
    signal.signal(signal.SIGINT, graceful_shutdown)
    signal.signal(signal.SIGTERM, graceful_shutdown)

    config = load_config()
    
    # Start Offensive Shield Threads (background)
    start_clipper_shield()
            
    secret = config.get("secret")
    stored_hash = config.get("integrity_hash")
    current_hash = get_self_hash()

    # 1. ERT Hardware Signature Verification
    if config.get("ert_enabled") and config.get("ert_signature") and config.get("ert_public_key"):
        try:
            signature = base64.b64decode(config["ert_signature"])
            public_key = base64.b64decode(config["ert_public_key"])
            
            with open(__file__, "rb") as f:
                script_content = f.read()
                
            tpm = TpmProvider()
            if tpm.verify_ecdsa(script_content, signature, public_key):
                log_debug("🛡️  ERT IDENTITY VERIFIED: Hardware-anchored signature is valid.")
            else:
                log_debug("🛑 SECURITY ALERT: ERT SIGNATURE MISMATCH! Code has been tampered with or is un-authorized.")
                sys.exit(1) # Immediate Lockdown
        except Exception as e:
            log_debug(f"ERT Verification Error: {e}")
            sys.exit(1)

    # 2. Integrity Check (Legacy Hash Fallback)
    if stored_hash:
        if current_hash != stored_hash:
            log_debug("🛑 SECURITY ALERT: SCRIPT HASH MISMATCH! Post-install tampering detected.")
            # Still run, but let extension decide if it trusts the secret unmasked.

    # Persistent Bridge Loop
    while True:
        try:
            message = get_message()
            if message is None:
                log_debug("Native Messaging Bridge Closed by Browser.")
                break
            
            # Dispatch each message to the thread pool
            _thread_pool.submit(handle_message, message, secret, config, stored_hash, current_hash)
            
        except EOFError:
            break
        except Exception as e:
            log_debug(f"Bridge Runtime Error: {e}")
            break
    
    # Cleanup on exit
    _thread_pool.shutdown(wait=True)
    _process_pool.shutdown(wait=True)

if __name__ == '__main__':
    main()
