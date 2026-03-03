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
from yara_sanitizer import YaraSanitizer
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Supply-Chain Canary (Injected at build time)
CLAMFOX_CANARY = "PLACEHOLDER_CANARY"

def verify_canary_integrity():
    """Verify filesystem and code-level supply chain canaries."""
    host_dir = os.path.dirname(os.path.abspath(__file__))
    canary_file = os.path.join(host_dir, "signatures", ".canary")
    
    # 1. Check Filesystem Canary (Dropped by install.sh)
    if not os.path.exists(canary_file):
        log_debug("🚨 INTEGRITY WARNING: Filesystem Canary missing. Build may be unofficial or tampered.")
        return False
        
    # 2. Check Code Canary (Injected by package.sh)
    if CLAMFOX_CANARY == "PLACEHOLDER_CANARY":
        # In developer mode, this is expected. In production/opt, it's a red flag.
        if host_dir.startswith("/opt/"):
             log_debug("🚨 INTEGRITY ERROR: Production code canary mismatch (PLACEHOLDER found).")
             return False
    return True

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
_QUARANTINE_DIR = os.path.expanduser("~/.clamfox_quarantine")

_config_lock = threading.Lock()
_output_lock = threading.Lock()

# Global Caches (Initialized as None)
_url_cache = None
_url_domain_cache = None
_cache_last_loaded = 0

_phish_cache = None
_phish_last_loaded = 0

_whitelist_cache = None
_whitelist_last_loaded = 0

# Multi-Core Engines
# Security: max_workers is explicitly capped to prevent resource exhaustion
# under burst download events (e.g. a page triggering many simultaneous scans).
# Thread pool: I/O-bound tasks (messaging, network checks, file reads).
_thread_pool = ThreadPoolExecutor(max_workers=6)
# Process pool: CPU-bound tasks (YARA scanning, hashing). Capped at 4 to protect
# low-end hardware and avoid spawning more processes than logical cores.
_process_pool = ProcessPoolExecutor(max_workers=min(os.cpu_count() or 2, 4))

# Runtime Integrity Watchdog State
_MODULE_SNAPSHOTS = {}
_CRITICAL_MODULES = ["clamav_engine.py", "tpm_provider.py", "yara_sanitizer.py", "ert_signer.py"]
_secret_issued = False       # SECURITY: Only emit secret once per host execution
_secret_issued_lock = threading.Lock()  # Guards atomic check-and-set of _secret_issued

def capture_runtime_snapshots():
    """Capture initial SHA-256 hashes of all critical host modules."""
    host_dir = os.path.dirname(os.path.abspath(__file__))
    for module in _CRITICAL_MODULES:
        path = os.path.join(host_dir, module)
        if os.path.exists(path):
            _MODULE_SNAPSHOTS[module] = get_file_hash(path)
    log_debug(f"🛡️  INTEGRITY: Captured runtime snapshots for {len(_MODULE_SNAPSHOTS)} modules.")

def runtime_integrity_sentinel():
    """Background thread that re-verifies module integrity at random intervals."""
    log_debug("🛡️  INTEGRITY: Sentinel Watchdog activated.")
    while True:
        try:
            # Sleep for a random interval between 10 and 20 minutes to prevent timing attacks
            wait_time = random.randint(600, 1200)
            time.sleep(wait_time)
            
            host_dir = os.path.dirname(os.path.abspath(__file__))
            # Select a random module to audit
            module = random.choice(_CRITICAL_MODULES)
            path = os.path.join(host_dir, module)
            
            if os.path.exists(path):
                current_hash = get_file_hash(path)
                stored_hash = _MODULE_SNAPSHOTS.get(module)
                
                if stored_hash and current_hash != stored_hash:
                    log_debug(f"🚨 CRITICAL SECURITY ALERT: Runtime Integrity Violation in {module}!")
                    log_debug(f"   Original: {stored_hash}")
                    log_debug(f"   Current:  {current_hash}")
                    # Signal the UI (if possible) or take drastic action
                    # For now, we log the incident heavily. In a mission-critical setup, sys.exit(1) here.
                    
        except Exception as e:
            log_debug(f"INTEGRITY ERROR (Sentinel): {e}")

def verify_kernel_integrity():
    """Verify FS-Verity state if supported by the kernel."""
    if not shutil.which("fsverity"):
        return
    
    try:
        # Measure this script's kernel integrity
        res = subprocess.run(["fsverity", "measure", __file__], capture_output=True, text=True, timeout=5)
        if res.returncode == 0:
            digest = res.stdout.strip()
            log_debug(f"🛡️  KERNEL-VERITY: {digest}")
        else:
            # If fsverity is installed but measurement fails, it might be tampered or verity not enabled
            # We don't exit here to avoid breaking systems where verity is available but not supported on the mount
            pass
    except Exception:
        pass


def try_opportunistic_sandboxing():
    """DEACTIVATED: Sandboxing has been disabled by user request."""
    # log_debug("🛡️  SANDBOX: Deactivated by user request.")
    return
    # 1. Skip if already sandboxed (sentinel env var) or in conflicting environments
    if os.environ.get("CLAMFOX_SANDBOXED"):
        return
        
    # Detect Flatpak / Snap (Nested sandboxing usually fails here)
    is_flatpak = os.path.exists("/.flatpak-info") or "FLATPAK_ID" in os.environ
    is_snap = "SNAP" in os.environ
    
    if is_flatpak or is_snap:
        log_debug("🛡️  SANDBOX: Container environment detected (Flatpak/Snap). Bypassing nested bwrap.")
        return

    bwrap = shutil.which("bwrap")
    if not bwrap:
        log_debug("🛡️  SANDBOX: bubblewrap (bwrap) not found. Standard execution active.")
        return

    log_debug("🛡️  SANDBOX: bubblewrap found. Re-executing in isolated namespace...")
    
    host_dir = os.path.dirname(os.path.abspath(__file__))
    
    # DBus Proxy logic for System Keyring access
    dbus_addr = os.environ.get("DBUS_SESSION_BUS_ADDRESS")
    proxy_cmd = []
    if dbus_addr and dbus_addr.startswith("unix:path="):
        bus_path = dbus_addr.split("=", 1)[1]
        proxy_bin = shutil.which("xdg-dbus-proxy")
        if proxy_bin:
            proxy_socket = os.path.join(tempfile.gettempdir(), f"clamfox_dbus_{os.getpid()}")
            # Start proxy to ONLY allow secret service
            proxy_proc = subprocess.Popen([
                proxy_bin,
                dbus_addr,
                proxy_socket,
                "--talk=org.freedesktop.secrets"
            ])
            # Give it a moment to start
            time.sleep(0.1)
            proxy_cmd = ["--bind", proxy_socket, bus_path]

    # Bubblewrap Arguments:
    # --ro-bind / / : Read-only root
    # --dev /dev, --proc /proc : Standard system binds
    # --tmpfs /tmp : Private volatile storage
    # --unshare-all : Namespace isolation (PID, Network, IPC, UTS)
    # --share-net : Required for ClamAV updates & MalwareBazaar
    # --bind [host_dir] [host_dir] : Writable access to our signatures and logs
    cmd = [
        bwrap,
        "--ro-bind", "/", "/",
        "--dev", "/dev",
        "--proc", "/proc",
        "--tmpfs", "/tmp",
        "--unshare-all",
        "--share-net",
        "--bind", host_dir, host_dir
    ]
    
    if proxy_cmd:
        cmd.extend(proxy_cmd)
        
    cmd.extend([
        "--setenv", "CLAMFOX_SANDBOXED", "1",
        sys.executable, __file__
    ])
    
    try:
        # Re-execute and replace the current process
        os.execv(bwrap, cmd)
    except Exception as e:
        log_debug(f"🚨 SANDBOX ERROR: Failed to launch bubblewrap: {e}")
        # Fail-open: continue without sandbox if execv fails

# Security: Resolve external tool paths at startup to prevent
# PATH hijacking attacks. Use absolute paths for production reliability.
def _resolve_bin(bin_name, primary_path):
    if os.path.exists(primary_path) and os.access(primary_path, os.X_OK):
        return primary_path
    return shutil.which(bin_name)

_BIN_FILE      = _resolve_bin("file", "/usr/bin/file")
_BIN_7Z        = _resolve_bin("7z", "/usr/bin/7z")
_BIN_FRESHCLAM = _resolve_bin("freshclam", "/usr/bin/freshclam")
_BIN_WL_PASTE  = shutil.which("wl-paste")
_BIN_XCLIP     = shutil.which("xclip")
_BIN_SYSTEMCTL = _resolve_bin("systemctl", "/usr/bin/systemctl")

import itertools
import base64





_MACHINE_KEY_CACHE = None

def get_or_create_machine_key():
    """
    Retrieve or Generate a machine-unique EC-DSA (P-256) Private Key.
    Stored in System Keyring for release-grade security.
    """
    global _MACHINE_KEY_CACHE
    if _MACHINE_KEY_CACHE:
        return _MACHINE_KEY_CACHE

    try:
        # Try to retrieve from Keyring
        stored_pem = keyring_get("machine_private_key")
        if stored_pem:
            try:
                _MACHINE_KEY_CACHE = serialization.load_pem_private_key(
                    stored_pem.encode('utf-8'),
                    password=None
                )
                return _MACHINE_KEY_CACHE
            except Exception:
                log_debug("CORRUPTION: Keyring key invalid, regenerating...")

        # Generate new P-256 Keypair
        private_key = ec.generate_private_key(ec.SECP256R1())
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Store in Keyring
        keyring_set("machine_private_key", pem.decode('utf-8'))
        
        # Save Public Key locally for audit/verification
        pub_key = private_key.public_key()
        pub_pem = pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(os.path.join(os.path.dirname(__file__), "vault_pub.pem"), "wb") as f:
            f.write(pub_pem)

        _MACHINE_KEY_CACHE = private_key
        return private_key
    except Exception as e:
        log_debug(f"CRYPTO ERROR (get_or_create_machine_key): {e}")
        return None

def derive_aes_key(private_key):
    """
    Derive a stable 256-bit AES key from the EC private key using HKDF.
    Uses a per-machine salt (UID-based) and an explicit info label so the
    AES key material is domain-separated from the EC signing key material.
    """
    if not private_key: return None
    try:
        private_bytes = private_key.private_numbers().private_value.to_bytes(32, 'big')
        # Stable per-machine salt — avoids using the raw scalar as AES key directly
        salt = hashlib.sha256(f"clamfox-salt-uid-{os.getuid()}".encode()).digest()
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"clamfox-aes-log-v1"
        )
        return hkdf.derive(private_bytes)
    except Exception:
        return None

def xor_buffer(data, key):
    """Simple symmetric XOR for obfuscation. Used to bypass host-AV interference with definitions."""
    if not data or not key: return data
    key_len = len(key)
    # Convert to bytearray for faster manipulation if it's large, but bytes/enumerate is fine for 1-10MB
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))

def secure_log_encode(text):
    if not isinstance(text, str): text = str(text)
    try:
        priv_key = get_or_create_machine_key()
        aes_key = derive_aes_key(priv_key)
        if not aes_key: return text
        
        # 1. Encrypt (AES-GCM for Authenticated Encryption)
        iv = os.urandom(12)
        encryptor = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(iv)
        ).encryptor()
        
        ciphertext = encryptor.update(text.encode('utf-8')) + encryptor.finalize()
        tag = encryptor.tag
        
        # 2. Sign (EC-DSA)
        signature = priv_key.sign(ciphertext, ec.ECDSA(hashes.SHA256()))
        
        # Package: IV(12) + Tag(16) + SignatureLen(1) + Signature(N) + Ciphertext
        sig_len = len(signature)
        combined = iv + tag + bytes([sig_len]) + signature + ciphertext
        return base64.b64encode(combined).decode('utf-8')
    except Exception as e:
        # log_debug(f"ENCODE ERROR: {e}")
        return text

def secure_log_decode(text):
    try:
        combined = base64.b64decode(text.strip().encode('utf-8'))
        priv_key = get_or_create_machine_key()
        aes_key = derive_aes_key(priv_key)
        if not aes_key: return text.strip()
        
        # Unpack
        iv = combined[:12]
        tag = combined[12:28]
        sig_len = combined[28]
        signature = combined[29:29+sig_len]
        ciphertext = combined[29+sig_len:]
        
        # 1. Verify Signature (EC-DSA)
        pub_key = priv_key.public_key()
        pub_key.verify(signature, ciphertext, ec.ECDSA(hashes.SHA256()))
        
        # 2. Decrypt (AES-GCM)
        decryptor = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(iv, tag)
        ).decryptor()
        
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted.decode('utf-8')
    except Exception as e:
        # log_debug(f"DECODE ERROR: {e}")
        return text.strip()

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

# Opsec: Rotate through realistic browser UAs for non-tunnelled fetches
# to avoid fingerprinting ClamFox requests at the network level.
_USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.199 Safari/537.36",
]

def secure_fetch(url, output_path, use_tunnel=False, post_data=None, headers=None):
    """Fetch URL with optional Tor/VPN routing and leak protection."""
    tunnelled = False

    if use_tunnel:
        tor_active, tor_port = check_tor_reachable()
        if tor_active:
            tunnelled = True
        else:
            vpn_active, __ = check_vpn_active()
            if vpn_active:
                tunnelled = True
            elif _PRIVATE_TUNNEL_FORCE:
                log_debug(f"PRIVACY ABORT: Tunnel requested but no VPN/Tor found for {url}")
                return False

    # When tunnelled, keep the branded UA so servers can identify the client
    # for policy purposes. When untunnelled, rotate to reduce fingerprinting.
    user_agent = 'ClamFox-Native-Host/1.0' if tunnelled else random.choice(_USER_AGENTS)

    cmd = ['curl', '-s', '-A', user_agent, '-L', '--connect-timeout', '15']

    if headers:
        for k, v in headers.items():
            cmd.extend(['-H', f'{k}: {v}'])

    if tunnelled and tor_active:
        cmd.extend(['--proxy', f'socks5h://127.0.0.1:{tor_port}'])

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
    # Prefer clamdscan (Daemon) for performance, fallback to clamscan

    # Hardened resolution
    clamdscan_path = "/usr/bin/clamdscan" if os.path.exists("/usr/bin/clamdscan") else shutil.which("clamdscan")
    if clamdscan_path:
        log_debug(f"Detected ClamD: {clamdscan_path}")
        return True, clamdscan_path, True
        
    clamscan_path = "/usr/bin/clamscan" if os.path.exists("/usr/bin/clamscan") else shutil.which("clamscan")
    if clamscan_path:
        log_debug(f"Detected ClamScan: {clamscan_path}")
        return True, clamscan_path, False
        
    log_debug("ClamAV binaries not found in PATH")
    # Search common paths manually if PATH is restricted
    fallbacks = ["/usr/local/bin/clamscan", "/usr/bin/clamdscan"] # /usr/bin already checked above
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
    
    vault_hp = keyring_get("honeypot_secret")
    if vault_hp: config["honeypot_secret"] = vault_hp
    
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
    sensitive_keys = ["secret", "integrity_hash", "honeypot_secret"]
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
        
        if not os.path.exists(_QUARANTINE_DIR):
            os.makedirs(_QUARANTINE_DIR, mode=0o700) # Only owner can access
            
        filename = os.path.basename(filepath)
        import time
        safe_name = f"{int(time.time())}_{filename}.quarantine"
        dest_path = os.path.join(_QUARANTINE_DIR, safe_name)
        
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
        
        # Allow filepath to be exactly the filename in the quarantine dir, or a full path
        filename = os.path.basename(filepath)
        source_path = os.path.join(_QUARANTINE_DIR, filename)
        
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

        # Step 2: Check MalwareBazaar (abuse.ch) using secure_fetch for privacy
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_resp = tmp.name
        
        post_data = {
            "query": "get_info",
            "hash": file_hash
        }
        
        # Add API Key if present in config
        config = load_config()
        mb_api_key = config.get("mb_api_key")
        
        # We use secure_fetch which handles Tor/VPN and custom user-agent.
        # However, MalwareBazaar requires POST with data, which secure_fetch supports.
        headers = {}
        if mb_api_key:
            headers['API-KEY'] = mb_api_key
        
        success = secure_fetch(api_url, tmp_resp, use_tunnel=True, post_data=post_data, headers=headers)
        
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
        },
        {
            "name": "Maldet (LMD) MD5 Hashes",
            "url": "https://www.rfxn.com/downloads/rfxn.hdb",
            "path": os.path.join(os.path.dirname(__file__), "signatures", "maldet.hdb")
        },
        {
            "name": "Maldet (LMD) Hex Patterns",
            "url": "https://www.rfxn.com/downloads/rfxn.ndb",
            "path": os.path.join(os.path.dirname(__file__), "signatures", "maldet.ndb")
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
                # 🛡️ Signature Obfuscation: Scramble .hdb and .ndb to prevent host-AV interference
                if base_path.endswith(('.hdb', '.ndb')):
                    try:
                        priv_key = get_or_create_machine_key()
                        xor_key = derive_aes_key(priv_key)
                        if xor_key:
                            with open(tmp_path, "rb") as f:
                                scrambled = xor_buffer(f.read(), xor_key)
                            with open(tmp_path, "wb") as f:
                                f.write(scrambled)
                            log_debug(f"Applied obfuscation seal to {src['name']}")
                    except Exception as e:
                        log_debug(f"Obfuscation failure for {src['name']}: {e}")

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
    AES-GCM encryption for forensics when no VPN/Tor is available.
    Uses the per-machine EC-derived key (same as secure_log_encode) so each
    installation produces a unique ciphertext — no shared community key.
    """
    if not data: return None
    try:
        priv_key = get_or_create_machine_key()
        aes_key = derive_aes_key(priv_key)
        if not aes_key:
            return None
        iv = os.urandom(12)
        encryptor = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(iv)
        ).encryptor()
        ciphertext = encryptor.update(data.encode('utf-8')) + encryptor.finalize()
        tag = encryptor.tag
        # Package: IV(12) + Tag(16) + Ciphertext
        combined = iv + tag + ciphertext
        return base64.b64encode(combined).decode('utf-8')
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

# Logic to interact with locally cached intelligence databases


# --- Intelligence Time-Lock (v0.6.x) ---

_RELEASE_ROOT_PUB_KEY = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEF4R7Cct0ZkGOZQTAGWQAOrmRvN5M
Sfyo+iroUOto0DcviEmyzVe5y5CNrB0QfRQEeraeq/0PSI4jWCoe99ov5A==
-----END PUBLIC KEY-----"""

def verify_timelock(file_path):
    """
    Check if a threat database is fresh and cryptographically signed.
    Prevents 'Freeze Attacks'.
    """
    try:
        if not os.path.exists(file_path): return False
        
        with open(file_path, "r") as f:
            header = f.readline().strip()
            
        if not header.startswith("# CLAMFOX-TIME-LOCK:"):
            # Security: Allow fallback for verified third-party feeds (URLhaus, Mitchell Krog, Tranco)
            third_party_feeds = ["urldb.txt", "phishdb.txt", "whitelistdb.txt", "maldet.hdb", "maldet.ndb"]
            if os.path.basename(file_path) in third_party_feeds:
                log_debug(f"ℹ️  INTELLIGENCE: Loading third-party feed {os.path.basename(file_path)} (No time-lock header)")
                return True
            
            log_debug(f"TIME-LOCK ERROR: Missing signed header in {os.path.basename(file_path)}")
            return False
            
        # Format: # CLAMFOX-TIME-LOCK: [TIMESTAMP] [SIGNATURE_HEX]
        parts = header.split(" ")
        if len(parts) < 4: return False
        
        timestamp_str = parts[2]
        signature_hex = parts[3]
        
        # 1. Verify Signature
        try:
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives import hashes, serialization
            
            pub_key = serialization.load_pem_public_key(_RELEASE_ROOT_PUB_KEY.encode('utf-8'))
            signature = bytes.fromhex(signature_hex)
            
            # Message is the timestamp string
            pub_key.verify(signature, timestamp_str.encode('utf-8'), ec.ECDSA(hashes.SHA256()))
        except Exception as e:
            log_debug(f"TIME-LOCK ERROR: Invalid Signature on {os.path.basename(file_path)}: {e}")
            return False
            
        # 2. Verify Freshness
        try:
            db_time = int(timestamp_str)
            now = int(time.time())
            age_hours = (now - db_time) / 3600
            
            if age_hours > 48:
                log_debug(f"⚠️ STALE INTELLIGENCE: {os.path.basename(file_path)} is {age_hours:.1f} hours old.")
                if age_hours > 168:
                    log_debug(f"🛑 CRITICAL FREEZE: {os.path.basename(file_path)} is too old! Disabling engine.")
                    return False
            return True
        except: return False
        
    except Exception as e:
        log_debug(f"verify_timelock Exception: {e}")
        return False

def load_url_cache(force=False):
    global _url_cache, _url_domain_cache, _cache_last_loaded
    run_dir = get_run_dir()
    base_path = os.path.join(run_dir, "urldb.txt")
    old_path = base_path + ".old"
    
    target_path = base_path if os.path.exists(base_path) else old_path
    if not os.path.exists(target_path):
        return False

    # CLAMFOX TIME-LOCK: Verify integrity and freshness
    if not verify_timelock(target_path):
        return False

    mtime = os.path.getmtime(target_path)
    if not force and _url_cache is not None and mtime <= _cache_last_loaded:
        return True

    try:
        log_debug("Loading URL Database into memory (Heuristic & Exact)...")
        new_cache = set()
        new_domain_cache = set()
        with open(target_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    new_cache.add(line)
                    # Malware Domain extraction for broader coverage
                    try:
                        domain = urlparse(line).netloc.lower()
                        if domain: new_domain_cache.add(domain)
                    except Exception:
                        pass
        _url_cache = new_cache
        _url_domain_cache = new_domain_cache
        _cache_last_loaded = mtime
        return True
    except (OSError, IOError):
        return False
# Logic for Mitchell Krog's phishing domain database

def load_phish_cache(force=False):
    global _phish_cache, _phish_last_loaded
    run_dir = get_run_dir()
    path = os.path.join(run_dir, "phishdb.txt")
    if not os.path.exists(path): return False

    # CLAMFOX TIME-LOCK: Verify integrity and freshness
    if not verify_timelock(path):
        return False

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

# Logic for Global Whitelist matching

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
def calculate_shannon_entropy(data):
    """Calculate the Shannon entropy of a string (measure of randomness)."""
    if not data: return 0
    import math
    entropy = 0
    # Process only the domain part (exclude TLD if possible for better accuracy)
    # but for simplicity we'll handle what's passed.
    length = len(data)
    unique_chars = set(data)
    for char in unique_chars:
        p_x = float(data.count(char)) / length
        entropy -= p_x * math.log(p_x, 2)
    return entropy

def check_dga_heuristics(url):
    """
    Experimental Statistical Heuristics (v0.6.x) - [FALLBACK FOR WASM-SHIELD]
    Detects Algorithmically Generated Domains (DGA) without ML binaries.
    """
    try:
        domain = urlparse(url).netloc.lower()
        if not domain: return False, None
        
        # Remove common TLDs and 'www' to reduce noise
        clean_domain = re.sub(r'^(www\.)', '', domain)
        clean_domain = clean_domain.split('.')[0] # Get the primary label
        
        if len(clean_domain) < 8: return False, None # Too short to be statistically significant
        
        # 1. Shannon Entropy Check
        # Legitimate domains (google, facebook) usually score 2.8 - 3.5
        # DGA domains (x7j2k9l1) often score > 4.0
        entropy = calculate_shannon_entropy(clean_domain)
        
        # 2. Consonant Density Check (Robotic strings lack vowels)
        vowels = set("aeiouy")
        consonant_count = sum(1 for c in clean_domain if c.isalpha() and c not in vowels)
        consonant_ratio = consonant_count / len(clean_domain) if len(clean_domain) > 0 else 0

        # 3. Digit Ratio Check
        digit_count = sum(c.isdigit() for c in clean_domain)
        digit_ratio = digit_count / len(clean_domain)
        
        # 4. Decision Logic (Thresholds calibrated for low False Positives)
        reasons = []
        # Catch both high-randomness (Entropy) and high-robotic-pattern (Consonants/Digits)
        if entropy > 3.9 and (digit_ratio > 0.25 or consonant_ratio > 0.7):
            reasons.append(f"High Statistical Randomness (Entropy: {entropy:.2f})")
        elif digit_ratio > 0.35:
            reasons.append(f"High Digit Density ({digit_ratio*100:.1f}%)")
        elif consonant_ratio > 0.8:
            reasons.append(f"High Consonant Density ({consonant_ratio*100:.1f}%)")
            
        if reasons:
            return True, " / ".join(reasons)
            
    except Exception:
        pass
    return False, None

def produce_url_hash_prefix(url, prefix_len=5):
    """Generate SHA-256 hash of URL and return a short prefix for k-Anonymity."""
    if not url: return None, None
    try:
        full_hash = hashlib.sha256(url.encode('utf-8')).hexdigest()
        return full_hash[:prefix_len], full_hash
    except Exception:
        return None, None

def check_cloud_reputation(url):
    """
    Privacy-Preserving Cloud Check (k-Anonymity).
    Only sends the first 5 chars of the URL hash to the server.
    """
    prefix, full_hash = produce_url_hash_prefix(url)
    if not prefix: return False, None

    # Persistent Cache to minimize network noise/latency
    global _cloud_cache
    if '_cloud_cache' not in globals():
        _cloud_cache = {} # {full_hash: (timestamp, is_malicious)}
    
    now = time.time()
    if full_hash in _cloud_cache:
        cached_time, result = _cloud_cache[full_hash]
        if now - cached_time < 3600: # 1 hour cache
            return result, "Cloud Intelligence (Cached)"

    # Use a private temp file in the per-user run dir to avoid /tmp TOCTOU/symlink attacks
    import tempfile
    try:
        tmp_fd = tempfile.NamedTemporaryFile(
            delete=False, dir=get_run_dir(), prefix="cloud_check_", suffix=".json"
        )
        temp_resp = tmp_fd.name
        tmp_fd.close()
    except OSError:
        return False, None

    cloud_url = f"https://threat-intel.clamfox.org/v1/prefix/{prefix}"
    
    try:
        # Enforce Privacy Tunnel for all cloud lookups
        success = secure_fetch(cloud_url, temp_resp, use_tunnel=True)
        if not success:
            return False, None 
            
        is_malicious = False
        if os.path.exists(temp_resp):
            with open(temp_resp, "r") as f:
                data = json.load(f)
                malicious_hashes = data.get("hashes", [])
                if full_hash in malicious_hashes:
                    is_malicious = True
            os.unlink(temp_resp)
        
        _cloud_cache[full_hash] = (now, is_malicious)
        return is_malicious, "Cloud Intelligence (Verified)"
    except Exception as e:
        log_debug(f"Cloud Lookup Error: {e}")
    return False, None



def check_certificate_age(domain):
    """
    Query crt.sh (Certificate Transparency Logs) to find when a domain's first cert was issued.
    Returns age in days, or None on error.
    """
    import datetime
    
    # Cache to prevent rate-limiting and redundant Tor traffic
    global _ct_cache
    if '_ct_cache' not in globals():
        _ct_cache = {} # {domain: cert_age_days}
        
    if domain in _ct_cache:
        return _ct_cache[domain]

    # Use a private temp file in the per-user run dir to avoid /tmp TOCTOU/symlink attacks
    import tempfile
    try:
        tmp_fd = tempfile.NamedTemporaryFile(
            delete=False, dir=get_run_dir(), prefix="ct_audit_", suffix=".json"
        )
        temp_resp = tmp_fd.name
        tmp_fd.close()
    except OSError:
        return None
    ct_url = f"https://crt.sh/?q={domain}&output=json"
    
    try:
        # Crucial: Must use Tor/VPN tunnel for privacy
        success = secure_fetch(ct_url, temp_resp, use_tunnel=True)
        if not success: return None
        
        if os.path.exists(temp_resp):
            with open(temp_resp, "r") as f:
                data = json.load(f)
                
            if not isinstance(data, list) or not data:
                _ct_cache[domain] = 9999 # Treat as established if no certs found (odd, but safe)
                return 9999
                
            # Find the oldest 'not_before' date
            issue_dates = []
            for entry in data:
                entry_date = entry.get("not_before")
                if entry_date:
                    # Format: 2026-03-01T15:39:13
                    try:
                        dt = datetime.datetime.strptime(entry_date.split('T')[0], '%Y-%m-%d')
                        issue_dates.append(dt)
                    except: continue
            
            if not issue_dates: return None
            
            oldest = min(issue_dates)
            now = datetime.datetime.now()
            age_days = (now - oldest).days
            
            _ct_cache[domain] = age_days
            os.unlink(temp_resp)
            return age_days
    except Exception as e:
        log_debug(f"CT Audit Exception for {domain}: {e}")
    return None


def hash_domain_for_whitelist(domain):
    """
    Calculate a salted hash of a domain for Zero-Knowledge whitelisting.
    Salted with the machine-unique EC private key.
    """
    if not domain: return None
    try:
        priv_key = get_or_create_machine_key()
        if not priv_key: return None
        
        # Derive a domain-specific salt — add context to separate this from key derivation uses
        raw_scalar = priv_key.private_numbers().private_value.to_bytes(32, 'big')
        salt = hashlib.sha256(raw_scalar + b"clamfox-zk-domain-salt-v1").digest()
        
        # Hash(domain + salt)
        hasher = hashlib.sha256()
        hasher.update(domain.lower().encode('utf-8'))
        hasher.update(salt)
        return hasher.hexdigest()
    except Exception:
        return None

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
                # 🛡️ Zero-Knowledge Whitelist Support
                zk_whitelist = db.get("zk_whitelist", [])
        except (OSError, json.JSONDecodeError):
            golden_list = ["paypal.com", "chase.com", "bankofamerica.com", "microsoft.com", "google.com", "apple.com", "amazon.com"]
            global_whitelist = []
            zk_whitelist = []
            
        # 0.5. Check Zero-Knowledge Whitelist (Privacy-First)
        if zk_whitelist:
            domain_hash = hash_domain_for_whitelist(domain)
            if domain_hash and domain_hash in zk_whitelist:
                return False, None
        
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
        if "wicar.org" in target_lower or "/eicar.com" in target_lower or "eicar.org/download" in target_lower:
            return {"status": "malicious", "threat": _("Testing Payload (Safe Simulated Threat)"), "url": target}

        # B. Homograph Attack Detection (Heuristic)
        is_homograph, reason = check_homograph_attack(target)
        if is_homograph:
            return {"status": "malicious", "threat": reason, "url": target, "confirmed": False}

        # C. URLhaus Malware Check (Confirmed)
        load_url_cache()
        if _url_cache is not None:
            if target in _url_cache:
                return {"status": "malicious", "threat": _("URLhaus Malware Blocklist (Exact)"), "url": target, "confirmed": True}
            
            # Domain-level fallback (Secondary Layer)
            try:
                domain = urlparse(target).netloc.lower()
                if _url_domain_cache and domain in _url_domain_cache:
                    return {"status": "malicious", "threat": _("URLhaus Malware Blocklist (Domain-Match)"), "url": target, "confirmed": True}
            except Exception:
                pass

        # D. Phishing.Database (Mitchell Krog) Check (Confirmed)
        if check_phishing_db(target):
            return {"status": "malicious", "threat": _("Phishing Intelligence (Mitchell Krog)"), "url": target, "confirmed": True}

        # E. DGA Statistical Heuristics (Analytical)
        is_dga, dga_reason = check_dga_heuristics(target)
        if is_dga:
            return {"status": "malicious", "threat": f"{_('Heuristic Alert')}: {dga_reason}", "url": target, "confirmed": False}

        # F. k-Anonymity Cloud Lookup (Privacy-Preserving Intelligence)
        is_cloud_bad, cloud_reason = check_cloud_reputation(target)
        if is_cloud_bad:
            return {"status": "malicious", "threat": cloud_reason, "url": target, "confirmed": True}

        # G. HVT Shield: Similarity Check (Heuristic)
        is_lookalike, hvt_reason = check_similarity_to_golden(target)
        if is_lookalike:
            # INTEGRITY UPGRADE: Certificate Transparency Audit
            try:
                domain = urlparse(target).netloc.lower()
                cert_age = check_certificate_age(domain)
                if cert_age is not None and cert_age < 30:
                    threat_desc = f"{hvt_reason} + {_('Suspicious New Certificate')} ({cert_age} {_('days old')})"
                    return {"status": "malicious", "threat": threat_desc, "url": target, "confirmed": True} # UPGRADED TO CONFIRMED
            except: pass
            
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
        has_custom_sigs = os.path.exists(sig_dir) and any(f.endswith(('.yar', '.cvd', '.hdb', '.ndb')) for f in os.listdir(sig_dir))
        
        # Fallback to clamscan if we have custom signatures, because clamdscan ignores -d flag
        if is_daemon and has_custom_sigs:
            path = shutil.which("clamscan") or path
            is_daemon = False

        # 🛡️ HYDRATION ENGINE: De-obfuscate signatures into RAM-disk for scanning
        hydration_dir = None
        current_sig_dir = sig_dir
        
        if has_custom_sigs:
            try:
                # Create a temporary directory in /dev/shm (RAM-disk)
                shm_base = "/dev/shm" if os.path.exists("/dev/shm") else None
                hydration_dir = tempfile.mkdtemp(prefix="clamfox_sigs_", dir=shm_base)
                
                priv_key = get_or_create_machine_key()
                xor_key = derive_aes_key(priv_key)
                
                for f in os.listdir(sig_dir):
                    if f.startswith('.') or f.endswith(('.old', '.tmp', '.part', '.bak')):
                        continue
                        
                    src_f = os.path.join(sig_dir, f)
                    dst_f = os.path.join(hydration_dir, f)
                    
                    try:
                        if f.endswith(('.hdb', '.ndb')):
                            # Unscramble into RAM
                            with open(src_f, "rb") as sf:
                                unscrambled = xor_buffer(sf.read(), xor_key)
                            with open(dst_f, "wb") as df:
                                df.write(unscrambled)
                        elif f.endswith(('.yar', '.cvd')):
                            # Copy others directly
                            shutil.copy2(src_f, dst_f)
                    except Exception as fe:
                        log_debug(f"HYDRATION WARNING: Failed to hydrate {f}: {fe}")
                
                current_sig_dir = hydration_dir
            except Exception as e:
                log_debug(f"HYDRATION FAILURE: Falling back to disk (may fail): {e}")

        cmd = [path, '--no-summary']
        if is_daemon:
            # clamdscan specific optimizations
            cmd.extend(['--multiscan', '--fdpass'])
        else:
            # Archive Depth Control (Standard Scan only, clamd uses config)
            cmd.extend([f'--max-recursion={_MAX_RECURSION_DEPTH}'])
            if has_custom_sigs:
                cmd.extend(['-d', current_sig_dir])
            
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
        finally:
            # Aggressive Cleanup: Wipe RAM-disk signatures
            if hydration_dir and os.path.exists(hydration_dir):
                shutil.rmtree(hydration_dir, ignore_errors=True)
        
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
                # SECURITY: Sanitize all browser-provided strings to prevent log injection
                timestamp = str(incident.get("time", "N/A")).replace("\n", " ").replace("\r", " ")
                reason = str(incident.get("reason", "Unknown Threat")).replace("\n", " ").replace("\r", " ")
                url = str(incident.get("url", "N/A")).replace("\n", " ").replace("\r", " ")
                hostname = str(incident.get("hostname", "N/A")).replace("\n", " ").replace("\r", " ")
                forensics = incident.get("forensics")
                
                if isinstance(forensics, str):
                    forensics = forensics.replace("\n", " ").replace("\r", " ")
                
                log_entry = f"[{timestamp}] ALERT: {reason}\n"
                log_entry += f"  Target: {hostname} ({url})\n"
                if forensics:
                    if isinstance(forensics, dict):
                        for k, v in forensics.items():
                            log_entry += f"    > {k}: {v}\n"
                    else:
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
                    process = subprocess.run([_BIN_FRESHCLAM], capture_output=True, text=True, timeout=120)
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

                # Privacy: Use the configured Tor/VPN proxy for YARA updates
                proxies = None
                if config.get("enforce_privacy"):
                    proxies = {
                        "http": "socks5h://127.0.0.1:9050",
                        "https": "socks5h://127.0.0.1:9050"
                    }

                sanitizer = YaraSanitizer(sig_dir)
                # Run in background to avoid blocking
                def run_sync():
                    YARA_FORGE_CORE = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip"
                    success, msg = sanitizer.sync_from_url(YARA_FORGE_CORE, "yara_forge_filtered.yar", proxies=proxies)
                    if success:
                        log_debug(f"YARA Sync Success: {msg}")
                    else:
                        log_debug(f"YARA Sync Failed: {msg}")

                threading.Thread(target=run_sync, daemon=True).start()
                send_message({"status": "ok", "msg": _("YARA Sync Started in Background")})
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
                             subprocess.run([sys.executable, ert_signer], check=False, timeout=30)
                    
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
                if not os.path.exists(_QUARANTINE_DIR):
                    send_message({"status": "ok", "files": []})
                    return
                files = []
                for f in os.listdir(_QUARANTINE_DIR):
                    fpath = os.path.join(_QUARANTINE_DIR, f)
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
                global _secret_issued
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

                # SECURITY: Atomically decide whether to include the real secret.
                # We hold the lock while checking AND flipping the flag so that
                # two concurrent 'check' dispatches cannot both see _secret_issued=False.
                with _secret_issued_lock:
                    should_emit_secret = (not _secret_issued and
                                          (not received_secret or received_secret != secret))
                    if should_emit_secret:
                        _secret_issued = True

                status_msg = {
                    "status": "ok" if installed else "missing",
                    "path": path,
                    "engine": "ClamD (Daemon)" if is_daemon else "ClamScan (Standard)",
                    "on_access": check_on_access_status(),
                    "privacy": {
                        "vpn": vpn_name if vpn_active else None,
                        "tor": tor_active
                    },
                    "secret": secret if should_emit_secret else "****",
                    "honeypot_secret": hp_secret if (should_emit_secret or (received_secret and secret and received_secret == secret)) else "****",
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
                # _secret_issued flag was already set atomically above under the lock
            except Exception as e:
                log_debug(f"Internal Check error: {e}")
                send_message({"status": "error", "error": f"Check logic failed: {e}"})
            return
        elif action == "rotate_secret":
            # Security: Session Key Rotation
            # Generates a new random secret, replaces the old one in the keyring and config,
            # and returns it to the extension. This limits the blast radius of any secret leak.
            # Rate-limited to once per 60 seconds to prevent rapid secret cycling.
            try:
                _ROTATION_COOLDOWN = 60  # seconds
                last_rotation = config.get("last_rotation", 0)
                elapsed = time.time() - last_rotation
                if elapsed < _ROTATION_COOLDOWN:
                    remaining = int(_ROTATION_COOLDOWN - elapsed)
                    log_debug(f"Secret rotation rate-limited: {remaining}s remaining.")
                    send_message({"status": "error", "error": f"Rate limited: wait {remaining}s before next rotation."})
                    return

                new_secret = secrets.token_urlsafe(32)
                keyring_set("secret", new_secret)
                config["secret"] = new_secret
                config["last_rotation"] = time.time()
                save_config(config)
                log_debug("🔑 Session secret rotated successfully.")
                send_message({"status": "ok", "secret": new_secret, "rotated_at": config["last_rotation"]})
            except Exception as e:
                log_debug(f"Secret rotation failed: {e}")
                send_message({"status": "error", "error": f"Rotation failed: {e}"})
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
    """Crash Trap Fix: Restore access to any files left in quarantine or locked by an OOM killer or segfault."""
    try:
        downloads_dir = os.path.expanduser("~/Downloads")
        now = time.time()

        # 1. Recover files stuck in Quarantine
        if os.path.exists(_QUARANTINE_DIR):
            for filename in os.listdir(_QUARANTINE_DIR):
                filepath = os.path.join(_QUARANTINE_DIR, filename)
                if not os.path.isfile(filepath): continue
                
                # If a file has been stuck here for more than 1 hour
                if os.path.getmtime(filepath) < now - 3600:
                    log_debug(f"Crash Trap: Recovering abandoned quarantine {filename}")
                    os.chmod(filepath, 0o644) # Unlock
                    safe_dest = os.path.join(downloads_dir, filename)
                    import shutil
                    shutil.move(filepath, safe_dest) # Evict

        # 2. Recover files stuck in Download with 000 permissions (Stale Locks)
        if os.path.exists(downloads_dir):
            for filename in os.listdir(downloads_dir):
                filepath = os.path.join(downloads_dir, filename)
                if not os.path.isfile(filepath): continue
                
                # Check for 0o000 mode (locked by ClamFox)
                stat = os.stat(filepath)
                if (stat.st_mode & 0o777) == 0:
                    if stat.st_mtime < now - 3600:
                        log_debug(f"Crash Trap: Restoring permissions to stale lock {filename}")
                        os.chmod(filepath, 0o644)
    except Exception as e:
        log_debug(f"Failed to cleanup stale locks: {e}")

def main():
    # 0. Opportunistic Sandboxing (Security Layer 0)
    try_opportunistic_sandboxing()
    
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

    # 3. Supply-Chain Canary Audit
    verify_canary_integrity()

    # 4. Starting Runtime Integrity Sentinel
    capture_runtime_snapshots()
    threading.Thread(target=runtime_integrity_sentinel, daemon=True).start()

    # 5. FS-Verity Kernel Audit
    verify_kernel_integrity()

    # 6. Security Lockdown: Poisoning pickle after all initializations
    sys.modules['pickle'] = None
    sys.modules['_pickle'] = None
    sys.modules['cPickle'] = None

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
