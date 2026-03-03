#!/usr/bin/env python3
import subprocess
import os
import hashlib
import json
import base64
import time
import sys


def _tpm_log(msg):
    """Write TPM operation details to the standard ClamFox log file (encrypted at-rest by the engine)."""
    log_path = os.path.expanduser("~/.clamfox_host.log")
    try:
        import datetime
        with open(log_path, "a") as f:
            f.write(f"[TPM {datetime.datetime.now().isoformat()}] {msg}\n")
    except OSError:
        pass

class TpmProvider:
    """Provides TPM 2.0 hardware-anchored security operations for ClamFox."""
    
    def __init__(self):
        self.tpm_present = self._check_tpm()
        # Use a persistent runtime dir for context files
        uid = os.getuid()
        self.run_dir = f"/run/user/{uid}/clamfox"
        if not os.path.exists(self.run_dir):
            try: os.makedirs(self.run_dir, mode=0o700, exist_ok=True)
            except: self.run_dir = f"/tmp/clamfox_{uid}"
            
        self.primary_ctx = os.path.join(self.run_dir, "clamfox_primary.ctx")
        self.key_pub = os.path.join(self.run_dir, "clamfox_key.pub")
        self.key_priv = os.path.join(self.run_dir, "clamfox_key.priv")
        self.key_ctx = os.path.join(self.run_dir, "clamfox_key.ctx")

    def _check_tpm(self):
        """Check if TPM 2.0 is available and tools are installed."""
        try:
            res = subprocess.run(["tpm2_getcap", "properties-fixed"], capture_output=True, timeout=2)
            return res.returncode == 0
        except:
            return False

    def _run(self, cmd, input_data=None):
        """Helper to run tpm2-tools commands."""
        try:
            res = subprocess.run(cmd, input=input_data, capture_output=True, timeout=10)
            return res.returncode == 0, res.stdout, res.stderr
        except Exception as e:
            return False, b"", str(e).encode()

    def create_primary(self):
        """Create a Primary Storage Key in the Owner hierarchy."""
        if not self.tpm_present: return False
        cmd = ["tpm2_createprimary", "-C", "o", "-g", "sha256", "-G", "ecc", "-c", self.primary_ctx]
        success, _, _ = self._run(cmd)
        return success

    def seal_secret(self, secret_bytes, pcr_list="sha256:0,1,7"):
        """Seal a secret to specific PCR values."""
        if not self.tpm_present: return False, None, None
        
        # 1. Create sealed object bound to PCRs
        cmd = ["tpm2_create", "-C", self.primary_ctx, "-u", self.key_pub, "-r", self.key_priv, 
               "-l", pcr_list, "-i", "-"]
        success, stdout, stderr = self._run(cmd, input_data=secret_bytes)
        
        if not success:
            _tpm_log(f"tpm2_create (seal) failed: {stderr.decode(errors='replace')}")

        if success:
            with open(self.key_pub, "rb") as f: pub = f.read()
            with open(self.key_priv, "rb") as f: priv = f.read()
            return True, pub, priv
        return False, None, None

    def unseal_secret(self, pub_bytes, priv_bytes):
        """Unseal a secret using the TPM primary key and current PCR state."""
        if not self.tpm_present: return None
        try:
            # Write bytes to temp files for TPM tools
            with open(self.key_pub, "wb") as f: f.write(pub_bytes)
            with open(self.key_priv, "wb") as f: f.write(priv_bytes)
            
            # 1. Load the sealed object
            load_cmd = ["tpm2_load", "-C", self.primary_ctx, "-u", self.key_pub, "-r", self.key_priv, "-c", self.key_ctx]
            if not self._run(load_cmd)[0]: return None
            
            # 2. Unseal
            unseal_cmd = ["tpm2_unseal", "-c", self.key_ctx]
            success, stdout, _ = self._run(unseal_cmd)
            
            # Cleanup transient context
            self._run(["tpm2_flushcontext", self.key_ctx])
            
            return stdout if success else None
        except:
            return None

    def sign_ecdsa(self, data_bytes):
        """Generate a transient ECDSA key, sign data, and return (signature, public_key_pem)."""
        if not self.tpm_present: return None, None
        
        import tempfile
        with tempfile.TemporaryDirectory(prefix="clamfox_sign_") as tmp_dir:
            sig_file = os.path.join(tmp_dir, "clamfox.sig")
            pub_file = os.path.join(tmp_dir, "clamfox_pub.pem")
            key_pub = os.path.join(tmp_dir, "clamfox_key.pub")
            key_priv = os.path.join(tmp_dir, "clamfox_key.priv")
            key_ctx = os.path.join(tmp_dir, "clamfox_key.ctx")
            
            # 1. Create Transient ECDSA Key
            create_cmd = ["tpm2_create", "-C", self.primary_ctx, "-G", "ecc", "-u", key_pub, "-r", key_priv]
            if not self._run(create_cmd)[0]: return None, None
            
            # 2. Load Key
            load_cmd = ["tpm2_load", "-C", self.primary_ctx, "-u", key_pub, "-r", key_priv, "-c", key_ctx]
            if not self._run(load_cmd)[0]: return None, None
            
            # 3. Sign (Pre-hash to avoid TPM timeouts on large files)
            digest = hashlib.sha256(data_bytes).digest()
            digest_file = os.path.join(tmp_dir, "digest_to_sign")
            with open(digest_file, "wb") as f:
                f.write(digest)
                
            # Use -d to indicate input is already a digest, -f plain for raw signature
            sign_cmd = ["tpm2_sign", "-c", key_ctx, "-g", "sha256", "-d", "-f", "plain", "-o", sig_file, digest_file]
            success, _, stderr = self._run(sign_cmd)
            
            if not success:
                _tpm_log(f"tpm2_sign failed: {stderr.decode(errors='replace')}")

            # 4. Export Public Key (PEM for OpenSSL compatibility)
            self._run(["tpm2_readpublic", "-c", key_ctx, "-f", "pem", "-o", pub_file])
            
            if success:
                with open(sig_file, "rb") as f: sig = f.read()
                with open(pub_file, "rb") as f: pub = f.read()
                
                # 5. FLUSH/BURN the key context immediately
                self._run(["tpm2_flushcontext", key_ctx])
                
                return sig, pub
        return None, None

    def _raw_sig_to_der(self, raw_sig):
        """Convert a 64-byte raw [R, S] ECDSA signature to ASN.1 DER format."""
        if len(raw_sig) != 64: return raw_sig # Not a raw P-256 signature
        
        r = int.from_bytes(raw_sig[:32], 'big')
        s = int.from_bytes(raw_sig[32:], 'big')
        
        def encode_integer(n):
            b = n.to_bytes((n.bit_length() + 8) // 8, 'big') or b'\x00'
            if b[0] & 0x80: b = b'\x00' + b
            return b'\x02' + bytes([len(b)]) + b
            
        r_der = encode_integer(r)
        s_der = encode_integer(s)
        payload = r_der + s_der
        return b'\x30' + bytes([len(payload)]) + payload

    def verify_ecdsa(self, data_bytes, signature_bytes, pub_key_bytes):
        """Verify an ECDSA signature using OpenSSL (Fast & Stateless)."""
        # Convert raw [R, S] signature to DER for OpenSSL compatibility
        der_sig = self._raw_sig_to_der(signature_bytes)

        import tempfile
        try:
            # Use a private TemporaryDirectory (unique per call) to prevent
            # race conditions if verify_ecdsa() is ever called concurrently.
            with tempfile.TemporaryDirectory(prefix="clamfox_verify_") as tmp_dir:
                sig_file  = os.path.join(tmp_dir, "verify.sig")
                pub_file  = os.path.join(tmp_dir, "verify_pub.pem")
                data_file = os.path.join(tmp_dir, "verify_data")

                with open(sig_file,  "wb") as f: f.write(der_sig)
                with open(pub_file,  "wb") as f: f.write(pub_key_bytes)
                with open(data_file, "wb") as f: f.write(data_bytes)

                # Use OpenSSL for fast verification
                cmd = ["openssl", "dgst", "-sha256", "-verify", pub_file,
                       "-signature", sig_file, data_file]
                res = subprocess.run(cmd, capture_output=True, timeout=5)

                if res.returncode != 0:
                    _tpm_log(f"OpenSSL verification failed: {res.stderr.decode(errors='replace')}")

                return res.returncode == 0
        except Exception as e:
            _tpm_log(f"Verification exception: {e}")
            return False

    def cleanup(self):
        """Flush the primary context from TPM memory."""
        if os.path.exists(self.primary_ctx):
            self._run(["tpm2_flushcontext", self.primary_ctx])
            try: os.remove(self.primary_ctx)
            except: pass

if __name__ == "__main__":
    tpm = TpmProvider()
    if tpm.tpm_present:
        print("✅ TPM 2.0 Detected.")
        if tpm.create_primary():
            print("✅ Primary Storage Key created.")
            sig, pub = tpm.sign_ecdsa(b"ClamFox-Integrity-Check")
            if sig:
                print(f"✅ Disposable ECDSA Signature generated ({len(sig)} bytes).")
                print("🔥 Private key flushed.")
            tpm.cleanup()
    else:
        print("❌ TPM 2.0 not available.")

