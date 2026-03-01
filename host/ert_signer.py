#!/usr/bin/env python3
import os
import sys
import json
import base64
import hashlib
import subprocess
from tpm_provider import TpmProvider

def keyring_set(key, value):
    """Store sensitive data in System Keyring using secret-tool."""
    try:
        cmd = ["secret-tool", "store", "--label=ClamFox Security Vault", 
               "application", "clamfox", "type", "security-data", "key", key]
        subprocess.run(cmd, input=value, text=True, capture_output=True, timeout=5)
        return True
    except:
        return False

def run_ert_workflow():
    """Orchestrates the full ERT workflow: sign and seal."""
    host_dir = os.path.dirname(os.path.abspath(__file__))
    engine_path = os.path.join(host_dir, "clamav_host.py")
    if not os.path.exists(engine_path):
        engine_path = os.path.join(host_dir, "clamav_engine.py")
        
    config_path = os.path.join(host_dir, "config.json")
    
    tpm = TpmProvider()
    if not tpm.tpm_present:
         print("❌ ERT Error: TPM 2.0 not detected. Hardware signing unavailable.")
         return False
    
    if not tpm.create_primary():
         print("❌ ERT Error: Failed to initialize TPM Primary Storage Key.")
         return False

    try:
        # 1. SIGN HOST SCRIPT
        print(f"🛡️  ERT SIGNER: Measuring integrity of {os.path.basename(engine_path)}...")
        with open(engine_path, "rb") as f:
            script_content = f.read()
            
        signature, public_key_pem = tpm.sign_ecdsa(script_content)
        if not signature or not public_key_pem:
            print("❌ ERT Error: Hardware signing failed.")
            return False
            
        print("🔥 ERT SIGNER: Private key burned. Integrity anchored to hardware.")
        
        # 2. SEAL HANDSHAKE SECRET
        if os.path.exists(config_path):
            with open(config_path, "r") as f:
                config = json.load(f)
            
            secret = config.get("secret")
            if secret:
                print("🛡️  ERT SIGNER: Sealing handshake secret to hardware (PCR 0,1,7)...")
                success, pub, priv = tpm.seal_secret(secret.encode())
                if success:
                    pub_blob_path = os.path.join(host_dir, "vault_sealed_pub.bin")
                    priv_blob_path = os.path.join(host_dir, "vault_sealed_priv.bin")
                    with open(pub_blob_path, "wb") as f: f.write(pub)
                    with open(priv_blob_path, "wb") as f: f.write(priv)
                    
                    config["ert_sealed"] = True
                    # Hardening: Purge plaintext secret
                    if "secret" in config: del config["secret"]
                    print(f"✅ ERT SIGNER: Hardware Seal locked. Blobs stored.")
                else:
                    print("⚠️ ERT Warning: Handshake sealing failed, continuing with signing only.")
            else:
                print("ℹ️ ERT Info: No secret found to seal.")
        
        # Save config updates
        config["ert_signature"] = base64.b64encode(signature).decode('utf-8')
        config["ert_public_key"] = base64.b64encode(public_key_pem).decode('utf-8')
        config["integrity_hash"] = hashlib.sha256(script_content).hexdigest()
        config["ert_enabled"] = True
        
        # Sync with legacy Software Vault (Keyring) if available
        keyring_set("integrity_hash", config["integrity_hash"])
        
        config["ert_last_seal"] = int(os.path.getmtime(engine_path))
        
        with open(config_path, "w") as f:
            json.dump(config, f, indent=4)
            
        print(f"✅ ERT SIGNER: Workflow complete. Settings persisted.")
        return True
    except Exception as e:
        print(f"❌ ERT Error: {e}")
        return False
    finally:
        tpm.cleanup()

if __name__ == "__main__":
    if run_ert_workflow():
        sys.exit(0)
    else:
        sys.exit(1)
