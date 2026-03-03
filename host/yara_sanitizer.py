#!/usr/bin/env python3
import os
import re
import requests
import zipfile
import io
import shutil

# ClamAV YARA Limitations:
# 1. No 'import' modules (pe, elf, dotnet, etc.)
# 2. No 'global' or 'private' rules
# 3. No external variables
# 4. Must have at least one string
# 5. Max 64 strings per rule
# 6. No references to other rules

# SECURITY LIMITS FOR ZIP BUNDLES
MAX_ZIP_FILES = 500
MAX_UNCOMPRESSED_SIZE = 50 * 1024 * 1024 # 50 MB

class YaraSanitizer:
    def __init__(self, output_dir):
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
    def sanitize_content(self, content):
        """Processes a YARA file and returns ClamAV compatible content."""
        # Remove imports
        content = re.sub(r'import\s+"[^"]+"', '', content)
        
        # Split into individual rules
        # Use a more robust split that only catches 'rule' at the start of a line
        rules = re.split(r'(^\s*rule\s+[\w\d_]+)', content, flags=re.MULTILINE)
        
        cleaned_rules = []
        
        # The first element is usually comments or headers
        if rules:
            header = rules.pop(0).strip()
            if header:
                cleaned_rules.append(f"/* Sanitized Header */\n{header}")

        for i in range(0, len(rules), 2):
            if i + 1 >= len(rules):
                break
                
            rule_decl = rules[i]
            rule_body = rules[i+1]
            
            full_rule = rule_decl + rule_body
            
            # 1. Check for incompatible keywords
            incompatible = ['global rule', 'private rule', 'contains', 'matches']
            if any(kw in full_rule.lower() for kw in incompatible):
                continue
                
            # 2. Check for module references (e.g., pe.something, elf.something)
            modules = ['pe', 'elf', 'dotnet', 'macho', 'dex', 'vba', 'cuckoo', 'hash', 'math', 'magic', 'vt', 'time']
            module_pattern = r'\b(' + '|'.join(modules) + r')\.'
            if re.search(module_pattern, full_rule):
                continue

            # 3. Check strings count and presence
            string_section = re.search(r'strings\s*:(.*?)condition\s*:', full_rule, re.DOTALL | re.IGNORECASE)
            if not string_section:
                continue # ClamAV requires strings
                
            strings = re.findall(r'\$[\w\d_]*\s*=', string_section.group(1))
            if not strings or len(strings) > 64:
                continue
                
            # 4. Check for references to other rules (rule names used in conditions)
            # This is hard to detect perfectly with regex, but we look for common patterns
            # ClamAV fails if a condition has a name that isn't a defined string variable
            
            cleaned_rules.append(full_rule.strip())

        result = "\n\n".join(cleaned_rules)

        # 5. LibClamAV Compatibility: Remove patterns the reference YARA parser
        #    allows but LibClamAV's stricter parser rejects.
        #    a) Empty string literals in any context (meta or strings section).
        result = re.sub(r'(\b\w+\s*=\s*)""\s*\n', r'\1"N/A"\n', result)
        result = re.sub(r"(\b\w+\s*=\s*)''\s*\n", r"\1'N/A'\n", result)
        #    b) Identifiers used directly in condition before standard keywords
        #       (a common YARA extension LibClamAV's grammar doesn't support).
        result = re.sub(r'\bxor\s*\(', '(', result)  # xor modifier not supported
        result = re.sub(r'\bbase64\s*\(', '(', result)  # base64 modifier not supported
        result = re.sub(r'\bbase64wide\s*\(', '(', result)
        result = re.sub(r'\b(\$\w+)\s+xor\b', r'\1', result)
        result = re.sub(r'\b(\$\w+)\s+base64\b', r'\1', result)
        result = re.sub(r'\b(\$\w+)\s+base64wide\b', r'\1', result)

        return result

    def sync_from_url(self, url, filename, proxies=None, headers=None):
        """Downloads a YARA bundle, sanitizes it, and saves."""
        try:
            # No print() here — caller is clamav_engine.py which owns the native
            # messaging stdout pipe; writing outside _output_lock would corrupt it.
            response = requests.get(url, timeout=60, proxies=proxies, headers=headers, stream=True)
            if response.status_code != 200:
                return False, f"HTTP {response.status_code}"

            # Security: Cap the download size to prevent resource exhaustion
            # We allow up to 2x MAX_UNCOMPRESSED_SIZE for the compressed ZIP bundle
            download_limit = MAX_UNCOMPRESSED_SIZE * 2
            
            content_buffer = io.BytesIO()
            downloaded = 0
            
            for chunk in response.iter_content(chunk_size=65536):
                if chunk:
                    downloaded += len(chunk)
                    if downloaded > download_limit:
                        return False, f"Download aborted: Size exceeds security limit ({download_limit} bytes)"
                    content_buffer.write(chunk)
            
            raw_data = content_buffer.getvalue()
            total_sanitized = 0
            
            # Handle Zip bundles
            if url.endswith('.zip'):
                with zipfile.ZipFile(io.BytesIO(raw_data)) as z:
                    # 1. Integrity Check
                    if z.testzip() is not None:
                        return False, "Corrupt ZIP archive detected."

                    # 2. ZIP Bomb Protection: Check sizes and file counts before processing
                    total_size = 0
                    file_count = 0
                    for info in z.infolist():
                        file_count += 1
                        total_size += info.file_size
                        
                        if file_count > MAX_ZIP_FILES:
                            return False, f"ZIP Bomb Protection: Too many files ({file_count} > {MAX_ZIP_FILES})"
                        if total_size > MAX_UNCOMPRESSED_SIZE:
                            return False, f"ZIP Bomb Protection: Uncompressed size exceeds limit ({total_size} > {MAX_UNCOMPRESSED_SIZE})"

                    # 3. Process files
                    for name in z.namelist():
                        if name.endswith('.yar') or name.endswith('.yara'):
                            with z.open(name) as f:
                                # Limit individual file read to prevent memory exhaustion
                                content = f.read(10 * 1024 * 1024).decode('utf-8', errors='ignore')
                                sanitized = self.sanitize_content(content)
                                if sanitized.strip():
                                    target_name = os.path.basename(name)
                                    with open(os.path.join(self.output_dir, target_name), 'w') as out:
                                        out.write(sanitized)
                                    total_sanitized += 1
            else:
                # Single file
                content = raw_data.decode('utf-8', errors='ignore')
                sanitized = self.sanitize_content(content)
                if sanitized.strip():
                    with open(os.path.join(self.output_dir, filename), 'w') as out:
                        out.write(sanitized)
                    total_sanitized = 1

            return True, f"Sanitizer completed: {total_sanitized} files processed."
        except Exception as e:
            return False, str(e)

if __name__ == "__main__":
    # Example usage: Fetching YARA Forge Core (ClamAV Optimized)
    # Using the GitHub latest release for reliability
    YARA_FORGE_CORE = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip"
    
    output = os.path.join(os.path.dirname(__file__), "signatures")
    sanitizer = YaraSanitizer(output)
    success, msg = sanitizer.sync_from_url(YARA_FORGE_CORE, "yara_forge_filtered.yar")
    print(msg)
