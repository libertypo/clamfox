# Script to package the extension
VERSION="0.0.6.5"
FULL_PACKAGE="clamfox_full_${VERSION}.zip"
AMO_SOURCE="clamfox_amo_source_${VERSION}.zip"
XPI_FULL="clamfox_full_${VERSION}.xpi"
XPI_STANDALONE="clamfox_standalone_${VERSION}.xpi"

echo "Packaging ClamFox..."

# Cleanup
rm -f "$FULL_PACKAGE" "$AMO_SOURCE" "$XPI_FULL" "$XPI_STANDALONE"
rm -rf build_full build_amo build_xpi_full build_xpi_standalone

# 1. Create FULL package (for GitHub/Manual install)
mkdir -p build_full
cp -r background.js content.js content.css design_tokens.css manifest.json popup icons _locales host data wasm_shield README.md PRIVACY_SUMMARY.txt build_full/

# Supply-Chain Canary Injection
BUILD_CANARY="cf_canary_$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16)"
echo "🛡️  Injecting Supply-Chain Canary: $BUILD_CANARY"
sed -i "s/PLACEHOLDER_CANARY/$BUILD_CANARY/g" build_full/background.js
sed -i "s/PLACEHOLDER_CANARY/$BUILD_CANARY/g" build_full/host/clamav_engine.py

# Privacy: Remove local state/secrets from host before packaging
rm -f build_full/host/config.json
rm -f build_full/host/host_debug.log build_full/host/alert_log.txt build_full/host/tpm_debug.err
rm -f build_full/host/urldb.txt* build_full/host/trust_db.json
rm -f build_full/host/vault_sealed_priv.bin build_full/host/vault_sealed_pub.bin
rm -f build_full/host/verify.sig build_full/host/verify_digest build_full/host/verify_pub
rm -f build_full/host/decode_log.py
rm -rf build_full/host/__pycache__
cd build_full && zip -r "../$FULL_PACKAGE" ./* && cd ..

# 2. Create Standalone XPI (AMO Submission Ready - No Native Host)
mkdir -p build_xpi_standalone
cp -r background.js content.js content.css design_tokens.css popup icons _locales data wasm_shield build_xpi_standalone/
cp manifest_amo.json build_xpi_standalone/manifest.json
mkdir -p build_xpi_standalone/META-INF
cd build_xpi_standalone && sed -i "s/PLACEHOLDER_CANARY/$BUILD_CANARY/g" background.js && zip -r "../$XPI_STANDALONE" ./* && cd ..

# 3. Create Full XPI (Includes Native Host)
mkdir -p build_xpi_full
cp -r background.js content.js content.css design_tokens.css manifest.json popup icons _locales host data wasm_shield build_xpi_full/
rm -f build_xpi_full/host/config.json
rm -f build_xpi_full/host/host_debug.log build_xpi_full/host/alert_log.txt build_xpi_full/host/tpm_debug.err
rm -f build_xpi_full/host/urldb.txt* build_xpi_full/host/trust_db.json
rm -f build_xpi_full/host/vault_sealed_priv.bin build_xpi_full/host/vault_sealed_pub.bin
rm -f build_xpi_full/host/verify.sig build_xpi_full/host/verify_digest build_xpi_full/host/verify_pub
rm -f build_xpi_full/host/decode_log.py
rm -rf build_xpi_full/host/__pycache__
sed -i "s/PLACEHOLDER_CANARY/$BUILD_CANARY/g" build_xpi_full/background.js
sed -i "s/PLACEHOLDER_CANARY/$BUILD_CANARY/g" build_xpi_full/host/clamav_engine.py
mkdir -p build_xpi_full/META-INF
cd build_xpi_full && zip -r "../$XPI_FULL" ./* && cd ..

# 4. Create Source Zip for AMO (Required for review)
mkdir -p build_amo
cp -r background.js content.js content.css design_tokens.css manifest.json manifest_amo.json popup icons _locales host data wasm_shield wasm-shield README.md PRIVACY_SUMMARY.txt package.sh build_amo/
rm -f build_amo/host/config.json build_amo/host/host_debug.log build_amo/host/alert_log.txt build_amo/host/tpm_debug.err
rm -f build_amo/host/urldb.txt* build_amo/host/trust_db.json
rm -f build_amo/host/vault_sealed_priv.bin build_amo/host/vault_sealed_pub.bin
rm -f build_amo/host/verify.sig build_amo/host/verify_digest build_amo/host/verify_pub
rm -f build_amo/host/decode_log.py
rm -rf build_amo/host/__pycache__
sed -i "s/PLACEHOLDER_CANARY/$BUILD_CANARY/g" build_amo/background.js
sed -i "s/PLACEHOLDER_CANARY/$BUILD_CANARY/g" build_amo/host/clamav_engine.py
cd build_amo && zip -r "../$AMO_SOURCE" ./* && cd ..

# Cleanup
rm -rf build_full build_amo build_xpi_full build_xpi_standalone

echo "-------------------------------------------"
echo "✅ BUILD COMPLETE"
echo "1. STANDALONE XPI (AMO): $XPI_STANDALONE"
echo "2. FULL XPI (Side-load): $XPI_FULL"
echo "3. FULL BUNDLE (GitHub): $FULL_PACKAGE"
echo "4. SOURCE FOR REVIEW: $AMO_SOURCE"
echo "-------------------------------------------"
