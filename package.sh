# Script to package the extension
VERSION="0.0.5.9"
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
cp -r background.js content.js content.css design_tokens.css manifest.json popup icons _locales host data README.md PRIVACY_SUMMARY.txt build_full/
# Privacy: Remove local state/secrets from host before packaging
rm -f build_full/host/config.json
rm -f build_full/host/host_debug.log
rm -f build_full/host/urldb.txt*
cd build_full && zip -r "../$FULL_PACKAGE" ./* && cd ..

# 2. Create Standalone XPI (AMO Submission Ready - No Native Host)
mkdir -p build_xpi_standalone
cp -r background.js content.js content.css design_tokens.css popup icons _locales data build_xpi_standalone/
cp manifest_amo.json build_xpi_standalone/manifest.json
mkdir -p build_xpi_standalone/META-INF
cd build_xpi_standalone && zip -r "../$XPI_STANDALONE" ./* && cd ..

# 3. Create Full XPI (Includes Native Host)
mkdir -p build_xpi_full
cp -r background.js content.js content.css design_tokens.css manifest.json popup icons _locales host data build_xpi_full/
rm -f build_xpi_full/host/config.json
rm -f build_xpi_full/host/host_debug.log
rm -f build_xpi_full/host/urldb.txt*
mkdir -p build_xpi_full/META-INF
cd build_xpi_full && zip -r "../$XPI_FULL" ./* && cd ..

# 4. Create Source Zip for AMO (Required for review)
mkdir -p build_amo
cp -r background.js content.js content.css design_tokens.css manifest.json manifest_amo.json popup icons _locales host data README.md PRIVACY_SUMMARY.txt package.sh build_amo/
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
