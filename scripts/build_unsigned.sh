#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ "$(uname -s)" != Darwin ]]; then
  echo 'A macOS host with Xcode and the iPhoneOS SDK is required.' >&2
  exit 1
fi
build_root="$PWD/build"
mkdir -p "$build_root"
rm -f "$build_root/A16Probe-unsigned.ipa" "$build_root/A16Probe-unsigned.ipa.sha256" "$build_root/ipa-verification.json"
{
  xcodebuild -version
  xcodebuild -showsdks
  xcrun --sdk iphoneos --show-sdk-version
  git rev-parse HEAD
} > "$build_root/toolchain.txt"
xcrun swiftc A16Probe/Compatibility.swift Tests/CompatibilityTests.swift -o "$build_root/compatibility-tests"
"$build_root/compatibility-tests" | tee "$build_root/compatibility-tests.log"
python3 -m unittest discover -s Tests -p 'test_*.py' -v
xcodebuild -project A16Probe.xcodeproj -scheme A16Probe -configuration Release \
  -sdk iphoneos -destination 'generic/platform=iOS' \
  -derivedDataPath "$build_root/DerivedData" \
  CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY= \
  build 2>&1 | tee "$build_root/xcodebuild.log"
# Use a fresh staging directory so repeated builds cannot reuse stale bundles.
staging="$(mktemp -d "$build_root/package.XXXXXX")"
trap 'rm -rf "$staging"' EXIT
mkdir "$staging/Payload"
ditto "$build_root/DerivedData/Build/Products/Release-iphoneos/A16Probe.app" "$staging/Payload/A16Probe.app"
rm -f "$build_root/A16Probe-unsigned.ipa"
(cd "$staging" && ditto -c -k --keepParent Payload "$build_root/A16Probe-unsigned.ipa")
python3 scripts/verify_ipa.py "$build_root/A16Probe-unsigned.ipa" --output "$build_root/ipa-verification.json"
(cd "$build_root" && shasum -a 256 A16Probe-unsigned.ipa > A16Probe-unsigned.ipa.sha256)
