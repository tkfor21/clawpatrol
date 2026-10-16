#!/bin/bash
# Build (and optionally sign+notarize) Clawpatrol.app for distribution.
#
# Without APPLE_ID set: produces an unsigned build (used for PR checks
# and local dev verification). With all the APPLE_* secrets set, signs
# with Developer ID Application + notarizes via notarytool + staples.
#
# The Apple team and bundle IDs come from macos/Signing.xcconfig. To
# sign under another team, set CLAWPATROL_TEAM_ID and
# CLAWPATROL_BUNDLE_ID_PREFIX (release.yml maps repo variables of the
# same names), and name the Developer ID profiles with
# CLAWPATROL_RELEASE_APP_PROFILE / CLAWPATROL_RELEASE_EXT_PROFILE if
# they aren't "Clawpatrol App" / "Clawpatrol Extension".
#
# Output: macos/Clawpatrol.app.tar.gz
set -euo pipefail

SCHEME="Clawpatrol"
PROJECT="macos/Clawpatrol.xcodeproj"
BUILD_DIR="build"
EXPORT_OPTIONS="$BUILD_DIR/ExportOptions.plist"
LOCAL_XCCONFIG="macos/Signing.local.xcconfig"

# write_signing_overrides puts CLAWPATROL_TEAM_ID /
# CLAWPATROL_BUNDLE_ID_PREFIX from the environment into
# Signing.local.xcconfig. They can't go on the xcodebuild command
# line: Xcode resolves the embedded .systemextension's file name
# without command-line settings, so a prefix passed there builds the
# extension under the new name and then fails to copy it into the app.
write_signing_overrides() {
  if [ -z "${CLAWPATROL_TEAM_ID:-}" ] && [ -z "${CLAWPATROL_BUNDLE_ID_PREFIX:-}" ]; then
    return
  fi
  if [ -e "$LOCAL_XCCONFIG" ]; then
    echo "error: $LOCAL_XCCONFIG already exists; put the overrides there or unset CLAWPATROL_TEAM_ID / CLAWPATROL_BUNDLE_ID_PREFIX" >&2
    exit 1
  fi
  {
    echo "// Written by $0 from the environment."
    if [ -n "${CLAWPATROL_TEAM_ID:-}" ]; then
      echo "CLAWPATROL_TEAM_ID = $CLAWPATROL_TEAM_ID"
    fi
    if [ -n "${CLAWPATROL_BUNDLE_ID_PREFIX:-}" ]; then
      echo "CLAWPATROL_BUNDLE_ID_PREFIX = $CLAWPATROL_BUNDLE_ID_PREFIX"
    fi
  } > "$LOCAL_XCCONFIG"
  echo "==> Signing overrides written to $LOCAL_XCCONFIG"
}

# signing_setting prints one resolved build setting of the app target,
# so the derived IDs come from Signing.xcconfig, not a second copy of
# its rules.
signing_setting() {
  xcodebuild -project "$PROJECT" -target Clawpatrol -configuration Release \
    -showBuildSettings 2>/dev/null \
    | awk -v k="$1" '$1 == k && $2 == "=" { sub(/^[^=]*= /, ""); print; exit }'
}

build_netstack() {
  # Clawpatrol's macOS extension links libwgnetstack.a — a Go cgo
  # c-archive bundling wireguard-go + gVisor netstack. Built outside
  # the Xcode project so CI doesn't need brew-go in the Xcode shell
  # phase.
  pushd macos/netstack >/dev/null
  CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 \
    go build -buildmode=c-archive -o libwgnetstack.a .
  popd >/dev/null
}

# bump_build_number stamps CFBundleVersion = git commit count on both
# the .app and extension Info.plists. sysextd treats system extensions
# with the same (CFBundleShortVersionString, CFBundleVersion) tuple as
# the running one as a no-op activation, so without a bump here a
# `Clawpatrol install` after an in-place .app replacement leaves the
# old extension binary running. Commit count is monotonic across
# rebuilds; sysextd accepts the higher number and swaps the ext.
bump_build_number() {
  # CFBundleShortVersionString = release tag (`v0.1.2` → `0.1.2`).
  # CFBundleVersion bumps too. sysextd treats the (short, build) tuple
  # as the ext identity — same tuple = no-op activation, leaves the
  # running ext in place. Bumping short to the release tag forces
  # sysextd to swap on next `Clawpatrol install`.
  #
  # Local dev builds (no RELEASE_TAG) fall back to a timestamp so
  # iterating builds also rotates the version.
  local v
  if [ -n "${RELEASE_TAG:-}" ]; then
    v="${RELEASE_TAG#v}"
  else
    v="0.0.$(date +%s)"
  fi
  /usr/bin/plutil -replace CFBundleShortVersionString -string "$v" \
    macos/Clawpatrol/Info.plist
  /usr/bin/plutil -replace CFBundleShortVersionString -string "$v" \
    macos/ClawpatrolExtension/Info.plist
  /usr/bin/plutil -replace CFBundleVersion -string "$v" \
    macos/Clawpatrol/Info.plist
  /usr/bin/plutil -replace CFBundleVersion -string "$v" \
    macos/ClawpatrolExtension/Info.plist
  echo "==> CFBundleShortVersionString = CFBundleVersion = $v"
}

# If no Apple ID, build unsigned (local dev / PR checks).
if [ -z "${APPLE_ID:-}" ]; then
  echo "==> Building unsigned (no APPLE_ID set)"
  write_signing_overrides
  build_netstack
  bump_build_number
  brew install xcodegen 2>/dev/null || true
  xcodegen --spec macos/project.yml
  xcodebuild \
    -project "$PROJECT" \
    -scheme "$SCHEME" \
    -configuration Release \
    -arch arm64 ONLY_ACTIVE_ARCH=NO \
    CODE_SIGN_IDENTITY="-" \
    CODE_SIGNING_REQUIRED=NO \
    CODE_SIGN_ALLOW_ENTITLEMENTS_MODIFICATION=YES \
    PROVISIONING_PROFILE_SPECIFIER="" \
    build

  APP_OUTPUT=$(xcodebuild -project "$PROJECT" -scheme "$SCHEME" -configuration Release -showBuildSettings 2>/dev/null \
    | awk '/ BUILT_PRODUCTS_DIR /{print $3}' | head -1)
  mkdir -p macos
  tar -czf "macos/Clawpatrol.app.tar.gz" -C "$APP_OUTPUT" "Clawpatrol.app"
  echo "==> Unsigned build: macos/Clawpatrol.app.tar.gz"
  exit 0
fi

echo "==> Building signed + notarized"

# 1. Temporary keychain for the signing identity.
KEYCHAIN_PATH="$RUNNER_TEMP/app-signing.keychain"
security create-keychain -p "app-signing" "$KEYCHAIN_PATH"
security set-keychain-settings -lut 21600 "$KEYCHAIN_PATH"
security unlock-keychain -p "app-signing" "$KEYCHAIN_PATH"

# 2. Import Developer ID Application cert.
echo -n "$APPLE_CERTIFICATE" | base64 --decode > "$RUNNER_TEMP/cert.p12"
security import "$RUNNER_TEMP/cert.p12" \
  -k "$KEYCHAIN_PATH" \
  -P "$APPLE_CERTIFICATE_PASSWORD" \
  -A
security set-key-partition-list -S apple-tool:,apple: -s -k "app-signing" "$KEYCHAIN_PATH"
security list-keychain -s "$KEYCHAIN_PATH"

# 3. Install Developer ID provisioning profiles.
mkdir -p ~/Library/MobileDevice/Provisioning\ Profiles
echo -n "$APPLE_PROVISIONING_PROFILE_APP" | base64 --decode \
  > ~/Library/MobileDevice/Provisioning\ Profiles/clawpatrol_app.provisionprofile
echo -n "$APPLE_PROVISIONING_PROFILE_EXT" | base64 --decode \
  > ~/Library/MobileDevice/Provisioning\ Profiles/clawpatrol_ext.provisionprofile

# 4. Build the Go cgo netstack archive.
build_netstack
bump_build_number

# 5. Generate the project and resolve the signing values. Distribution
#    differs from development in four build settings: the identity, the
#    two profile names, and the -systemextension form of the Network
#    Extension entitlement that Developer ID requires. They don't change
#    any product name, so they're safe on the command line.
write_signing_overrides
brew install xcodegen 2>/dev/null || true
xcodegen --spec macos/project.yml

RELEASE_APP_PROFILE="${CLAWPATROL_RELEASE_APP_PROFILE:-Clawpatrol App}"
RELEASE_EXT_PROFILE="${CLAWPATROL_RELEASE_EXT_PROFILE:-Clawpatrol Extension}"
RELEASE_SIGNING=(
  CLAWPATROL_SIGN_IDENTITY="Developer ID Application"
  CLAWPATROL_APP_PROFILE="$RELEASE_APP_PROFILE"
  CLAWPATROL_EXT_PROFILE="$RELEASE_EXT_PROFILE"
  CLAWPATROL_NE_PROVIDER=app-proxy-provider-systemextension
)

TEAM_ID=$(signing_setting CLAWPATROL_TEAM_ID)
APP_ID=$(signing_setting CLAWPATROL_APP_BUNDLE_ID)
EXT_ID=$(signing_setting CLAWPATROL_EXT_BUNDLE_ID)
if [ -z "$TEAM_ID" ] || [ -z "$APP_ID" ] || [ -z "$EXT_ID" ]; then
  echo "error: couldn't resolve CLAWPATROL_TEAM_ID / _APP_BUNDLE_ID / _EXT_BUNDLE_ID from $PROJECT" >&2
  exit 1
fi
echo "==> Signing as team $TEAM_ID: $APP_ID, $EXT_ID"

mkdir -p "$BUILD_DIR"
cat > "$EXPORT_OPTIONS" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>destination</key>
    <string>export</string>
    <key>method</key>
    <string>developer-id</string>
    <key>provisioningProfiles</key>
    <dict>
        <key>$APP_ID</key>
        <string>$RELEASE_APP_PROFILE</string>
        <key>$EXT_ID</key>
        <string>$RELEASE_EXT_PROFILE</string>
    </dict>
    <key>signingStyle</key>
    <string>manual</string>
    <key>teamID</key>
    <string>$TEAM_ID</string>
</dict>
</plist>
EOF
plutil -lint "$EXPORT_OPTIONS" >/dev/null

# 6. Archive. arm64-only — libwgnetstack.a is built for darwin/arm64
# (apple silicon). Universal would require a separate amd64 build of
# the Go archive + lipo, which we skip until x86_64 macs matter.
xcodebuild \
  -project "$PROJECT" \
  -scheme "$SCHEME" \
  -configuration Release \
  -arch arm64 ONLY_ACTIVE_ARCH=NO \
  -archivePath "$BUILD_DIR/Clawpatrol.xcarchive" \
  OTHER_CODE_SIGN_FLAGS="--keychain $KEYCHAIN_PATH" \
  "${RELEASE_SIGNING[@]}" \
  archive

# 7. Export.
xcodebuild \
  -exportArchive \
  -archivePath "$BUILD_DIR/Clawpatrol.xcarchive" \
  -exportOptionsPlist "$EXPORT_OPTIONS" \
  -exportPath "$BUILD_DIR"

# 8. Notarize.
xcrun notarytool store-credentials "AC_PASSWORD" \
  --keychain "$KEYCHAIN_PATH" \
  --apple-id "$APPLE_ID" \
  --team-id "$TEAM_ID" \
  --password "$APPLE_APP_PASSWORD"

ditto -c -k --keepParent "$BUILD_DIR/Clawpatrol.app" "$BUILD_DIR/Clawpatrol.app.zip"

xcrun notarytool submit \
  "$BUILD_DIR/Clawpatrol.app.zip" \
  --keychain "$KEYCHAIN_PATH" \
  --keychain-profile "AC_PASSWORD" \
  --wait

xcrun stapler staple "$BUILD_DIR/Clawpatrol.app"

# 9. Package.
mkdir -p macos
tar -czf "macos/Clawpatrol.app.tar.gz" -C "$BUILD_DIR" "Clawpatrol.app"

echo "==> Signed + notarized: macos/Clawpatrol.app.tar.gz"
