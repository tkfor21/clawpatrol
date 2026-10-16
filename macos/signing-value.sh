#!/bin/sh
# Print one Clawpatrol.app signing input for tooling outside Xcode
# (the Go build's -ldflags, the release script). The lookup order is
# the environment, then macos/Signing.local.xcconfig, then
# macos/Signing.xcconfig.
#
#   macos/signing-value.sh CLAWPATROL_BUNDLE_ID_PREFIX   # -> dev.clawpatrol
set -eu

key="${1:-}"
case "$key" in
  CLAWPATROL_TEAM_ID | CLAWPATROL_BUNDLE_ID_PREFIX) ;;
  *)
    echo "usage: $0 CLAWPATROL_TEAM_ID|CLAWPATROL_BUNDLE_ID_PREFIX" >&2
    exit 2
    ;;
esac

v=$(printenv "$key" || true)
if [ -n "$v" ]; then
  printf '%s\n' "$v"
  exit 0
fi

dir=$(dirname "$0")
for f in "$dir/Signing.local.xcconfig" "$dir/Signing.xcconfig"; do
  [ -f "$f" ] || continue
  v=$(sed -n "s/^[[:space:]]*$key[[:space:]]*=[[:space:]]*//p" "$f" \
    | tail -1 | sed 's/[[:space:]]*$//')
  if [ -n "$v" ]; then
    printf '%s\n' "$v"
    exit 0
  fi
done

echo "$0: $key not set in the environment or $dir/Signing*.xcconfig" >&2
exit 1
