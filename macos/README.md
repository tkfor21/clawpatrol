# clawpatrol macOS — `clawpatrol run` per-process tunnel

NETransparentProxyProvider system extension. Intercepts every outbound
TCP/UDP flow, walks the source process's PPID chain back to
`dev.clawpatrol.app`, tunnels matching flows through a userspace
WireGuard + gVisor netstack to the gateway. Non-matching flows
passthrough untouched. Whole-machine mode (`install --whole-machine`)
short-circuits the filter and tunnels everything.

## Layout

```
macos/
  project.yml                            # xcodegen spec
  Signing.xcconfig                       # team, bundle IDs, profiles (see below)
  signing-value.sh                       # reads them for non-Xcode tooling
  install.sh                             # build + cp to /Applications + LS rebuild
  Clawpatrol/                            # parent app (CLI helper)
    main.swift                           # install / start / stop / wipe / run
    Info.plist                           # NSSystemExtensionUsageDescription
    Clawpatrol.entitlements
  ClawpatrolExtension/                   # the system extension
    main.swift                           # NEProvider.startSystemExtensionMode()
    Provider.swift                       # TransparentProxyProvider + flow bridge
    BridgingHeader.h                     # libwgnetstack.h + libbsm + libproc
    Info.plist                           # NEExtensionPointIdentifier=app-proxy
    ClawpatrolExtension.entitlements     # app-proxy-provider, app-groups
  netstack/                              # Go cgo c-archive
    wgnetstack.go                        # wireguard-go + gVisor netstack +
                                         # cgo bridge (dial_tcp/udp/resolve)
    go.mod / go.sum
```

The Go module embeds wireguard-go + gVisor netstack and exposes a C
ABI: `wg_netstack_init`, `wg_netstack_dial_tcp`, `wg_netstack_dial_udp`,
`wg_netstack_resolve`, `wg_netstack_close`. Each dial returns one end
of a unix socketpair; the Go side pumps bytes between the gVisor
connection and the fd. Provider.swift hands off bytes from each
intercepted `NEAppProxyTCPFlow` / `UDPFlow` to those fds.

Same wireguard-go + gvisor stack the gateway uses (`../wireguard.go`),
client side.

## Build

Pre-reqs:
- macOS 13+, Apple Silicon
- Xcode 15+
- [xcodegen](https://github.com/yonaskolb/XcodeGen) (`brew install xcodegen`)
- Go 1.22+ (`brew install go`)
- Apple Development cert + manually-created (non-XcodeManaged)
  provisioning profiles `Clawpatrol App Dev` and `Clawpatrol Extension Dev`
  in your Apple Developer account, both with App Groups +
  Network Extensions capabilities

```sh
cd macos
xcodegen generate
./install.sh                 # builds, copies to /Applications, rebuilds LS
```

## Signing under your own Apple team

The team ID, bundle IDs, app group, profile names and Network
Extension entitlement value all live in `Signing.xcconfig`. The
entitlements files, Info.plists and Swift code reference them as
build settings, so a fork changes two values and nothing else:

```sh
cat > macos/Signing.local.xcconfig <<'EOF'
CLAWPATROL_TEAM_ID = <your team ID>
CLAWPATROL_BUNDLE_ID_PREFIX = <your prefix, e.g. dev.clawpatrol.myfork>
EOF
```

`Signing.local.xcconfig` is gitignored and included last, so it wins.
From those two values you get:

| Setting | Value |
|---|---|
| App bundle ID | `<prefix>.app` |
| Extension bundle ID (and product name) | `<prefix>.app.extension` |
| App group | `group.<team>.<prefix>.app` |

Register both App IDs and the app group under your team, then create
the profiles with the names in `Signing.xcconfig`: `Clawpatrol App Dev`
and `Clawpatrol Extension Dev` for development, `Clawpatrol App` and
`Clawpatrol Extension` (Developer ID) for release.

Put team and prefix overrides in an xcconfig, **not** on the xcodebuild
command line. Xcode resolves the embedded `.systemextension`'s file
name without command-line settings, so a prefix passed there builds
the extension under the new name and then fails to embed it.

The Go CLI needs the same prefix, because `clawpatrol doctor` looks
the extension up by bundle ID. `make build` / `make release` read it
with `macos/signing-value.sh`, which checks the environment first,
then `Signing.local.xcconfig`, then `Signing.xcconfig`.

**Releases.** `.github/scripts/build-macos-app.sh` takes
`CLAWPATROL_TEAM_ID` and `CLAWPATROL_BUNDLE_ID_PREFIX` from the
environment and writes them to `Signing.local.xcconfig`. It refuses to
run if that file already exists. It generates `ExportOptions.plist`
from the resolved settings. `release.yml` maps repo **variables** of
the same names (`gh variable set CLAWPATROL_TEAM_ID ...`) into both the
macOS app job and the Go build, so a fork sets them once next to the
`APPLE_*` secrets. Developer ID profiles with other names can be
passed as `CLAWPATROL_RELEASE_APP_PROFILE` /
`CLAWPATROL_RELEASE_EXT_PROFILE`.

## Use

```sh
sudo systemextensionsctl developer on    # one-time, allows Apple Dev sysexts

/Applications/Clawpatrol.app/Contents/MacOS/Clawpatrol install
# → System Settings → Login Items & Extensions → Network Extensions
#   → toggle Clawpatrol on (one-time approval)

/Applications/Clawpatrol.app/Contents/MacOS/Clawpatrol start \
  ~/.config/clawpatrol/wg.conf

# Verify per-process scoping:
/Applications/Clawpatrol.app/Contents/MacOS/Clawpatrol run -- curl https://api.ipify.org
# → gateway IP
curl https://api.ipify.org
# → real IP
```

Subcommands:
- `install [--whole-machine]` — submit OSSystemExtensionRequest, save
  proxy profile (default per-process, optional whole-machine)
- `start <wg-conf>` — load wg-quick conf, fire startVPNTunnel
- `stop` — stopVPNTunnel
- `run -- <cmd> [args...]` — fork+exec cmd as child of clawpatrol so
  the extension's PPID walk picks it up
- `wipe` — remove every NETunnelProviderManager + NETransparentProxyManager
  this app has registered (escape hatch when System Settings is broken)

## Why these specific choices

- **NETransparentProxyProvider, not NEPacketTunnelProvider**: per-app VPN
  via NEAppRule.matchTools requires an MDM-pushed appmapping payload on
  macOS — NETestAppMapping is silently ignored. Transparent proxy gets
  `flow.metaData.sourceAppAuditToken` for free; we filter ourselves.
- **system-extension, not app-extension**: NETransparentProxyProvider on
  macOS *must* be a sysext. App-extension form refuses to launch
  (`OSLaunchdErrorDomain Code=137`).
- **app-proxy-provider, not packet-tunnel-provider**: app-proxy is
  treated as removable-with-auth by sysextd → activates with Apple
  Development cert + dev mode. Packet-tunnel is "nonRemovable" → only
  activates with notarized Developer ID + Apple-granted entitlement.
- **PRODUCT_NAME = bundle ID for the extension target**: sysextd matches
  embedded `.systemextension` bundle basenames against the requested
  identifier. Default product name produces `ClawpatrolExtension.systemextension`
  → "Extension not found in App bundle" on activation.
- **Manual non-XcodeManaged profiles**: Xcode's auto-generated Mac Team
  Provisioning Profiles aren't trusted by sysextd's path gate.
- **App in `/Applications`, not from DerivedData**: sysextd's
  "/Applications-only" check resolves the parent bundle via
  LaunchServices. `install.sh` rebuilds the LS DB to drop the stale
  DerivedData entry.
