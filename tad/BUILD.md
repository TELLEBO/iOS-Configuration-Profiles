# Building the TAD iOS configuration profile

The profile is the last step, not the first. A `com.apple.vpn.managed` payload naming an
app that does not read `providerConfiguration` installs cleanly and does nothing — that is
exactly the inert artifact [`../daita/`](../daita/) exists to document. Steps 1–5 build the
app that makes the profile mean something; step 6 builds the profile.

If you only want to see the profile, skip to step 6 — but ship nothing until 1–5 are done.

## 1. Apple Developer setup

Create two App IDs and enable the capabilities the extension needs:

| Identifier | Role | Capabilities |
|---|---|---|
| `com.yourco.vpn` | container app | Network Extensions, App Groups, Keychain Sharing |
| `com.yourco.vpn.PacketTunnel` | packet-tunnel extension | Network Extensions, App Groups, Keychain Sharing |

The extension identifier **must** be a child of the app identifier — `build_profile.py`
asserts this, because iOS will not pair them otherwise.

Entitlements on both targets:

```xml
<key>com.apple.developer.networking.networkextension</key>
<array><string>packet-tunnel-provider</string></array>
<key>com.apple.security.application-groups</key>
<array><string>group.com.yourco.vpn</string></array>
<key>keychain-access-groups</key>
<array><string>$(AppIdentifierPrefix)com.yourco.vpn</string></array>
```

The shared keychain group is what lets the app write its origin nonce and the extension
read it — the mechanism that distinguishes a profile-provisioned configuration from one the
app created itself.

## 2. Build the engine for iOS

```bash
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
cargo install --force cbindgen

cd tad/engine
cargo build --release --target aarch64-apple-ios
cargo build --release --target aarch64-apple-ios-sim

cbindgen --lang c --output tad_engine.h .

# The extra libraries the static lib needs at link time:
RUSTFLAGS="--print native-static-libs" cargo build --release --target aarch64-apple-ios
```

Package the per-architecture `libtad_engine.a` into an `.xcframework` (`xcodebuild
-create-xcframework`) rather than `lipo`-ing device and simulator slices together — they
have overlapping architectures on Apple silicon and `lipo` cannot hold both.

## 3. Wire the extension target

1. Add the `.xcframework` to the extension target's *Link Binary With Libraries*.
2. Add `tad_engine.h` to a bridging header for the extension target.
3. Add the linker flags `--print native-static-libs` reported (typically `-lc++ -lSystem`
   and friends).
4. Add `ios/TadPolicy.swift`, `ios/TadEngine.swift`, `ios/PacketTunnelProvider.swift`.
5. Set the extension's principal class to `PacketTunnelProvider` in its `Info.plist`
   (`NSExtension` → `NSExtensionPrincipalClass`).

`ios/*.swift` in this repository has never been compiled — there is no Swift toolchain in
the environment it was written in. Expect to fix compile errors, and read
`PacketTunnelProvider.swift`'s two `fatalError` stubs: the transport and the tunnel
addresses/routes/MTU are yours to supply.

## 4. Implement the two stubs

- `makeTransport()` — your `TadTransport`. Constant packet size lives here, applied to the
  **encrypted datagram**.
- `makeTransportNetworkSettings()` — addresses, routes and MTU. DNS is already handled:
  `makeNetworkSettings(dns:)` builds `NEDNSOverHTTPSSettings` from the profile's keys.

## 5. Make the app stamp its own configurations

`TadKeychain.appInstanceNonce()` currently returns `nil`, which makes *every* configuration
look profile-provisioned. Before shipping:

1. On first launch, generate a random nonce and store it in the shared keychain group.
2. Write it as `TADAppInstanceNonce` into the `providerConfiguration` of any
   `NETunnelProviderManager` the app creates.
3. Return it from `appInstanceNonce()`.

A profile must never write that key. `build_profile.py` asserts it does not — otherwise a
profile-delivered policy could masquerade as app-created and lose its authority.

## 6. Build the profile

```bash
cd tad/profile
python3 build_profile.py \
    --bundle-id com.yourco.vpn \
    --provider-bundle-id com.yourco.vpn.PacketTunnel \
    --endpoint vpn.yourco.com:51820 \
    --level moderate \
    --resolver dnsforge-hard
```

Options worth knowing:

| Flag | Effect |
|---|---|
| `--level light\|moderate\|heavy` | the enforced floor. `light` needs no peer but does not defend against website fingerprinting |
| `--resolver dnsforge-hard\|quad9` | `dnsforge-hard` filters ~2.8M domains and breaks things by design; `quad9` is conservative |
| `--allow-undefended-servers` | disables fail-closed peer gating. Weakens the defense substantially |
| `--no-carrier-bypass` | stops excluding carrier visual-voicemail domains from encrypted DNS |

The build asserts: `PayloadVersion == 1` everywhere, no trap keys, `VPNSubType` present
(required when `VPNType` is `VPN`), extension identifier under the app's, on-demand both
enabled *and* pinned, floor not `off`, padding/blocking fractions in range, no
`TADAppInstanceNonce`, and that the in-tunnel resolver and the fallback DNS payload name
the same resolver.

## 7. Sign the profile (optional, recommended)

An unsigned profile shows "Not Verified" on install. To sign with an Apple-issued
certificate:

```bash
openssl smime -sign \
    -signer signing-cert.pem -inkey signing-key.pem -certfile chain.pem \
    -nodetach -outform der \
    -in TAD-Enforced-VPN.mobileconfig \
    -out TAD-Enforced-VPN-signed.mobileconfig

# verify before distributing
openssl smime -verify -inform DER -in TAD-Enforced-VPN-signed.mobileconfig -noverify
```

Signing does not change behaviour; it changes what the install screen tells the user.

## 8. Install and verify

1. AirDrop or email the profile. **Settings → General → VPN & Device Management →
   Downloaded Profile → Install.**
2. Check **Settings → General → VPN & Device Management** lists one profile with two
   payloads.
3. Check **Settings → VPN** shows the configuration, and that *Connect On Demand* is
   present and **greyed out** (`OnDemandUserOverrideDisabled` took effect — iOS 14+).
4. Generate traffic; confirm the tunnel comes up by itself.
5. In the app, confirm the defense control shows as **locked** at or above the floor, and
   that attempting to lower it explains why rather than snapping back.
6. Point the client at a server with no server-side machines and confirm it **refuses** to
   connect (unless built with `--allow-undefended-servers`).
7. Confirm DNS: with the tunnel up, queries should go to the pinned resolver over DoH from
   inside the tunnel; with it down, the DNS payload should still apply.

If you use **Lockdown Mode**, install and verify profiles *first* — Lockdown Mode blocks
configuration-profile installation.

## 9. Supervised hardening (optional)

Supervision cannot add defense capability, only make the deployment harder to undo:
`allowAppRemoval = false`, `allowUIConfigurationProfileInstallation = false`, and a
profile-removal password. Each has a real usability cost — see
[`../daita/README.md`](../daita/README.md) before enabling any of them.

On an unsupervised iPhone the owner can remove the profile, and the VPN, the defense floor
and the pinned DNS all go with it.
