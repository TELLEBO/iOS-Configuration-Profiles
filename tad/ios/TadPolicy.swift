// TadPolicy.swift — turning what iOS hands the tunnel into an authoritative policy.
//
// NOT COMPILED IN THIS REPOSITORY. There is no Swift toolchain or Apple SDK in the
// environment this was written in, so treat these three files as reference integration
// code to be dropped into an Xcode target, not as build-verified sources. The Rust engine
// they call is built and tested (`cd ../engine && cargo test`).
//
// ── How the enforcement channel works ─────────────────────────────────────────────────
//
// A configuration profile's VPN payload carries a `VendorConfig` dictionary. iOS delivers
// it to this app's packet-tunnel extension as
// `NETunnelProviderProtocol.providerConfiguration`. The app must *choose* to honour it —
// that choice is the entire difference between this design and Mullvad's DAITA, which
// cannot be configured from outside its own app because it never reads this dictionary.
//
// ── Telling a profile-provisioned configuration from our own ──────────────────────────
//
// Only two things can create a VPN configuration bound to our extension: this app (via
// NETunnelProviderManager) and a configuration profile. So the app stamps every
// configuration it creates with a nonce it keeps in its own keychain; a configuration
// carrying TAD keys *without* the nonce came from a profile.
//
// This is deliberately not based on an error code. There is no documented
// `NEVPNError.configurationReadOnly` — the current NEVPNError set is configurationDisabled,
// configurationInvalid, connectionFailed, configurationStale, configurationReadWriteFailed
// and configurationUnknown — so "try to write it and see if it fails" is not a signal that
// can be relied on.
//
// ── What "enforced" honestly means ────────────────────────────────────────────────────
//
// As long as the profile is installed. On a supervised/MDM-managed device that is a real
// control: the profile can be made non-removable. On a personal device the owner can
// remove the profile from Settings, and then the floor goes with it. Enforcement here is a
// commitment device against casual or accidental downgrade, not a defence against the
// device's owner.

import Foundation
import NetworkExtension

enum TadConfigKey {
    static let level = "TADDefenseLevel"
    static let enforced = "TADEnforced"
    static let requirePeerSupport = "TADRequirePeerSupport"
    static let maxPaddingFraction = "TADMaxPaddingFraction"
    static let maxBlockingFraction = "TADMaxBlockingFraction"
    static let constantPacketSize = "TADConstantPacketSize"
    static let serverEndpoint = "TADServerEndpoint"
    /// Written only by this app, never by a profile. Its absence is what identifies a
    /// profile-provisioned configuration.
    static let appNonce = "TADAppInstanceNonce"
}

struct TadPolicyLoader {
    /// The nonce this app wrote into configurations it created, read from the keychain
    /// group shared between the app and the extension.
    let appNonce: String?

    enum Origin: String {
        case profile
        case user
        case `default`
    }

    /// Build the JSON the Rust engine parses.
    ///
    /// Plist values arrive as `String`, `NSNumber` or `Bool` depending on how the profile
    /// was authored — MDM vendors are inconsistent about this and hand-written profiles
    /// more so — so every field is coerced rather than cast.
    func policyJSON(from providerConfiguration: [String: Any]?) throws -> String {
        guard let config = providerConfiguration, !config.isEmpty else {
            return #"{"level":"off","source":"default"}"#
        }

        let origin: Origin = {
            guard let nonce = appNonce,
                  let stamped = config[TadConfigKey.appNonce] as? String,
                  stamped == nonce
            else {
                // No matching stamp: this configuration was not created by this app.
                return .profile
            }
            return .user
        }()

        var policy: [String: Any] = [
            "level": string(config[TadConfigKey.level]) ?? "off",
            "source": origin.rawValue,
        ]

        // A non-profile configuration may not claim enforcement. Dropping the key here
        // rather than passing it through means the engine's own check
        // (EnforcedWithoutProfile) stays a backstop rather than the only guard.
        if origin == .profile, let enforced = bool(config[TadConfigKey.enforced]) {
            policy["enforced"] = enforced
        }
        if let v = bool(config[TadConfigKey.requirePeerSupport]) {
            policy["require_peer_support"] = v
        }
        if let v = double(config[TadConfigKey.maxPaddingFraction]) {
            policy["max_padding_frac"] = v
        }
        if let v = double(config[TadConfigKey.maxBlockingFraction]) {
            policy["max_blocking_frac"] = v
        }
        if let v = bool(config[TadConfigKey.constantPacketSize]) {
            policy["constant_packet_size"] = v
        }

        let data = try JSONSerialization.data(withJSONObject: policy, options: [])
        guard let json = String(data: data, encoding: .utf8) else {
            throw TadError.policyEncodingFailed
        }
        return json
    }

    // MARK: - Coercion

    private func string(_ any: Any?) -> String? {
        switch any {
        case let s as String: return s.lowercased()
        case let n as NSNumber: return n.stringValue
        default: return nil
        }
    }

    private func bool(_ any: Any?) -> Bool? {
        switch any {
        case let b as Bool: return b
        case let n as NSNumber: return n.boolValue
        case let s as String:
            switch s.lowercased() {
            case "true", "yes", "1": return true
            case "false", "no", "0": return false
            default: return nil
            }
        default: return nil
        }
    }

    private func double(_ any: Any?) -> Double? {
        switch any {
        case let d as Double: return d
        case let n as NSNumber: return n.doubleValue
        case let s as String: return Double(s)
        default: return nil
        }
    }
}

enum TadError: Error {
    case policyEncodingFailed
    case policyRejected(TadResult)
    case engineStartFailed(TadResult)

    /// What to show the user. A refused downgrade is not a failure to apologise for — the
    /// control is locked and the person should be told by whom and to what.
    var userFacingDescription: String {
        switch self {
        case .policyEncodingFailed:
            return "The traffic-analysis defense policy could not be read."
        case .policyRejected:
            return "The traffic-analysis defense policy delivered by your configuration profile is invalid."
        case .engineStartFailed(let r) where r == TadResultBelowEnforcedFloor:
            return "Your configuration profile requires a minimum traffic-analysis defense level. You can raise it, but not turn it off."
        case .engineStartFailed(let r) where r == TadResultPeerUnsupported:
            return "This server cannot run the required traffic-analysis defense. Connecting would leave you unprotected, so the connection was refused."
        case .engineStartFailed:
            return "The traffic-analysis defense could not be started."
        }
    }
}
