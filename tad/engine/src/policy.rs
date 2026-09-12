//! The policy layer — what makes the defense *enforceable* rather than merely available.
//!
//! A policy arrives from one of two places, and the difference is the whole point:
//!
//! - [`PolicySource::Profile`]: the dictionary iOS handed the tunnel in
//!   `NETunnelProviderProtocol.providerConfiguration`, which an MDM/configuration profile
//!   populated via the VPN payload's `VendorConfig`. The user cannot edit it without
//!   removing the profile.
//! - [`PolicySource::User`]: the app's own settings UI.
//!
//! A profile-sourced policy with `enforced = true` establishes a *floor*. The user may
//! raise the defense level above it; any attempt to go below is refused rather than
//! silently clamped, so the UI can render the control as locked and explain why.

use serde::{Deserialize, Serialize};

/// How much cover traffic the defense is allowed to generate.
///
/// Ordered: a higher level is strictly more protective and strictly more expensive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DefenseLevel {
    /// No machines. The tunnel is a plain tunnel.
    Off,
    /// Coarsen NetFlow records only. Negligible overhead; does not defend against
    /// website fingerprinting.
    Light,
    /// Interspace. General-purpose website-fingerprinting defense.
    Moderate,
    /// Scrambler. Aimed at traffic with strong shape signal (video, large page loads).
    Heavy,
}

/// Which end of the tunnel an engine is running on.
///
/// The same crate runs on the phone and on the VPN server; only the machine set differs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Client,
    Server,
}

impl DefenseLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Light => "light",
            Self::Moderate => "moderate",
            Self::Heavy => "heavy",
        }
    }

    /// Client-side machine specifications for this level, in `maybenot-machines`
    /// string form.
    pub fn client_machines(self) -> &'static [&'static str] {
        match self {
            Self::Off => &[],
            Self::Light => &["netflow"],
            Self::Moderate => &["interspace_client"],
            Self::Heavy => &["scrambler_client"],
        }
    }

    /// Machines the *peer* must run for this level to actually defend anything.
    ///
    /// This is not decoration. Maybenot machines are paired: the client shapes what it
    /// sends, the server shapes what it sends back. Downstream traffic carries most of
    /// the website-fingerprinting signal, so a client-only deployment defends roughly
    /// the direction that matters least. If the peer cannot run these, the honest
    /// options are to refuse the connection or to tell the user the defense is partial —
    /// see [`Policy::preflight`].
    pub fn server_machines(self) -> &'static [&'static str] {
        match self {
            Self::Off => &[],
            // NetFlow coarsening is symmetric and self-contained; no peer machine.
            Self::Light => &[],
            Self::Moderate => &["interspace_server"],
            Self::Heavy => &["scrambler_server 4.0 2.0 1.0 8.0"],
        }
    }

    /// Machine specifications for one end of the tunnel.
    pub fn machines(self, role: Role) -> &'static [&'static str] {
        match role {
            Role::Client => self.client_machines(),
            Role::Server => self.server_machines(),
        }
    }

    /// Whether this level is meaningless without peer-side machines.
    ///
    /// Empirically, not a formality: `interspace_client`'s start state transitions on
    /// `PaddingRecv`, so with no peer sending padding the client machine never leaves
    /// state 0 and the "defense" is a no-op. See tests/two_sided.rs.
    pub fn requires_peer(self) -> bool {
        !self.server_machines().is_empty()
    }
}

impl std::str::FromStr for DefenseLevel {
    type Err = PolicyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "light" => Ok(Self::Light),
            "moderate" => Ok(Self::Moderate),
            "heavy" => Ok(Self::Heavy),
            other => Err(PolicyError::UnknownLevel(other.to_string())),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicySource {
    /// Built-in fallback used when nothing else supplied a policy.
    Default,
    /// The app's own settings UI.
    User,
    /// `providerConfiguration`, i.e. a configuration profile's `VendorConfig`.
    Profile,
}

#[derive(Clone, Debug, PartialEq)]
pub enum PolicyError {
    UnknownLevel(String),
    /// `enforced` was set by something other than a configuration profile. Only a
    /// profile-sourced policy may bind the user, otherwise the app's own UI could
    /// claim to be enforcing against the person operating it.
    EnforcedWithoutProfile,
    FractionOutOfRange(&'static str, f64),
    /// The user asked for a level below the enforced floor.
    BelowEnforcedFloor {
        requested: DefenseLevel,
        floor: DefenseLevel,
    },
    /// The peer cannot run the machines this level needs, and the policy says fail closed.
    PeerUnsupported(DefenseLevel),
    Malformed(String),
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownLevel(s) => write!(f, "unknown defense level: {s}"),
            Self::EnforcedWithoutProfile => {
                write!(f, "only a profile-delivered policy may set enforced = true")
            }
            Self::FractionOutOfRange(k, v) => write!(f, "{k} must be in [0.0, 1.0], got {v}"),
            Self::BelowEnforcedFloor { requested, floor } => write!(
                f,
                "defense level {} is below the enforced floor {}",
                requested.as_str(),
                floor.as_str()
            ),
            Self::PeerUnsupported(l) => write!(
                f,
                "peer does not support the machines required for level {}",
                l.as_str()
            ),
            Self::Malformed(s) => write!(f, "malformed policy: {s}"),
        }
    }
}

impl std::error::Error for PolicyError {}

/// The wire form of a policy, as delivered in `VendorConfig`.
///
/// Plist values reach the extension as strings, numbers or booleans depending on how the
/// profile was authored, so every field is tolerant on the way in. The Swift side
/// serialises `providerConfiguration` to JSON and hands it to [`Policy::from_json`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Policy {
    /// The floor when `enforced`, otherwise the default the app starts at.
    pub level: DefenseLevel,
    /// Whether the user may go below `level`. Only meaningful from a profile.
    #[serde(default)]
    pub enforced: bool,
    /// Refuse to connect rather than run a level the peer cannot support.
    #[serde(default = "default_true")]
    pub require_peer_support: bool,
    /// Fraction of traffic that may be padding, passed to Maybenot as a hard cap.
    #[serde(default = "default_padding_frac")]
    pub max_padding_frac: f64,
    /// Fraction of time outgoing traffic may be blocked, passed to Maybenot.
    #[serde(default = "default_blocking_frac")]
    pub max_blocking_frac: f64,
    /// Pad every tunnel packet to a constant size. This is a transport-layer setting,
    /// not a Maybenot machine — see ARCHITECTURE.md.
    #[serde(default = "default_true")]
    pub constant_packet_size: bool,
    #[serde(default = "default_source")]
    pub source: PolicySource,
}

fn default_true() -> bool {
    true
}
fn default_padding_frac() -> f64 {
    0.5
}
fn default_blocking_frac() -> f64 {
    0.2
}
fn default_source() -> PolicySource {
    PolicySource::Default
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            level: DefenseLevel::Off,
            enforced: false,
            require_peer_support: true,
            max_padding_frac: default_padding_frac(),
            max_blocking_frac: default_blocking_frac(),
            constant_packet_size: true,
            source: PolicySource::Default,
        }
    }
}

impl Policy {
    /// Parse and validate a policy delivered as JSON.
    pub fn from_json(s: &str) -> Result<Self, PolicyError> {
        let p: Policy =
            serde_json::from_str(s).map_err(|e| PolicyError::Malformed(e.to_string()))?;
        p.validate()?;
        Ok(p)
    }

    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.enforced && self.source != PolicySource::Profile {
            return Err(PolicyError::EnforcedWithoutProfile);
        }
        if !(0.0..=1.0).contains(&self.max_padding_frac) {
            return Err(PolicyError::FractionOutOfRange(
                "max_padding_frac",
                self.max_padding_frac,
            ));
        }
        if !(0.0..=1.0).contains(&self.max_blocking_frac) {
            return Err(PolicyError::FractionOutOfRange(
                "max_blocking_frac",
                self.max_blocking_frac,
            ));
        }
        Ok(())
    }

    /// Resolve the level to actually run, given what the user asked for.
    ///
    /// Raising above an enforced floor is always allowed — enforcement sets a minimum,
    /// not a maximum. Going below is refused, never silently clamped, so the caller has
    /// to decide what to show the user.
    pub fn resolve(&self, requested: DefenseLevel) -> Result<DefenseLevel, PolicyError> {
        if !self.enforced {
            return Ok(requested);
        }
        if requested < self.level {
            return Err(PolicyError::BelowEnforcedFloor {
                requested,
                floor: self.level,
            });
        }
        Ok(requested)
    }

    /// Whether the user interface should present the defense control as locked.
    pub fn is_locked(&self) -> bool {
        self.enforced && self.source == PolicySource::Profile
    }

    /// Gate the connection on peer capability.
    ///
    /// With `require_peer_support` set, a level whose machines need a peer counterpart
    /// will not start against a peer that lacks them. That is the fail-closed choice:
    /// better no tunnel than a tunnel the user believes is defended and is not.
    pub fn preflight(
        &self,
        level: DefenseLevel,
        peer_supports: bool,
    ) -> Result<(), PolicyError> {
        if level.requires_peer() && !peer_supports && self.require_peer_support {
            return Err(PolicyError::PeerUnsupported(level));
        }
        Ok(())
    }
}
