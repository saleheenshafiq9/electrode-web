//! Electrode command authority.
//!
//! Browser peers and native vehicle peers use separate Zenoh sessions. The
//! browser-to-vehicle paths are the typed mappings and bounded Packet Traffic
//! path in [`CommandPolicy`], plus the schema-verified private simulator
//! MocapFrame relay.

#[allow(unreachable_pub)]
mod firmware;
mod firmware_gate;
mod policy;
mod runtime;
mod velocity_budget;

pub use policy::{
    AuthorizedCommand, CommandPolicy, Delivery, PolicyConfig, PolicyError,
    CANONICAL_FIRMWARE_QUERY_KEYS,
};
pub use runtime::{CommandAuthority, CommandAuthorityConfig};
