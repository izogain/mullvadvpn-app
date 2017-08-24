#![deny(missing_docs)]

//! The core components of the talpidaemon VPN client.

#[cfg(test)]
#[macro_use]
extern crate assert_matches;

extern crate duct;

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
extern crate mktemp;

#[macro_use]
extern crate error_chain;
extern crate jsonrpc_core;
#[macro_use]
extern crate jsonrpc_macros;

extern crate talpid_ipc;
extern crate openvpn_plugin;

#[cfg(target_os = "macos")]
extern crate pfctl;

/// Working with processes.
pub mod process;

/// Network primitives.
pub mod net;

/// Abstracts over different VPN tunnel technologies
pub mod tunnel;

/// Abstractions and extra features on `std::mpsc`
pub mod mpsc;

/// Abstractions over different firewalls
pub mod firewall;