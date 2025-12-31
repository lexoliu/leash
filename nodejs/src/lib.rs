//! Node.js bindings for leash sandbox library
//!
//! This crate provides NAPI-RS bindings to expose leash's sandboxing
//! capabilities to Node.js/TypeScript applications.

#![deny(clippy::all)]

mod child;
mod command;
mod config;
mod error;
mod ipc;
mod network;
mod python;
mod sandbox;
mod security;

// Re-export main types for NAPI
pub use child::ChildProcessJs;
pub use command::{Command, ExitStatusJs, ProcessOutputJs, StdioConfigJs};
pub use config::{preset_python_data_science, preset_python_dev, preset_strict, SandboxConfigJs};
pub use ipc::{create_ipc_router, IpcRouterJs};
pub use network::{DomainRequestJs, NetworkPolicyConfig};
pub use python::{PythonConfigJs, VenvConfigJs};
pub use sandbox::{create_sandbox, Sandbox};
pub use security::{security_config_permissive, security_config_strict, SecurityConfigJs};
