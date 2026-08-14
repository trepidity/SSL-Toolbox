//! Headless orchestration layer for ssl-toolbox.
//!
//! This crate owns everything the toolbox does *between* raw crypto primitives
//! (`ssl-toolbox-core`) and a user interface. It never prompts, never prints,
//! and never touches a terminal — every result is returned as structured,
//! serde-serializable data so that the CLI, the Tauri GUI, and any future
//! front-end share one implementation.
//!
//! Front-ends are responsible for two things this crate deliberately refuses to
//! do: collecting secrets from the user, and rendering results for humans.

pub mod audit;
pub mod credentials;
pub mod endpoint;
pub mod ops;
pub mod secret;
pub mod settings;
pub mod workflow;

pub use endpoint::EndpointProtocol;
pub use ops::{OpOutcome, OpRequest, OpResult, run};
pub use secret::Secret;
/// Re-exported so front-ends can validate a format choice without depending on
/// the CA trait crate directly.
pub use ssl_toolbox_ca::{CertificateDetails, CertificateSummary, CollectFormat};
