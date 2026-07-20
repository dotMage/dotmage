//! dotmage-client — I/O layer, storage backends, and keychain integration.

pub mod backend;
pub mod backend_fs;
pub mod backend_http;
pub mod config;
pub mod container;
pub mod keychain;
pub mod sync_state;
pub mod token;
pub mod types;
