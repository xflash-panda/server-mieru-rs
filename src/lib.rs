#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

pub mod acl;
pub mod business;
pub mod config;
pub mod config_auto;
pub mod connection;
pub mod core;
pub mod error;
pub mod logger;
pub mod net;
pub mod outbound;
pub mod relay;

pub use error::{Error, Result};
