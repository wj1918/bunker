//! DNS server module with caching and query validation.

mod cache;
mod resolver;
mod server;
mod validation;
pub mod wire;

pub use server::run_dns_server;
