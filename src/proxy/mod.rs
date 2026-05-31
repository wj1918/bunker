//! HTTP/HTTPS proxy module with connection pooling.

mod connect;
#[cfg(feature = "engine")]
pub mod engine;
#[cfg(feature = "engine")]
pub mod forward;
pub mod framing;
mod handler;
mod pool;

pub use handler::handle_client;
pub use pool::ShardedSenderPool;
