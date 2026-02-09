//! HTTP/HTTPS proxy module with connection pooling.

mod connect;
mod handler;
mod pool;

pub use handler::handle_client;
pub use pool::SenderPool;
