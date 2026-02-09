//! Bunker - A lightweight HTTP/HTTPS and DNS proxy library.
//!
//! This crate provides the core functionality for the bunker proxy,
//! exposed as a library for testing and integration purposes.

pub mod body;
pub mod config;
pub mod dns;
pub mod error;
pub mod helpers;
pub mod logging;
pub mod platform;
pub mod proxy;
pub mod security;
pub mod tokio_io;
