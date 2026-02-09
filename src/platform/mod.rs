//! Platform-specific code (Windows tray, etc.)

#[cfg(windows)]
pub mod windows_tray;

#[cfg(windows)]
#[allow(unused_imports)]
pub use windows_tray::{setup_tray, TrayMessage};
