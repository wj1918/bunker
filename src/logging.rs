//! Structured logging setup using tracing.

use crate::config::{FileLoggingConfig, LogFormat, LogRotation, LoggingConfig};
use flate2::write::GzEncoder;
use flate2::Compression;
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

/// Guard that must be kept alive for the duration of the program.
/// When dropped, flushes and closes the file writer.
pub struct LogGuard {
    _file_guard: Option<WorkerGuard>,
}

/// Initialize the logging system based on configuration.
/// Returns a guard that must be kept alive for file logging to work.
pub fn init_logging(config: &LoggingConfig) -> LogGuard {
    if !config.log_requests {
        return LogGuard { _file_guard: None };
    }

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    match (&config.format, &config.file) {
        // Text to stdout only
        (LogFormat::Text, None) => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().with_writer(io::stdout))
                .init();
            LogGuard { _file_guard: None }
        }

        // JSON to stdout only
        (LogFormat::Json, None) => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().json().with_writer(io::stdout))
                .init();
            LogGuard { _file_guard: None }
        }

        // Text to stdout + JSON to file
        (LogFormat::Text, Some(file_config)) => {
            let (file_writer, guard) = create_file_writer(file_config);
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().with_writer(io::stdout))
                .with(fmt::layer().json().with_writer(file_writer))
                .init();
            LogGuard {
                _file_guard: Some(guard),
            }
        }

        // JSON to stdout + JSON to file
        (LogFormat::Json, Some(file_config)) => {
            let (file_writer, guard) = create_file_writer(file_config);
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().json().with_writer(io::stdout))
                .with(fmt::layer().json().with_writer(file_writer))
                .init();
            LogGuard {
                _file_guard: Some(guard),
            }
        }
    }
}

fn create_file_writer(
    config: &FileLoggingConfig,
) -> (tracing_appender::non_blocking::NonBlocking, WorkerGuard) {
    // Ensure log directory exists
    fs::create_dir_all(&config.log_dir).ok();

    let rotation = match config.rotation {
        LogRotation::Daily => Rotation::DAILY,
        LogRotation::Hourly => Rotation::HOURLY,
        LogRotation::Never => Rotation::NEVER,
    };

    let file_appender = RollingFileAppender::new(rotation, &config.log_dir, &config.file_prefix);

    tracing_appender::non_blocking(file_appender)
}

/// Spawn a background task to compress rotated logs and clean up old files.
pub fn spawn_log_cleanup_task(config: Arc<LoggingConfig>) {
    if let Some(ref file_config) = config.file {
        let log_dir = file_config.log_dir.clone();
        let file_prefix = file_config.file_prefix.clone();
        let max_age_days = file_config.max_age_days;
        let compress = file_config.compress;

        tokio::spawn(async move {
            // Initial run after 1 minute
            tokio::time::sleep(Duration::from_secs(60)).await;
            if compress {
                compress_rotated_logs(&log_dir, &file_prefix);
            }
            if max_age_days > 0 {
                cleanup_old_logs(&log_dir, &file_prefix, max_age_days);
            }

            // Then hourly (to catch rotated logs promptly)
            loop {
                tokio::time::sleep(Duration::from_secs(3600)).await;
                if compress {
                    compress_rotated_logs(&log_dir, &file_prefix);
                }
                if max_age_days > 0 {
                    cleanup_old_logs(&log_dir, &file_prefix, max_age_days);
                }
            }
        });
    }
}

/// Compress rotated log files that haven't been compressed yet.
/// Rotated files have a date suffix like "proxy.log.2024-01-15".
/// With tracing-appender DAILY rotation, current file is "proxy.log.{today's date}".
fn compress_rotated_logs(log_dir: &str, file_prefix: &str) {
    // Get today's date suffix (UTC) - tracing-appender uses this format
    let today_suffix = chrono::Utc::now().format(".%Y-%m-%d").to_string();
    let today_filename = format!("{}{}", file_prefix, today_suffix);

    let entries = match fs::read_dir(log_dir) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to read log directory for compression");
            return;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();

        // Only process files
        if !path.is_file() {
            continue;
        }

        let filename = match path.file_name().and_then(|n| n.to_str()) {
            Some(name) => name,
            None => continue,
        };

        // Skip if not a log file with our prefix
        if !filename.starts_with(file_prefix) {
            continue;
        }

        // Skip the current active log file (exact match with prefix, or today's dated file)
        if filename == file_prefix || filename == today_filename {
            continue;
        }

        // Skip already compressed files
        if filename.ends_with(".gz") {
            continue;
        }

        // This is a rotated log file - compress it
        if let Err(e) = compress_file(&path) {
            tracing::warn!(path = %path.display(), error = %e, "Failed to compress log file");
        } else {
            tracing::info!(path = %path.display(), "Compressed rotated log file");
        }
    }
}

/// Compress a single file with gzip and remove the original.
fn compress_file(path: &Path) -> io::Result<()> {
    let gz_path = path.with_extension(
        path.extension()
            .map(|e| format!("{}.gz", e.to_string_lossy()))
            .unwrap_or_else(|| "gz".to_string()),
    );

    // Open input file
    let input = File::open(path)?;
    let reader = BufReader::new(input);

    // Create compressed output file
    let output = File::create(&gz_path)?;
    let writer = BufWriter::new(output);
    let mut encoder = GzEncoder::new(writer, Compression::default());

    // Copy data through compressor
    io::copy(&mut BufReader::new(reader), &mut encoder)?;
    encoder.finish()?;

    // Remove original file
    fs::remove_file(path)?;

    Ok(())
}

fn cleanup_old_logs(log_dir: &str, file_prefix: &str, max_age_days: u64) {
    let max_age = Duration::from_secs(max_age_days * 24 * 60 * 60);

    let entries = match fs::read_dir(log_dir) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to read log directory for cleanup");
            return;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();

        // Only process files starting with our prefix
        let filename = match path.file_name().and_then(|n| n.to_str()) {
            Some(name) if name.starts_with(file_prefix) => name,
            _ => continue,
        };

        // Skip the current log file (exact match with prefix)
        if filename == file_prefix {
            continue;
        }

        // Check file age
        let metadata = match path.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };

        let modified = match metadata.modified() {
            Ok(m) => m,
            Err(_) => continue,
        };

        let age = match SystemTime::now().duration_since(modified) {
            Ok(a) => a,
            Err(_) => continue,
        };

        if age > max_age {
            if let Err(e) = fs::remove_file(&path) {
                tracing::warn!(path = %path.display(), error = %e, "Failed to delete old log file");
            } else {
                tracing::info!(path = %path.display(), age_days = age.as_secs() / 86400, "Deleted old log file");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_format_default() {
        assert_eq!(LogFormat::default(), LogFormat::Text);
    }

    #[test]
    fn test_log_rotation_default() {
        assert_eq!(LogRotation::default(), LogRotation::Daily);
    }

    #[test]
    fn test_file_logging_config_default() {
        let config = FileLoggingConfig::default();
        assert_eq!(config.log_dir, "logs");
        assert_eq!(config.file_prefix, "proxy.log");
        assert_eq!(config.max_age_days, 7);
        assert!(config.compress);
    }

    #[test]
    fn test_logging_config_default() {
        let config = LoggingConfig::default();
        assert!(config.log_requests);
        assert_eq!(config.format, LogFormat::Text);
        assert!(config.file.is_none());
    }
}
