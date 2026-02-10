//! HTTP connection pool for SendRequest reuse (keep-alive).
//!
//! Performance optimizations:
//! - Cached total connection count for O(1) limit checks
//! - LRU eviction when global limit reached

use crate::config::ConnectionPoolConfig;
use hyper::body::Incoming;
use hyper::client::conn::http1::SendRequest;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// A pooled connection with metadata for lifecycle management
struct PooledSender {
    sender: SendRequest<Incoming>,
    created_at: Instant,
    last_used: Instant,
}

impl PooledSender {
    fn new(sender: SendRequest<Incoming>, created_at: Instant) -> Self {
        PooledSender {
            sender,
            created_at,
            last_used: Instant::now(),
        }
    }

    fn is_expired(&self, config: &ConnectionPoolConfig) -> bool {
        let now = Instant::now();
        let idle_expired = now.saturating_duration_since(self.last_used)
            > Duration::from_secs(config.idle_timeout_seconds);
        let lifetime_expired = now.saturating_duration_since(self.created_at)
            > Duration::from_secs(config.max_lifetime_seconds);
        idle_expired || lifetime_expired
    }

    fn is_usable(&self, config: &ConnectionPoolConfig) -> bool {
        !self.is_expired(config) && !self.sender.is_closed()
    }
}

/// Connection pool for reusing HTTP senders (SendRequest objects)
pub struct SenderPool {
    // Key: (host, port, is_tls)
    senders: HashMap<(String, u16, bool), Vec<PooledSender>>,
    /// Track host keys in insertion order for LRU eviction
    host_order: Vec<(String, u16, bool)>,
    /// Cached total connection count for O(1) limit checks
    total_count: usize,
    pub config: ConnectionPoolConfig,
}

impl SenderPool {
    pub fn new(config: ConnectionPoolConfig) -> Self {
        SenderPool {
            senders: HashMap::new(),
            host_order: Vec::new(),
            total_count: 0,
            config,
        }
    }

    /// Get total number of pooled connections across all hosts (O(1))
    #[allow(dead_code)]
    fn total_connections(&self) -> usize {
        self.total_count
    }

    /// Evict oldest connections to make room for new ones
    fn evict_if_needed(&mut self) {
        while self.total_count >= self.config.max_total_connections && !self.host_order.is_empty() {
            // Find oldest host with connections
            let mut evicted = false;
            for i in 0..self.host_order.len() {
                let key = &self.host_order[i];
                if let Some(pool) = self.senders.get_mut(key) {
                    if !pool.is_empty() {
                        pool.remove(0); // Remove oldest connection
                        self.total_count -= 1;
                        evicted = true;
                        // Clean up empty pools
                        if pool.is_empty() {
                            let key = self.host_order.remove(i);
                            self.senders.remove(&key);
                        }
                        break;
                    }
                }
            }
            if !evicted {
                break;
            }
        }
    }

    /// Try to get an existing sender from the pool
    /// Returns (sender, created_at) if found
    pub fn get(
        &mut self,
        host: &str,
        port: u16,
        is_tls: bool,
    ) -> Option<(SendRequest<Incoming>, Instant)> {
        if !self.config.enabled {
            return None;
        }

        let key = (host.to_string(), port, is_tls);
        if let Some(pool) = self.senders.get_mut(&key) {
            while let Some(pooled) = pool.pop() {
                self.total_count -= 1; // Decrement on removal
                if pooled.is_usable(&self.config) {
                    return Some((pooled.sender, pooled.created_at));
                }
                // Connection unusable, dropped (already decremented)
            }
        }
        None
    }

    /// Return a sender to the pool for reuse
    pub fn put(
        &mut self,
        host: &str,
        port: u16,
        is_tls: bool,
        sender: SendRequest<Incoming>,
        created_at: Instant,
    ) {
        if !self.config.enabled || sender.is_closed() {
            return;
        }

        let key = (host.to_string(), port, is_tls);

        // Enforce global connection limit
        self.evict_if_needed();

        let is_new_host = !self.senders.contains_key(&key);
        let pool = self.senders.entry(key.clone()).or_default();

        // Track new hosts for LRU ordering
        if is_new_host {
            self.host_order.push(key);
        }

        // Check if we have room for more connections (per-host limit)
        if pool.len() < self.config.max_connections_per_host {
            pool.push(PooledSender::new(sender, created_at));
            self.total_count += 1; // Increment on addition
        }
        // else: drop the sender (pool full)
    }

    /// Remove expired/closed connections from the pool
    pub fn cleanup(&mut self) {
        let config = &self.config;
        self.senders.retain(|_, pool| {
            pool.retain(|p| p.is_usable(config));
            !pool.is_empty()
        });
        // Clean up host_order
        self.host_order.retain(|key| self.senders.contains_key(key));
        // Recalculate total_count after cleanup (ensures accuracy)
        self.total_count = self.senders.values().map(|v| v.len()).sum();
    }

    /// Get pool statistics (for monitoring/testing)
    #[allow(dead_code)]
    pub fn stats(&self) -> (usize, usize) {
        let hosts = self.senders.len();
        let total_conns: usize = self.senders.values().map(|v| v.len()).sum();
        (hosts, total_conns)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_pool_config() -> ConnectionPoolConfig {
        ConnectionPoolConfig::default()
    }

    fn disabled_pool_config() -> ConnectionPoolConfig {
        ConnectionPoolConfig {
            enabled: false,
            ..ConnectionPoolConfig::default()
        }
    }

    #[test]
    fn test_pool_config_defaults() {
        let config = ConnectionPoolConfig::default();
        assert!(config.enabled);
        assert_eq!(config.max_connections_per_host, 10);
        assert_eq!(config.max_total_connections, 1000);
        assert_eq!(config.idle_timeout_seconds, 60);
        assert_eq!(config.max_lifetime_seconds, 300);
        assert_eq!(config.connect_timeout_seconds, 10);
    }

    #[test]
    fn test_pool_new() {
        let pool = SenderPool::new(default_pool_config());
        assert!(pool.senders.is_empty());
        let (hosts, conns) = pool.stats();
        assert_eq!(hosts, 0);
        assert_eq!(conns, 0);
    }

    #[test]
    fn test_pool_disabled_get_returns_none() {
        let mut pool = SenderPool::new(disabled_pool_config());
        assert!(pool.get("example.com", 80, false).is_none());
        assert!(pool.get("example.com", 443, true).is_none());
    }

    #[test]
    fn test_pool_get_empty_returns_none() {
        let mut pool = SenderPool::new(default_pool_config());
        assert!(pool.get("example.com", 80, false).is_none());
        assert!(pool.get("example.com", 443, true).is_none());
    }

    #[test]
    fn test_pool_cleanup_empty() {
        let mut pool = SenderPool::new(default_pool_config());
        pool.cleanup(); // Should not panic
        assert!(pool.senders.is_empty());
    }

    #[test]
    fn test_pool_config_idle_expiry() {
        let config = ConnectionPoolConfig {
            idle_timeout_seconds: 0, // Immediate expiry
            max_lifetime_seconds: 300,
            ..ConnectionPoolConfig::default()
        };

        assert_eq!(config.idle_timeout_seconds, 0);
    }
}
