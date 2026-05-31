//! DNS response cache for reducing upstream queries.

use crate::config::DnsCacheConfig;
use crate::dns::wire::RecordType;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// A cached DNS response entry
struct DnsCacheEntry {
    response: Vec<u8>,
    expires_at: Instant,
    #[allow(dead_code)] // Useful for debugging
    ttl_seconds: u64,
}

/// DNS response cache for reducing upstream queries
pub struct DnsCache {
    entries: HashMap<String, DnsCacheEntry>,
    config: DnsCacheConfig,
}

impl DnsCache {
    pub fn new(config: DnsCacheConfig) -> Self {
        DnsCache {
            entries: HashMap::new(),
            config,
        }
    }

    /// Create cache key from query name and type
    fn make_key(name: &str, query_type: RecordType) -> String {
        format!("{}:{:?}", name.to_lowercase(), query_type)
    }

    /// Get cached response if valid and not expired
    pub fn get(&self, name: &str, query_type: RecordType, query_id: u16) -> Option<Vec<u8>> {
        if !self.config.enabled {
            return None;
        }

        let key = Self::make_key(name, query_type);
        if let Some(entry) = self.entries.get(&key) {
            if Instant::now() < entry.expires_at {
                // Clone and update the ID to match the query
                let mut response = entry.response.clone();
                if response.len() >= 2 {
                    response[0] = (query_id >> 8) as u8;
                    response[1] = query_id as u8;
                }
                return Some(response);
            }
        }
        None
    }

    /// Get cached response even if expired (for serve_stale when all upstreams fail)
    pub fn get_stale(&self, name: &str, query_type: RecordType, query_id: u16) -> Option<Vec<u8>> {
        let key = Self::make_key(name, query_type);
        if let Some(entry) = self.entries.get(&key) {
            // Return response regardless of expiry (serve stale)
            let mut response = entry.response.clone();
            if response.len() >= 2 {
                response[0] = (query_id >> 8) as u8;
                response[1] = query_id as u8;
            }
            return Some(response);
        }
        None
    }

    /// Store response in cache with TTL
    pub fn put(&mut self, name: &str, query_type: RecordType, response: Vec<u8>, ttl: u64) {
        if !self.config.enabled {
            return;
        }

        // Enforce max entries limit (simple eviction: remove oldest expired first, then any)
        if self.entries.len() >= self.config.max_entries {
            self.cleanup();
            // If still at limit after cleanup, remove one entry
            if self.entries.len() >= self.config.max_entries {
                if let Some(key) = self.entries.keys().next().cloned() {
                    self.entries.remove(&key);
                }
            }
        }

        // Apply min/max TTL bounds
        let effective_ttl = ttl
            .max(self.config.min_ttl_seconds)
            .min(self.config.max_ttl_seconds);

        let key = Self::make_key(name, query_type);
        self.entries.insert(
            key,
            DnsCacheEntry {
                response,
                expires_at: Instant::now() + Duration::from_secs(effective_ttl),
                ttl_seconds: effective_ttl,
            },
        );
    }

    /// Remove expired entries
    pub fn cleanup(&mut self) {
        let now = Instant::now();
        self.entries.retain(|_, entry| entry.expires_at > now);
    }

    /// Get cache statistics (test only)
    #[cfg(test)]
    pub fn stats(&self) -> (usize, usize) {
        let total = self.entries.len();
        let now = Instant::now();
        let valid = self.entries.values().filter(|e| e.expires_at > now).count();
        (total, valid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> DnsCacheConfig {
        DnsCacheConfig::default()
    }

    #[test]
    fn test_cache_new() {
        let cache = DnsCache::new(default_config());
        let (total, valid) = cache.stats();
        assert_eq!(total, 0);
        assert_eq!(valid, 0);
    }

    #[test]
    fn test_cache_put_get() {
        let mut cache = DnsCache::new(default_config());
        let response = vec![0, 1, 2, 3, 4, 5];

        cache.put("example.com", RecordType::A, response.clone(), 300);

        let result = cache.get("example.com", RecordType::A, 0x1234);
        assert!(result.is_some());

        let cached = result.unwrap();
        // First two bytes should be updated to query ID
        assert_eq!(cached[0], 0x12);
        assert_eq!(cached[1], 0x34);
        // Rest should match
        assert_eq!(&cached[2..], &response[2..]);
    }

    #[test]
    fn test_cache_disabled() {
        let config = DnsCacheConfig {
            enabled: false,
            ..default_config()
        };
        let mut cache = DnsCache::new(config);

        cache.put("example.com", RecordType::A, vec![0, 1, 2, 3], 300);

        let result = cache.get("example.com", RecordType::A, 0);
        assert!(result.is_none());
    }

    #[test]
    fn test_cache_ttl_bounds() {
        let config = DnsCacheConfig {
            enabled: true,
            min_ttl_seconds: 60,
            max_ttl_seconds: 3600,
            ..default_config()
        };
        let mut cache = DnsCache::new(config);

        // TTL should be clamped to min/max
        cache.put("example.com", RecordType::A, vec![0, 1, 2, 3], 5); // Below min
        let (total, _) = cache.stats();
        assert_eq!(total, 1);
    }

    #[test]
    fn test_cache_cleanup() {
        let mut cache = DnsCache::new(default_config());
        cache.put("example.com", RecordType::A, vec![0, 1, 2, 3], 1);

        let (total_before, _) = cache.stats();
        assert_eq!(total_before, 1);

        cache.cleanup();
        let (total_after, _) = cache.stats();
        assert!(total_after <= total_before);
    }

    #[test]
    fn test_cache_key_case_insensitive() {
        let mut cache = DnsCache::new(default_config());
        cache.put("EXAMPLE.COM", RecordType::A, vec![0, 1, 2, 3], 300);

        let result = cache.get("example.com", RecordType::A, 0);
        assert!(result.is_some());
    }

    #[test]
    fn test_cache_different_record_types() {
        let mut cache = DnsCache::new(default_config());
        cache.put("example.com", RecordType::A, vec![1, 1, 1, 1], 300);
        cache.put("example.com", RecordType::AAAA, vec![2, 2, 2, 2], 300);

        let a_result = cache.get("example.com", RecordType::A, 0);
        let aaaa_result = cache.get("example.com", RecordType::AAAA, 0);

        assert!(a_result.is_some());
        assert!(aaaa_result.is_some());
        assert_ne!(a_result.unwrap()[2], aaaa_result.unwrap()[2]);
    }

    #[test]
    fn test_cache_get_stale() {
        let mut cache = DnsCache::new(default_config());
        let response = vec![0, 1, 2, 3, 4, 5];

        cache.put("example.com", RecordType::A, response.clone(), 300);

        // get_stale should work even for valid entries
        let result = cache.get_stale("example.com", RecordType::A, 0xABCD);
        assert!(result.is_some());

        let stale = result.unwrap();
        // First two bytes should be updated to query ID
        assert_eq!(stale[0], 0xAB);
        assert_eq!(stale[1], 0xCD);
    }

    #[test]
    fn test_cache_get_stale_nonexistent() {
        let cache = DnsCache::new(default_config());
        let result = cache.get_stale("nonexistent.com", RecordType::A, 0);
        assert!(result.is_none());
    }

    #[test]
    fn test_cache_max_entries_eviction() {
        let config = DnsCacheConfig {
            enabled: true,
            max_entries: 3,
            min_ttl_seconds: 30,
            max_ttl_seconds: 300,
        };
        let mut cache = DnsCache::new(config);

        // Add 3 entries (at max)
        cache.put("one.com", RecordType::A, vec![1, 1], 300);
        cache.put("two.com", RecordType::A, vec![2, 2], 300);
        cache.put("three.com", RecordType::A, vec![3, 3], 300);

        let (total, _) = cache.stats();
        assert_eq!(total, 3);

        // Add 4th entry - should trigger eviction
        cache.put("four.com", RecordType::A, vec![4, 4], 300);

        let (total_after, _) = cache.stats();
        assert!(total_after <= 3);

        // New entry should be accessible
        let result = cache.get("four.com", RecordType::A, 0);
        assert!(result.is_some());
    }

    #[test]
    fn test_cache_ttl_max_bound() {
        let config = DnsCacheConfig {
            enabled: true,
            min_ttl_seconds: 30,
            max_ttl_seconds: 100,
            max_entries: 1000,
        };
        let mut cache = DnsCache::new(config);

        // TTL above max should be clamped
        cache.put("example.com", RecordType::A, vec![0, 1, 2, 3], 10000);
        let (total, _) = cache.stats();
        assert_eq!(total, 1);
    }

    #[test]
    fn test_cache_query_id_update_short_response() {
        let mut cache = DnsCache::new(default_config());
        // Response with only 2 bytes
        let response = vec![0xFF, 0xFF];
        cache.put("example.com", RecordType::A, response, 300);

        let result = cache.get("example.com", RecordType::A, 0x0102);
        assert!(result.is_some());
        let cached = result.unwrap();
        assert_eq!(cached[0], 0x01);
        assert_eq!(cached[1], 0x02);
    }

    #[test]
    fn test_cache_get_missing_entry() {
        let cache = DnsCache::new(default_config());
        let result = cache.get("nonexistent.com", RecordType::A, 0);
        assert!(result.is_none());
    }

    #[test]
    fn test_cache_mx_record() {
        let mut cache = DnsCache::new(default_config());
        cache.put("example.com", RecordType::MX, vec![0, 1, 2, 3], 300);

        let result = cache.get("example.com", RecordType::MX, 0);
        assert!(result.is_some());

        // Should not match different record type
        let wrong_type = cache.get("example.com", RecordType::A, 0);
        assert!(wrong_type.is_none());
    }

    #[test]
    fn test_cache_txt_record() {
        let mut cache = DnsCache::new(default_config());
        cache.put("example.com", RecordType::TXT, vec![0, 1, 2, 3, 4, 5], 300);

        let result = cache.get("example.com", RecordType::TXT, 0x5678);
        assert!(result.is_some());
    }

    #[test]
    fn test_cache_ptr_record() {
        let mut cache = DnsCache::new(default_config());
        cache.put(
            "1.168.192.in-addr.arpa",
            RecordType::PTR,
            vec![0, 1, 2, 3],
            300,
        );

        let result = cache.get("1.168.192.in-addr.arpa", RecordType::PTR, 0);
        assert!(result.is_some());
    }

    #[test]
    fn test_cache_make_key() {
        // Test key generation is consistent
        let key1 = DnsCache::make_key("Example.COM", RecordType::A);
        let key2 = DnsCache::make_key("example.com", RecordType::A);
        assert_eq!(key1, key2);

        let key3 = DnsCache::make_key("example.com", RecordType::AAAA);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_cache_put_when_disabled() {
        let config = DnsCacheConfig {
            enabled: false,
            ..default_config()
        };
        let mut cache = DnsCache::new(config);
        cache.put("example.com", RecordType::A, vec![0, 1, 2, 3], 300);

        // Cache should remain empty when disabled
        let (total, _) = cache.stats();
        assert_eq!(total, 0);
    }
}
