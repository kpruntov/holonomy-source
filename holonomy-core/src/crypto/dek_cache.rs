// @trace TASK-009
use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A wrapper around a raw encryption key that guarantees the memory
/// is securely zeroed out when it is dropped from the cache.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PlaintextKey {
    key: Vec<u8>,
}

impl PlaintextKey {
    pub fn new(key: Vec<u8>) -> Self {
        Self { key }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.key
    }
}

/// Internal struct to track the key alongside its expiration time
struct CacheEntry {
    key: Arc<PlaintextKey>,
    expires_at: Instant,
}

/// A thread-safe, concurrent registry for caching Data Encryption Keys (DEKs).
/// Uses DashMap to allow lock-free reads/writes across multiple compute threads.
pub struct DekCache {
    cache: DashMap<String, CacheEntry>,
    default_ttl: Duration,
}

impl DekCache {
    /// Creates a new, empty DEK Cache with a specific default TTL for keys.
    pub fn new(default_ttl: Duration) -> Self {
        Self {
            cache: DashMap::new(),
            default_ttl,
        }
    }

    /// Inserts a new plaintext key into the cache.
    /// The key will automatically be considered expired after the `default_ttl` duration.
    pub fn insert(&self, dek_id: String, raw_key: Vec<u8>) {
        let key = Arc::new(PlaintextKey::new(raw_key));
        let expires_at = Instant::now() + self.default_ttl;

        self.cache.insert(dek_id, CacheEntry { key, expires_at });
    }

    /// Attempts to retrieve a key from the cache.
    /// If the key exists but its TTL has expired, it is lazily removed and `None` is returned.
    pub fn get(&self, dek_id: &str) -> Option<Arc<PlaintextKey>> {
        let mut expired = false;

        // Block to scope the read reference
        if let Some(entry) = self.cache.get(dek_id) {
            if Instant::now() < entry.expires_at {
                return Some(entry.key.clone());
            } else {
                expired = true;
            }
        }

        // Lazy cleanup: if we found it was expired, remove it.
        // We do this outside the read scope to avoid deadlock if DashMap internal buckets collide.
        if expired {
            self.remove(dek_id);
        }

        None
    }

    /// Manually removes a key from the cache.
    /// Once the Arc count reaches 0, the PlaintextKey drop logic will zero the memory.
    pub fn remove(&self, dek_id: &str) {
        self.cache.remove(dek_id);
    }

    /// Actively sweeps the entire cache and removes all expired keys.
    /// Can be called periodically by a background task.
    pub fn sweep(&self) {
        let now = Instant::now();
        self.cache.retain(|_, entry| now < entry.expires_at);
    }
}

impl Default for DekCache {
    fn default() -> Self {
        // Default TTL of 5 minutes if not specified
        Self::new(Duration::from_secs(300))
    }
}
