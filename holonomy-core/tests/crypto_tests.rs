// @trace TASK-009
mod common;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// We will import this from our module once implemented
use holonomy_core::crypto::dek_cache::DekCache;

#[test]
fn test_cache_hit_and_miss() {
    let cache = DekCache::default();
    let dek_id = "partition_001".to_string();
    let raw_key = vec![0u8; 32]; // Fake 256-bit AES key

    // Ensure it's a miss initially
    assert!(cache.get(&dek_id).is_none());

    // Insert the key
    cache.insert(dek_id.clone(), raw_key.clone());

    // Ensure it's a hit now
    let cached_key = cache.get(&dek_id).expect("Key should be in cache");
    assert_eq!(cached_key.as_slice(), raw_key.as_slice());
}

#[test]
fn test_cache_ttl_expiry() {
    // Create a cache with a very short TTL of 50ms
    let cache = DekCache::new(Duration::from_millis(50));
    let dek_id = "partition_ttl".to_string();
    let raw_key = vec![1u8; 32];

    cache.insert(dek_id.clone(), raw_key);

    // Immediately fetch it (should hit)
    assert!(cache.get(&dek_id).is_some());

    // Sleep for 100ms to force expiry
    thread::sleep(Duration::from_millis(100));

    // Fetch it again (should miss due to lazy expiry)
    assert!(cache.get(&dek_id).is_none());
}

#[test]
fn test_concurrent_access() {
    let cache = Arc::new(DekCache::default());
    let mut handles = vec![];

    // Spawn multiple threads reading and writing to the cache
    for i in 0..10 {
        let c = cache.clone();
        handles.push(thread::spawn(move || {
            let key_id = format!("key_{}", i);
            c.insert(key_id.clone(), vec![i as u8; 32]);
            let val = c.get(&key_id).unwrap();
            assert_eq!(val.as_slice()[0], i as u8);
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

// @trace TASK-031
#[test]
fn test_resolve_dek_partition_logic() {
    let dek_cache = Arc::new(DekCache::default());
    let manager = holonomy_core::manager::crypto_manager::CryptoManager::new(
        dek_cache,
        Arc::new(common::MockKmsProvider),
    );

    let hash1 = manager.resolve_dek("s3://bucket/year=2026", None);
    let hash2 = manager.resolve_dek("s3://bucket/year=2026/", None);

    assert_eq!(hash1, hash2, "Trailing slashes must be sanitized");

    let mut ctx = std::collections::HashMap::new();
    ctx.insert("year".to_string(), "2026".to_string());
    ctx.insert("month".to_string(), "06".to_string());

    // Test context determinism
    let hash_ctx1 = manager.resolve_dek("s3://bucket", Some(&ctx));
    let hash_ctx2 = manager.resolve_dek("s3://bucket/", Some(&ctx));

    assert_eq!(
        hash_ctx1, hash_ctx2,
        "Trailing slashes with context must be sanitized"
    );
}
