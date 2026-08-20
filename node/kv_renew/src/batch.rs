//! Packs `(stream_id, key, value)` writes into stream-data payloads capped by
//! total value bytes and key count, and wraps the encoded payload for upload
//! (plaintext, symmetric encryption, or ECIES). See spec §4 steps 4 and 6.

use anyhow::{Context, Result};
use ethereum_types::H256;
use std::collections::HashSet;
use std::sync::Arc;
use zg_storage_client::core::dataflow::IterableData;
use zg_storage_client::core::encrypted_data::EncryptedData;
use zg_storage_client::core::in_mem::DataInMemory;
use zg_storage_client::kv::builder::StreamDataBuilder;

/// Accumulates writes for a single upload, bounded by `max_bytes` (total
/// value bytes) and `max_keys` (number of writes). Caller re-pushes a
/// rejected item into a fresh batch.
pub struct ValueBatcher {
    builder: StreamDataBuilder,
    max_bytes: usize,
    max_keys: usize,
    bytes: usize,
    keys: Vec<(H256, Vec<u8>)>,
    seen: HashSet<(H256, Vec<u8>)>,
}

/// Result of [`ValueBatcher::finish`]: the encoded stream-data payload ready
/// for upload, its stream-id tags, and the `(stream_id, key)` pairs this
/// batch renews (for cycle bookkeeping).
pub struct BuiltBatch {
    pub encoded: Vec<u8>,
    pub tags: Vec<u8>,
    pub keys: Vec<(H256, Vec<u8>)>,
    pub bytes: usize,
}

impl ValueBatcher {
    pub fn new(max_bytes: usize, max_keys: usize) -> Self {
        Self {
            builder: StreamDataBuilder::new(u64::MAX),
            max_bytes,
            max_keys,
            bytes: 0,
            keys: Vec::new(),
            seen: HashSet::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// `false` = batch full, item NOT added (caller finishes batch and re-pushes).
    /// An oversized value is accepted when the batch is empty (its own batch).
    ///
    /// A repeated `(stream_id, key)` within the same batch is dropped:
    /// `push` returns `true` without touching `builder`/`bytes`/`keys`. The
    /// scanner feeds only the latest version per key, so a duplicate push
    /// carries the same value — dropping it keeps the bytes/keys bookkeeping
    /// accurate without attempting newest-wins overwrite. Returning `false`
    /// here would be wrong: `false` means "batch full, retry in a new
    /// batch," and retrying a duplicate would loop forever since it can
    /// never fit even an empty batch.
    pub fn push(&mut self, stream_id: H256, key: Vec<u8>, value: Vec<u8>) -> bool {
        let dup = (stream_id, key.clone());
        if self.seen.contains(&dup) {
            return true;
        }
        let empty = self.is_empty();
        let full = (!empty && self.bytes + value.len() > self.max_bytes)
            || self.keys.len() >= self.max_keys;
        if full {
            return false;
        }
        self.bytes += value.len();
        self.builder.set(stream_id, &key, value);
        self.seen.insert(dup);
        self.keys.push((stream_id, key));
        true
    }

    /// Builds and encodes the accumulated writes. Consumes `self` since a
    /// finished batch is not meant to be reused.
    pub fn finish(self) -> Result<BuiltBatch> {
        let data = self.builder.build(None)?;
        let encoded = data.encode()?;
        let tags = self.builder.build_tags(None);
        Ok(BuiltBatch {
            encoded,
            tags,
            keys: self.keys,
            bytes: self.bytes,
        })
    }
}

/// Wraps an encoded batch for upload. v1 (symmetric): `EncryptedData::new`
/// with the given key. v2 (ECIES): derives the recipient's compressed SEC1
/// public key from `wallet_private_key` and calls `EncryptedData::new_ecies`.
/// Neither: uploads the plaintext `DataInMemory` as-is.
pub fn into_upload_data(
    encoded: Vec<u8>,
    encryption_key: Option<[u8; 32]>,
    wallet_private_key: Option<[u8; 32]>,
) -> Result<Arc<dyn IterableData>> {
    let inner: Arc<dyn IterableData> = Arc::new(DataInMemory::new(encoded)?);
    match (encryption_key, wallet_private_key) {
        (Some(key), _) => Ok(Arc::new(EncryptedData::new(inner, key)?)),
        (None, Some(pk)) => {
            let secret = k256::SecretKey::from_slice(&pk).context("invalid wallet_private_key")?;
            let pubkey = secret.public_key().to_sec1_bytes();
            Ok(Arc::new(EncryptedData::new_ecies(inner, &pubkey)?))
        }
        (None, None) => Ok(inner),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethereum_types::H256;

    #[test]
    fn caps_by_bytes_and_keys() {
        let sid = H256::repeat_byte(1);
        let mut b = ValueBatcher::new(100, 10);
        assert!(b.push(sid, b"a".to_vec(), vec![0; 60]));
        assert!(!b.push(sid, b"b".to_vec(), vec![0; 60])); // would exceed 100 bytes

        let mut b2 = ValueBatcher::new(1 << 20, 2);
        assert!(b2.push(sid, b"a".to_vec(), vec![1]));
        assert!(b2.push(sid, b"b".to_vec(), vec![2]));
        assert!(!b2.push(sid, b"c".to_vec(), vec![3])); // key cap
    }

    #[test]
    fn oversized_value_allowed_alone() {
        let sid = H256::repeat_byte(1);
        let mut b = ValueBatcher::new(10, 10);
        assert!(b.push(sid, b"big".to_vec(), vec![0; 500]));
        assert!(!b.push(sid, b"next".to_vec(), vec![0]));
    }

    #[test]
    fn finish_encodes_with_tags_and_keys() {
        let sid = H256::repeat_byte(1);
        let mut b = ValueBatcher::new(1 << 20, 10);
        b.push(sid, b"k".to_vec(), b"v".to_vec());
        let built = b.finish().unwrap();
        assert!(!built.encoded.is_empty());
        assert_eq!(built.tags.len(), 64); // STREAM_DOMAIN + one stream id
        assert_eq!(built.keys, vec![(sid, b"k".to_vec())]);
        assert_eq!(built.bytes, 1); // len(b"v")
                                    // declared version is u64::MAX (first 8 bytes of encoding)
        assert_eq!(&built.encoded[..8], &u64::MAX.to_be_bytes());
    }

    #[test]
    fn duplicate_key_push_is_dropped() {
        let sid = H256::repeat_byte(1);
        let mut b = ValueBatcher::new(1 << 20, 10);
        assert!(b.push(sid, b"k".to_vec(), b"v".to_vec()));
        // Same (stream_id, key) pushed again: dropped, not double-counted.
        assert!(b.push(sid, b"k".to_vec(), b"v".to_vec()));
        let built = b.finish().unwrap();
        assert_eq!(built.keys, vec![(sid, b"k".to_vec())]);
        assert_eq!(built.bytes, 1); // counted once, not twice
                                    // version (8 bytes) + reads count (4 bytes, 0 reads) + writes count
                                    // (4 bytes) must show exactly one write, not two.
        assert_eq!(&built.encoded[8..12], &0u32.to_be_bytes());
        assert_eq!(&built.encoded[12..16], &1u32.to_be_bytes());
    }

    #[test]
    fn encryption_wrap_changes_size() {
        let plain = into_upload_data(vec![0u8; 32], None, None).unwrap();
        let v1 = into_upload_data(vec![0u8; 32], Some([7u8; 32]), None).unwrap();
        assert!(v1.size() > plain.size()); // header prepended
    }
}
