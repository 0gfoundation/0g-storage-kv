//! Packs `(stream_id, key, value)` writes into stream-data payloads capped by
//! total value bytes and key count, and wraps the encoded payload for upload
//! (plaintext, symmetric encryption, or ECIES). See spec §4 steps 4 and 6.

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
        // declared version is u64::MAX (first 8 bytes of encoding)
        assert_eq!(&built.encoded[..8], &u64::MAX.to_be_bytes());
    }

    #[test]
    fn encryption_wrap_changes_size() {
        let plain = into_upload_data(vec![0u8; 32], None, None).unwrap();
        let v1 = into_upload_data(vec![0u8; 32], Some([7u8; 32]), None).unwrap();
        assert!(v1.size() > plain.size()); // header prepended
    }
}
