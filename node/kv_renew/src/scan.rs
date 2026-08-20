//! Scans a stream's stale keys and fills a [`ValueBatcher`] with their
//! current values, applying the permission/missing/backoff/already-uploaded
//! filters from spec §4 step 3.

use std::collections::HashSet;
use std::sync::Arc;

use anyhow::Result;
use ethereum_types::{H160, H256};
use kv_types::KeyValuePair;
use storage_with_stream::store::read_pair_value;
use storage_with_stream::Store;
use tokio::sync::RwLock;

use crate::batch::ValueBatcher;

/// Stale keys fetched per `get_stale_stream_keys` call. Chosen well under any
/// reasonable SQLite page/row limit; tuned only for scan throughput.
const PAGE_SIZE: u64 = 256;

/// Default cycle length assumed by [`fill_batch`]'s in-scan backoff check
/// when computing [`backoff_until`]'s retry window. `fill_batch`'s signature
/// is frozen (Task 17 depends on it) and carries no live `cycle_secs` input,
/// so this mirrors `RenewConfig::cycle_interval_secs`'s spec default
/// (`renew_cycle_interval_secs = 604800`, spec §4/§7). A future task with the
/// live configured value in scope can call [`backoff_until`] directly (it is
/// a plain pure function) if a non-default cycle length needs to be honored
/// here.
const DEFAULT_CYCLE_SECS: u64 = 604_800;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ScanCounters {
    pub scanned: u64,
    pub skipped_permission: u64,
    pub skipped_missing: u64,
    pub skipped_backoff: u64,
}

/// Fills `batcher` with stale values starting after `cursor`, advancing it.
/// Returns (counters, stream_exhausted).
///
/// Skip rules (spec §4 step 3), checked in order per key:
/// 1. Already uploaded earlier this cycle (`uploaded_this_cycle`) — skipped
///    silently, only `scanned` moves.
/// 2. A prior renew attempt recorded `attempts >= max_attempts` and `now` is
///    still inside its backoff window — `skipped_backoff` counts, no new
///    attempt is recorded (that would just re-arm the same window).
/// 3. `signer` lacks write permission on the key (checked at `u64::MAX`) —
///    `skipped_permission` counts and the denial is recorded.
/// 4. The value bytes are not present locally — `skipped_missing` counts and
///    the read error (or "value missing locally") is recorded.
///
/// When `batcher.push` refuses an item (batch full), `cursor` is NOT
/// advanced past that key: the caller finishes this batch and re-scans from
/// `cursor`, so the same key leads the next batch.
#[allow(clippy::too_many_arguments)] // signature is frozen: Task 17 depends on it exactly
pub async fn fill_batch(
    store: &Arc<RwLock<dyn Store>>,
    stream_id: H256,
    cutoff: u64,
    cursor: &mut Vec<u8>,
    batcher: &mut ValueBatcher,
    signer: H160,
    uploaded_this_cycle: &HashSet<(H256, Vec<u8>)>,
    max_attempts: u64,
    now: u64,
) -> Result<(ScanCounters, bool)> {
    // TODO(step 3): scan pages, apply the four skip rules, feed the batcher.
    let _ = (
        &store,
        stream_id,
        cutoff,
        &cursor,
        &batcher,
        signer,
        uploaded_this_cycle,
        max_attempts,
        now,
    );
    Ok((ScanCounters::default(), true))
}

/// Exponential backoff deadline for a key stuck past `max_attempts`:
/// `last_ts + cycle_secs << min(attempts, 4)` (capped at a 16x multiplier).
pub fn backoff_until(_attempts: u64, _last_ts: u64, _cycle_secs: u64) -> u64 {
    // TODO(step 3): last_ts + cycle_secs << min(attempts, 4)
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethereum_types::H160;
    use kv_types::StreamWrite as KvStreamWrite;
    use kv_types::{AccessControl, AccessControlSet, KVTransaction, StreamWriteSet};
    use storage_with_stream::{AccessControlOps, StoreManager};

    /// Seeds `keys` (each `(key_bytes, present)`) as stale stream writes at
    /// `ts`, one per sequential tx starting at seq 0 (required by
    /// `put_stream`'s replay-progress guard on a fresh DB).
    ///
    /// Seeding approach: rather than writing real flow-store chunks, a
    /// `present` key gets an EMPTY write range (`start_index == end_index`)
    /// so `read_pair_value`'s fast path returns `Some(vec![])` without
    /// touching the flow store; a `missing` key gets a non-empty range with
    /// no chunks ever appended, so `get_chunk_by_flow_index` finds nothing
    /// and `read_pair_value` returns `Ok(None)`. This sidesteps
    /// `put_chunks_with_tx_hash`'s entry/proof bookkeeping entirely, which
    /// the task brief calls out as an acceptable simplification.
    async fn seed_stale_keys(
        store: &Arc<RwLock<dyn Store>>,
        stream_id: H256,
        keys: &[(&[u8], bool)],
        ts: u64,
    ) {
        let mut guard = store.write().await;
        for (i, (key, present)) in keys.iter().enumerate() {
            let seq = i as u64;
            let tx = KVTransaction {
                stream_ids: vec![stream_id],
                sender: H160::zero(),
                data_merkle_root: H256::zero(),
                merkle_nodes: vec![(1, H256::zero())],
                start_entry_index: seq + 1,
                size: 256,
                seq,
            };
            guard.put_tx(tx).unwrap();
            guard.put_tx_block_time(seq, ts).unwrap();

            let (start_index, end_index) = if *present {
                (0u64, 0u64)
            } else {
                (0u64, 256u64)
            };
            let write_set = StreamWriteSet {
                stream_writes: vec![KvStreamWrite {
                    stream_id,
                    key: Arc::new(key.to_vec()),
                    start_index,
                    end_index,
                }],
            };
            let acl = AccessControlSet {
                access_controls: vec![],
                is_admin: Default::default(),
            };
            guard
                .put_stream(seq, H256::zero(), "Commit".into(), Some((write_set, acl)))
                .await
                .unwrap();
        }
    }

    /// Seeds one stale key at `seq` 0 plus a foreign admin grant in the same
    /// commit, so the stream is no longer "new" (an access-control row now
    /// exists) but `signer` holds no role on it — `has_write_permission`
    /// returns false for `signer`.
    async fn seed_stream_with_foreign_admin(
        store: &Arc<RwLock<dyn Store>>,
        stream_id: H256,
        key: &[u8],
        foreign_admin: H160,
        ts: u64,
    ) {
        let mut guard = store.write().await;
        let tx = KVTransaction {
            stream_ids: vec![stream_id],
            sender: H160::zero(),
            data_merkle_root: H256::zero(),
            merkle_nodes: vec![(1, H256::zero())],
            start_entry_index: 1,
            size: 256,
            seq: 0,
        };
        guard.put_tx(tx).unwrap();
        guard.put_tx_block_time(0, ts).unwrap();

        let write_set = StreamWriteSet {
            stream_writes: vec![KvStreamWrite {
                stream_id,
                key: Arc::new(key.to_vec()),
                start_index: 0,
                end_index: 0,
            }],
        };
        let acl = AccessControlSet {
            access_controls: vec![AccessControl {
                op_type: AccessControlOps::GRANT_ADMIN_ROLE,
                stream_id,
                key: Arc::new(vec![]),
                account: foreign_admin,
                operator: foreign_admin,
            }],
            is_admin: Default::default(),
        };
        guard
            .put_stream(0, H256::zero(), "Commit".into(), Some((write_set, acl)))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn fill_batch_filters_and_advances_cursor() {
        let store: Arc<RwLock<dyn Store>> =
            Arc::new(RwLock::new(StoreManager::memorydb().await.unwrap()));
        let sid = H256::repeat_byte(5);
        let signer = H160::repeat_byte(9);
        seed_stale_keys(
            &store,
            sid,
            &[(b"a", true), (b"b", false), (b"c", true)],
            100,
        )
        .await;

        let mut batcher = ValueBatcher::new(1 << 20, 100);
        let mut cursor = vec![];
        let (counters, done) = fill_batch(
            &store,
            sid,
            1_000,
            &mut cursor,
            &mut batcher,
            signer,
            &HashSet::new(),
            3,
            2_000,
        )
        .await
        .unwrap();

        assert!(done);
        assert_eq!(counters.scanned, 3);
        assert_eq!(counters.skipped_missing, 1);
        assert_eq!(counters.skipped_permission, 0);
        assert_eq!(counters.skipped_backoff, 0);
        let built = batcher.finish().unwrap();
        assert_eq!(built.keys.len(), 2);
        // missing key got an attempt row
        assert!(store
            .read()
            .await
            .get_renew_attempt(sid, b"b".to_vec())
            .await
            .unwrap()
            .is_some());
    }

    #[test]
    fn backoff_doubles_capped() {
        assert_eq!(backoff_until(3, 100, 10), 100 + 80);
        assert_eq!(backoff_until(10, 100, 10), 100 + 160); // capped at <<4
    }

    #[tokio::test]
    async fn fill_batch_skips_permission_denied() {
        let store: Arc<RwLock<dyn Store>> =
            Arc::new(RwLock::new(StoreManager::memorydb().await.unwrap()));
        let sid = H256::repeat_byte(6);
        let signer = H160::repeat_byte(9);
        let foreign_admin = H160::repeat_byte(11);
        seed_stream_with_foreign_admin(&store, sid, b"x", foreign_admin, 100).await;

        let mut batcher = ValueBatcher::new(1 << 20, 100);
        let mut cursor = vec![];
        let (counters, done) = fill_batch(
            &store,
            sid,
            1_000,
            &mut cursor,
            &mut batcher,
            signer,
            &HashSet::new(),
            3,
            2_000,
        )
        .await
        .unwrap();

        assert!(done);
        assert_eq!(counters.scanned, 1);
        assert_eq!(counters.skipped_permission, 1);
        assert!(batcher.is_empty());
        let attempt = store
            .read()
            .await
            .get_renew_attempt(sid, b"x".to_vec())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(attempt.last_error.as_deref(), Some("no write permission"));
    }

    #[tokio::test]
    async fn fill_batch_skips_when_backed_off() {
        let store: Arc<RwLock<dyn Store>> =
            Arc::new(RwLock::new(StoreManager::memorydb().await.unwrap()));
        let sid = H256::repeat_byte(7);
        let signer = H160::repeat_byte(9);
        seed_stale_keys(&store, sid, &[(b"y", true)], 100).await;

        // Pre-existing attempts at (>=) max_attempts, recorded recently.
        for _ in 0..3 {
            store
                .write()
                .await
                .record_renew_attempt(sid, b"y".to_vec(), 1_500, None, Some("boom".into()))
                .await
                .unwrap();
        }

        let mut batcher = ValueBatcher::new(1 << 20, 100);
        let mut cursor = vec![];
        let (counters, done) = fill_batch(
            &store,
            sid,
            1_000,
            &mut cursor,
            &mut batcher,
            signer,
            &HashSet::new(),
            3,
            2_000, // well inside the backoff window
        )
        .await
        .unwrap();

        assert!(done);
        assert_eq!(counters.scanned, 1);
        assert_eq!(counters.skipped_backoff, 1);
        assert!(batcher.is_empty());
        // No new attempt recorded while backing off.
        let attempt = store
            .read()
            .await
            .get_renew_attempt(sid, b"y".to_vec())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(attempt.attempts, 3);
    }

    #[tokio::test]
    async fn fill_batch_retries_after_backoff_window_elapses() {
        let store: Arc<RwLock<dyn Store>> =
            Arc::new(RwLock::new(StoreManager::memorydb().await.unwrap()));
        let sid = H256::repeat_byte(8);
        let signer = H160::repeat_byte(9);
        seed_stale_keys(&store, sid, &[(b"z", true)], 100).await;

        for _ in 0..3 {
            store
                .write()
                .await
                .record_renew_attempt(sid, b"z".to_vec(), 1_500, None, Some("boom".into()))
                .await
                .unwrap();
        }

        let mut batcher = ValueBatcher::new(1 << 20, 100);
        let mut cursor = vec![];
        // now far past 1_500 + DEFAULT_CYCLE_SECS << 3 (backoff window has elapsed).
        let now = 1_500 + (DEFAULT_CYCLE_SECS << 3) + 1;
        let (counters, done) = fill_batch(
            &store,
            sid,
            1_000,
            &mut cursor,
            &mut batcher,
            signer,
            &HashSet::new(),
            3,
            now,
        )
        .await
        .unwrap();

        assert!(done);
        assert_eq!(counters.scanned, 1);
        assert_eq!(counters.skipped_backoff, 0);
        let built = batcher.finish().unwrap();
        assert_eq!(built.keys.len(), 1);
    }

    #[tokio::test]
    async fn fill_batch_skips_already_uploaded_this_cycle() {
        let store: Arc<RwLock<dyn Store>> =
            Arc::new(RwLock::new(StoreManager::memorydb().await.unwrap()));
        let sid = H256::repeat_byte(12);
        let signer = H160::repeat_byte(9);
        seed_stale_keys(&store, sid, &[(b"a", true), (b"b", true)], 100).await;

        let mut uploaded = HashSet::new();
        uploaded.insert((sid, b"a".to_vec()));

        let mut batcher = ValueBatcher::new(1 << 20, 100);
        let mut cursor = vec![];
        let (counters, done) = fill_batch(
            &store,
            sid,
            1_000,
            &mut cursor,
            &mut batcher,
            signer,
            &uploaded,
            3,
            2_000,
        )
        .await
        .unwrap();

        assert!(done);
        assert_eq!(counters.scanned, 2);
        assert_eq!(counters.skipped_permission, 0);
        assert_eq!(counters.skipped_missing, 0);
        assert_eq!(counters.skipped_backoff, 0);
        let built = batcher.finish().unwrap();
        assert_eq!(built.keys, vec![(sid, b"b".to_vec())]);
        // Silent skip: no renew-attempt row for the already-uploaded key.
        assert!(store
            .read()
            .await
            .get_renew_attempt(sid, b"a".to_vec())
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn fill_batch_stops_at_full_batch_without_advancing_cursor() {
        let store: Arc<RwLock<dyn Store>> =
            Arc::new(RwLock::new(StoreManager::memorydb().await.unwrap()));
        let sid = H256::repeat_byte(13);
        let signer = H160::repeat_byte(9);
        seed_stale_keys(
            &store,
            sid,
            &[(b"a", true), (b"b", true), (b"c", true)],
            100,
        )
        .await;

        // max_keys = 1: the batcher accepts "a" then refuses "b".
        let mut batcher = ValueBatcher::new(1 << 20, 1);
        let mut cursor = vec![];
        let (counters, done) = fill_batch(
            &store,
            sid,
            1_000,
            &mut cursor,
            &mut batcher,
            signer,
            &HashSet::new(),
            3,
            2_000,
        )
        .await
        .unwrap();

        assert!(!done);
        assert_eq!(counters.scanned, 2); // "a" (pushed) + "b" (rejected)
        let built = batcher.finish().unwrap();
        assert_eq!(built.keys, vec![(sid, b"a".to_vec())]);
        // Cursor sits after "a" (last consumed), not after "b" (rejected).
        assert_eq!(cursor, b"a".to_vec());

        // Re-scanning from that cursor picks "b" up as the lead item.
        let mut batcher2 = ValueBatcher::new(1 << 20, 100);
        let (counters2, done2) = fill_batch(
            &store,
            sid,
            1_000,
            &mut cursor,
            &mut batcher2,
            signer,
            &HashSet::new(),
            3,
            2_000,
        )
        .await
        .unwrap();
        assert!(done2);
        assert_eq!(counters2.scanned, 2); // "b", "c"
        let built2 = batcher2.finish().unwrap();
        assert_eq!(
            built2.keys,
            vec![(sid, b"b".to_vec()), (sid, b"c".to_vec())]
        );
    }
}
