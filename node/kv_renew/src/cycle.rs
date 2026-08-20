//! Drains one stream's stale keys (scan -> pack -> upload, repeated until
//! none remain) and verifies a renewal landed via replay. See spec §4 steps
//! 5-8.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use ethereum_types::{H160, H256};
use storage_with_stream::Store;
use tokio::sync::RwLock;
use tokio::time::Instant;

use crate::batch::{into_upload_data, ValueBatcher};
use crate::scan::fill_batch;
use crate::upload::BatchSink;
use crate::{RenewConfig, SharedRenewStatus};

/// Dependencies threaded through one renewal cycle (Task 18 wires these up
/// from `ZgsKVConfig`/`StoreManager`/`RenewUploader`).
pub struct CycleDeps {
    pub store: Arc<RwLock<dyn Store>>,
    pub sink: Arc<dyn BatchSink>,
    pub config: Arc<RenewConfig>,
    pub status: SharedRenewStatus,
    pub signer: H160,
}

/// Drain one stream: scan -> pack -> upload -> repeat until no stale keys
/// remain. Returns the keys uploaded this call (for verification) and the
/// stream's `next_tx_seq` observed before any upload — the baseline
/// `verify_renewed` checks new versions against.
///
/// In dry-run, nothing is ever marked uploaded (so nothing here ever stops
/// being stale); to avoid spinning on the same keys forever, dry-run stops
/// after the first pack attempt (one scan pass over the stream) rather than
/// looping until "exhausted".
pub async fn drain_stream(
    deps: &CycleDeps,
    stream_id: H256,
    cutoff: u64,
    now: u64,
) -> Result<(Vec<(H256, Vec<u8>)>, u64)> {
    let pre_seq = deps.store.read().await.next_tx_seq();
    let mut uploaded_this_cycle: HashSet<(H256, Vec<u8>)> = HashSet::new();
    let mut uploaded_keys: Vec<(H256, Vec<u8>)> = Vec::new();
    let mut cursor: Vec<u8> = Vec::new();

    loop {
        let mut batcher =
            ValueBatcher::new(deps.config.batch_max_bytes, deps.config.batch_max_keys);

        // `fill_batch` already pages internally until either the batcher
        // gets content or the stream is exhausted, so a single call per
        // drain-loop iteration is enough here.
        let (counters, exhausted) = fill_batch(
            &deps.store,
            stream_id,
            cutoff,
            &mut cursor,
            &mut batcher,
            deps.signer,
            &uploaded_this_cycle,
            deps.config.max_attempts,
            deps.config.cycle_interval_secs,
            now,
        )
        .await?;

        {
            let mut status = deps.status.write().await;
            // NOTE: `counters.scanned` can double-count a key that sits
            // exactly on a batch-full boundary: `fill_batch` counts it once
            // when the full batch rejects it, then again when the next call
            // re-scans from the cursor and re-encounters it as the lead
            // item. Acceptable per Task 16 — this is an approximate
            // progress counter, not an exact audit trail.
            status.keys_scanned += counters.scanned;
            status.keys_skipped_permission += counters.skipped_permission;
            status.keys_skipped_missing += counters.skipped_missing;
            // `counters.skipped_backoff` has no dedicated `RenewStatus`
            // field to land in; it's tracked internally by the scanner only.
        }

        if batcher.is_empty() && exhausted {
            break;
        }

        let built = batcher.finish()?;
        let bytes = built.bytes as u64;
        let data = into_upload_data(
            built.encoded,
            deps.config.encryption_key,
            deps.config.wallet_private_key,
        )?;

        if deps.config.dry_run {
            info!(
                "renew dry-run: would upload {} keys / {} bytes for stream {:?}",
                built.keys.len(),
                built.bytes,
                stream_id
            );
            {
                let mut status = deps.status.write().await;
                status.bytes_uploaded += bytes;
            }
            // Dry-run never marks anything uploaded, so a second pass would
            // just re-scan the same stale keys forever: stop after this one
            // pack attempt regardless of `exhausted`.
            break;
        }

        let root = deps.sink.submit(data, built.tags).await?;
        for (key_stream_id, key) in &built.keys {
            deps.store
                .write()
                .await
                .record_renew_attempt(*key_stream_id, key.clone(), now, Some(root), None)
                .await?;
            uploaded_this_cycle.insert((*key_stream_id, key.clone()));
        }
        uploaded_keys.extend(built.keys);

        {
            let mut status = deps.status.write().await;
            status.bytes_uploaded += bytes;
        }

        tokio::time::sleep(Duration::from_millis(deps.config.pause_between_batches_ms)).await;

        if exhausted {
            break;
        }
    }

    Ok((uploaded_keys, pre_seq))
}

/// A key is verified renewed when its latest version now exceeds `pre_seq`.
/// Clears the renew attempt on success; records the failure otherwise.
/// Returns the renewed count.
pub async fn verify_renewed(
    store: &Arc<RwLock<dyn Store>>,
    keys: &[(H256, Vec<u8>)],
    pre_seq: u64,
    now: u64,
) -> Result<u64> {
    let mut renewed = 0;
    for (stream_id, key) in keys {
        let latest = store
            .read()
            .await
            .get_latest_version_before(*stream_id, Arc::new(key.clone()), u64::MAX)
            .await?;
        if latest > pre_seq {
            store
                .write()
                .await
                .clear_renew_attempt(*stream_id, key.clone())
                .await?;
            renewed += 1;
        } else {
            store
                .write()
                .await
                .record_renew_attempt(
                    *stream_id,
                    key.clone(),
                    now,
                    None,
                    Some("replayed but version did not advance (write rejected?)".into()),
                )
                .await?;
            warn!(
                "renewal for stream {:?} key 0x{} did not take effect",
                stream_id,
                hex::encode(key)
            );
        }
    }
    Ok(renewed)
}

/// Polls replay progress until it reaches `target_seq` or `timeout` elapses.
/// Returns whether the target was reached.
pub async fn wait_replay(
    store: &Arc<RwLock<dyn Store>>,
    target_seq: u64,
    timeout: Duration,
    poll: Duration,
) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        match store.read().await.get_stream_replay_progress().await {
            Ok(progress) if progress >= target_seq => return true,
            Ok(_) => {}
            Err(e) => warn!("wait_replay: get_stream_replay_progress error: {}", e),
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(poll).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use kv_types::StreamWrite as KvStreamWrite;
    use kv_types::{AccessControlSet, KVTransaction, StreamWriteSet};
    use std::sync::Mutex;
    use storage_with_stream::StoreManager;
    use zg_storage_client::core::dataflow::IterableData;

    use crate::RenewStatus;

    fn sid() -> H256 {
        H256::repeat_byte(0x42)
    }

    /// Seeds `n` present keys (`k0`..`k{n-1}`) as stale stream writes at
    /// `ts=100`, one per sequential tx starting at seq 0 -- adapted from
    /// `scan::tests::seed_stale_keys` (Task 16): an empty write range
    /// (`start_index == end_index`) makes the key "present" for
    /// `read_pair_value` without touching the flow store.
    async fn seeded_store_with_stale_keys(n: usize) -> Arc<RwLock<dyn Store>> {
        let store: Arc<RwLock<dyn Store>> =
            Arc::new(RwLock::new(StoreManager::memorydb().await.unwrap()));
        let mut guard = store.write().await;
        for i in 0..n {
            let key = format!("k{i}").into_bytes();
            let seq = i as u64;
            let tx = KVTransaction {
                stream_ids: vec![sid()],
                sender: H160::zero(),
                data_merkle_root: H256::zero(),
                merkle_nodes: vec![(1, H256::zero())],
                start_entry_index: seq + 1,
                size: 256,
                seq,
            };
            guard.put_tx(tx).unwrap();
            guard.put_tx_block_time(seq, 100).unwrap();

            let write_set = StreamWriteSet {
                stream_writes: vec![KvStreamWrite {
                    stream_id: sid(),
                    key: Arc::new(key),
                    start_index: 0,
                    end_index: 0,
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
        drop(guard);
        store
    }

    /// Bridges the stream's replay progress up to `seq` (filler commits with
    /// no write set for any intervening slot) and writes a fresh version of
    /// `key` at exactly `seq`, timestamped `ts`. `seq` must be `> pre_seq`
    /// (the `next_tx_seq()` read before calling this) for `verify_renewed`
    /// to detect it as a landed renewal.
    async fn append_new_version(
        store: &Arc<RwLock<dyn Store>>,
        stream_id: H256,
        key: &[u8],
        seq: u64,
        ts: u64,
    ) {
        let mut guard = store.write().await;
        let progress = guard.get_stream_replay_progress().await.unwrap();
        for s in progress..=seq {
            let tx = KVTransaction {
                stream_ids: vec![stream_id],
                sender: H160::zero(),
                data_merkle_root: H256::zero(),
                merkle_nodes: vec![(1, H256::zero())],
                start_entry_index: s + 1,
                size: 256,
                seq: s,
            };
            guard.put_tx(tx).unwrap();
            guard.put_tx_block_time(s, ts).unwrap();

            let commit = if s == seq {
                let write_set = StreamWriteSet {
                    stream_writes: vec![KvStreamWrite {
                        stream_id,
                        key: Arc::new(key.to_vec()),
                        start_index: 0,
                        end_index: 0,
                    }],
                };
                let acl = AccessControlSet {
                    access_controls: vec![],
                    is_admin: Default::default(),
                };
                Some((write_set, acl))
            } else {
                None
            };
            guard
                .put_stream(s, H256::zero(), "Commit".into(), commit)
                .await
                .unwrap();
        }
    }

    struct MockSink {
        submitted: Mutex<Vec<(usize, Vec<u8>)>>, // (data size, tags)
    }

    #[async_trait]
    impl BatchSink for MockSink {
        async fn submit(&self, data: Arc<dyn IterableData>, tags: Vec<u8>) -> Result<H256> {
            self.submitted
                .lock()
                .unwrap()
                .push((data.size() as usize, tags));
            Ok(H256::repeat_byte(0xaa))
        }
        async fn resolve_tx_seq(&self, _root: H256) -> Result<Option<u64>> {
            Ok(Some(42))
        }
    }

    fn base_config(max_bytes: usize, max_keys: usize, dry_run: bool) -> RenewConfig {
        RenewConfig {
            private_key: [0u8; 32],
            max_age_secs: 1_000,
            cycle_interval_secs: 10,
            batch_max_bytes: max_bytes,
            batch_max_keys: max_keys,
            pause_between_batches_ms: 0,
            startup_delay_secs: 0,
            expected_replica: 1,
            stream_ids: vec![],
            dry_run,
            max_attempts: 3,
            blockchain_rpc_endpoint: String::new(),
            log_contract_address: String::new(),
            indexer_url: None,
            zgs_node_urls: vec![],
            encryption_key: None,
            wallet_private_key: None,
        }
    }

    /// Builds `CycleDeps` wired to a fresh `MockSink`, returning the sink
    /// handle alongside so tests can inspect `submitted` directly (no
    /// downcasting `Arc<dyn BatchSink>`).
    async fn mock_deps(
        store: Arc<RwLock<dyn Store>>,
        max_bytes: usize,
        max_keys: usize,
    ) -> (CycleDeps, Arc<MockSink>) {
        let sink = Arc::new(MockSink {
            submitted: Mutex::new(Vec::new()),
        });
        let deps = CycleDeps {
            store,
            sink: sink.clone(),
            config: Arc::new(base_config(max_bytes, max_keys, false)),
            status: Arc::new(RwLock::new(RenewStatus::default())),
            signer: H160::repeat_byte(9),
        };
        (deps, sink)
    }

    async fn mock_deps_dry_run(store: Arc<RwLock<dyn Store>>) -> (CycleDeps, Arc<MockSink>) {
        let sink = Arc::new(MockSink {
            submitted: Mutex::new(Vec::new()),
        });
        let deps = CycleDeps {
            store,
            sink: sink.clone(),
            config: Arc::new(base_config(1 << 20, 100, true)),
            status: Arc::new(RwLock::new(RenewStatus::default())),
            signer: H160::repeat_byte(9),
        };
        (deps, sink)
    }

    #[tokio::test]
    async fn drain_uploads_until_no_stale_left() {
        let store = seeded_store_with_stale_keys(3).await;
        let (deps, sink) = mock_deps(store.clone(), 1 << 20, 2).await;
        let (uploaded, _pre) = drain_stream(&deps, sid(), 1_000, 2_000).await.unwrap();
        assert_eq!(uploaded.len(), 3);
        // 3 keys with max_keys=2 -> exactly 2 batches
        assert_eq!(sink.submitted.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn verify_clears_on_new_version_and_records_failure() {
        let store = seeded_store_with_stale_keys(2).await;
        let keys = vec![(sid(), b"k0".to_vec()), (sid(), b"k1".to_vec())];
        let pre = store.read().await.next_tx_seq();
        // simulate replay landing a renewal write for k0 only
        append_new_version(&store, sid(), b"k0", pre + 1, 9_999).await;

        let renewed = verify_renewed(&store, &keys, pre, 2_000).await.unwrap();
        assert_eq!(renewed, 1);
        assert!(store
            .read()
            .await
            .get_renew_attempt(sid(), b"k0".to_vec())
            .await
            .unwrap()
            .is_none());
        assert!(store
            .read()
            .await
            .get_renew_attempt(sid(), b"k1".to_vec())
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn dry_run_submits_nothing() {
        let store = seeded_store_with_stale_keys(2).await;
        let (deps, sink) = mock_deps_dry_run(store).await;
        let (uploaded, _) = drain_stream(&deps, sid(), 1_000, 2_000).await.unwrap();
        assert!(uploaded.is_empty());
        assert_eq!(sink.submitted.lock().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn wait_replay_returns_true_when_progress_reached() {
        let store = seeded_store_with_stale_keys(1).await; // progress becomes 1
        let reached = wait_replay(
            &store,
            1,
            Duration::from_millis(200),
            Duration::from_millis(10),
        )
        .await;
        assert!(reached);
    }

    #[tokio::test]
    async fn wait_replay_times_out_when_progress_never_reached() {
        let store = seeded_store_with_stale_keys(1).await; // progress stays 1
        let reached = wait_replay(
            &store,
            5,
            Duration::from_millis(50),
            Duration::from_millis(10),
        )
        .await;
        assert!(!reached);
    }
}
