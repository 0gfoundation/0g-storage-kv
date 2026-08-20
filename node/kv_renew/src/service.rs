//! Renewal service loop: startup checks, one-time backfill, scheduling, and
//! the trigger channel. Spawned as a single background task ("kv renewer")
//! that drives `cycle::{drain_stream, verify_renewed}` over the configured
//! streams on a timer (or on demand via `trigger_rx`). See spec §4.
//!
//! Every failure in here -- bad config, a down RPC endpoint, a panic deep
//! inside the storage SDK's `must_new_*` connectivity helpers -- is caught,
//! logged, and turned into "skip this cycle, try again next time". The
//! service must never take the node down with it.

use std::collections::{BTreeSet, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use ethereum_types::{H160, H256};
use ethers::signers::{LocalWallet, Signer};
use storage_with_stream::Store;
use tokio::sync::RwLock;
use tokio::time::Instant;

/// Current unix time in seconds. Never panics on a clock that reports
/// before the epoch (defaults to 0 instead).
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Derives the renew signer's address from its configured private key.
/// Pure; unit-tested against `ethers::signers::LocalWallet` directly.
pub fn signer_address(private_key: &[u8; 32]) -> Result<H160> {
    let wallet = LocalWallet::from_bytes(private_key)?;
    Ok(H160::from_slice(wallet.address().as_bytes()))
}

/// Filters `live` (the current `live_stream_set` snapshot) down to
/// `configured` (`RenewConfig::stream_ids`) when `configured` is non-empty,
/// and dedupes the result into a deterministic order. `configured` is not
/// deduped upstream, so this is the one place a stream can't end up drained
/// twice in the same cycle.
pub fn select_streams(live: &HashSet<H256>, configured: &[H256]) -> Vec<H256> {
    let selected: BTreeSet<H256> = if configured.is_empty() {
        live.iter().copied().collect()
    } else {
        let configured_set: HashSet<H256> = configured.iter().copied().collect();
        live.iter()
            .filter(|id| configured_set.contains(id))
            .copied()
            .collect()
    };
    selected.into_iter().collect()
}

/// Waits (bounded by `timeout`, polling every `poll`) for every key's latest
/// version to exceed `pre_seq` -- i.e. for the replayer to catch up with the
/// renewal upload. Returns as soon as all keys are caught up; otherwise
/// returns once `timeout` elapses regardless, leaving `verify_renewed` (a
/// single call, made by the caller once this returns) to decide what's
/// actually landed vs. still stuck.
pub async fn wait_for_renewals(
    store: &Arc<RwLock<dyn Store>>,
    keys: &[(H256, Vec<u8>)],
    pre_seq: u64,
    timeout: Duration,
    poll: Duration,
) {
    if keys.is_empty() {
        return;
    }
    let deadline = Instant::now() + timeout;
    loop {
        let mut all_caught_up = true;
        for (stream_id, key) in keys {
            let latest = match store
                .read()
                .await
                .get_latest_version_before(*stream_id, Arc::new(key.clone()), u64::MAX)
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    warn!(
                        "wait_for_renewals: get_latest_version_before failed for stream {:?}: {}",
                        stream_id, e
                    );
                    0
                }
            };
            if latest <= pre_seq {
                all_caught_up = false;
                break;
            }
        }
        if all_caught_up || Instant::now() >= deadline {
            return;
        }
        tokio::time::sleep(poll).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::signers::Wallet;
    use kv_types::StreamWrite as KvStreamWrite;
    use kv_types::{AccessControlSet, KVTransaction, StreamWriteSet};
    use storage_with_stream::StoreManager;

    fn sid() -> H256 {
        H256::repeat_byte(0x7)
    }

    #[test]
    fn signer_address_matches_ethers_wallet() {
        // well-known test vector: private key 0x01.. -> address of that key
        let key = {
            let mut k = [0u8; 32];
            k[31] = 1;
            k
        };
        let addr = signer_address(&key).unwrap();
        let wallet: ethers::signers::LocalWallet = Wallet::from_bytes(&key).unwrap();
        assert_eq!(addr.as_bytes(), wallet.address().as_bytes());
    }

    #[test]
    fn select_streams_empty_config_returns_all_live() {
        let live: HashSet<H256> = [H256::repeat_byte(1), H256::repeat_byte(2)]
            .into_iter()
            .collect();
        let mut got = select_streams(&live, &[]);
        got.sort();
        let mut want: Vec<H256> = live.iter().copied().collect();
        want.sort();
        assert_eq!(got, want);
    }

    #[test]
    fn select_streams_filters_to_configured_intersection() {
        let live: HashSet<H256> = [
            H256::repeat_byte(1),
            H256::repeat_byte(2),
            H256::repeat_byte(3),
        ]
        .into_iter()
        .collect();
        // stream 2 appears twice and stream 9 isn't live at all -- both the
        // dedup and the live-intersection behavior get exercised here.
        let configured = vec![
            H256::repeat_byte(2),
            H256::repeat_byte(2),
            H256::repeat_byte(9),
        ];
        let got = select_streams(&live, &configured);
        assert_eq!(got, vec![H256::repeat_byte(2)]);
    }

    /// Seeds a single present stale key (`k0`) for `sid()` at seq 0, ts=100
    /// -- minimal replica of `cycle::tests::seeded_store_with_stale_keys`
    /// (not reusable directly: those helpers are private to `cycle`'s own
    /// test module).
    async fn seeded_store_with_one_key() -> Arc<RwLock<dyn Store>> {
        let store: Arc<RwLock<dyn Store>> =
            Arc::new(RwLock::new(StoreManager::memorydb().await.unwrap()));
        let mut guard = store.write().await;
        let tx = KVTransaction {
            stream_ids: vec![sid()],
            sender: H160::zero(),
            data_merkle_root: H256::zero(),
            merkle_nodes: vec![(1, H256::zero())],
            start_entry_index: 1,
            size: 256,
            seq: 0,
        };
        guard.put_tx(tx).unwrap();
        guard.put_tx_block_time(0, 100).unwrap();
        let write_set = StreamWriteSet {
            stream_writes: vec![KvStreamWrite {
                stream_id: sid(),
                key: Arc::new(b"k0".to_vec()),
                start_index: 0,
                end_index: 0,
            }],
        };
        let acl = AccessControlSet {
            access_controls: vec![],
            is_admin: Default::default(),
        };
        guard
            .put_stream(0, H256::zero(), "Commit".into(), Some((write_set, acl)))
            .await
            .unwrap();
        drop(guard);
        store
    }

    /// Appends a fresh version of `k0` at `seq` (bridging replay progress up
    /// to it with filler commits), timestamped `ts`.
    async fn append_new_version(store: &Arc<RwLock<dyn Store>>, seq: u64, ts: u64) {
        let mut guard = store.write().await;
        let progress = guard.get_stream_replay_progress().await.unwrap();
        for s in progress..=seq {
            let tx = KVTransaction {
                stream_ids: vec![sid()],
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
                        stream_id: sid(),
                        key: Arc::new(b"k0".to_vec()),
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

    #[tokio::test]
    async fn wait_for_renewals_breaks_early_once_version_advances() {
        let store = seeded_store_with_one_key().await;
        let pre_seq = store.read().await.next_tx_seq();

        // Land the new version shortly after the wait starts -- if
        // `wait_for_renewals` only returned on timeout, this test would take
        // the full (generously long) timeout to pass instead of finishing
        // almost immediately.
        let bg_store = store.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            append_new_version(&bg_store, pre_seq + 1, 9_999).await;
        });

        let started = Instant::now();
        wait_for_renewals(
            &store,
            &[(sid(), b"k0".to_vec())],
            pre_seq,
            Duration::from_secs(10),
            Duration::from_millis(10),
        )
        .await;
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(2),
            "wait_for_renewals should have broken out early, took {:?}",
            elapsed
        );

        let latest = store
            .read()
            .await
            .get_latest_version_before(sid(), Arc::new(b"k0".to_vec()), u64::MAX)
            .await
            .unwrap();
        assert!(latest > pre_seq);
    }

    #[tokio::test]
    async fn wait_for_renewals_returns_immediately_for_empty_keys() {
        let store = seeded_store_with_one_key().await;
        let started = Instant::now();
        wait_for_renewals(
            &store,
            &[],
            0,
            Duration::from_secs(10),
            Duration::from_millis(10),
        )
        .await;
        assert!(started.elapsed() < Duration::from_millis(500));
    }
}
