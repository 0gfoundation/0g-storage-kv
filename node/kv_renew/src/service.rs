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
use ethers::providers::{Http, Middleware, Provider};
use ethers::signers::{LocalWallet, Signer};
use ethers::types::Address;
use storage_with_stream::Store;
use task_executor::TaskExecutor;
use tokio::sync::{mpsc, RwLock};
use tokio::time::Instant;

use crate::cycle::{drain_stream, verify_renewed, CycleDeps};
use crate::probe::build_clock;
use crate::upload::{BatchSink, RenewUploader};
use crate::{RenewConfig, SharedRenewStatus, StuckKey};

/// How often `wait_for_renewals` re-checks replay progress while waiting for
/// a batch's keys to show a newer version.
const REPLAY_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Page size for the backfill pass's `get_null_time_versions` loop.
const BACKFILL_PAGE: u64 = 1024;

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

/// Drains, waits for replay, and verifies renewal for one stream. Runs as
/// the body of the `tokio::spawn` in `run_cycle`'s per-stream loop below --
/// see that function's doc comment for why this needs its own task rather
/// than just running inline.
async fn drain_and_verify_stream(
    deps: CycleDeps,
    stream_id: H256,
    cutoff: u64,
    now: u64,
) -> Result<()> {
    let (keys, pre_seq) = drain_stream(&deps, stream_id, cutoff, now).await?;

    if keys.is_empty() {
        // Nothing uploaded this pass (nothing stale, or dry-run) --
        // nothing to wait for or verify.
        return Ok(());
    }

    wait_for_renewals(
        &deps.store,
        &keys,
        pre_seq,
        Duration::from_secs(deps.config.cycle_interval_secs.max(1)),
        REPLAY_POLL_INTERVAL,
    )
    .await;

    let renewed = verify_renewed(&deps.store, &keys, pre_seq, unix_now()).await?;
    deps.status.write().await.keys_renewed += renewed;
    Ok(())
}

/// Runs one renewal cycle over `streams`: for each stream, drain its stale
/// keys, wait (bounded) for the renewal to replay, then verify+record the
/// outcome.
///
/// Each stream's work runs inside its own `tokio::spawn`, awaited
/// immediately. This isn't just task hygiene: `RenewUploader::submit`
/// (invoked from `drain_stream`) falls through to the storage SDK's
/// `must_new_zgs_clients` when no indexer is configured, and that panics if
/// a configured storage node is unreachable. Because `spawn_renewer` spawns
/// this whole service via `TaskExecutor::spawn`, which monitors its task and
/// shuts the *entire node* down (`ShutdownReason::Failure`) on any panic
/// from it, an unguarded panic here wouldn't just kill this cycle or this
/// stream -- it would take the node down. Wrapping each stream's body in its
/// own `tokio::spawn` turns that into a caught `JoinError`: this stream is
/// logged and skipped, the rest of the cycle (and the node) carries on.
///
/// `acl_disabled` is the startup-computed set of streams where the renew
/// signer isn't admin (see `run`'s startup check). Task 19's ACL-renewal
/// hook will consult it before draining a stream; it's threaded through
/// unused for now so that hook has a single place to land.
pub async fn run_cycle(deps: &CycleDeps, streams: &[H256], _acl_disabled: &HashSet<H256>) {
    let now = unix_now();
    let cutoff = now.saturating_sub(deps.config.max_age_secs);

    for &stream_id in streams {
        let deps_owned = deps.clone();
        match tokio::spawn(async move {
            drain_and_verify_stream(deps_owned, stream_id, cutoff, now).await
        })
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => error!("renew: stream {:?} cycle failed: {}", stream_id, e),
            Err(join_err) => error!(
                "renew: stream {:?} cycle panicked: {} -- continuing with the next stream",
                stream_id, join_err
            ),
        }
    }
}

/// One-time backfill of NULL-timestamped rows (spec §3), run once at
/// startup (after the startup delay) when any such rows exist. Any probe
/// failure -- bad RPC endpoint, unparsable contract address, a chain-probe
/// error -- is non-fatal: it's logged and backfill is skipped entirely for
/// this run; NULL rows simply stay deferred, exactly as spec §3 allows.
async fn run_backfill(store: &Arc<RwLock<dyn Store>>, config: &RenewConfig) {
    let has_null_rows = match store.read().await.get_null_time_versions(1).await {
        Ok(versions) => !versions.is_empty(),
        Err(e) => {
            warn!(
                "renew: backfill: get_null_time_versions probe failed: {} -- skipping backfill",
                e
            );
            return;
        }
    };
    if !has_null_rows {
        return;
    }

    let provider = match Provider::<Http>::try_from(&config.blockchain_rpc_endpoint) {
        Ok(p) => Arc::new(p),
        Err(e) => {
            warn!(
                "renew: backfill: failed to build provider for {:?}: {} -- skipping backfill",
                config.blockchain_rpc_endpoint, e
            );
            return;
        }
    };
    let flow_addr = match config.log_contract_address.parse::<Address>() {
        Ok(a) => a,
        Err(e) => {
            warn!(
                "renew: backfill: failed to parse log_contract_address {:?}: {} -- skipping backfill",
                config.log_contract_address, e
            );
            return;
        }
    };

    let next_tx_seq = store.read().await.next_tx_seq();
    let now = unix_now();
    let age_points = [config.max_age_secs, config.max_age_secs * 2];
    let clock = match build_clock(provider, flow_addr, &age_points, next_tx_seq, now).await {
        Ok(c) => c,
        Err(e) => {
            warn!(
                "renew: backfill: build_clock failed: {} -- skipping backfill",
                e
            );
            return;
        }
    };

    // Loop guard: if a batch's first version is identical to the previous
    // batch's first version, `backfill_version_time` isn't actually making
    // progress (persistent write failure or similar) -- stop rather than
    // spin forever re-fetching the same page.
    let mut last_first_version: Option<u64> = None;
    loop {
        let versions = match store
            .read()
            .await
            .get_null_time_versions(BACKFILL_PAGE)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                warn!(
                    "renew: backfill: get_null_time_versions failed: {} -- stopping backfill",
                    e
                );
                return;
            }
        };
        let Some(&first_version) = versions.first() else {
            break;
        };
        if last_first_version == Some(first_version) {
            warn!(
                "renew: backfill: batch did not shrink past version {} -- stopping to avoid an infinite loop",
                first_version
            );
            return;
        }
        last_first_version = Some(first_version);

        for version in versions {
            let ts = clock.time_at(version);
            if let Err(e) = store.write().await.backfill_version_time(version, ts).await {
                warn!(
                    "renew: backfill: backfill_version_time({}) failed: {} -- stopping backfill",
                    version, e
                );
                return;
            }
        }
    }
}

/// Constructs the balance-check provider, checks the signer's balance,
/// constructs a fresh uploader (panic-contained), selects this cycle's
/// streams, and runs `run_cycle`. Every failure short-circuits to "skip this
/// cycle" rather than propagating -- the caller (`run`'s main loop) always
/// proceeds to the end-of-cycle status update regardless.
async fn run_one_cycle(
    store: &Arc<RwLock<dyn Store>>,
    live_stream_set: &Arc<RwLock<HashSet<H256>>>,
    config: &Arc<RenewConfig>,
    status: &SharedRenewStatus,
    signer: H160,
    acl_disabled: &HashSet<H256>,
) {
    let provider = match Provider::<Http>::try_from(&config.blockchain_rpc_endpoint) {
        Ok(p) => p,
        Err(e) => {
            error!(
                "renew: failed to build provider for balance check: {} -- skipping cycle",
                e
            );
            return;
        }
    };
    let balance = match provider.get_balance(signer, None).await {
        Ok(b) => b,
        Err(e) => {
            error!("renew: get_balance failed: {} -- skipping cycle", e);
            return;
        }
    };
    if balance.is_zero() {
        error!(
            "renew: signer {:?} has zero balance -- skipping cycle",
            signer
        );
        return;
    }

    // Constructed fresh each cycle (never at service start, since the
    // endpoint may be down at boot) and inside `tokio::spawn` so that a
    // `must_new_*`-style panic from the SDK's connectivity helpers is
    // contained to this cycle instead of killing the whole "kv renewer"
    // task.
    let cfg_for_uploader = config.clone();
    let sink: Arc<dyn BatchSink> =
        match tokio::spawn(async move { RenewUploader::new(&cfg_for_uploader).await }).await {
            Ok(Ok(uploader)) => Arc::new(uploader),
            Ok(Err(e)) => {
                error!("renew: RenewUploader::new failed: {} -- skipping cycle", e);
                return;
            }
            Err(join_err) => {
                error!(
                    "renew: RenewUploader::new panicked: {} -- skipping cycle",
                    join_err
                );
                return;
            }
        };

    let live = live_stream_set.read().await.clone();
    let streams = select_streams(&live, &config.stream_ids);

    let deps = CycleDeps {
        store: store.clone(),
        sink,
        config: config.clone(),
        status: status.clone(),
        signer,
    };

    run_cycle(&deps, &streams, acl_disabled).await;
}

/// The renewal service loop, run as the body of the "kv renewer" task
/// spawned by `spawn_renewer`.
async fn run(
    store: Arc<RwLock<dyn Store>>,
    live_stream_set: Arc<RwLock<HashSet<H256>>>,
    config: RenewConfig,
    status: SharedRenewStatus,
    mut trigger_rx: mpsc::UnboundedReceiver<()>,
) {
    let signer = match signer_address(&config.private_key) {
        Ok(addr) => {
            info!("renew: signer address {:?}", addr);
            addr
        }
        Err(e) => {
            error!(
                "renew: failed to derive signer address from configured private key: {} -- renewal service disabled",
                e
            );
            return;
        }
    };

    let config = Arc::new(config);

    tokio::time::sleep(Duration::from_secs(config.startup_delay_secs)).await;

    // Startup admin check: streams where the renew signer isn't an admin
    // get recorded here so Task 19's ACL-renewal hook can skip/handle them
    // specially. Draining a stream's stale keys doesn't itself require
    // admin (only ACL-op renewal does), so this doesn't stop those streams
    // from being drained below.
    let mut acl_disabled: HashSet<H256> = HashSet::new();
    {
        let snapshot: HashSet<H256> = live_stream_set.read().await.clone();
        // Re-acquire the store's read lock per stream rather than holding
        // one guard across every `is_admin` await in the loop -- keeps this
        // startup scan from blocking a concurrent writer (e.g. an
        // `admin_addStream` RPC call) for the whole pass.
        for stream_id in &snapshot {
            match store
                .read()
                .await
                .is_admin(signer, *stream_id, u64::MAX)
                .await
            {
                Ok(true) => {}
                Ok(false) => {
                    error!(
                        "ACL renewal disabled for stream {:?}: renew signer is not admin",
                        stream_id
                    );
                    acl_disabled.insert(*stream_id);
                }
                Err(e) => {
                    error!(
                        "renew: startup is_admin check failed for stream {:?}: {}",
                        stream_id, e
                    );
                }
            }
        }
    }

    run_backfill(&store, &config).await;

    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(config.cycle_interval_secs)) => {}
            Some(_) = trigger_rx.recv() => {}
        }

        // Collapse a burst of queued trigger requests (e.g. several
        // `admin_renewNow` calls landing while a cycle is running) into the
        // one cycle we're about to run, instead of racing through
        // back-to-back cycles for each queued message.
        while trigger_rx.try_recv().is_ok() {}

        let should_run = {
            let mut s = status.write().await;
            if s.cycle_running {
                false
            } else {
                s.cycle_running = true;
                s.dry_run = config.dry_run;
                s.last_cycle_start = Some(unix_now());
                true
            }
        };
        if !should_run {
            info!("renew: cycle trigger skipped -- previous cycle is still running");
            continue;
        }

        run_one_cycle(
            &store,
            &live_stream_set,
            &config,
            &status,
            signer,
            &acl_disabled,
        )
        .await;

        let stuck_keys = match store
            .read()
            .await
            .list_stuck_renewals(config.max_attempts, 100)
            .await
        {
            Ok(rows) => rows
                .into_iter()
                .map(|(stream_id, key, attempt)| StuckKey {
                    stream_id,
                    key: format!("0x{}", hex::encode(key)),
                    attempts: attempt.attempts,
                    last_error: attempt.last_error,
                })
                .collect(),
            Err(e) => {
                error!("renew: list_stuck_renewals failed: {}", e);
                Vec::new()
            }
        };

        let mut s = status.write().await;
        s.last_cycle_end = Some(unix_now());
        s.cycle_running = false;
        s.stuck_keys = stuck_keys;
    }
}

/// Spawns the renewal service loop as task "kv renewer". Never blocks the
/// caller; every error inside the loop is caught and logged rather than
/// propagated, so this task runs for the lifetime of the process.
pub fn spawn_renewer(
    executor: TaskExecutor,
    store: Arc<RwLock<dyn Store>>,
    live_stream_set: Arc<RwLock<HashSet<H256>>>,
    config: RenewConfig,
    status: SharedRenewStatus,
    trigger_rx: mpsc::UnboundedReceiver<()>,
) {
    executor.spawn(
        async move { run(store, live_stream_set, config, status, trigger_rx).await },
        "kv renewer",
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use ethers::signers::Wallet;
    use kv_types::StreamWrite as KvStreamWrite;
    use kv_types::{AccessControlSet, KVTransaction, StreamWriteSet};
    use std::sync::Mutex;
    use storage_with_stream::StoreManager;
    use zg_storage_client::core::dataflow::IterableData;

    fn sid() -> H256 {
        H256::repeat_byte(0x7)
    }

    fn sid2() -> H256 {
        H256::repeat_byte(0x8)
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

    /// Seeds one stale key each for `sid()` (seq 0) and `sid2()` (seq 1) --
    /// two distinct streams, so `run_cycle` drives its per-stream loop over
    /// more than one stream.
    async fn seeded_store_with_two_streams() -> Arc<RwLock<dyn Store>> {
        let store: Arc<RwLock<dyn Store>> =
            Arc::new(RwLock::new(StoreManager::memorydb().await.unwrap()));
        let mut guard = store.write().await;
        for (seq, stream_id) in [sid(), sid2()].into_iter().enumerate() {
            let seq = seq as u64;
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
            guard.put_tx_block_time(seq, 100).unwrap();
            let write_set = StreamWriteSet {
                stream_writes: vec![KvStreamWrite {
                    stream_id,
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
                .put_stream(seq, H256::zero(), "Commit".into(), Some((write_set, acl)))
                .await
                .unwrap();
        }
        drop(guard);
        store
    }

    /// A `BatchSink` whose `submit` always panics -- stands in for
    /// `RenewUploader::submit` panicking via the storage SDK's
    /// `must_new_zgs_clients` when a configured storage node is unreachable
    /// mid-cycle (a real, supported no-indexer configuration). Counts calls
    /// so the test can prove every stream got a chance to run rather than
    /// the whole cycle aborting after the first panic.
    struct PanicSink {
        calls: Mutex<u32>,
    }

    #[async_trait]
    impl BatchSink for PanicSink {
        async fn submit(&self, _data: Arc<dyn IterableData>, _tags: Vec<u8>) -> Result<H256> {
            *self.calls.lock().unwrap() += 1;
            panic!("PanicSink: simulated must_new_zgs_clients-style panic");
        }
        async fn resolve_tx_seq(&self, _root: H256) -> Result<Option<u64>> {
            Ok(None)
        }
    }

    fn panic_sink_config() -> RenewConfig {
        RenewConfig {
            private_key: [0u8; 32],
            max_age_secs: 1_000,
            cycle_interval_secs: 10,
            batch_max_bytes: 1 << 20,
            batch_max_keys: 10,
            pause_between_batches_ms: 0,
            startup_delay_secs: 0,
            expected_replica: 1,
            stream_ids: vec![],
            dry_run: false,
            max_attempts: 3,
            blockchain_rpc_endpoint: String::new(),
            log_contract_address: String::new(),
            indexer_url: None,
            zgs_node_urls: vec![],
            encryption_key: None,
            wallet_private_key: None,
        }
    }

    #[tokio::test]
    async fn run_cycle_contains_per_stream_panic_and_continues() {
        let store = seeded_store_with_two_streams().await;
        let sink = Arc::new(PanicSink {
            calls: Mutex::new(0),
        });
        let deps = CycleDeps {
            store: store.clone(),
            sink: sink.clone(),
            config: Arc::new(panic_sink_config()),
            status: Arc::new(RwLock::new(crate::RenewStatus::default())),
            signer: H160::repeat_byte(9),
        };
        let streams = vec![sid(), sid2()];
        let acl_disabled: HashSet<H256> = HashSet::new();

        // If a per-stream panic escaped its `tokio::spawn` boundary instead
        // of being caught as a `JoinError`, this call itself would panic and
        // fail the test -- the real-world equivalent is `must_new_zgs_clients`
        // panicking and (via `TaskExecutor::spawn`'s panic monitor) taking
        // the whole node down with it.
        run_cycle(&deps, &streams, &acl_disabled).await;

        // Both streams should have reached `submit` despite each panicking --
        // proof the first stream's panic didn't abort the rest of the cycle.
        assert_eq!(
            *sink.calls.lock().unwrap(),
            2,
            "both streams' uploads should have been attempted despite each panicking"
        );
    }
}
