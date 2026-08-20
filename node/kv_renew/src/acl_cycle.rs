//! Emits one ACL snapshot batch per stream per cycle, guarded against the
//! revocation race described in spec §5 ("The revocation race — IMPORTANT
//! NOTICE"): a caught-up gate before snapshotting, a pre-submit re-check
//! immediately before the on-chain send, and a post-replay detection scan
//! that surfaces anything that slipped through anyway. The race cannot be
//! fully eliminated by a node that only observes the chain rather than
//! locking it -- this module's job is prevent-cheaply, always-detect,
//! remediate-manually, not prevent-perfectly.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use ethereum_types::{H160, H256};
use ethers::providers::{Http, Provider};
use ethers::types::Address;
use kv_types::{AclOpRow, EffectiveAcl};
use storage_with_stream::store::to_access_control_op_name;
use storage_with_stream::{AccessControlOps, Store};
use tokio::sync::RwLock;
use tokio::time::Instant;
use zg_storage_client::kv::builder::StreamDataBuilder;

use crate::acl::emit_acl_ops;
use crate::batch::into_upload_data;
use crate::cycle::{wait_replay, CycleDeps};
use crate::{AclConflict, SharedRenewStatus};

/// Chain-side view shared by `service.rs` (the balance check) and this
/// module (the caught-up gate). Built once per cycle from
/// `RenewConfig::blockchain_rpc_endpoint` / `log_contract_address`.
pub struct ChainView {
    pub provider: Arc<Provider<Http>>,
    pub flow: Address,
}

impl ChainView {
    /// `numSubmissions` on the flow contract -- the chain's count of
    /// submitted log entries. The caught-up gate waits for local replay to
    /// reach this before it's safe to take the ACL snapshot (spec §5, guard
    /// 1). ethers' `abigen!` lower-cases the ABI method name to
    /// `num_submissions` on the generated `contract_interface::ZgsFlow`.
    pub async fn head_submissions(&self) -> Result<u64> {
        let n = contract_interface::ZgsFlow::new(self.flow, self.provider.clone())
            .num_submissions()
            .call()
            .await?;
        Ok(n.as_u64())
    }
}

/// Pure: which window ops touch pairs the snapshot re-emitted? (spec §5
/// detection). Matches by `(category = op_type & 0xf0, identity)`:
/// admin-category by account, excluding `signer` (its own admin grant is
/// deliberately never emitted -- see `acl::emit_acl_ops` -- so a
/// resurrection of it can never be a renewal-caused conflict); writer-
/// category by account; special-key category by key; special-writer
/// category by the `(key, account)` pair.
pub fn find_conflicts(
    window_ops: &[AclOpRow],
    emitted: &EffectiveAcl,
    signer: H160,
) -> Vec<AclOpRow> {
    window_ops
        .iter()
        .filter(|op| match op.op_type & 0xf0 {
            AccessControlOps::GRANT_ADMIN_ROLE => {
                op.account != signer && emitted.admins.contains(&op.account)
            }
            AccessControlOps::GRANT_WRITER_ROLE => emitted.writers.contains(&op.account),
            AccessControlOps::SET_KEY_TO_SPECIAL => emitted.special_keys.contains(&op.key),
            AccessControlOps::GRANT_SPECIAL_WRITER_ROLE => emitted
                .special_writers
                .contains(&(op.key.clone(), op.account)),
            _ => false,
        })
        .cloned()
        .collect()
}

/// Builds one ACL emission batch from `acl`. `None` when the effective ACL
/// is empty -- nothing to (re-)emit, matching spec §5's "a stream that
/// never had any access-control op emits nothing and stays open."
fn build_acl_batch(
    stream_id: H256,
    acl: &EffectiveAcl,
    signer: H160,
) -> Option<(StreamDataBuilder, usize)> {
    let mut builder = StreamDataBuilder::new(u64::MAX);
    let n = emit_acl_ops(&mut builder, stream_id, acl, signer);
    if n == 0 {
        None
    } else {
        Some((builder, n))
    }
}

/// `true` when an access-control op has replayed strictly after
/// `snapshot_seq` -- the pre-submit re-check (spec §5, guard 2): a batch
/// built from a now-stale snapshot must be discarded and rebuilt.
async fn acl_advanced_past(
    store: &Arc<RwLock<dyn Store>>,
    stream_id: H256,
    snapshot_seq: u64,
) -> Result<bool> {
    let latest = store
        .read()
        .await
        .get_latest_access_control_seq(stream_id)
        .await?;
    Ok(latest > snapshot_seq)
}

/// Reads `(snapshot_seq, EffectiveAcl)` under one store read guard.
///
/// `get_stream_replay_progress` returns the NEXT tx_seq to be replayed, not
/// the last one actually replayed: `put_stream` (and the stream replayer)
/// both advance it to `version + 1` in the same transaction that commits
/// `version`. So the highest version already reflected in the snapshot is
/// `progress - 1`, not `progress` -- hence the `saturating_sub(1)` below
/// (`progress == 0`, meaning nothing has replayed yet, saturates to `0`
/// harmlessly: the effective ACL is empty at that point too, so the caller
/// finds 0 ops to emit and never acts on `snapshot_seq` at all).
///
/// With that correction applied, replay's strict sequentiality means every
/// access-control op with `version <= snapshot_seq` is already reflected in
/// the snapshot; see the ordering-contract doc comments on
/// `Store::get_effective_access_control`.
async fn take_snapshot(
    store: &Arc<RwLock<dyn Store>>,
    stream_id: H256,
) -> Result<(u64, EffectiveAcl)> {
    let guard = store.read().await;
    let snapshot_seq = guard.get_stream_replay_progress().await?.saturating_sub(1);
    let acl = guard.get_effective_access_control(stream_id).await?;
    drop(guard);
    Ok((snapshot_seq, acl))
}

/// Scans the replayed window `(snapshot_seq, batch_seq)` (both bounds
/// exclusive) for access-control ops that touch a pair the snapshot
/// re-emitted, logs each at ERROR, and records it in `status.acl_conflicts`
/// (spec §5 detection). Keeps only the most recent 100 conflicts, truncating
/// from the front.
///
/// Detection is provably complete for this window: replay is strictly
/// sequential by tx_seq, so once the caller has confirmed replay reached
/// `batch_seq` (via `wait_replay`), every op in the window is already in
/// `t_access_control`.
async fn detect_and_record_conflicts(
    store: &Arc<RwLock<dyn Store>>,
    status: &SharedRenewStatus,
    stream_id: H256,
    snapshot_seq: u64,
    batch_seq: u64,
    acl: &EffectiveAcl,
    signer: H160,
) -> Result<()> {
    let window = store
        .read()
        .await
        .get_access_control_ops_in_range(stream_id, snapshot_seq, batch_seq)
        .await?;
    let conflicts = find_conflicts(&window, acl, signer);
    if conflicts.is_empty() {
        return Ok(());
    }

    let mut status = status.write().await;
    for c in &conflicts {
        let op_name = to_access_control_op_name(c.op_type);
        error!(
            "ACL op overridden by renewal -- re-issue it manually: stream={:?} op={} account={:?} key=0x{} version={}",
            stream_id,
            op_name,
            c.account,
            hex::encode(&c.key),
            c.version
        );
        status.acl_conflicts.push(AclConflict {
            stream_id,
            op: op_name.to_string(),
            account: c.account,
            key: format!("0x{}", hex::encode(&c.key)),
            version: c.version,
        });
    }
    let len = status.acl_conflicts.len();
    if len > 100 {
        status.acl_conflicts.drain(0..len - 100);
    }
    Ok(())
}

/// Snapshot -> `emit_acl_ops` (skip if 0 ops) -> `build`/`encode`/tags, in
/// one unit so the pre-submit re-check (below) can redo the whole thing from
/// a fresh snapshot with a single call. `None` means "nothing to emit" --
/// the caller returns `Ok(())` without ever touching the sink.
async fn snapshot_and_encode(
    deps: &CycleDeps,
    stream_id: H256,
) -> Result<Option<(u64, EffectiveAcl, usize, Vec<u8>, Vec<u8>)>> {
    let (snapshot_seq, acl) = take_snapshot(&deps.store, stream_id).await?;
    let Some((builder, n)) = build_acl_batch(stream_id, &acl, deps.signer) else {
        return Ok(None);
    };
    let built = builder.build(None)?;
    let encoded = built.encode()?;
    let tags = builder.build_tags(None);
    Ok(Some((snapshot_seq, acl, n, encoded, tags)))
}

/// Everything from the snapshot fence onward (spec §5 steps 3-8): touches
/// only the store and the sink, never the chain directly, so it's the piece
/// unit-tested against a mock `BatchSink`. `renew_stream_acl_inner` wraps
/// this with the chain-side caught-up gate.
async fn renew_stream_acl_after_gate(deps: &CycleDeps, stream_id: H256) -> Result<()> {
    let Some((mut snapshot_seq, mut acl, n, encoded, mut tags)) =
        snapshot_and_encode(deps, stream_id).await?
    else {
        return Ok(());
    };

    if deps.config.dry_run {
        info!(
            "renew dry-run: would emit {} ACL op(s) for stream {:?}",
            n, stream_id
        );
        return Ok(());
    }

    let mut data = into_upload_data(
        encoded,
        deps.config.encryption_key,
        deps.config.wallet_private_key,
    )?;

    // Pre-submit re-check, placed immediately before the on-chain send so it
    // also covers the build/encode/encrypt work just above (not only the
    // snapshot read itself): one retry, redoing the whole snapshot -> emit
    // -> encode -> encrypt sequence from a fresh snapshot, if any ACL op
    // replayed past `snapshot_seq` while all of that ran; still dirty after
    // the retry -> skip rather than pay for a batch that's doomed to race
    // again (spec §5, guard 2).
    if acl_advanced_past(&deps.store, stream_id, snapshot_seq).await? {
        warn!(
            "renew: ACL snapshot for stream {:?} went stale before submit -- retrying from a fresh snapshot",
            stream_id
        );
        let Some((seq2, acl2, _n2, encoded2, tags2)) = snapshot_and_encode(deps, stream_id).await?
        else {
            return Ok(());
        };
        snapshot_seq = seq2;
        acl = acl2;
        tags = tags2;
        data = into_upload_data(
            encoded2,
            deps.config.encryption_key,
            deps.config.wallet_private_key,
        )?;
        if acl_advanced_past(&deps.store, stream_id, snapshot_seq).await? {
            warn!(
                "renew: ACL snapshot for stream {:?} still stale after retry -- skipping ACL renewal this cycle",
                stream_id
            );
            return Ok(());
        }
    }

    let root = deps.sink.submit(data, tags).await?;

    // Poll for the tx seq the upload resolved to (10s interval, 120s
    // timeout) -- storage nodes need a beat to log the file before
    // `resolve_tx_seq` can answer.
    let resolve_deadline = Instant::now() + Duration::from_secs(120);
    let mut batch_seq = None;
    loop {
        match deps.sink.resolve_tx_seq(root).await {
            Ok(Some(seq)) => {
                batch_seq = Some(seq);
                break;
            }
            Ok(None) => {}
            Err(e) => warn!(
                "renew: ACL batch resolve_tx_seq failed for stream {:?}: {}",
                stream_id, e
            ),
        }
        if Instant::now() >= resolve_deadline {
            break;
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
    let Some(batch_seq) = batch_seq else {
        warn!(
            "renew: ACL batch for stream {:?} did not resolve to a tx seq within 120s -- conflict detection skipped for this batch; overrides in this window will not be reported",
            stream_id
        );
        return Ok(());
    };

    if !wait_replay(
        &deps.store,
        batch_seq,
        Duration::from_secs(600),
        Duration::from_secs(2),
    )
    .await
    {
        warn!(
            "renew: ACL batch for stream {:?} (seq {}) had not replayed after 10 minutes -- conflict detection skipped for this batch; overrides in this window will not be reported",
            stream_id, batch_seq
        );
        return Ok(());
    }

    detect_and_record_conflicts(
        &deps.store,
        &deps.status,
        stream_id,
        snapshot_seq,
        batch_seq,
        &acl,
        deps.signer,
    )
    .await
}

/// The chain-side caught-up gate (spec §5, guard 1): waits, bounded to 60s
/// (2s polls), for local replay to have reached the chain's latest
/// submission count. Only once that holds is it safe to take the ACL
/// snapshot below -- taking it earlier risks missing a revoke that already
/// landed on chain but hasn't replayed locally yet. On timeout, ACL renewal
/// is skipped for this stream this cycle; values still renew regardless
/// (see `renew_stream_acl`'s caller in `service.rs`).
///
/// `numSubmissions` (`head`) is a count, so the highest actual on-chain
/// tx_seq is `head - 1`; `get_stream_replay_progress` is itself a count (the
/// next tx_seq to be replayed, not the last one replayed -- see
/// `take_snapshot`'s doc comment), so "the last submission has replayed" is
/// `replay_progress >= head`, not `replay_progress + 1 >= head`.
///
/// A transient `head_submissions` RPC error does not abort the gate: it's
/// logged at WARN and treated as "not caught up yet" for this iteration,
/// same as any other not-yet-caught-up outcome, so a single flaky RPC call
/// doesn't cost the whole 60s budget in one shot.
async fn caught_up_with_chain(
    deps: &CycleDeps,
    chain: &ChainView,
    stream_id: H256,
) -> Result<bool> {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        match chain.head_submissions().await {
            Ok(head) => {
                let next_tx_seq = deps.store.read().await.next_tx_seq();
                let replay_progress = deps.store.read().await.get_stream_replay_progress().await?;
                if next_tx_seq >= head && replay_progress >= head {
                    return Ok(true);
                }
                if Instant::now() >= deadline {
                    warn!(
                        "renew: ACL caught-up gate timed out for stream {:?} (chain head {}, next_tx_seq {}, replay_progress {}) -- skipping ACL renewal this cycle",
                        stream_id, head, next_tx_seq, replay_progress
                    );
                    return Ok(false);
                }
            }
            Err(e) => {
                warn!(
                    "renew: ACL caught-up gate: head_submissions failed for stream {:?}: {} -- treating as not-caught-up and retrying within the 60s budget",
                    stream_id, e
                );
                if Instant::now() >= deadline {
                    warn!(
                        "renew: ACL caught-up gate timed out for stream {:?} (last error: {}) -- skipping ACL renewal this cycle",
                        stream_id, e
                    );
                    return Ok(false);
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

async fn renew_stream_acl_inner(
    deps: &CycleDeps,
    chain: &ChainView,
    stream_id: H256,
) -> Result<()> {
    if !caught_up_with_chain(deps, chain, stream_id).await? {
        return Ok(());
    }
    renew_stream_acl_after_gate(deps, stream_id).await
}

/// Emit one ACL snapshot batch for the stream. Steps: caught-up gate ->
/// snapshot (seq + `EffectiveAcl` under ONE store read guard) ->
/// `emit_acl_ops` (skip if 0 ops) -> pre-submit re-check (discard + retry
/// once) -> submit -> resolve seq -> `wait_replay` -> detection scan ->
/// `status.acl_conflicts` + ERROR log. See spec §5.
///
/// Sets `status.acl_renewal_in_progress` before doing anything and clears it
/// on every exit path. Deliberately a thin wrapper around
/// `renew_stream_acl_inner` rather than a `Drop` guard -- the flag only ever
/// needs to be true for the duration of this one `.await`, so an explicit
/// set/call/clear is simpler and just as safe.
pub async fn renew_stream_acl(deps: &CycleDeps, chain: &ChainView, stream_id: H256) -> Result<()> {
    deps.status.write().await.acl_renewal_in_progress = true;
    let result = renew_stream_acl_inner(deps, chain, stream_id).await;
    deps.status.write().await.acl_renewal_in_progress = false;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use kv_types::{AccessControl, AccessControlSet, KVTransaction, StreamWriteSet};
    use std::sync::Mutex;
    use storage_with_stream::StoreManager;
    use zg_storage_client::core::dataflow::IterableData;

    use crate::upload::BatchSink;
    use crate::{RenewConfig, RenewStatus};

    fn sid() -> H256 {
        H256::repeat_byte(0x9)
    }

    // ---- find_conflicts -----------------------------------------------

    #[test]
    fn conflict_matching_by_category_and_identity() {
        let u2 = H160::repeat_byte(2);
        let u3 = H160::repeat_byte(3);
        let emitted = EffectiveAcl {
            admins: vec![],
            writers: vec![u2],
            special_keys: vec![],
            special_writers: vec![],
        };
        let window = vec![
            AclOpRow {
                op_type: AccessControlOps::REVOKE_WRITER_ROLE,
                key: vec![],
                account: u2,
                version: 10,
            }, // conflict
            AclOpRow {
                op_type: AccessControlOps::GRANT_WRITER_ROLE,
                key: vec![],
                account: u3,
                version: 11,
            }, // untouched pair
            AclOpRow {
                op_type: AccessControlOps::RENOUNCE_WRITER_ROLE,
                key: vec![],
                account: u2,
                version: 12,
            }, // conflict
        ];
        let c = find_conflicts(&window, &emitted, H160::zero());
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].version, 10);
    }

    #[test]
    fn admin_category_excludes_signers_own_account() {
        let signer = H160::repeat_byte(9);
        let emitted = EffectiveAcl {
            admins: vec![signer],
            writers: vec![],
            special_keys: vec![],
            special_writers: vec![],
        };
        let window = vec![AclOpRow {
            op_type: AccessControlOps::RENOUNCE_ADMIN_ROLE,
            key: vec![],
            account: signer,
            version: 5,
        }];
        let c = find_conflicts(&window, &emitted, signer);
        assert!(
            c.is_empty(),
            "signer's own admin grant is never emitted, so a renounce of it can't be a renewal-caused conflict"
        );
    }

    #[test]
    fn admin_category_conflict_for_non_signer_account() {
        let signer = H160::repeat_byte(9);
        let other = H160::repeat_byte(2);
        let emitted = EffectiveAcl {
            admins: vec![other],
            writers: vec![],
            special_keys: vec![],
            special_writers: vec![],
        };
        let window = vec![AclOpRow {
            op_type: AccessControlOps::RENOUNCE_ADMIN_ROLE,
            key: vec![],
            account: other,
            version: 7,
        }];
        let c = find_conflicts(&window, &emitted, signer);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].version, 7);
    }

    #[test]
    fn special_writer_matching_requires_both_key_and_account() {
        let u2 = H160::repeat_byte(2);
        let u3 = H160::repeat_byte(3);
        let emitted = EffectiveAcl {
            admins: vec![],
            writers: vec![],
            special_keys: vec![],
            special_writers: vec![(b"s1".to_vec(), u2)],
        };
        let window = vec![
            // same account, different key -> not a conflict
            AclOpRow {
                op_type: AccessControlOps::REVOKE_SPECIAL_WRITER_ROLE,
                key: b"s2".to_vec(),
                account: u2,
                version: 1,
            },
            // same key, different account -> not a conflict
            AclOpRow {
                op_type: AccessControlOps::REVOKE_SPECIAL_WRITER_ROLE,
                key: b"s1".to_vec(),
                account: u3,
                version: 2,
            },
            // matching (key, account) pair -> conflict
            AclOpRow {
                op_type: AccessControlOps::REVOKE_SPECIAL_WRITER_ROLE,
                key: b"s1".to_vec(),
                account: u2,
                version: 3,
            },
        ];
        let c = find_conflicts(&window, &emitted, H160::zero());
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].version, 3);
    }

    #[test]
    fn special_key_category_matches_by_key() {
        let emitted = EffectiveAcl {
            admins: vec![],
            writers: vec![],
            special_keys: vec![b"special".to_vec()],
            special_writers: vec![],
        };
        let window = vec![
            AclOpRow {
                op_type: AccessControlOps::SET_KEY_TO_NORMAL,
                key: b"special".to_vec(),
                account: H160::zero(),
                version: 1,
            },
            AclOpRow {
                op_type: AccessControlOps::SET_KEY_TO_NORMAL,
                key: b"other".to_vec(),
                account: H160::zero(),
                version: 2,
            },
        ];
        let c = find_conflicts(&window, &emitted, H160::zero());
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].version, 1);
    }

    // ---- acl_advanced_past ----------------------------------------------

    async fn seed_acl_commit(
        store: &Arc<RwLock<dyn Store>>,
        stream_id: H256,
        seq: u64,
        ops: Vec<(u8, H160, Vec<u8>)>,
    ) {
        let mut guard = store.write().await;
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
        let acl = AccessControlSet {
            access_controls: ops
                .into_iter()
                .map(|(op_type, account, key)| AccessControl {
                    op_type,
                    stream_id,
                    key: Arc::new(key),
                    account,
                    operator: account,
                })
                .collect(),
            is_admin: Default::default(),
        };
        let write_set = StreamWriteSet {
            stream_writes: vec![],
        };
        guard
            .put_stream(seq, H256::zero(), "Commit".into(), Some((write_set, acl)))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn acl_advanced_past_detects_a_later_op() {
        // Derives `snapshot_seq` from a real `take_snapshot` call rather
        // than a hand-picked constant -- a regression in the fence's
        // `progress - 1` arithmetic (the exact off-by-one this guards
        // against) would show up here as a wrong `snapshot_seq` value, not
        // just a wrong `acl_advanced_past` verdict.
        let store: Arc<RwLock<dyn Store>> =
            Arc::new(RwLock::new(StoreManager::memorydb().await.unwrap()));
        let u1 = H160::repeat_byte(1);
        // ACL op at version 0.
        seed_acl_commit(
            &store,
            sid(),
            0,
            vec![(AccessControlOps::GRANT_WRITER_ROLE, u1, vec![])],
        )
        .await;
        // Real fence right after version 0 lands: replay progress is 1
        // (next tx_seq to replay), so the corrected snapshot_seq is 0 (the
        // highest version actually reflected in the snapshot).
        let (snapshot_seq, _) = take_snapshot(&store, sid()).await.unwrap();
        assert_eq!(snapshot_seq, 0);
        assert!(!acl_advanced_past(&store, sid(), snapshot_seq)
            .await
            .unwrap());

        // A second ACL op lands at version == snapshot_seq + 1 -- exactly
        // the edge the off-by-one bug missed (a racing op landing in the
        // very next tx after the fence). The fence taken above must now be
        // considered stale.
        seed_acl_commit(
            &store,
            sid(),
            1,
            vec![(AccessControlOps::GRANT_WRITER_ROLE, u1, vec![])],
        )
        .await;
        assert!(acl_advanced_past(&store, sid(), snapshot_seq)
            .await
            .unwrap());

        // A fresh fence taken now (after both ops) is not stale relative to
        // itself.
        let (snapshot_seq2, _) = take_snapshot(&store, sid()).await.unwrap();
        assert_eq!(snapshot_seq2, 1);
        assert!(!acl_advanced_past(&store, sid(), snapshot_seq2)
            .await
            .unwrap());
    }

    // ---- detect_and_record_conflicts ------------------------------------

    #[tokio::test]
    async fn detect_and_record_conflicts_populates_status_and_logs() {
        let store: Arc<RwLock<dyn Store>> =
            Arc::new(RwLock::new(StoreManager::memorydb().await.unwrap()));
        let u2 = H160::repeat_byte(2);
        seed_acl_commit(
            &store,
            sid(),
            0,
            vec![(AccessControlOps::GRANT_WRITER_ROLE, u2, vec![])],
        )
        .await;

        // Real fence, taken right after version 0 -- exercises the
        // corrected `progress - 1` arithmetic instead of a hand-picked
        // constant divorced from what `take_snapshot` actually produces.
        let (snapshot_seq, acl) = take_snapshot(&store, sid()).await.unwrap();
        assert_eq!(snapshot_seq, 0);
        assert_eq!(acl.writers, vec![u2]);

        // The racing revoke lands immediately after the fence, at
        // version == snapshot_seq + 1 -- the exact edge the off-by-one bug
        // missed (the window used to require version > 1, excluding it).
        seed_acl_commit(
            &store,
            sid(),
            1,
            vec![(AccessControlOps::REVOKE_WRITER_ROLE, u2, vec![])],
        )
        .await;

        let status: SharedRenewStatus = Arc::new(RwLock::new(RenewStatus::default()));

        detect_and_record_conflicts(&store, &status, sid(), snapshot_seq, 2, &acl, H160::zero())
            .await
            .unwrap();

        let s = status.read().await;
        assert_eq!(s.acl_conflicts.len(), 1);
        assert_eq!(s.acl_conflicts[0].op, "REVOKE_WRITER_ROLE");
        assert_eq!(s.acl_conflicts[0].account, u2);
        assert_eq!(s.acl_conflicts[0].version, 1);
        assert_eq!(s.acl_conflicts[0].stream_id, sid());
    }

    #[tokio::test]
    async fn detect_and_record_conflicts_truncates_to_100_from_the_front() {
        let store: Arc<RwLock<dyn Store>> =
            Arc::new(RwLock::new(StoreManager::memorydb().await.unwrap()));
        let u2 = H160::repeat_byte(2);
        seed_acl_commit(
            &store,
            sid(),
            0,
            vec![(AccessControlOps::GRANT_WRITER_ROLE, u2, vec![])],
        )
        .await;
        let (snapshot_seq, acl) = take_snapshot(&store, sid()).await.unwrap();
        assert_eq!(snapshot_seq, 0);
        seed_acl_commit(
            &store,
            sid(),
            1,
            vec![(AccessControlOps::REVOKE_WRITER_ROLE, u2, vec![])],
        )
        .await;

        let status: SharedRenewStatus = Arc::new(RwLock::new(RenewStatus::default()));
        {
            let mut s = status.write().await;
            for i in 0..100u64 {
                s.acl_conflicts.push(AclConflict {
                    stream_id: sid(),
                    op: "PRE_EXISTING".into(),
                    account: u2,
                    key: "0x".into(),
                    version: i,
                });
            }
        }

        detect_and_record_conflicts(&store, &status, sid(), snapshot_seq, 2, &acl, H160::zero())
            .await
            .unwrap();

        let s = status.read().await;
        assert_eq!(s.acl_conflicts.len(), 100);
        // The oldest pre-existing entry (version 0) was dropped; the newest
        // pre-existing entry (version 99) and the freshly recorded conflict
        // both survive, in order.
        assert_eq!(s.acl_conflicts[0].version, 1);
        assert_eq!(s.acl_conflicts[97].op, "PRE_EXISTING");
        assert_eq!(s.acl_conflicts[98].op, "PRE_EXISTING");
        assert_eq!(s.acl_conflicts[99].op, "REVOKE_WRITER_ROLE");
    }

    // ---- renew_stream_acl_after_gate (mock sink, no ChainView) ----------

    /// Minimal local replica of `cycle::tests::MockSink` (that one is
    /// private to `cycle`'s own `cfg(test)` module).
    struct MockSink {
        submitted: Mutex<u32>,
        resolve_seq: Option<u64>,
    }

    #[async_trait]
    impl BatchSink for MockSink {
        async fn submit(&self, _data: Arc<dyn IterableData>, _tags: Vec<u8>) -> Result<H256> {
            *self.submitted.lock().unwrap() += 1;
            Ok(H256::repeat_byte(0xaa))
        }
        async fn resolve_tx_seq(&self, _root: H256) -> Result<Option<u64>> {
            Ok(self.resolve_seq)
        }
    }

    fn base_config(dry_run: bool) -> RenewConfig {
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

    fn deps_with(
        store: Arc<RwLock<dyn Store>>,
        sink: Arc<MockSink>,
        dry_run: bool,
        signer: H160,
    ) -> CycleDeps {
        CycleDeps {
            store,
            sink,
            config: Arc::new(base_config(dry_run)),
            status: Arc::new(RwLock::new(RenewStatus::default())),
            signer,
        }
    }

    #[tokio::test]
    async fn zero_acl_ops_skips_without_submitting() {
        // Fresh store, stream never touched by any access-control op:
        // `get_effective_access_control` returns the all-empty default, so
        // `emit_acl_ops` emits 0 ops and the function must return early
        // without ever calling the sink.
        let store: Arc<RwLock<dyn Store>> =
            Arc::new(RwLock::new(StoreManager::memorydb().await.unwrap()));
        let sink = Arc::new(MockSink {
            submitted: Mutex::new(0),
            resolve_seq: Some(0),
        });
        let deps = deps_with(store, sink.clone(), false, H160::repeat_byte(9));

        renew_stream_acl_after_gate(&deps, sid()).await.unwrap();

        assert_eq!(*sink.submitted.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn dry_run_logs_and_skips_without_submitting() {
        let store: Arc<RwLock<dyn Store>> =
            Arc::new(RwLock::new(StoreManager::memorydb().await.unwrap()));
        let u1 = H160::repeat_byte(1);
        seed_acl_commit(
            &store,
            sid(),
            0,
            vec![(AccessControlOps::GRANT_WRITER_ROLE, u1, vec![])],
        )
        .await;
        let sink = Arc::new(MockSink {
            submitted: Mutex::new(0),
            resolve_seq: Some(0),
        });
        let deps = deps_with(store, sink.clone(), true, H160::repeat_byte(9));

        renew_stream_acl_after_gate(&deps, sid()).await.unwrap();

        assert_eq!(*sink.submitted.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn successful_emission_submits_and_finds_no_conflict_in_an_empty_window() {
        let store: Arc<RwLock<dyn Store>> =
            Arc::new(RwLock::new(StoreManager::memorydb().await.unwrap()));
        let u1 = H160::repeat_byte(1);
        // One commit at seq 0 grants u1 the writer role; replay progress is
        // then 1 (put_stream sets progress = tx_seq + 1).
        seed_acl_commit(
            &store,
            sid(),
            0,
            vec![(AccessControlOps::GRANT_WRITER_ROLE, u1, vec![])],
        )
        .await;
        assert_eq!(
            store
                .read()
                .await
                .get_stream_replay_progress()
                .await
                .unwrap(),
            1
        );

        // resolve_tx_seq resolves to the current replay progress (1) so
        // `wait_replay` (target 1) is satisfied on its very first check --
        // no real sleeping. The corrected fence sees snapshot_seq = 0 (the
        // one committed op, at version 0), so the detection window (0, 1)
        // is empty by construction (exclusive both ends), and no conflict
        // is expected.
        let sink = Arc::new(MockSink {
            submitted: Mutex::new(0),
            resolve_seq: Some(1),
        });
        let deps = deps_with(store, sink.clone(), false, H160::repeat_byte(9));

        renew_stream_acl_after_gate(&deps, sid()).await.unwrap();

        assert_eq!(*sink.submitted.lock().unwrap(), 1);
        assert!(deps.status.read().await.acl_conflicts.is_empty());
    }
}
