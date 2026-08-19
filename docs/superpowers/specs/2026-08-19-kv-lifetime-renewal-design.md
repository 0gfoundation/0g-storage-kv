# KV Lifetime Renewal

Design spec — 2026-08-19

## Problem

Data on the 0G storage layer has a finite lifetime (~1 year). A KV stream is
reconstructed by replaying the KV files that carry its writes, so when those
files expire the stream's contents become unrecoverable for any node that has
not already synced them. There is no on-chain extension primitive — the
`FixedPrice` and `DummyMarket` contracts expose only `chargeFee` and
`pricePerSector` — so the only way to renew a value's lifetime is to write it
again.

The KV node already holds every value locally in its own flow store, and it
already depends on `zg-storage-client`. It is therefore the natural place to
run renewal: it can read the current state, re-pack it, and submit it as a
fresh KV file.

## Goal

A background service inside `zgs_kv` that, on a slow cycle (weekly by
default), finds every key whose latest write is older than a threshold (180
days by default), re-writes it to the stream, and confirms the write took
effect. Renewal must survive a from-scratch resync: a node that syncs after
the original files have expired must be able to replay the renewal files and
arrive at the same state.

## Background — what exists today

- `t_stream` is the key-value table: `(stream_id, key, version, start_index,
  end_index)`, primary key `(stream_id, key, version)`. Rows are immutable —
  each version of a key is its own row. `version` is the tx_seq of the write.
  There is no timestamp anywhere in the KV DB.
- `t_access_control` holds the access-control op log:
  `(stream_id, key, version, account, op_type, operator)`.
- Values live in the local flow store, addressed by the `start_index` /
  `end_index` byte range recorded on the `t_stream` row, and are read with
  `get_chunk_by_flow_index` (see `kv_rpc_server::impl::get_value_segment`).
- `log_entry_sync` feeds `LogFetchProgress::{SyncedBlock, Transaction}` into
  `handle_data`, which already fetches the block for every synced block and
  already issues a `get_transaction` per submit log.
- `COL_BLOCK_PROGRESS` maps block number to first submission index, but
  `start_remove_finalized_block_task` deletes every entry below the finalized
  block, so no historical block-to-tx_seq mapping survives locally.
- The stream replayer validates each write with
  `has_write_permission(tx.sender, stream_id, key, tx.seq)`, and rejects the
  file with `VersionConfliction` if any written key's latest version exceeds
  the file's declared `version`.
- `parse_access_control_data` auto-grants admin to `tx.sender` for any stream
  that `is_new_stream` reports as having no access-control history.

## Decisions

| Decision | Choice | Why |
|---|---|---|
| Where renewal lives | New `kv_renew` crate, inside the node | `stream` is ~2200 lines across two files doing ingest; renewal is egress. Separate crate keeps both testable. |
| How age is known | `created_at` / `updated_at` columns on `t_stream`, filled from the write's on-chain block time | Timestamps become a property of the data, so a node that resyncs five years of history computes the same ages as one that was live throughout. Wall-clock-at-replay would stamp ancient writes with today's time and disable renewal for six months after any resync. |
| Cycle shape | Drain to completion each cycle, paced between batches | A per-cycle byte cap would defer a backlog by a week per slice. Per-batch caps bound each upload; the loop bounds nothing. |
| Scope | Latest version per key, plus the stream's effective access-control state | Renewing values alone leaves the grant that authorizes the renewal signer in an expiring file — a fresh node would then reject the renewal writes and lose the data anyway. |
| Signer key | `renew_private_key` in config, `ZGS_KV_RENEW_PRIVATE_KEY` overrides | Matches the existing `encryption_key` / `wallet_private_key` convention while letting deployments keep a spending key off disk. |
| Operator control | `kv_getRenewStatus` plus `admin_renewNow` | Makes the integration test deterministic and lets operators confirm renewal without grepping logs. |
| ACL cadence | Full effective-state snapshot every cycle, batch-first | Permission sets are small and change rarely; an unconditional weekly snapshot deletes all per-op age tracking and keeps permission state the freshest data in the stream. |
| Deployment model | The stream admin runs the KV node; `renew_private_key` is the admin key; a single admin is recommended | ACL re-emission only validates for an admin sender, so this is forced, not chosen. It also routes every revoke through the operator's own tooling (revokes are admin-only), making the operational lock airtight for the dangerous case. |
| Default state | On when `renew_private_key` is set; `renew_enabled` is a kill switch | Renewal is part of normal node operation, but a spending feature needs an off switch that does not require deleting the key. |

## Design

### 1. Timestamps on the KV table

`t_stream` gains two nullable columns and an index:

```sql
created_at INTEGER,   -- unix seconds, block time of the key's FIRST write
updated_at INTEGER    -- unix seconds, block time of THIS write
CREATE INDEX IF NOT EXISTS stream_updated_idx ON t_stream(updated_at)
```

New databases get the columns from `CREATE_STREAM_TABLE_STATEMENT`. Existing
databases get `ALTER TABLE t_stream ADD COLUMN`, guarded by a
`PRAGMA table_info(t_stream)` check, run from `create_tables_if_not_exist`.

Because rows are immutable per version, `created_at` is carried forward at
insert time rather than updated:

```sql
INSERT OR REPLACE INTO t_stream
    (stream_id, key, version, start_index, end_index, created_at, updated_at)
VALUES
    (:stream_id, :key, :version, :start_index, :end_index,
     COALESCE((SELECT MIN(created_at) FROM t_stream
               WHERE stream_id = :stream_id AND key = :key), :ts),
     :ts)
```

`t_access_control` gains the same two columns by the same mechanism, because
access-control ops age exactly like values do and section 5 needs to know when
a grant is close to expiring. It has no uniqueness constraint, so its rows
take `created_at = updated_at = :ts` with no carry-forward.

`store_manager::put_stream` resolves `:ts` itself from the tx-time store for
both tables, so the replayer's call signature does not change.

### 2. Recording each tx's block time

A new rocksdb column family `COL_TX_TIME` maps `tx_seq` to a `u64` unix
timestamp. `COL_NUM` goes from 5 to 6; this is safe on existing databases
because `kvdb-rocksdb`'s `open_primary` falls back to opening with no column
families and creating the missing ones.

`log_entry_sync::handle_data` keeps a small bounded `block_number ->
timestamp` cache. On `LogFetchProgress::Transaction((tx, block_number))` it
resolves the timestamp from the cache, fetching the block once on a miss, and
writes `tx_seq -> timestamp`. Note that in the recovery path the
`Transaction` message is emitted *before* the `SyncedBlock` for the same
block, so the cache must not be assumed warm. The added cost is at most one
`eth_getBlockByNumber` per distinct block containing submissions, against a
path that already issues one `get_transaction` per submit log.

If the timestamp cannot be resolved, the row is written with NULL and the
backfill handles it.

`remove_tx_after` (the reorg path) deletes the reverted seqs' `COL_TX_TIME`
rows alongside their `COL_TX` and `COL_TX_COMPLETED` rows, so a re-orged seq
cannot briefly carry the old chain's timestamp.

### 3. Backfilling legacy rows

Rows written before this change have NULL timestamps. On startup, if any NULL
rows exist, `kv_renew::backfill` runs once:

1. Probe the chain at a small number of age points (default: 6, 12 and 24
   months ago). Each probe binary-searches `eth_getBlockByNumber` for the
   block at that time, then issues `getLogs` on the flow contract forward
   from that block until it finds the first `Submit` event, whose
   `submissionIndex` is the tx_seq at that time.
2. Build a piecewise-linear `version -> time` map from the probes plus the
   known present point `(next_tx_seq, now)`.
3. `UPDATE t_stream SET updated_at = <interpolated>, created_at =
   COALESCE(created_at, <interpolated>) WHERE updated_at IS NULL`.

This costs roughly 50-100 RPC calls, once. It uses logs rather than
historical state, so it does not require an archive node. Precision is not
important: the threshold is 180 days against a 1-year lifetime.

If the backfill cannot run (RPC unavailable), NULL rows are deferred — not
renewed — the failure is logged at WARN, and the backfill is retried at the
next cycle. Treating NULL as stale would spend real fees re-uploading
possibly-fresh data on nothing more than a transient RPC outage.

### 4. The renewer

New crate `node/kv_renew`, spawned from `ClientBuilder::with_renew(...)`
after `with_stream`, as a `task_executor` task named `kv renewer`.

Startup:

- Derive the signer address from `renew_private_key`. Log the address, never
  the key.
- Check `is_admin(signer, stream_id, u64::MAX)` for each monitored stream.
  The expected deployment is that the signer IS the stream admin (see the
  deployment model decision); on a stream where it is not, value renewal
  still runs for keys the signer can write, but ACL renewal is skipped with
  an ERROR log.
- Sleep `renew_startup_delay_secs` so sync and replay can warm up.

Each cycle:

1. **Cutoff** — `cutoff = now - renew_max_age_secs`.
2. **Scan** — per stream in the live stream set:

   ```sql
   SELECT stream_id, key, MAX(version) AS version, start_index, end_index, updated_at
   FROM t_stream
   WHERE stream_id = :stream_id AND key > :cursor
   GROUP BY stream_id, key
   HAVING updated_at <= :cutoff
   ORDER BY key ASC
   LIMIT :limit
   ```

   SQLite's bare-column rule returns the other columns from the `MAX(version)`
   row. Pagination is on `key` so a cycle interrupted by a restart resumes
   cleanly. NULL `updated_at` rows are excluded by the comparison — they are
   the backfill's job (section 3), never the scanner's.
3. **Filter** — skip and warn on keys where
   `has_write_permission(signer, stream_id, key, u64::MAX)` is false, or where
   the value bytes are not present locally (a tx the fetcher gave up on).
   Skip keys already uploaded earlier in this cycle; their `updated_at` will
   not move until replay catches up, and without this guard the drain loop
   would re-upload them indefinitely.
4. **Pack** — read each value through the shared flow-store reader (factored
   out of `kv_rpc_server::impl::get_value_segment`) and feed
   `StreamDataBuilder::set` until `renew_batch_max_bytes` or
   `renew_batch_max_keys` is reached. A value larger than the batch cap
   becomes its own batch. `version` is `u64::MAX`, making every renewal an
   unconditional write that can never trip `VersionConfliction`.
5. **Access control** — every cycle, each stream where the signer holds
   admin gets one small batch re-emitting the stream's full effective
   access-control state as fresh grants (see section 5). This batch goes out
   FIRST, before any value batches, so the window the operational lock must
   cover is seconds rather than the length of the drain. Emission is
   unconditional — permission sets are small, so a weekly snapshot costs a
   few hundred bytes and removes any need to track per-op ages.
6. **Upload** — `build() -> encode() -> DataInMemory -> Uploader::upload`,
   with `tags = build_tags()`. Two non-defaults matter:
   - `skip_tx = false`. The SDK default of `true` skips the on-chain
     submission when the file already exists, which is exactly the submission
     that renews the lifetime.
   - If the node has `encryption_key` (v1) or `wallet_private_key` (v2 ECIES)
     configured, the encoded batch is wrapped in `EncryptedData::new` or
     `EncryptedData::new_ecies` before upload. Without this, renewed data
     lands in plaintext and every reader of that stream breaks.

   `fee` stays 0, letting the SDK compute it from `pricePerSector`.

   A storage-node response indicating the file is already finalized counts as
   success: the on-chain submission — the thing that renews the lifetime —
   has already landed by the time segments are pushed, and nodes deduplicate
   data by merkle root.
7. **Drain** — repeat 2-6 until a scan pass returns nothing, pausing
   `renew_pause_between_batches_ms` between uploads.
8. **Verify** — each upload yields the batch's merkle root, which is resolved
   to a tx_seq by querying the storage node or indexer for the file's info.
   The cycle then polls `get_stream_replay_progress()` until it reaches the
   highest tx_seq submitted, bounded by a timeout, and re-scans the renewed
   keys to report how many actually moved past the cutoff. This is the check
   that renewal took effect rather than merely being submitted — a write
   rejected at replay for permissions leaves `updated_at` untouched and is
   caught here.
9. Sleep `renew_cycle_interval_secs`.

### 5. Access-control renewal

Effective state is reconstructed from `t_access_control` with the same
last-op-wins rule the store's permission queries use:

- **Admins** — accounts whose latest op in `{GRANT_ADMIN_ROLE,
  RENOUNCE_ADMIN_ROLE}` is the grant.
- **Stream writers** — accounts whose latest op in `{GRANT_WRITER_ROLE,
  REVOKE_WRITER_ROLE, RENOUNCE_WRITER_ROLE}` is the grant.
- **Special keys** — keys whose latest op in `{SET_KEY_TO_SPECIAL,
  SET_KEY_TO_NORMAL}` is `SET_KEY_TO_SPECIAL`.
- **Special writers** — `(account, key)` pairs whose latest op in
  `{GRANT_SPECIAL_WRITER_ROLE, REVOKE_SPECIAL_WRITER_ROLE,
  RENOUNCE_SPECIAL_WRITER_ROLE}` is the grant.

Only grants are re-emitted; revocations need not be, because absence is the
default. A stream that never had any access-control op emits nothing and
stays open, matching its original state. The signer's own admin grant is
deliberately skipped: the replayer drops a `GRANT_ADMIN_ROLE` whose account
equals the file's sender (`parse_access_control_data`), and on a fresh resync
the auto-admin rule below re-establishes it anyway.

The full effective set is re-emitted every cycle rather than when ops near
expiry. The set is small — permissions change rarely — so the cost is a few
hundred bytes per stream per week, and the snapshot approach needs no per-op
age tracking at all.

`validate_access_control_set` computes the admin set from store state *before*
applying the file's own ops, so a file cannot bootstrap its own authority. Two
cases follow:

- On a node that has lost all access-control history for the stream,
  `is_new_stream` is true, the replayer auto-grants admin to the renewal
  file's sender, and the re-emitted grants validate.
- On a node where some access-control rows survive, the renewal signer must
  genuinely hold admin. This is the case the startup check warns about.

#### The revocation race

Re-emitting effective state is only correct if the snapshot is current.
Because permission ops are themselves on-chain writes that this node merely
replays, there is a race:

```
t1 grant u1 → [snapshot: sees only t1] → t2 revoke u1 → t3 renewal file
```

The snapshot sees u1 granted, t3 re-emits the grant, and last-op-wins makes
the revoked u1 writable again. The same happens when t2 is already on-chain
but not yet replayed locally at snapshot time. Note that per-cycle full
re-emission does NOT self-heal this: once t3 lands, u1-granted IS the
effective state, and every later snapshot faithfully perpetuates it.

The snapshot itself is taken at a single fixed seq: the snapshotter holds
the store's read guard across its queries, which blocks the replayer's
writes for the milliseconds involved, and pins `snapshot_seq` to the replay
progress read under that same guard. Pausing anything for longer buys
nothing — the race is in chain ordering, which local pauses cannot touch;
a paused node is merely blind to competitors, not protected from them.

Four guards, layered:

1. **Caught-up gate** — the renewer snapshots only after local replay
   progress has reached the chain's latest submission (`numSubmissions` on
   the flow contract, one RPC). Removes the replay-lag variant.
2. **Operational lock** — `kv_getRenewStatus` exposes
   `aclRenewalInProgress`; operators MUST hold role changes while it is
   true. The ACL batch is emitted first each cycle, so the flag is up for
   seconds. This is a documented convention, not enforcement: the KV node
   observes writes, it does not admit them, so it cannot block a third
   party's on-chain op.

   There is no push channel to the wallets that can issue role changes, so
   the lock is surfaced as pull mechanisms, cheapest first:

   - the RPC flag itself, for anything that automates role changes;
   - an SDK courtesy check (upstream): the SDK's access-control write paths
     accept an optional KV node URL and wait while the flag is up — the one
     surface that reaches third-party writers, who can grant roles too;
   - a predictable cadence: the window opens at cycle start and lasts
     seconds per stream, so manual changes simply avoid the known minute;
   - INFO logs at window open and close, for the operator's existing
     alerting.

   An on-chain sentinel key was considered and rejected: it is the only
   surface visible beyond this node without SDK cooperation, but it costs a
   transaction per cycle, propagates with the same delay it tries to guard,
   and its end-marker has the same race. The lock is a courtesy layer that
   makes corrective churn rare; guards 3 and 4 provide the correctness.
3. **Pre-submit re-check** — sync and replay keep running while the batch is
   built and encrypted; immediately before the on-chain transaction is sent,
   the renewer re-checks whether any ACL op has replayed past
   `snapshot_seq`. If one has, the batch is discarded and rebuilt from a
   fresh snapshot. One local query, and it shrinks the blind window from the
   whole build-and-upload span to roughly one block confirmation.
4. **Post-replay conflict check** — after the ACL batch replays, scan
   `t_access_control` for ops with `snapshot_seq < version < batch_seq`
   touching any (account, role) pair the batch re-emitted. Any hit means a
   role change landed inside the window and was overridden: re-assert it in
   a corrective batch and log at ERROR. This is the safety net that needs
   nobody's cooperation, and it is mandatory — without it a resurrected
   grant persists silently forever.

#### What the guards do and do not guarantee

Detection is complete: replay is strictly sequential by tx_seq, so once
`stream_replay_progress` reaches the batch's seq, every op in the window is
already in `t_access_control` — the scan cannot be raced by a late arrival.

Under the deployment model (signer = admin), the lock covers the dangerous
case outright: revokes and special-key flips are admin-only ops, and the
admin's tooling honors its own node's flag. Third parties can still act in
the window, but only in two ways:

- **Grants** (`GRANT_WRITER_ROLE` validates for any existing writer) —
  harmless: the snapshot emits nothing for an account it did not see, so
  last-op-wins leaves the new grant standing.
- **Renounces** of their own roles — resurrectable: the re-emitted grant
  outranks the renounce. The corrective batch re-asserts a writer renounce
  as an admin revoke, which has the same effect. An admin renounce cannot be
  re-asserted at all — there is no `REVOKE_ADMIN_ROLE` op, so admin-ship is
  only ever given up voluntarily — which is why a single-admin stream is the
  recommended deployment: with no co-admin grants to re-emit, the case
  cannot arise. On a multi-admin stream it is detected and logged at ERROR,
  and only the resurrected admin can renounce again.

Three residual risks remain, in decreasing severity:

1. **Writes made during the wrong-permission interval stay valid forever.**
   A write by a wrongly re-granted account at seq W, with
   `batch_seq < W < corrective_seq`, is validated at W — where the
   resurrected grant is the latest op — and commits on every node, including
   future fresh resyncs. Correction does not retroact. The conflict check
   therefore also flags any writes by re-asserted accounts inside the
   interval; remediation is the operator overwriting those keys.
2. **The corrective batch races itself.** It is an ACL write with its own
   window. Correction is a loop — re-gate, re-snapshot the affected pairs,
   emit, re-check — that terminates when a window is clean. ACL churn is
   rare, so this converges immediately in practice; continuous concurrent
   churn is a livelock, not corruption.
3. **An undownloadable file in the window is invisible** to the scan. This is
   the system's pre-existing data-availability divergence, not something
   renewal introduces, but it does pierce the check.

The only complete fix is protocol-level and deferred to v2: the renewal file
declares its snapshot seq, and the replayer rejects the file's ACL portion
whenever any ACL op exists between the declared seq and the file's seq — the
same optimistic-concurrency pattern `VersionConfliction` already applies to
values, extended to permissions. It is deterministic across nodes, but it
changes replay semantics, so it requires every KV node monitoring the stream
to upgrade in step.

Worst case with the v1 guards: a permission wrongly live for the interval
between the renewal batch replaying and the corrective batch replaying, with
any writes it admitted flagged at ERROR for manual remediation. Without the
guards: silent and permanent until an admin happens to re-issue the revoke.

### 6. Renewal tracking

A new table records renewal attempts so failures are visible rather than
silent:

```sql
CREATE TABLE IF NOT EXISTS t_renew (
    stream_id BLOB NOT NULL,
    key BLOB NOT NULL,
    attempts INTEGER NOT NULL,
    last_attempt_ts INTEGER NOT NULL,
    last_tx_hash BLOB,
    last_error TEXT,
    PRIMARY KEY (stream_id, key)
) WITHOUT ROWID
```

A key still stale on a later cycle after `renew_max_attempts` attempts is
logged at WARN with its last tx hash, and backs off exponentially rather than
being retried every cycle. Rows are deleted once the key is fresh again.

### 7. Configuration

```toml
renew_enabled = true                # kill switch; renewer starts only if a key is also set
renew_private_key = ""              # 32-byte hex; ZGS_KV_RENEW_PRIVATE_KEY overrides
renew_max_age_secs = 15552000       # 180 days
renew_cycle_interval_secs = 604800  # 7 days
renew_batch_max_bytes = 8388608     # 8 MiB per KV file
renew_batch_max_keys = 1000
renew_pause_between_batches_ms = 2000
renew_startup_delay_secs = 300
renew_expected_replica = 1
renew_stream_ids = []               # empty = every stream in the live set
renew_dry_run = false               # scan and log the would-be spend, submit nothing
renew_max_attempts = 3
```

`renew_private_key` is distinct from `wallet_private_key`, which is an ECIES
decryption key and holds no funds. The `build_config!` macro reads only the
config file and CLI, so the env-var override is a small piece of custom code
in the config conversion layer. Chain RPC endpoint, indexer URL and static
node list are reused from the existing configuration. The env var takes
precedence over the config file when both are set.

### 8. RPC

- `kv_getRenewStatus` — last cycle start and end, keys scanned, renewed,
  skipped by permission, skipped for missing data, bytes uploaded, the list
  of keys stuck past `renew_max_attempts`, and `aclRenewalInProgress` (the
  operational-lock flag from section 5).
- `admin_renewNow` — triggers a cycle immediately, behind the same EIP-712
  domain as `admin_addStream` but with its own message shape:
  `{ purpose: "renew-now", wallet, issuedAt }`, where `issuedAt` must be
  within a short freshness window so a captured signature cannot be replayed
  later. Returns whether a cycle was started or one was already running.

The status cell is shared state created before the RPC server starts:
`with_rpc` runs earlier in the builder chain than the renewer (`start_node`
calls `with_rpc` before `with_stream`), so the cell is constructed up front
and handed to both — the same pattern `stream_set` already uses.

## Error handling

| Condition | Behaviour |
|---|---|
| Signer lacks write permission on a key | Skip, warn, record in `t_renew`, continue the cycle |
| Value bytes missing locally | Skip, warn, record, continue |
| Signer is not admin on a stream | Warn at startup; values still renew, access control does not |
| Upload fails (RPC, node, revert) | Record error, back off, retry next cycle; never crash the node |
| Signer balance too low | Abort the cycle with an ERROR log; retry next cycle |
| Chain probe or backfill fails | Warn; defer NULL-timestamp rows and retry the backfill next cycle |
| Replay does not catch up within the verify timeout | Warn; verification deferred to the next cycle |

## Testing

Unit:

- `version -> time` interpolation, including probes out of order and a single
  probe point.
- Stale-key SQL against `memorydb`: NULL timestamps, `created_at`
  carry-forward across versions, `HAVING` on the `MAX(version)` row,
  pagination by key.
- Batch packing against both caps, including an oversized single value.
- Effective access-control reconstruction: grant, revoke, re-grant, renounce,
  and special-key transitions.
- The ACL snapshot skips the signer's own admin grant and emits nothing for
  a stream with no access-control history.
- The pre-submit re-check: an ACL op replayed after snapshot_seq aborts the
  built batch; a clean window submits.
- The post-replay conflict check: an op landing between snapshot_seq and
  batch_seq on a re-emitted pair is detected and re-asserted; ops outside
  the window or on untouched pairs are not. Writes admitted during the
  wrong-permission interval are flagged. A resurrected writer renounce is
  re-asserted as an admin revoke; a resurrected admin renounce is logged,
  not corrected.
- Permission skip and backoff behaviour.

Migration:

- Open a database written with the pre-change schema, assert the ALTER runs on
  both `t_stream` and `t_access_control`, old rows still read, and new writes
  carry timestamps.

Integration (`tests/kv_renew_test.py`):

- Write keys, set `renew_max_age_secs` low, trigger with `admin_renewNow`,
  assert a new tx appears and `version` and `updated_at` advance.
- Assert a key the signer cannot write is skipped rather than paid for.
- Assert an encrypted stream's renewed file is still encrypted and readable.
- Assert access-control state re-emitted by renewal is replayed correctly by
  a node that starts with an empty database.

## Upstream dependency

`0g-storage-sdk-rust` must land a small change first, since `kv_renew` needs
to emit access-control ops the SDK cannot currently express:

- `StreamDataBuilder::with_control` is private and only `grant_admin_role`,
  `renounce_admin_role` and `set_key_to_special` are exposed. Add
  `grant_writer_role` and `grant_special_writer_role` at minimum; the
  remaining revoke and renounce variants round the API out.
- `StreamDataBuilder::set` contains a `println!("key hex: ...")` that would
  print one line per renewed key.
- The SDK's access-control write paths gain an optional KV node URL and, when
  configured, wait on `kv_getRenewStatus.aclRenewalInProgress` before
  submitting (the operational-lock courtesy check from section 5).

`node/stream/Cargo.toml` then moves to the new rev.

## Operational notes

- The renewal signer is the stream admin, so the stream's highest-privilege
  key lives on the KV server. Prefer the `ZGS_KV_RENEW_PRIVATE_KEY` env var
  over the config file, and treat the node's host accordingly. Granting
  write access to users is unchanged: the admin issues grants via the SDK or
  CLI, and the renewer's weekly snapshot preserves them from then on.
- Renewal spends real funds on a timer. `renew_dry_run` and the requirement
  that a key be configured are the guardrails; the first cycle over an old
  stream will still re-upload a large amount of data, merely paced.
- Run the renewer on one node per stream. Two nodes renewing the same stream
  both pay for it.
- Every KV node monitoring the stream re-downloads renewed data, and each
  renewal appends a row per key permanently.

## Out of scope

- Renewing historical versions of a key. Only the latest value is preserved;
  older versions remain readable only while their original files live.
- Any on-chain lifetime-extension mechanism, which does not exist.
- The protocol-level ACL optimistic-concurrency rule (section 5), which
  requires a coordinated replayer upgrade across all KV nodes.
- Coordination between multiple renewing nodes.

## Delivery

Implementation is split into small, independently reviewable pull requests of
roughly 100 lines each, one per tracked issue, sequenced so every PR leaves
the tree building and tested. The detailed breakdown belongs in the
implementation plan, not this spec.
