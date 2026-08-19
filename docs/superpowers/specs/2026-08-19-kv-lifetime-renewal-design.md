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

If the backfill cannot run (RPC unavailable), NULL rows are treated as stale
and the renewer proceeds; this is safe but may renew data earlier than
necessary, so the failure is logged at WARN.

### 4. The renewer

New crate `node/kv_renew`, spawned from `ClientBuilder::with_renew(...)`
after `with_stream`, as a `task_executor` task named `kv renewer`.

Startup:

- Derive the signer address from `renew_private_key`. Log the address, never
  the key.
- Check `is_admin(signer, stream_id, u64::MAX)` for each monitored stream and
  WARN on any stream where the signer is not admin, since access-control
  renewal for that stream will be rejected.
- Sleep `renew_startup_delay_secs` so sync and replay can warm up.

Each cycle:

1. **Cutoff** — `cutoff = now - renew_max_age_secs`.
2. **Scan** — per stream in the live stream set:

   ```sql
   SELECT stream_id, key, MAX(version) AS version, start_index, end_index, updated_at
   FROM t_stream
   WHERE stream_id = :stream_id AND key > :cursor
   GROUP BY stream_id, key
   HAVING updated_at IS NULL OR updated_at <= :cutoff
   ORDER BY key ASC
   LIMIT :limit
   ```

   SQLite's bare-column rule returns the other columns from the `MAX(version)`
   row. Pagination is on `key` so a cycle interrupted by a restart resumes
   cleanly.
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
5. **Access control** — for each stream whose effective access-control state
   has any op older than the cutoff, the stream's first batch of the cycle
   also carries that state re-emitted as fresh grants (see section 5). A
   stream with stale grants but no stale values still gets a batch, carrying
   access control alone.
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
stays open, matching its original state.

Re-emission is triggered per stream when the oldest op in the effective set is
older than the cutoff — that op is the one closest to expiring, and losing it
is what breaks the permission chain. Re-emitting the whole effective set at
once keeps the reconstruction trivially correct and costs only a few hundred
bytes, since access-control sets are small relative to values.

`validate_access_control_set` computes the admin set from store state *before*
applying the file's own ops, so a file cannot bootstrap its own authority. Two
cases follow:

- On a node that has lost all access-control history for the stream,
  `is_new_stream` is true, the replayer auto-grants admin to the renewal
  file's sender, and the re-emitted grants validate.
- On a node where some access-control rows survive, the renewal signer must
  genuinely hold admin. This is the case the startup check warns about.

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
decryption key and holds no funds. Chain RPC endpoint, indexer URL and static
node list are reused from the existing configuration. The env var takes
precedence over the config file when both are set.

### 8. RPC

- `kv_getRenewStatus` — last cycle start and end, keys scanned, renewed,
  skipped by permission, skipped for missing data, bytes uploaded, and the
  list of keys stuck past `renew_max_attempts`.
- `admin_renewNow` — triggers a cycle immediately, behind the same EIP-712
  auth as `admin_addStream`. Returns whether a cycle was started or one was
  already running.

## Error handling

| Condition | Behaviour |
|---|---|
| Signer lacks write permission on a key | Skip, warn, record in `t_renew`, continue the cycle |
| Value bytes missing locally | Skip, warn, record, continue |
| Signer is not admin on a stream | Warn at startup; values still renew, access control does not |
| Upload fails (RPC, node, revert) | Record error, back off, retry next cycle; never crash the node |
| Signer balance too low | Abort the cycle with an ERROR log; retry next cycle |
| Chain probe or backfill fails | Warn; treat NULL timestamps as stale and continue |
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
- Access-control re-emission fires when the oldest op in the effective set
  crosses the cutoff, and not before, including a stream with stale grants but
  no stale values.
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

`node/stream/Cargo.toml` then moves to the new rev.

## Operational notes

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
- Coordination between multiple renewing nodes.

## Delivery

Implementation is split into small, independently reviewable pull requests of
roughly 100 lines each, one per tracked issue, sequenced so every PR leaves
the tree building and tested. The detailed breakdown belongs in the
implementation plan, not this spec.
