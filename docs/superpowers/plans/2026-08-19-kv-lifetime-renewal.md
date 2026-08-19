# KV Lifetime Renewal Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A background service in `zgs_kv` that re-uploads KV values (and each stream's effective access-control state) whose last write is older than a threshold, renewing their storage lifetime.

**Architecture:** Timestamps (`created_at`/`updated_at`) are added to the SQLite KV tables and filled from each write's on-chain block time (recorded by log sync into a new rocksdb column). A new `kv_renew` crate scans for stale keys, packs them with the SDK's `StreamDataBuilder`, uploads via the SDK `Uploader` with the configured admin key, and verifies replay moved the versions. ACL state is re-emitted every cycle; races are prevented cheaply, detected completely, remediated manually.

**Tech Stack:** Rust (tokio, rusqlite via tokio-rusqlite, kvdb-rocksdb, ethers 2), `zg-storage-client` SDK (git dep), jsonrpsee 0.14 RPC, Python integration test framework in `tests/`.

**Spec:** `docs/superpowers/specs/2026-08-19-kv-lifetime-renewal-design.md` — read it first; every task below implements a section of it.

## Global Constraints

- Repos: `0gfoundation/0g-storage-kv` (this repo, remote `origin`) and `0gfoundation/0g-storage-sdk-rust` (`/Users/peter/ZeroGravity/0g-storage-sdk-rust`). Task 1 is in the SDK repo; all others here.
- Every task = one GitHub issue + one PR (~100 changed lines; if a task exceeds ~150, stop and split it). PRs target `main`, sequential: a task assumes all lower-numbered PRs are merged.
- Branch naming: `feat/renew-NN-<slug>`. PR titles follow repo history style: `feat(scope): summary (resolves #N)`.
- **No AI attribution anywhere** — commits, issue bodies, PR bodies must read as user-authored. No `Co-Authored-By: Claude`, no "Generated with" footers.
- Before every commit claim: `./rustlint.sh` (runs `cargo fmt --all` and `cargo clippy -- -D warnings`) and the task's `cargo test` command must pass.
- Commit small and often: each write-test/implement pair is its own commit minimum.
- New SQL follows `sqlite_db_statements.rs` const style; new store methods follow the `StreamRead`/`StreamWrite` async-trait split; forwarding through `StoreManager` is mandatory for every new store method.
- Timestamps are unix seconds stored as SQLite INTEGER (i64 in Rust, converted from u64 like `convert_to_i64` does for versions).

## Issue/PR workflow (identical for every task — referenced as "STD-OPEN" / "STD-CLOSE")

**STD-OPEN(title, body):**
```bash
gh issue create -R 0gfoundation/0g-storage-kv --title "<title>" --body "<body>"   # note the printed issue number N
git checkout main && git pull && git checkout -b feat/renew-NN-<slug>
```

**STD-CLOSE(N):**
```bash
./rustlint.sh && git push -u origin HEAD
gh pr create -R 0gfoundation/0g-storage-kv --title "<type>(scope): <summary> (resolves #N)" --body "<what/why/how-tested, references #N>"
```
For Task 1 substitute `-R 0gfoundation/0g-storage-sdk-rust`.

## File Map

| File | Tasks | Responsibility |
|---|---|---|
| SDK `src/kv/builder.rs` | 1 | ACL builder methods; remove stray println |
| `node/storage_with_stream/src/store/sqlite_db_statements.rs` | 2,5,6,7,11,15 | all SQL consts |
| `node/storage_with_stream/src/store/stream_store.rs` | 2,5,6,7,11,15 | SQLite access + migration |
| `node/storage_with_stream/src/store/data_store.rs` | 3 | rocksdb columns, forwards |
| `node/storage_with_stream/src/store/tx_store.rs` | 3 | tx block-time rows |
| `node/storage_with_stream/src/store/store_manager.rs` | 3,5,6,7,11,15 | trait impl forwarding |
| `node/storage_with_stream/src/store/mod.rs` | 3,5,6,7,10,11,15 | trait defs, `read_pair_value` |
| `node/kv_types/src/lib.rs` | 6,7,15 | `StaleKey`, `RenewAttempt`, `EffectiveAcl`, `AclOpRow` |
| `node/log_entry_sync/src/sync_manager/mod.rs` | 4 | block-time capture |
| `node/kv_renew/*` | 8,11,12,13,14,16,17,18,19 | the renewal service |
| `node/src/config/mod.rs`, `convert.rs` | 9 | `renew_*` params |
| `node/rpc/src/kv_rpc_server/*` | 10,21 | value reader reuse; status RPC |
| `node/rpc/src/admin_rpc_server/*` | 22 | renewNow + EIP-712 |
| `node/rpc/src/lib.rs` | 20 | Context fields |
| `node/src/client/builder.rs`, `node/src/main.rs` | 20 | wiring |
| `README.md`, `run/config_example.toml` | 23 | docs + IMPORTANT notice |
| `tests/kv_renew_test.py` | 24 | end-to-end test |

---

### Task 1: SDK — ACL builder methods + println removal (repo: 0g-storage-sdk-rust)

**Files:**
- Modify: `src/kv/builder.rs` (methods around line 175, println at ~146)
- Test: `src/kv/builder.rs` `#[cfg(test)]` module (append)

**Interfaces:**
- Consumes: existing private `with_control(control_type, stream_id, account, key)`, `AccessControlType` enum in `src/kv/types.rs`.
- Produces (Task 15 depends on these exact names): `grant_writer_role(stream_id: H256, account: Address)`, `revoke_writer_role(stream_id, account)`, `renounce_writer_role(stream_id)`, `grant_special_writer_role(stream_id, key: Vec<u8>, account)`, `revoke_special_writer_role(stream_id, key, account)`, `renounce_special_writer_role(stream_id, key)`, `set_key_to_normal(stream_id, key)` — all `&mut self -> &mut Self` like `grant_admin_role`.

- [ ] **Step 1: Open issue + branch** — STD-OPEN in the SDK repo. Title: `StreamDataBuilder: missing access-control methods and stray println in set()`. Body: "Only grant_admin_role / renounce_admin_role / set_key_to_special are exposed while the wire format and AccessControlType support the full op set; with_control is private so callers cannot express writer grants. Also set() prints 'key hex: ...' per call. Needed by the KV node's lifetime-renewal service."

- [ ] **Step 2: Write failing tests** (append to builder tests; if no test module exists, create one):

```rust
#[cfg(test)]
mod acl_method_tests {
    use super::*;
    use ethers::types::{Address, H256};

    #[test]
    fn full_acl_surface_builds() {
        let sid = H256::repeat_byte(1);
        let acct = Address::repeat_byte(2);
        let mut b = StreamDataBuilder::new(0);
        b.grant_writer_role(sid, acct)
            .revoke_writer_role(sid, acct)
            .renounce_writer_role(sid)
            .grant_special_writer_role(sid, vec![7], acct)
            .revoke_special_writer_role(sid, vec![7], acct)
            .renounce_special_writer_role(sid, vec![7])
            .set_key_to_normal(sid, vec![7]);
        let data = b.build(None).unwrap();
        assert_eq!(data.controls.len(), 7);
        // every op tagged the stream id
        assert!(b.build_tags(None).len() >= 64);
    }
}
```

- [ ] **Step 3: Run to verify fail** — `cargo test acl_method_tests` → FAIL: no method `grant_writer_role`.

- [ ] **Step 4: Implement** (next to `set_key_to_special`, all via the private `with_control`; mirror `AccessControlType` variants `GrantWriteRole`, `RevokeWriteRole`, `RenounceWriteRole`, `GrantSpecialWriteRole`, `RevokeSpecialWriteRole`, `RenounceSpecialWriteRole`, `SetKeyToNormal`):

```rust
pub fn grant_writer_role(&mut self, stream_id: H256, account: Address) -> &mut Self {
    self.with_control(AccessControlType::GrantWriteRole, stream_id, Some(account), None)
}

pub fn revoke_writer_role(&mut self, stream_id: H256, account: Address) -> &mut Self {
    self.with_control(AccessControlType::RevokeWriteRole, stream_id, Some(account), None)
}

pub fn renounce_writer_role(&mut self, stream_id: H256) -> &mut Self {
    self.with_control(AccessControlType::RenounceWriteRole, stream_id, None, None)
}

pub fn grant_special_writer_role(&mut self, stream_id: H256, key: Vec<u8>, account: Address) -> &mut Self {
    self.with_control(AccessControlType::GrantSpecialWriteRole, stream_id, Some(account), Some(key))
}

pub fn revoke_special_writer_role(&mut self, stream_id: H256, key: Vec<u8>, account: Address) -> &mut Self {
    self.with_control(AccessControlType::RevokeSpecialWriteRole, stream_id, Some(account), Some(key))
}

pub fn renounce_special_writer_role(&mut self, stream_id: H256, key: Vec<u8>) -> &mut Self {
    self.with_control(AccessControlType::RenounceSpecialWriteRole, stream_id, None, Some(key))
}

pub fn set_key_to_normal(&mut self, stream_id: H256, key: Vec<u8>) -> &mut Self {
    self.with_control(AccessControlType::SetKeyToNormal, stream_id, None, Some(key))
}
```

Also delete the `println!("key hex: {:?}", key_hex);` line in `set()`.

CHECK the wire encode order in `types.rs::encode()` for special-writer ops: it writes `key` then `account`; the KV replayer parses `key` then `account` for 0x30/0x31 — matches, no encode change needed.

- [ ] **Step 5: Run to verify pass** — `cargo test acl_method_tests` → PASS. Full `cargo test` still green.

- [ ] **Step 6: Commit + PR** — commits: `fix(kv): remove stray println in StreamDataBuilder::set`, `feat(kv): expose full access-control surface on StreamDataBuilder`. STD-CLOSE. **Record the merge commit SHA — Task 15 pins it as the git rev.**

---

### Task 2: Schema — created_at/updated_at columns + migration

**Files:**
- Modify: `node/storage_with_stream/src/store/sqlite_db_statements.rs` (CREATE_STREAM_TABLE_STATEMENT, CREATE_ACCESS_CONTROL_TABLE_STATEMENT, CREATE_STREAM_INDEX_STATEMENTS)
- Modify: `node/storage_with_stream/src/store/stream_store.rs` (`create_tables_if_not_exist`, tests)

**Interfaces:**
- Produces: both tables have nullable `created_at INTEGER` / `updated_at INTEGER`; index `stream_updated_idx ON t_stream(updated_at)`; migration is idempotent and runs inside `create_tables_if_not_exist`.

- [ ] **Step 1: STD-OPEN.** Title: `KV tables lack write timestamps needed for lifetime renewal`. Body: "t_stream/t_access_control rows carry only version (tx_seq). The renewal service (see docs/superpowers/specs/2026-08-19-kv-lifetime-renewal-design.md §1) needs created_at/updated_at filled from block time. Adds nullable columns + ALTER migration + updated_at index."

- [ ] **Step 2: Write failing test** (append to `stream_store.rs` tests):

```rust
#[tokio::test]
async fn migration_adds_time_columns_to_old_schema() {
    let store = StreamStore::new_in_memory().await.unwrap();
    // simulate a pre-upgrade DB: old-shape tables already exist
    store.connection.call(|conn| {
        conn.execute(
            "CREATE TABLE t_stream (stream_id BLOB NOT NULL, key BLOB NOT NULL, version INTEGER NOT NULL, start_index INTEGER NOT NULL, end_index INTEGER NOT NULL, PRIMARY KEY (stream_id, key, version)) WITHOUT ROWID", [])?;
        conn.execute(
            "CREATE TABLE t_access_control (stream_id BLOB NOT NULL, key BLOB, version INTEGER NOT NULL, account BLOB, op_type INTEGER NOT NULL, operator BLOB NOT NULL)", [])?;
        Ok(())
    }).await.unwrap();

    store.create_tables_if_not_exist().await.unwrap();
    // columns exist and are writable on both tables
    store.connection.call(|conn| {
        conn.execute("INSERT INTO t_stream (stream_id, key, version, start_index, end_index, created_at, updated_at) VALUES (X'01', X'02', 1, 0, 0, 5, 5)", [])?;
        conn.execute("INSERT INTO t_access_control (stream_id, version, op_type, operator, created_at, updated_at) VALUES (X'01', 1, 0, X'00', 5, 5)", [])?;
        Ok(())
    }).await.unwrap();
    // idempotent: second run must not fail with duplicate column
    store.create_tables_if_not_exist().await.unwrap();
}
```

(If `connection` is private, make it `pub(crate)` — the existing tests live in the same file, so direct field access already works.)

- [ ] **Step 3: Run to verify fail** — `cargo test -p storage_with_stream migration_adds_time_columns` → FAIL (`no such column: created_at`).

- [ ] **Step 4: Implement.** In `sqlite_db_statements.rs`, extend both CREATE statements with `created_at INTEGER,` and `updated_at INTEGER,` (before PRIMARY KEY for t_stream; at the end of the column list for t_access_control) and grow the index array:

```rust
pub const CREATE_STREAM_INDEX_STATEMENTS: [&'static str; 3] = [
    "CREATE INDEX IF NOT EXISTS stream_key_idx ON t_stream(stream_id, key)",
    "CREATE INDEX IF NOT EXISTS stream_version_idx ON t_stream(version)",
    "CREATE INDEX IF NOT EXISTS stream_updated_idx ON t_stream(updated_at)",
];
```

In `stream_store.rs`, add a free function and call it for both tables inside the `create_tables_if_not_exist` closure, after the CREATE statements and before the index statements:

```rust
fn add_time_columns_if_missing(conn: &rusqlite::Connection, table: &str) -> rusqlite::Result<()> {
    let (mut has_created, mut has_updated) = (false, false);
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({})", table))?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        match row.get::<_, String>(1)?.as_str() {
            "created_at" => has_created = true,
            "updated_at" => has_updated = true,
            _ => {}
        }
    }
    if !has_created {
        conn.execute(&format!("ALTER TABLE {} ADD COLUMN created_at INTEGER", table), [])?;
    }
    if !has_updated {
        conn.execute(&format!("ALTER TABLE {} ADD COLUMN updated_at INTEGER", table), [])?;
    }
    Ok(())
}
```

```rust
add_time_columns_if_missing(conn, "t_stream")?;
add_time_columns_if_missing(conn, "t_access_control")?;
```

(SQLite allows ADD COLUMN on WITHOUT ROWID tables for nullable, non-PK, non-UNIQUE columns — which these are.)

- [ ] **Step 5: Run to verify pass** — `cargo test -p storage_with_stream` → all green (old tests untouched: INSERT statements name their columns).

- [ ] **Step 6: Commit + PR** — `feat(store): add created_at/updated_at columns to KV tables (resolves #N)`. STD-CLOSE.

---

### Task 3: COL_TX_TIME — per-tx block-time rows in rocksdb

**Files:**
- Modify: `node/storage_with_stream/src/store/data_store.rs` (columns + forwards)
- Modify: `node/storage_with_stream/src/store/tx_store.rs` (put/get/delete)
- Modify: `node/storage_with_stream/src/store/mod.rs` (trait methods)
- Modify: `node/storage_with_stream/src/store/store_manager.rs` (forwards)

**Interfaces:**
- Produces: `DataStoreWrite::put_tx_block_time(&self, tx_seq: u64, ts: u64) -> Result<()>`; `DataStoreRead::get_tx_block_time(&self, tx_seq: u64) -> Result<Option<u64>>`. `TransactionStore::remove_tx_after` also deletes the reverted seqs' time rows. `COL_TX_TIME: u32 = 5`, `COL_NUM = 6` (kvdb-rocksdb creates the missing column family on existing DBs automatically).

- [ ] **Step 1: STD-OPEN.** Title: `Record each tx's block timestamp for renewal staleness (spec §2)`.

- [ ] **Step 2: Write failing tests** (append to `tx_store.rs` tests):

```rust
#[test]
fn block_time_roundtrip_and_missing() {
    let store = create_test_store();
    assert_eq!(store.get_block_time(7).unwrap(), None);
    store.put_block_time(7, 1_755_000_000).unwrap();
    assert_eq!(store.get_block_time(7).unwrap(), Some(1_755_000_000));
}

#[test]
fn revert_deletes_block_time() {
    let store = create_test_store();
    // seed txs 0..2 so remove_tx_after walks them
    for seq in 0..2u64 {
        store.put_tx(make_tx(seq)).unwrap();  // reuse/create the tests' KVTransaction helper
        store.put_block_time(seq, 100 + seq).unwrap();
    }
    store.remove_tx_after(1).unwrap();
    assert_eq!(store.get_block_time(0).unwrap(), Some(100));
    assert_eq!(store.get_block_time(1).unwrap(), None);
}
```

If the test module lacks a `make_tx` helper, add one building a minimal `KVTransaction { stream_ids: vec![], sender: H160::zero(), data_merkle_root: H256::zero(), merkle_nodes: vec![(1, H256::zero())], start_entry_index: 0, size: 0, seq }`.

- [ ] **Step 3: Run to verify fail** — `cargo test -p storage_with_stream block_time` → FAIL (no method).

- [ ] **Step 4: Implement.** `data_store.rs`: `pub const COL_TX_TIME: u32 = 5;` and `pub const COL_NUM: u32 = 6;`. `tx_store.rs` (import COL_TX_TIME):

```rust
pub fn put_block_time(&self, tx_seq: u64, ts: u64) -> Result<()> {
    Ok(self.kvdb.put(COL_TX_TIME, &tx_seq.to_be_bytes(), &ts.to_be_bytes())?)
}

pub fn get_block_time(&self, tx_seq: u64) -> Result<Option<u64>> {
    self.kvdb.get(COL_TX_TIME, &tx_seq.to_be_bytes())?
        .map(|d| decode_tx_seq(&d))
        .transpose()
}
```

In `remove_tx_after`'s loop add `db_tx.delete(COL_TX_TIME, &seq.to_be_bytes());`. Add DataStore forwards (`put_tx_block_time`/`get_tx_block_time` calling `self.tx_store.put_block_time` etc.), trait methods on `DataStoreWrite`/`DataStoreRead` in `mod.rs`, and StoreManager forwards to `self.data_store`.

- [ ] **Step 5: Run to verify pass** — `cargo test -p storage_with_stream` → green; `cargo build --workspace` (trait additions compile everywhere).

- [ ] **Step 6: Commit + PR** — `feat(store): record per-tx block time in COL_TX_TIME (resolves #N)`. STD-CLOSE.

---

### Task 4: Log sync captures block timestamps

**Files:**
- Modify: `node/log_entry_sync/src/sync_manager/mod.rs` (struct field ~line 61, constructor, `handle_data` Transaction arm ~line 399)

**Interfaces:**
- Consumes: Task 3's `put_tx_block_time`. `self.log_fetcher.provider()` (ethers Middleware; `get_block(n)` → `Option<Block>` with `.timestamp: U256`).
- Produces: every tx that passes `put_tx` gets a `COL_TX_TIME` row when the block is resolvable; failures degrade to NULL (backfill's job). Bounded cache `block_time_cache: BTreeMap<u64, u64>` (cap 1024).

- [ ] **Step 1: STD-OPEN.** Title: `log_sync: persist block timestamps for synced txs (spec §2)`.

- [ ] **Step 2: Write failing test** for the pure cache-trim helper (bottom of `mod.rs`):

```rust
#[cfg(test)]
mod block_time_cache_tests {
    use super::trim_block_time_cache;
    use std::collections::BTreeMap;

    #[test]
    fn trims_oldest_entries_beyond_cap() {
        let mut cache: BTreeMap<u64, u64> = (0..1500u64).map(|i| (i, i)).collect();
        trim_block_time_cache(&mut cache);
        assert_eq!(cache.len(), 1024);
        assert!(cache.contains_key(&1499));
        assert!(!cache.contains_key(&0));
    }
}
```

- [ ] **Step 3: Run to verify fail** — `cargo test -p log_entry_sync trims_oldest` → FAIL.

- [ ] **Step 4: Implement.**

```rust
const BLOCK_TIME_CACHE_CAP: usize = 1024;

fn trim_block_time_cache(cache: &mut BTreeMap<u64, u64>) {
    while cache.len() > BLOCK_TIME_CACHE_CAP {
        let oldest = *cache.keys().next().unwrap();
        cache.remove(&oldest);
    }
}
```

Add field `block_time_cache: BTreeMap<u64, u64>` to `LogSyncManager` (init `BTreeMap::new()` where the struct is built). Add method:

```rust
async fn store_block_time(&mut self, tx_seq: u64, block_number: u64) {
    let ts = match self.block_time_cache.get(&block_number) {
        Some(ts) => Some(*ts),
        None => match self.log_fetcher.provider().get_block(block_number).await {
            Ok(Some(b)) => {
                let ts = b.timestamp.as_u64();
                self.block_time_cache.insert(block_number, ts);
                trim_block_time_cache(&mut self.block_time_cache);
                Some(ts)
            }
            other => {
                warn!("block time fetch failed for {}: {:?}", block_number, other);
                None
            }
        },
    };
    if let Some(ts) = ts {
        if let Err(e) = self.store.write().await.put_tx_block_time(tx_seq, ts) {
            warn!("failed to persist tx block time: {:?}", e);
        }
    }
}
```

In the `LogFetchProgress::Transaction((tx, block_number))` arm, capture `let tx_seq = tx.seq;` before `self.put_tx(tx.clone())`, and inside the `Some(true) =>` branch (the successful-store path) call `self.store_block_time(tx_seq, block_number).await;` before the existing `put_log_latest_block_number` handling.

- [ ] **Step 5: Run to verify pass** — `cargo test -p log_entry_sync` green; `cargo build --workspace`.

- [ ] **Step 6: Commit + PR** — `feat(log_sync): persist block timestamps for synced txs (resolves #N)`. STD-CLOSE.

---

### Task 5: put_stream stamps timestamps

**Files:**
- Modify: `node/storage_with_stream/src/store/sqlite_db_statements.rs` (both PUT statements)
- Modify: `node/storage_with_stream/src/store/stream_store.rs` (`put_stream` + tests)
- Modify: `node/storage_with_stream/src/store/store_manager.rs` (`put_stream` looks up block time)

**Interfaces:**
- Consumes: Task 3 `get_tx_block_time`.
- Produces: `StreamStore::put_stream(&self, tx_seq: u64, result: String, commit_data: Option<(StreamWriteSet, AccessControlSet)>, block_time: Option<u64>)`. The `Store` trait signature is UNCHANGED — `StoreManager::put_stream` resolves `block_time` itself.

- [ ] **Step 1: STD-OPEN.** Title: `Stamp created_at/updated_at at replay commit (spec §1)`.

- [ ] **Step 2: Write failing test** (in `stream_store.rs` tests; build a one-write `StreamWriteSet` + empty `AccessControlSet` helper):

```rust
fn write_set(stream_id: H256, key: &[u8]) -> (StreamWriteSet, AccessControlSet) {
    (
        StreamWriteSet { stream_writes: vec![StreamWrite {
            stream_id, key: Arc::new(key.to_vec()), start_index: 0, end_index: 0 }] },
        AccessControlSet { access_controls: vec![], is_admin: Default::default() },
    )
}

#[tokio::test]
async fn timestamps_carry_created_forward() {
    let store = StreamStore::new_in_memory().await.unwrap();
    store.create_tables_if_not_exist().await.unwrap();
    let sid = H256::repeat_byte(9);

    store.put_stream(1, "Commit".into(), Some(write_set(sid, b"k")), Some(100)).await.unwrap();
    store.put_stream(2, "Commit".into(), Some(write_set(sid, b"k")), Some(200)).await.unwrap();
    store.put_stream(3, "Commit".into(), Some(write_set(sid, b"k")), None).await.unwrap();

    let rows: Vec<(i64, Option<i64>, Option<i64>)> = store.connection.call(move |conn| {
        let mut stmt = conn.prepare("SELECT version, created_at, updated_at FROM t_stream ORDER BY version")?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }).await.unwrap();

    assert_eq!(rows[0], (1, Some(100), Some(100)));
    assert_eq!(rows[1], (2, Some(100), Some(200))); // created carried forward
    assert_eq!(rows[2], (3, Some(100), None));      // no block time -> NULL updated_at
}
```

- [ ] **Step 3: Run to verify fail** — signature mismatch / no column in statement.

- [ ] **Step 4: Implement.** New statements:

```rust
pub const PUT_STREAM_WRITE_STATEMENT: &'static str = "
    INSERT OR REPLACE INTO
        t_stream (stream_id, key, version, start_index, end_index, created_at, updated_at)
    VALUES
        (:stream_id, :key, :version, :start_index, :end_index,
         COALESCE((SELECT MIN(created_at) FROM t_stream
                   WHERE stream_id = :stream_id AND key = :key), :ts),
         :ts)
";

pub const PUT_ACCESS_CONTROL_STATEMENT: &'static str = "
    INSERT OR REPLACE INTO
        t_access_control (stream_id, key, version, account, op_type, operator, created_at, updated_at)
    VALUES
        (:stream_id, :key, :version, :account, :op_type, :operator, :ts, :ts)
";
```

`stream_store::put_stream` gains `block_time: Option<u64>`; inside the closure `let ts: Option<i64> = block_time.map(|t| t as i64);` and both `named_params!` gain `":ts": ts`. `StoreManager::put_stream` (trait impl) resolves before delegating:

```rust
let block_time = self.data_store.get_tx_block_time(tx_seq).unwrap_or(None);
self.stream_store.put_stream(tx_seq, result, commit_data, block_time).await
```

Fix the one other caller of `stream_store.put_stream` if any (grep) by passing `None`.

- [ ] **Step 5: Run to verify pass** — `cargo test -p storage_with_stream`; `cargo build --workspace`.

- [ ] **Step 6: Commit + PR** — `feat(store): stamp KV rows with block time at replay commit (resolves #N)`. STD-CLOSE.

---

### Task 6: Stale-key scan query

**Files:**
- Modify: `node/kv_types/src/lib.rs` (`StaleKey`)
- Modify: `node/storage_with_stream/src/store/sqlite_db_statements.rs`, `stream_store.rs`, `mod.rs`, `store_manager.rs`

**Interfaces:**
- Produces: `StreamRead::get_stale_stream_keys(&self, stream_id: H256, cutoff: u64, cursor: Vec<u8>, limit: u64) -> Result<Vec<StaleKey>>` with
  `pub struct StaleKey { pub stream_id: H256, pub key: Vec<u8>, pub version: u64, pub start_index: u64, pub end_index: u64, pub updated_at: u64 }` in `kv_types`.
- Semantics: latest version per key only; NULL `updated_at` excluded (backfill's job); `key > cursor` ascending; empty cursor starts from the beginning (`X''` compares below every non-empty BLOB).

- [ ] **Step 1: STD-OPEN.** Title: `Stale-key scan query for renewal (spec §4 step 2)`.

- [ ] **Step 2: Write failing test:**

```rust
#[tokio::test]
async fn stale_scan_latest_version_pagination_and_nulls() {
    let store = StreamStore::new_in_memory().await.unwrap();
    store.create_tables_if_not_exist().await.unwrap();
    let sid = H256::repeat_byte(1);
    // key a: old v1, fresh v2 -> NOT stale; key b: old only -> stale
    // key c: NULL ts -> excluded; key d: old -> stale
    store.put_stream(1, "Commit".into(), Some(write_set(sid, b"a")), Some(100)).await.unwrap();
    store.put_stream(2, "Commit".into(), Some(write_set(sid, b"a")), Some(9_000)).await.unwrap();
    store.put_stream(3, "Commit".into(), Some(write_set(sid, b"b")), Some(150)).await.unwrap();
    store.put_stream(4, "Commit".into(), Some(write_set(sid, b"c")), None).await.unwrap();
    store.put_stream(5, "Commit".into(), Some(write_set(sid, b"d")), Some(160)).await.unwrap();

    let page1 = store.get_stale_stream_keys(sid, 1000, vec![], 1).await.unwrap();
    assert_eq!(page1.len(), 1);
    assert_eq!(page1[0].key, b"b".to_vec());
    assert_eq!(page1[0].version, 3);

    let page2 = store.get_stale_stream_keys(sid, 1000, page1[0].key.clone(), 10).await.unwrap();
    assert_eq!(page2.len(), 1);
    assert_eq!(page2[0].key, b"d".to_vec());
}
```

- [ ] **Step 3: Run to verify fail.**

- [ ] **Step 4: Implement.** Statement:

```rust
pub const GET_STALE_STREAM_KEYS_STATEMENT: &'static str = "
    SELECT key, MAX(version) AS version, start_index, end_index, updated_at FROM
        t_stream
    WHERE
        stream_id = :stream_id AND key > :cursor
    GROUP BY key
    HAVING updated_at <= :cutoff
    ORDER BY key ASC LIMIT :limit
";
```

(SQLite bare-column rule: with a MAX aggregate the non-aggregated columns come from the max-version row; `NULL <= x` is not true, so NULLs drop out.) `StaleKey` in kv_types with derive(Debug, Clone). StreamStore method binds `":cutoff": convert_to_i64(cutoff)`, `":limit": limit as i64`, cursor as BLOB; maps rows; sets `stream_id`. Trait + StoreManager forward.

- [ ] **Step 5: Run to verify pass**; `cargo build --workspace`.

- [ ] **Step 6: Commit + PR** — `feat(store): stale-key scan query for renewal (resolves #N)`. STD-CLOSE.

---

### Task 7: t_renew attempt-tracking table

**Files:**
- Modify: `node/kv_types/src/lib.rs` (`RenewAttempt`)
- Modify: `node/storage_with_stream/src/store/sqlite_db_statements.rs`, `stream_store.rs`, `mod.rs`, `store_manager.rs`

**Interfaces:**
- Produces (`StreamWrite` unless noted):
  - `record_renew_attempt(&self, stream_id: H256, key: Vec<u8>, ts: u64, tx_hash: Option<H256>, error: Option<String>) -> Result<()>` (attempts auto-increments)
  - `clear_renew_attempt(&self, stream_id: H256, key: Vec<u8>) -> Result<()>`
  - `get_renew_attempt(&self, stream_id: H256, key: Vec<u8>) -> Result<Option<RenewAttempt>>` (StreamRead)
  - `list_stuck_renewals(&self, min_attempts: u64, limit: u64) -> Result<Vec<(H256, Vec<u8>, RenewAttempt)>>` (StreamRead)
  - `pub struct RenewAttempt { pub attempts: u64, pub last_attempt_ts: u64, pub last_tx_hash: Option<H256>, pub last_error: Option<String> }`

- [ ] **Step 1: STD-OPEN.** Title: `t_renew: persist renewal attempts and failures (spec §6)`.

- [ ] **Step 2: Write failing test:**

```rust
#[tokio::test]
async fn renew_tracking_upsert_clear_and_stuck() {
    let store = StreamStore::new_in_memory().await.unwrap();
    store.create_tables_if_not_exist().await.unwrap();
    let sid = H256::repeat_byte(2);

    store.record_renew_attempt(sid, b"k".to_vec(), 10, None, Some("no permission".into())).await.unwrap();
    store.record_renew_attempt(sid, b"k".to_vec(), 20, Some(H256::repeat_byte(7)), None).await.unwrap();

    let a = store.get_renew_attempt(sid, b"k".to_vec()).await.unwrap().unwrap();
    assert_eq!(a.attempts, 2);
    assert_eq!(a.last_attempt_ts, 20);
    assert_eq!(a.last_tx_hash, Some(H256::repeat_byte(7)));
    assert_eq!(a.last_error, None);

    assert_eq!(store.list_stuck_renewals(2, 10).await.unwrap().len(), 1);
    assert_eq!(store.list_stuck_renewals(3, 10).await.unwrap().len(), 0);

    store.clear_renew_attempt(sid, b"k".to_vec()).await.unwrap();
    assert!(store.get_renew_attempt(sid, b"k".to_vec()).await.unwrap().is_none());
}
```

- [ ] **Step 3: Run to verify fail.**

- [ ] **Step 4: Implement.** Statements:

```rust
pub const CREATE_RENEW_TABLE_STATEMENT: &'static str = "
    CREATE TABLE IF NOT EXISTS t_renew (
        stream_id BLOB NOT NULL,
        key BLOB NOT NULL,
        attempts INTEGER NOT NULL,
        last_attempt_ts INTEGER NOT NULL,
        last_tx_hash BLOB,
        last_error TEXT,
        PRIMARY KEY (stream_id, key)
    ) WITHOUT ROWID
";

pub const UPSERT_RENEW_ATTEMPT_STATEMENT: &'static str = "
    INSERT INTO t_renew (stream_id, key, attempts, last_attempt_ts, last_tx_hash, last_error)
    VALUES (:stream_id, :key, 1, :ts, :tx_hash, :error)
    ON CONFLICT(stream_id, key) DO UPDATE SET
        attempts = attempts + 1, last_attempt_ts = :ts,
        last_tx_hash = :tx_hash, last_error = :error
";

pub const CLEAR_RENEW_ATTEMPT_STATEMENT: &'static str =
    "DELETE FROM t_renew WHERE stream_id = :stream_id AND key = :key";

pub const GET_RENEW_ATTEMPT_STATEMENT: &'static str = "
    SELECT attempts, last_attempt_ts, last_tx_hash, last_error FROM t_renew
    WHERE stream_id = :stream_id AND key = :key
";

pub const LIST_STUCK_RENEWALS_STATEMENT: &'static str = "
    SELECT stream_id, key, attempts, last_attempt_ts, last_tx_hash, last_error FROM t_renew
    WHERE attempts >= :min_attempts ORDER BY last_attempt_ts ASC LIMIT :limit
";
```

Create the table in `create_tables_if_not_exist`. tx_hash binds as `Option<Vec<u8>>` (`h.as_bytes().to_vec()`), reads back via `H256::from_slice`. Trait methods + StoreManager forwards.

- [ ] **Step 5: Run to verify pass**; `cargo build --workspace`.

- [ ] **Step 6: Commit + PR** — `feat(store): t_renew attempt tracking (resolves #N)`. STD-CLOSE.

---

### Task 8: kv_renew crate skeleton — config + status types

**Files:**
- Create: `node/kv_renew/Cargo.toml`, `node/kv_renew/src/lib.rs`, `node/kv_renew/src/types.rs`
- Modify: `Cargo.toml` (workspace members += `"node/kv_renew"`)

**Interfaces:**
- Produces (everything later tasks import):

```rust
// types.rs
pub struct RenewConfig {
    pub private_key: [u8; 32],
    pub max_age_secs: u64,
    pub cycle_interval_secs: u64,
    pub batch_max_bytes: usize,
    pub batch_max_keys: usize,
    pub pause_between_batches_ms: u64,
    pub startup_delay_secs: u64,
    pub expected_replica: u64,
    pub stream_ids: Vec<H256>,          // empty = every live stream
    pub dry_run: bool,
    pub max_attempts: u64,
    pub blockchain_rpc_endpoint: String,
    pub log_contract_address: String,
    pub indexer_url: Option<String>,
    pub zgs_node_urls: Vec<String>,
    pub encryption_key: Option<[u8; 32]>,
    pub wallet_private_key: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RenewStatus {
    pub cycle_running: bool,
    pub acl_renewal_in_progress: bool,
    pub dry_run: bool,
    pub last_cycle_start: Option<u64>,
    pub last_cycle_end: Option<u64>,
    pub keys_scanned: u64,
    pub keys_renewed: u64,
    pub keys_skipped_permission: u64,
    pub keys_skipped_missing: u64,
    pub bytes_uploaded: u64,
    pub stuck_keys: Vec<StuckKey>,
    pub acl_conflicts: Vec<AclConflict>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StuckKey { pub stream_id: H256, pub key: String /* 0x-hex */, pub attempts: u64, pub last_error: Option<String> }

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AclConflict { pub stream_id: H256, pub op: String, pub account: H160, pub key: String, pub version: u64 }

pub type SharedRenewStatus = std::sync::Arc<tokio::sync::RwLock<RenewStatus>>;
```

- [ ] **Step 1: STD-OPEN.** Title: `kv_renew crate skeleton (spec §4)`.

- [ ] **Step 2: Write failing test** (in `types.rs`): serde camelCase roundtrip

```rust
#[test]
fn status_serializes_camel_case() {
    let s = RenewStatus { acl_renewal_in_progress: true, ..Default::default() };
    let v = serde_json::to_value(&s).unwrap();
    assert_eq!(v["aclRenewalInProgress"], true);
    assert!(v.get("acl_renewal_in_progress").is_none());
}
```

- [ ] **Step 3: Cargo.toml:**

```toml
[package]
name = "kv_renew"
version = "0.1.0"
edition = "2021"

[dependencies]
anyhow = { version = "1.0.58", features = ["backtrace"] }
async-trait = "0.1.56"
ethereum-types = "0.14"
ethers = "^2"
hex = "0.4.3"
k256 = "0.13"
kv_types = { path = "../kv_types" }
serde = { version = "1.0.137", features = ["derive"] }
serde_json = "1.0"
storage_with_stream = { path = "../storage_with_stream" }
task_executor = { workspace = true }
tokio = { version = "1.19.2", features = ["sync", "time", "macros"] }
tracing = "0.1.35"
contract-interface = { workspace = true }
zg-storage-client = { git = "https://github.com/0gfoundation/0g-storage-sdk-rust.git", rev = "660268e4db07f356d9d3169989d53a1f0d062308" }

[dev-dependencies]
tokio = { version = "1.19.2", features = ["rt", "macros"] }
```

(The rev matches `node/stream`'s pin today; Task 15 bumps both together.) `lib.rs`: `pub mod types; pub use types::*;` plus `#[macro_use] extern crate tracing;`.

- [ ] **Step 4: Run** — `cargo test -p kv_renew` → PASS; workspace builds.

- [ ] **Step 5: Commit + PR** — `feat(renew): kv_renew crate skeleton with config and status types (resolves #N)`. STD-CLOSE.

---

### Task 9: Config params + env override + conversion

**Files:**
- Modify: `node/src/config/mod.rs` (params), `node/src/config/convert.rs` (`renew_config()`), `node/Cargo.toml` (dep `kv_renew = { path = "./kv_renew" }`)

**Interfaces:**
- Consumes: `kv_renew::RenewConfig`, existing `parse_32byte_hex`, `to_zgs_nodes`.
- Produces: `ZgsKVConfig::renew_config(&self) -> Result<Option<kv_renew::RenewConfig>, String>` — `None` when disabled or no key; env `ZGS_KV_RENEW_PRIVATE_KEY` overrides the file value.

- [ ] **Step 1: STD-OPEN.** Title: `renew_* configuration (spec §7)`.

- [ ] **Step 2: Add params to `build_config!`:**

```rust
// renewal
(renew_enabled, (bool), true)
(renew_private_key, (String), "".to_string())  // 32-byte hex; env ZGS_KV_RENEW_PRIVATE_KEY overrides
(renew_max_age_secs, (u64), 15552000) // 180 days
(renew_cycle_interval_secs, (u64), 604800) // 7 days
(renew_batch_max_bytes, (usize), 8 * 1024 * 1024)
(renew_batch_max_keys, (usize), 1000)
(renew_pause_between_batches_ms, (u64), 2000)
(renew_startup_delay_secs, (u64), 300)
(renew_expected_replica, (u64), 1)
(renew_stream_ids, (Vec<String>), vec![]) // empty = every live stream
(renew_dry_run, (bool), false)
(renew_max_attempts, (u64), 3)
```

- [ ] **Step 3: Write failing tests** (bottom of `convert.rs`):

```rust
#[cfg(test)]
mod renew_config_tests {
    use crate::config::RawConfiguration;
    use crate::ZgsKVConfig;

    fn cfg_with(key: &str) -> ZgsKVConfig {
        let mut raw = RawConfiguration::default();
        raw.renew_private_key = key.to_string();
        raw.indexer_url = "http://indexer".to_string();
        ZgsKVConfig { raw_conf: raw }
    }

    #[test]
    fn no_key_means_disabled() {
        assert!(cfg_with("").renew_config().unwrap().is_none());
    }

    #[test]
    fn kill_switch_wins() {
        let mut c = cfg_with(&"11".repeat(32));
        c.raw_conf.renew_enabled = false;
        assert!(c.renew_config().unwrap().is_none());
    }

    #[test]
    fn key_enables_and_parses() {
        let c = cfg_with(&"11".repeat(32));
        let rc = c.renew_config().unwrap().unwrap();
        assert_eq!(rc.private_key, [0x11u8; 32]);
        assert_eq!(rc.max_age_secs, 15552000);
    }

    #[test]
    fn bad_key_is_an_error() {
        assert!(cfg_with("nothex").renew_config().is_err());
    }
}
```

(Env override is exercised manually — env mutation in parallel tests is flaky; note it in the PR body.)

- [ ] **Step 4: Implement** in `convert.rs`:

```rust
pub fn renew_config(&self) -> Result<Option<kv_renew::RenewConfig>, String> {
    let key_hex = std::env::var("ZGS_KV_RENEW_PRIVATE_KEY")
        .unwrap_or_else(|_| self.renew_private_key.clone());
    if !self.renew_enabled || key_hex.is_empty() {
        return Ok(None);
    }
    let private_key = parse_32byte_hex(&key_hex, "renew_private_key")?;

    let mut stream_ids = Vec::new();
    for id in &self.renew_stream_ids {
        stream_ids.push(H256::from_str(id).map_err(|e| format!("bad renew_stream_id {}: {:?}", id, e))?);
    }

    let stream_cfg = self.stream_config()?; // reuse parsed encryption keys
    Ok(Some(kv_renew::RenewConfig {
        private_key,
        max_age_secs: self.renew_max_age_secs,
        cycle_interval_secs: self.renew_cycle_interval_secs,
        batch_max_bytes: self.renew_batch_max_bytes,
        batch_max_keys: self.renew_batch_max_keys,
        pause_between_batches_ms: self.renew_pause_between_batches_ms,
        startup_delay_secs: self.renew_startup_delay_secs,
        expected_replica: self.renew_expected_replica,
        stream_ids,
        dry_run: self.renew_dry_run,
        max_attempts: self.renew_max_attempts,
        blockchain_rpc_endpoint: self.blockchain_rpc_endpoint.clone(),
        log_contract_address: self.log_contract_address.clone(),
        indexer_url: if self.indexer_url.is_empty() { None } else { Some(self.indexer_url.clone()) },
        zgs_node_urls: if self.zgs_node_urls.is_empty() { Vec::new() } else { to_zgs_nodes(self.zgs_node_urls.clone())? },
        encryption_key: stream_cfg.encryption_key,
        wallet_private_key: stream_cfg.wallet_private_key,
    }))
}
```

- [ ] **Step 5: Run to verify pass** — `cargo test -p zgs_kv renew_config`; workspace builds.

- [ ] **Step 6: Commit + PR** — `feat(config): renewal parameters with env key override (resolves #N)`. STD-CLOSE.

---

### Task 10: Shared value reader

**Files:**
- Modify: `node/storage_with_stream/src/store/mod.rs` (add `read_pair_value`)
- Modify: `node/rpc/src/kv_rpc_server/impl.rs` (`get_value_segment`/`get_key_value_segment` use it)

**Interfaces:**
- Produces:

```rust
/// Read the full value bytes for a KV pair out of the local flow store.
/// Ok(None) = data missing locally (tx never downloaded).
pub fn read_pair_value(store: &dyn Store, pair: &KeyValuePair) -> Result<Option<Vec<u8>>>
```

Mirrors the entry math in `kv_rpc_server::impl::get_value_segment` (`ENTRY_SIZE`, start/end entry rounding), for the whole `[start_index, end_index)` range.

- [ ] **Step 1: STD-OPEN.** Title: `Factor flow-store value read out of the RPC layer`.

- [ ] **Step 2: Write failing test** (storage_with_stream; StoreManager::memorydb + `put_chunks_with_tx_hash` seeded data):

```rust
#[tokio::test]
async fn read_pair_value_roundtrip_and_missing() {
    let mut store = StoreManager::memorydb().await.unwrap();
    // one entry (256 bytes) of 0xAB at flow index 0, via a seeded tx
    let tx = make_tx(0, vec![]); // existing helper in store_manager tests
    store.put_tx(tx.clone()).unwrap();
    let data = vec![0xABu8; 256];
    store.put_chunks_with_tx_hash(0, tx.hash(), ChunkArray { data, start_index: 0 }, None).unwrap();

    let pair = KeyValuePair { stream_id: H256::zero(), key: b"k".to_vec(),
                              start_index: 3, end_index: 10, version: 0 };
    assert_eq!(read_pair_value(&store, &pair).unwrap(), Some(vec![0xAB; 7]));

    let missing = KeyValuePair { stream_id: H256::zero(), key: b"k".to_vec(),
                                 start_index: 10_000_000, end_index: 10_000_005, version: 0 };
    assert_eq!(read_pair_value(&store, &missing).unwrap(), None);

    let empty = KeyValuePair { start_index: 5, end_index: 5, ..pair };
    assert_eq!(read_pair_value(&store, &empty).unwrap(), Some(vec![]));
}
```

(Adapt `make_tx` / entry seeding to the existing store_manager test helpers; the tx must cover the flow range so `get_chunk_by_flow_index` finds it.)

- [ ] **Step 3: Run to verify fail.**

- [ ] **Step 4: Implement** in `store/mod.rs`:

```rust
use storage::log_store::log_manager::ENTRY_SIZE;

pub fn read_pair_value(store: &dyn Store, pair: &KeyValuePair) -> Result<Option<Vec<u8>>> {
    if pair.end_index == pair.start_index {
        return Ok(Some(vec![]));
    }
    let start_entry = pair.start_index / ENTRY_SIZE as u64;
    let end_entry = (pair.end_index + ENTRY_SIZE as u64 - 1) / ENTRY_SIZE as u64;
    match store.get_chunk_by_flow_index(start_entry, end_entry - start_entry)? {
        Some(chunks) => {
            let off = (pair.start_index - start_entry * ENTRY_SIZE as u64) as usize;
            let len = (pair.end_index - pair.start_index) as usize;
            Ok(Some(chunks.data[off..off + len].to_vec()))
        }
        None => Ok(None),
    }
}
```

Rewire `kv_rpc_server/impl.rs::get_value_segment` only where it reads the FULL value is not the case — it reads sub-ranges, so leave its range math alone; instead just replace nothing there if the shapes differ. If the segment logic can't reuse it cleanly, keep `read_pair_value` new-code-only and say so in the PR body (the RPC dedup is a nice-to-have, not the deliverable).

- [ ] **Step 5: Run to verify pass**; workspace builds.

- [ ] **Step 6: Commit + PR** — `feat(store): read_pair_value helper for whole-value reads (resolves #N)`. STD-CLOSE.

---

### Task 11: PiecewiseClock + NULL backfill SQL

**Files:**
- Create: `node/kv_renew/src/clock.rs`
- Modify: `node/kv_renew/src/lib.rs` (`pub mod clock;`)
- Modify: `node/storage_with_stream` (statements, stream_store, mod.rs trait, store_manager)

**Interfaces:**
- Produces:
  - `kv_renew::clock::PiecewiseClock::new(points: Vec<(u64, u64)>) -> Self` (version→unix-ts points, sorted internally) and `fn time_at(&self, version: u64) -> u64` (clamped linear interpolation).
  - `StreamRead::get_null_time_versions(&self, limit: u64) -> Result<Vec<u64>>` — distinct versions with NULL `updated_at` across both tables.
  - `StreamWrite::backfill_version_time(&self, version: u64, ts: u64) -> Result<()>` — fills NULLs only.

- [ ] **Step 1: STD-OPEN.** Title: `version->time interpolation and NULL backfill (spec §3)`.

- [ ] **Step 2: Write failing tests:**

```rust
// clock.rs
#[cfg(test)]
mod tests {
    use super::PiecewiseClock;

    #[test]
    fn interpolates_between_points() {
        let c = PiecewiseClock::new(vec![(100, 1000), (200, 2000)]);
        assert_eq!(c.time_at(150), 1500);
    }

    #[test]
    fn clamps_outside_range_and_sorts_input() {
        let c = PiecewiseClock::new(vec![(200, 2000), (100, 1000)]);
        assert_eq!(c.time_at(50), 1000);
        assert_eq!(c.time_at(500), 2000);
    }

    #[test]
    fn single_point_is_constant() {
        let c = PiecewiseClock::new(vec![(10, 42)]);
        assert_eq!(c.time_at(0), 42);
        assert_eq!(c.time_at(99), 42);
    }
}
```

```rust
// stream_store.rs tests
#[tokio::test]
async fn backfill_fills_only_nulls() {
    let store = StreamStore::new_in_memory().await.unwrap();
    store.create_tables_if_not_exist().await.unwrap();
    let sid = H256::repeat_byte(3);
    store.put_stream(1, "Commit".into(), Some(write_set(sid, b"x")), None).await.unwrap();
    store.put_stream(2, "Commit".into(), Some(write_set(sid, b"y")), Some(999)).await.unwrap();

    assert_eq!(store.get_null_time_versions(10).await.unwrap(), vec![1]);
    store.backfill_version_time(1, 555).await.unwrap();
    assert!(store.get_null_time_versions(10).await.unwrap().is_empty());

    let stale = store.get_stale_stream_keys(sid, 556, vec![], 10).await.unwrap();
    assert_eq!(stale.len(), 1);
    assert_eq!(stale[0].updated_at, 555);
}
```

- [ ] **Step 3: Run to verify fail.**

- [ ] **Step 4: Implement.**

```rust
// clock.rs
pub struct PiecewiseClock { points: Vec<(u64, u64)> }

impl PiecewiseClock {
    pub fn new(mut points: Vec<(u64, u64)>) -> Self {
        points.sort();
        points.dedup_by_key(|p| p.0);
        Self { points }
    }

    pub fn time_at(&self, version: u64) -> u64 {
        match self.points.binary_search_by_key(&version, |p| p.0) {
            Ok(i) => self.points[i].1,
            Err(0) => self.points[0].1,
            Err(i) if i == self.points.len() => self.points[i - 1].1,
            Err(i) => {
                let (v0, t0) = self.points[i - 1];
                let (v1, t1) = self.points[i];
                t0 + (t1 - t0) * (version - v0) / (v1 - v0)
            }
        }
    }
}
```

Statements:

```rust
pub const GET_NULL_TIME_VERSIONS_STATEMENT: &'static str = "
    SELECT DISTINCT version FROM (
        SELECT version FROM t_stream WHERE updated_at IS NULL
        UNION SELECT version FROM t_access_control WHERE updated_at IS NULL
    ) ORDER BY version ASC LIMIT :limit
";

pub const BACKFILL_STREAM_TIME_STATEMENT: &'static str =
    "UPDATE t_stream SET updated_at = :ts, created_at = COALESCE(created_at, :ts) WHERE version = :version AND updated_at IS NULL";

pub const BACKFILL_ACCESS_CONTROL_TIME_STATEMENT: &'static str =
    "UPDATE t_access_control SET updated_at = :ts, created_at = COALESCE(created_at, :ts) WHERE version = :version AND updated_at IS NULL";
```

`backfill_version_time` runs both UPDATEs in one transaction. Trait + forwards. PiecewiseClock panics on empty input — assert `!points.is_empty()` in `new` with a message; the caller (Task 18) never builds an empty clock.

- [ ] **Step 5: Run to verify pass**; workspace builds.

- [ ] **Step 6: Commit + PR** — `feat(renew): piecewise version clock and NULL-timestamp backfill (resolves #N)`. STD-CLOSE.

---

### Task 12: Chain probes — block-at-time bisect + first submission seq

**Files:**
- Create: `node/kv_renew/src/probe.rs` (`pub mod probe;` in lib.rs)

**Interfaces:**
- Consumes: ethers `Provider<Http>` (built from `RenewConfig::blockchain_rpc_endpoint`), `contract_interface::ZgsFlow` (same crate log_entry_sync uses; its `submit_filter()` events expose `.submission_index: U256`).
- Produces:
  - `pub async fn bisect_block_at<F, Fut>(lo: u64, hi: u64, target_ts: u64, ts_of: F) -> Result<u64>` where `F: Fn(u64) -> Fut, Fut: Future<Output = Result<u64>>` — largest block with timestamp <= target (generic so it unit-tests without a chain).
  - `pub async fn first_submission_at_or_after(provider: Arc<Provider<Http>>, flow: Address, from_block: u64, page: u64) -> Result<Option<u64>>` — scans Submit logs forward in `page`-sized windows, returns the first `submission_index` seen.
  - `pub async fn build_clock(provider, flow, age_points_secs: &[u64], next_tx_seq: u64, now: u64) -> Result<crate::clock::PiecewiseClock>` — probes each age, always appends `(next_tx_seq, now)`.

- [ ] **Step 1: STD-OPEN.** Title: `chain probes for the backfill clock (spec §3)`.

- [ ] **Step 2: Write failing test** for the bisect (pure):

```rust
#[cfg(test)]
mod tests {
    use super::bisect_block_at;

    #[tokio::test]
    async fn bisect_finds_boundary_block() {
        // block n has timestamp n*10
        let ts_of = |n: u64| async move { Ok::<u64, anyhow::Error>(n * 10) };
        assert_eq!(bisect_block_at(0, 1000, 505, ts_of).await.unwrap(), 50);
        assert_eq!(bisect_block_at(0, 1000, 500, ts_of).await.unwrap(), 50);
        assert_eq!(bisect_block_at(0, 1000, 5, ts_of).await.unwrap(), 0);
        assert_eq!(bisect_block_at(0, 1000, 99999, ts_of).await.unwrap(), 1000);
    }
}
```

- [ ] **Step 3: Run to verify fail.**

- [ ] **Step 4: Implement:**

```rust
pub async fn bisect_block_at<F, Fut>(mut lo: u64, mut hi: u64, target_ts: u64, ts_of: F) -> Result<u64>
where F: Fn(u64) -> Fut, Fut: std::future::Future<Output = Result<u64>> {
    if ts_of(hi).await? <= target_ts { return Ok(hi); }
    if ts_of(lo).await? > target_ts { return Ok(lo); }
    while lo + 1 < hi {
        let mid = lo + (hi - lo) / 2;
        if ts_of(mid).await? <= target_ts { lo = mid; } else { hi = mid; }
    }
    Ok(lo)
}
```

`first_submission_at_or_after`: loop windows `[from, from+page)` up to the current head, `ZgsFlow::new(flow, provider.clone()).submit_filter().from_block(a).to_block(b).query().await?`, return `Some(events[0].submission_index.as_u64())` on first non-empty window, `Ok(None)` past head. `build_clock`: for each age in `age_points_secs` (defaults used by caller: `[15552000, 31104000]` — 6 and 12 months): `target = now - age`; `block = bisect_block_at(0, head, target, |n| provider block timestamp)?`; `if let Some(seq) = first_submission_at_or_after(...)` push `(seq, target)`. Append `(next_tx_seq, now)`; build `PiecewiseClock`. Network paths are covered by Task 24's integration test, not unit tests.

- [ ] **Step 5: Run to verify pass**; workspace builds.

- [ ] **Step 6: Commit + PR** — `feat(renew): chain probes for backfill clock (resolves #N)`. STD-CLOSE.

---

### Task 13: ValueBatcher — pack values, wrap encryption

**Files:**
- Create: `node/kv_renew/src/batch.rs` (`pub mod batch;`)

**Interfaces:**
- Consumes: SDK `zg_storage_client::kv::builder::StreamDataBuilder`, `core::in_mem::DataInMemory`, `core::encrypted_data::EncryptedData`, `core::dataflow::IterableData`.
- Produces:

```rust
pub struct ValueBatcher { /* builder, caps, counters, keys */ }
pub struct BuiltBatch {
    pub encoded: Vec<u8>,
    pub tags: Vec<u8>,
    pub keys: Vec<(H256, Vec<u8>)>,   // what this batch renews — cycle bookkeeping
    pub bytes: usize,
}

impl ValueBatcher {
    pub fn new(max_bytes: usize, max_keys: usize) -> Self;      // builder version = u64::MAX
    /// false = batch full, item NOT added (caller finishes batch and re-pushes).
    /// An oversized value is accepted when the batch is empty (its own batch).
    pub fn push(&mut self, stream_id: H256, key: Vec<u8>, value: Vec<u8>) -> bool;
    pub fn is_empty(&self) -> bool;
    pub fn finish(self) -> Result<BuiltBatch>;                   // build(None) + encode + build_tags(None)
}

/// v1: EncryptedData::new(inner, key); v2: derive recipient pubkey from
/// wallet_private_key (k256 SecretKey -> public -> sec1 compressed) then
/// EncryptedData::new_ecies; neither: DataInMemory as-is.
pub fn into_upload_data(
    encoded: Vec<u8>,
    encryption_key: Option<[u8; 32]>,
    wallet_private_key: Option<[u8; 32]>,
) -> Result<Arc<dyn IterableData>>;
```

- [ ] **Step 1: STD-OPEN.** Title: `renewal value batcher with byte/key caps and encryption wrap (spec §4 steps 4,6)`.

- [ ] **Step 2: Write failing tests:**

```rust
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
```

- [ ] **Step 3: Run to verify fail.**

- [ ] **Step 4: Implement.** `push` tracks `bytes += value.len()` and `keys.len()`; full when `(!empty && bytes + v.len() > max_bytes) || keys.len() >= max_keys`; delegates to `builder.set(stream_id, &key, value)`. `into_upload_data`:

```rust
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
```

- [ ] **Step 5: Run to verify pass**; workspace builds.

- [ ] **Step 6: Commit + PR** — `feat(renew): value batcher with caps and encryption wrap (resolves #N)`. STD-CLOSE.

---

### Task 14: RenewUploader

**Files:**
- Create: `node/kv_renew/src/upload.rs` (`pub mod upload;`)

**Interfaces:**
- Consumes: SDK `must_new_web3`, `must_new_zgs_clients`, `IndexerClient`, `Uploader`, `UploadOption`, `FinalityRequirement`, `merkle_tree` (core::dataflow); Task 13's `BuiltBatch`/`into_upload_data`.
- Produces:

```rust
#[async_trait]
pub trait BatchSink: Send + Sync {
    /// Uploads; returns the file's merkle root. "Already finalized" counts as success.
    async fn submit(&self, data: Arc<dyn IterableData>, tags: Vec<u8>) -> Result<H256>;
    /// Root -> tx seq via storage-node file info (None until nodes have logged it).
    async fn resolve_tx_seq(&self, root: H256) -> Result<Option<u64>>;
}

pub struct RenewUploader { /* web3, indexer, static urls, expected_replica */ }
impl RenewUploader { pub async fn new(cfg: &RenewConfig) -> Result<Self>; }
pub fn is_already_finalized_err(msg: &str) -> bool;
```

The trait exists so Tasks 17–19 unit-test cycles with a mock sink.

- [ ] **Step 1: STD-OPEN.** Title: `renewal uploader (skip_tx=false, already-finalized = success) (spec §4 step 6)`.

- [ ] **Step 2: Write failing test** (the pure matcher only; network paths are integration-tested in Task 24):

```rust
#[test]
fn already_finalized_matcher() {
    assert!(is_already_finalized_err("file already exists on node"));
    assert!(is_already_finalized_err("Transaction already finalized"));
    assert!(!is_already_finalized_err("connection refused"));
}
```

- [ ] **Step 3: Run to verify fail.**

- [ ] **Step 4: Implement.**

```rust
pub fn is_already_finalized_err(msg: &str) -> bool {
    let m = msg.to_lowercase();
    m.contains("already") && (m.contains("finaliz") || m.contains("exist"))
}
```

`RenewUploader::new`: `must_new_web3(&cfg.blockchain_rpc_endpoint, &hex::encode(cfg.private_key)).await`; `IndexerClient::new` when `indexer_url` set. `submit`:

```rust
async fn submit(&self, data: Arc<dyn IterableData>, tags: Vec<u8>) -> Result<H256> {
    let tree = merkle_tree(data.clone()).await?;
    let root = H256::from_slice(tree.root().as_ref());
    let clients = self.clients().await?; // indexer.select_nodes(expected_replica, &[]) or must_new_zgs_clients(static)
    let opt = UploadOption {
        tags,
        finality_required: FinalityRequirement::TransactionPacked,
        task_size: 10,
        expected_replica: self.expected_replica,
        skip_tx: false, // THE point of renewal: always submit on-chain
        fee: U256::zero(),
        nonce: U256::zero(),
    };
    let uploader = Uploader::new(self.web3.clone(), clients).await?;
    match uploader.upload(data, &opt).await {
        Ok(_) => Ok(root),
        Err(e) if is_already_finalized_err(&format!("{:?}", e)) => {
            info!("segments already on nodes for {:?}; tx submitted, counting as success", root);
            Ok(root)
        }
        Err(e) => Err(e),
    }
}
```

`resolve_tx_seq`: iterate clients, `client.get_file_info(root)` (check the exact method name on `ZgsClient` in `src/node/client_zgs.rs` — the uploader's skip_tx path calls it; mirror that call), return `Some(info.tx.seq)` when found/finalized.

- [ ] **Step 5: Run to verify pass** (`cargo test -p kv_renew`); workspace builds.

- [ ] **Step 6: Commit + PR** — `feat(renew): uploader with forced on-chain submission (resolves #N)`. STD-CLOSE.

---

### Task 15: Effective ACL snapshot — store queries + op emission (bump SDK rev)

**Files:**
- Modify: `node/kv_types/src/lib.rs` (`EffectiveAcl`, `AclOpRow`)
- Modify: `node/storage_with_stream` (statements, stream_store, mod.rs, store_manager)
- Create: `node/kv_renew/src/acl.rs` (`pub mod acl;`)
- Modify: `node/stream/Cargo.toml` + `node/kv_renew/Cargo.toml` (SDK `rev = "<Task-1 merge SHA>"`)

**Interfaces:**
- Produces:

```rust
// kv_types
pub struct EffectiveAcl {
    pub admins: Vec<H160>,
    pub writers: Vec<H160>,
    pub special_keys: Vec<Vec<u8>>,
    pub special_writers: Vec<(Vec<u8>, H160)>,
}
pub struct AclOpRow { pub op_type: u8, pub key: Vec<u8>, pub account: H160, pub version: u64 }

// StreamRead
async fn get_effective_access_control(&self, stream_id: H256) -> Result<EffectiveAcl>;
async fn get_latest_access_control_seq(&self, stream_id: H256) -> Result<u64>; // 0 when none
async fn get_access_control_ops_in_range(&self, stream_id: H256, after: u64, before: u64) -> Result<Vec<AclOpRow>>; // after < version < before

// kv_renew::acl — requires Task 1's SDK methods
pub fn emit_acl_ops(builder: &mut StreamDataBuilder, stream_id: H256, acl: &EffectiveAcl, signer: H160) -> usize; // returns op count; SKIPS signer's own admin grant
```

- [ ] **Step 1: STD-OPEN.** Title: `effective access-control snapshot for renewal (spec §5)`.

- [ ] **Step 2: Bump SDK rev** in `node/stream/Cargo.toml` and `node/kv_renew/Cargo.toml` to Task 1's merge SHA; `cargo build --workspace`; commit `chore(deps): bump zg-storage-client for ACL builder methods`.

- [ ] **Step 3: Write failing store tests** (seed ops through `put_stream` with an `AccessControlSet`):

```rust
fn acl_set(ops: Vec<(u8, H160, Vec<u8>)>, stream_id: H256) -> (StreamWriteSet, AccessControlSet) {
    (StreamWriteSet { stream_writes: vec![] },
     AccessControlSet {
         access_controls: ops.into_iter().map(|(op_type, account, key)| AccessControl {
             op_type, stream_id, key: Arc::new(key), account, operator: account }).collect(),
         is_admin: Default::default(),
     })
}

#[tokio::test]
async fn effective_acl_last_op_wins() {
    let store = StreamStore::new_in_memory().await.unwrap();
    store.create_tables_if_not_exist().await.unwrap();
    let sid = H256::repeat_byte(4);
    let (u1, u2) = (H160::repeat_byte(1), H160::repeat_byte(2));

    store.put_stream(1, "Commit".into(), Some(acl_set(vec![
        (AccessControlOps::GRANT_ADMIN_ROLE, u1, vec![]),
        (AccessControlOps::GRANT_WRITER_ROLE, u2, vec![]),
        (AccessControlOps::SET_KEY_TO_SPECIAL, H160::zero(), b"s".to_vec()),
        (AccessControlOps::GRANT_SPECIAL_WRITER_ROLE, u2, b"s".to_vec()),
    ], sid)), Some(100)).await.unwrap();
    store.put_stream(2, "Commit".into(), Some(acl_set(vec![
        (AccessControlOps::REVOKE_WRITER_ROLE, u2, vec![]),
    ], sid)), Some(200)).await.unwrap();

    let acl = store.get_effective_access_control(sid).await.unwrap();
    assert_eq!(acl.admins, vec![u1]);
    assert!(acl.writers.is_empty()); // revoked at v2
    assert_eq!(acl.special_keys, vec![b"s".to_vec()]);
    assert_eq!(acl.special_writers, vec![(b"s".to_vec(), u2)]);

    assert_eq!(store.get_latest_access_control_seq(sid).await.unwrap(), 2);
    let win = store.get_access_control_ops_in_range(sid, 1, 3).await.unwrap();
    assert_eq!(win.len(), 1);
    assert_eq!(win[0].op_type, AccessControlOps::REVOKE_WRITER_ROLE);
}
```

- [ ] **Step 4: Run to verify fail. Implement store side.** Groupwise-latest per category with `formatcp!` like existing statements — admins:

```rust
pub const GET_EFFECTIVE_ADMINS_STATEMENT: &'static str = formatcp!("
    SELECT account, op_type FROM t_access_control a
    WHERE stream_id = :stream_id AND op_type IN ({}, {}) AND version = (
        SELECT MAX(version) FROM t_access_control b
        WHERE b.stream_id = a.stream_id AND b.account = a.account AND b.op_type IN ({}, {}))",
    AccessControlOps::GRANT_ADMIN_ROLE, AccessControlOps::RENOUNCE_ADMIN_ROLE,
    AccessControlOps::GRANT_ADMIN_ROLE, AccessControlOps::RENOUNCE_ADMIN_ROLE);
```

Analogous statements for writers (group by account over 0x20/0x21/0x22), special keys (group by key over 0x10/0x11), special writers (group by key+account over 0x30/0x31/0x32). Rust filters keep only rows whose op_type is the grant/set variant. `get_latest_access_control_seq`: `SELECT COALESCE(MAX(version), 0) FROM t_access_control WHERE stream_id = :stream_id`. Range query: `WHERE stream_id = :stream_id AND version > :after AND version < :before ORDER BY version ASC`.

- [ ] **Step 5: Write failing acl.rs test, then implement:**

```rust
#[test]
fn emit_skips_signer_self_grant() {
    let sid = H256::repeat_byte(4);
    let signer = H160::repeat_byte(1);
    let other = H160::repeat_byte(2);
    let acl = EffectiveAcl {
        admins: vec![signer, other],
        writers: vec![other],
        special_keys: vec![b"s".to_vec()],
        special_writers: vec![(b"s".to_vec(), other)],
    };
    let mut b = StreamDataBuilder::new(u64::MAX);
    let n = emit_acl_ops(&mut b, sid, &acl, signer);
    assert_eq!(n, 4); // other-admin grant, writer grant, special key, special writer — NOT signer's own admin
    assert_eq!(b.build(None).unwrap().controls.len(), 4);
}
```

```rust
pub fn emit_acl_ops(builder: &mut StreamDataBuilder, stream_id: H256, acl: &EffectiveAcl, signer: H160) -> usize {
    let mut n = 0;
    let to_addr = |a: &H160| Address::from_slice(a.as_bytes());
    for admin in acl.admins.iter().filter(|a| **a != signer) {
        builder.grant_admin_role(stream_id, to_addr(admin)); n += 1;
    }
    for w in &acl.writers { builder.grant_writer_role(stream_id, to_addr(w)); n += 1; }
    for k in &acl.special_keys { builder.set_key_to_special(stream_id, k.clone()); n += 1; }
    for (k, a) in &acl.special_writers { builder.grant_special_writer_role(stream_id, k.clone(), to_addr(a)); n += 1; }
    n
}
```

(kv_types H256/H160 and ethers types are distinct — convert explicitly as shown; check whether `StreamDataBuilder` takes ethers `H256` and convert the stream id the same way if so.)

- [ ] **Step 6: Run to verify pass**; workspace builds. **Commit + PR** — `feat(renew): effective ACL snapshot queries and op emission (resolves #N)`. STD-CLOSE.

---

### Task 16: Scanner — stale collection, permission/missing filters, backoff

**Files:**
- Create: `node/kv_renew/src/scan.rs` (`pub mod scan;`)

**Interfaces:**
- Consumes: Tasks 6, 7, 10, 13; `Store::has_write_permission(signer, stream_id, key, u64::MAX)`.
- Produces:

```rust
pub struct ScanCounters { pub scanned: u64, pub skipped_permission: u64, pub skipped_missing: u64, pub skipped_backoff: u64 }

/// Fills `batcher` with stale values starting after `cursor`, advancing it.
/// Returns (counters, stream_exhausted).
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
) -> Result<(ScanCounters, bool)>;

pub fn backoff_until(attempts: u64, last_ts: u64, cycle_secs: u64) -> u64; // last_ts + cycle_secs << min(attempts, 4)
```

Skip rules per spec §4 step 3: already uploaded this cycle; attempts >= max_attempts and now < backoff_until (skip + count); no write permission (record attempt with error, warn, count); value missing locally (record attempt, count). Page size 256 per store call; stop when batcher refuses a push (keep that item for the next batch by NOT advancing cursor past it).

- [ ] **Step 1: STD-OPEN.** Title: `renewal scanner: filters, backoff, batch fill (spec §4 steps 2-4)`.

- [ ] **Step 2: Write failing tests** (StoreManager::memorydb; permission control via ACL seeding as in Task 15's helper — a stream with a foreign admin makes `has_write_permission(signer, ...)` false; a brand-new stream makes it true):

```rust
#[tokio::test]
async fn fill_batch_filters_and_advances_cursor() {
    let store: Arc<RwLock<dyn Store>> = Arc::new(RwLock::new(StoreManager::memorydb().await.unwrap()));
    let sid = H256::repeat_byte(5);
    let signer = H160::repeat_byte(9);
    // seed three stale keys via put_tx + chunks + put_stream(ts=100): "a" (value present),
    // "b" (no chunks -> missing), "c" (present)  — reuse Task 10's seeding helper pattern
    seed_stale_keys(&store, sid, &[(b"a", true), (b"b", false), (b"c", true)], 100).await;

    let mut batcher = ValueBatcher::new(1 << 20, 100);
    let mut cursor = vec![];
    let (counters, done) = fill_batch(&store, sid, 1_000, &mut cursor, &mut batcher,
        signer, &HashSet::new(), 3, 2_000).await.unwrap();

    assert!(done);
    assert_eq!(counters.scanned, 3);
    assert_eq!(counters.skipped_missing, 1);
    let built = batcher.finish().unwrap();
    assert_eq!(built.keys.len(), 2);
    // missing key got an attempt row
    assert!(store.read().await.get_renew_attempt(sid, b"b".to_vec()).await.unwrap().is_some());
}

#[test]
fn backoff_doubles_capped() {
    assert_eq!(backoff_until(3, 100, 10), 100 + 80);
    assert_eq!(backoff_until(10, 100, 10), 100 + 160); // capped at <<4
}
```

Include the `seed_stale_keys` helper in the test module: for each key, `put_tx` a minimal tx at the next seq, `put_chunks_with_tx_hash` 256 bytes when `present`, then `put_stream(seq, "Commit", one-write set with real flow indexes, Some(ts))`.

- [ ] **Step 3: Run to verify fail. Implement** per the interface block. Permission check: `store.read().await.has_write_permission(signer, stream_id, Arc::new(key.clone()), u64::MAX).await?` — on false, `record_renew_attempt(..., error = Some("no write permission"))`. Value read: `read_pair_value(&*store.read().await, &pair)`. Batch-full handling: when `push` returns false, return `(counters, false)` WITHOUT advancing `cursor` past that key.

- [ ] **Step 4: Run to verify pass**; workspace builds.

- [ ] **Step 5: Commit + PR** — `feat(renew): stale scanner with permission and backoff filters (resolves #N)`. STD-CLOSE.

---

### Task 17: Cycle — drain loop + verification

**Files:**
- Create: `node/kv_renew/src/cycle.rs` (`pub mod cycle;`)

**Interfaces:**
- Consumes: Tasks 13, 14 (`BatchSink`), 16; `Store::{get_stream_replay_progress, get_latest_version_before, clear_renew_attempt, record_renew_attempt, next_tx_seq}`.
- Produces:

```rust
pub struct CycleDeps {
    pub store: Arc<RwLock<dyn Store>>,
    pub sink: Arc<dyn BatchSink>,
    pub config: Arc<RenewConfig>,
    pub status: SharedRenewStatus,
    pub signer: H160,
}

/// Drain one stream: scan -> pack -> upload -> repeat until no stale keys remain.
/// Returns the keys uploaded (for verification) and the pre-upload next_tx_seq.
pub async fn drain_stream(deps: &CycleDeps, stream_id: H256, cutoff: u64, now: u64)
    -> Result<(Vec<(H256, Vec<u8>)>, u64)>;

/// A key is verified renewed when its latest version now exceeds pre_seq.
/// Clears t_renew on success; records the failure otherwise. Returns renewed count.
pub async fn verify_renewed(store: &Arc<RwLock<dyn Store>>, keys: &[(H256, Vec<u8>)], pre_seq: u64, now: u64) -> Result<u64>;

/// Poll replay progress until it reaches `target_seq` or `timeout` elapses. Returns reached?.
pub async fn wait_replay(store: &Arc<RwLock<dyn Store>>, target_seq: u64, timeout: Duration, poll: Duration) -> bool;
```

`drain_stream` loop: `pre_seq = store.read().await.next_tx_seq()`; then repeatedly `fill_batch` → if batcher empty and exhausted, stop; `finish()` → `into_upload_data` → dry-run? (log `would upload N keys / B bytes`, count into status, but DO NOT mark uploaded — and dry-run stops after ONE loop pass per stream to avoid spinning on the same stale keys) : `sink.submit` → extend `uploaded_this_cycle` + record attempts with the root as tx_hash → status counters (keys_renewed is set by verification, not here) → sleep `pause_between_batches_ms`.

- [ ] **Step 1: STD-OPEN.** Title: `renewal cycle: drain loop and replay verification (spec §4 steps 5-8)`.

- [ ] **Step 2: Write failing tests** with a mock sink:

```rust
struct MockSink { submitted: Mutex<Vec<(usize, Vec<u8>)>> } // (data size, tags)

#[async_trait]
impl BatchSink for MockSink {
    async fn submit(&self, data: Arc<dyn IterableData>, tags: Vec<u8>) -> Result<H256> {
        self.submitted.lock().unwrap().push((data.size() as usize, tags));
        Ok(H256::repeat_byte(0xaa))
    }
    async fn resolve_tx_seq(&self, _root: H256) -> Result<Option<u64>> { Ok(Some(42)) }
}

#[tokio::test]
async fn drain_uploads_until_no_stale_left() {
    let store = seeded_store_with_stale_keys(3).await; // helper from Task 16 tests
    let deps = mock_deps(store.clone(), 1 << 20, 2 /* max_keys per batch */).await;
    let (uploaded, _pre) = drain_stream(&deps, sid(), 1_000, 2_000).await.unwrap();
    assert_eq!(uploaded.len(), 3);
    // 3 keys with max_keys=2 -> exactly 2 batches
    assert_eq!(deps_sink(&deps).submitted.lock().unwrap().len(), 2);
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
    assert!(store.read().await.get_renew_attempt(sid(), b"k0".to_vec()).await.unwrap().is_none());
    assert!(store.read().await.get_renew_attempt(sid(), b"k1".to_vec()).await.unwrap().is_some());
}

#[tokio::test]
async fn dry_run_submits_nothing() {
    let store = seeded_store_with_stale_keys(2).await;
    let deps = mock_deps_dry_run(store).await;
    let (uploaded, _) = drain_stream(&deps, sid(), 1_000, 2_000).await.unwrap();
    assert!(uploaded.is_empty());
    assert_eq!(deps_sink(&deps).submitted.lock().unwrap().len(), 0);
}
```

- [ ] **Step 3: Run to verify fail. Implement.** `verify_renewed` core:

```rust
pub async fn verify_renewed(store: &Arc<RwLock<dyn Store>>, keys: &[(H256, Vec<u8>)], pre_seq: u64, now: u64) -> Result<u64> {
    let mut renewed = 0;
    for (stream_id, key) in keys {
        let latest = store.read().await
            .get_latest_version_before(*stream_id, Arc::new(key.clone()), u64::MAX).await?;
        if latest > pre_seq {
            store.write().await.clear_renew_attempt(*stream_id, key.clone()).await?;
            renewed += 1;
        } else {
            store.write().await.record_renew_attempt(*stream_id, key.clone(), now, None,
                Some("replayed but version did not advance (write rejected?)".into())).await?;
            warn!("renewal for stream {:?} key 0x{} did not take effect", stream_id, hex::encode(key));
        }
    }
    Ok(renewed)
}
```

`wait_replay`: loop `get_stream_replay_progress() >= target_seq` with `tokio::time::sleep(poll)`, deadline via `tokio::time::Instant`.

- [ ] **Step 4: Run to verify pass**; workspace builds.

- [ ] **Step 5: Commit + PR** — `feat(renew): drain loop and replay verification (resolves #N)`. STD-CLOSE.

---

### Task 18: Service loop — startup checks, backfill, scheduling, trigger

**Files:**
- Create: `node/kv_renew/src/service.rs` (`pub mod service;`)

**Interfaces:**
- Consumes: everything above; `contract_interface::ZgsFlow` for balance/head checks; ethers `LocalWallet` for address derivation.
- Produces:

```rust
/// Derive the signer address from the configured key. Pure; unit-tested.
pub fn signer_address(private_key: &[u8; 32]) -> Result<H160>;

pub fn spawn_renewer(
    executor: TaskExecutor,
    store: Arc<RwLock<dyn Store>>,
    live_stream_set: Arc<RwLock<HashSet<H256>>>,
    config: RenewConfig,
    status: SharedRenewStatus,
    trigger_rx: tokio::sync::mpsc::UnboundedReceiver<()>,
);
```

Service behavior (all in `run(...)` spawned as task "kv renewer"):
1. `signer_address`; `info!` the address (never the key).
2. Sleep `startup_delay_secs`.
3. Startup admin check per stream: `is_admin(signer, sid, u64::MAX)`; not admin → `error!("ACL renewal disabled for stream {sid:?}: renew signer is not admin")`, remember in a `HashSet<H256>` of acl-disabled streams (consumed by Task 19).
4. Backfill once if `get_null_time_versions(1)` is non-empty: build provider `Provider::<Http>::try_from(&cfg.blockchain_rpc_endpoint)`, `build_clock(provider, flow_addr, &[cfg.max_age_secs, cfg.max_age_secs * 2], store.next_tx_seq(), now)`, then loop `get_null_time_versions(1024)` → `backfill_version_time(v, clock.time_at(v))`. On probe failure: `warn!` and skip (NULL rows are deferred — spec §3).
5. Loop forever: `tokio::select! { _ = tokio::time::sleep(Duration::from_secs(cfg.cycle_interval_secs)) => {}, Some(_) = trigger_rx.recv() => {} }` then run one cycle guarded by `status.cycle_running` (skip re-entry, log).
6. Per cycle: balance check `provider.get_balance(signer, None)` — zero → `error!`, skip cycle. Streams = `live_stream_set` filtered by `cfg.stream_ids` when non-empty. For each stream: [Task 19 ACL hook] then `drain_stream` + `wait_replay(max uploaded seq via sink.resolve_tx_seq)` + `verify_renewed`. Update status (`last_cycle_start/end`, counters, `stuck_keys` from `list_stuck_renewals(cfg.max_attempts, 100)`). Every error is caught and logged — the service never panics the node.
7. `now` comes from `SystemTime::now().duration_since(UNIX_EPOCH)` via a small `fn unix_now() -> u64`.

- [ ] **Step 1: STD-OPEN.** Title: `renewal service loop: startup checks, backfill, scheduling (spec §4)`.

- [ ] **Step 2: Write failing test** for the pure part:

```rust
#[test]
fn signer_address_matches_ethers_wallet() {
    // well-known test vector: private key 0x01.. -> address of that key
    let key = {
        let mut k = [0u8; 32];
        k[31] = 1;
        k
    };
    let addr = signer_address(&key).unwrap();
    let wallet: ethers::signers::LocalWallet =
        ethers::signers::Wallet::from_bytes(&key).unwrap();
    use ethers::signers::Signer;
    assert_eq!(addr.as_bytes(), wallet.address().as_bytes());
}
```

- [ ] **Step 3: Run to verify fail. Implement** `signer_address` via `LocalWallet::from_bytes` + address bytes → `H160::from_slice`, then the service per the behavior list. The cycle body is a `run_cycle(deps, streams, acl_disabled)` free function so Task 19 extends it in one place.

- [ ] **Step 4: Run to verify pass**; workspace builds; clippy clean (the long function is fine, keep sub-steps as helpers).

- [ ] **Step 5: Commit + PR** — `feat(renew): service loop with startup checks and backfill (resolves #N)`. STD-CLOSE.

---

### Task 19: ACL emission in the cycle — gate, pre-submit re-check, detection

**Files:**
- Create: `node/kv_renew/src/acl_cycle.rs` (`pub mod acl_cycle;`)
- Modify: `node/kv_renew/src/service.rs` (call it at the top of each stream's cycle work)

**Interfaces:**
- Consumes: Task 15 queries + `emit_acl_ops`; Task 14 `BatchSink`; Task 17 `wait_replay`.
- Produces:

```rust
/// Pure: which window ops touch pairs the snapshot re-emitted? (spec §5 detection)
pub fn find_conflicts(window_ops: &[AclOpRow], emitted: &EffectiveAcl, signer: H160) -> Vec<AclOpRow>;

/// Chain-side view shared by service and acl_cycle (also used for the
/// balance check in Task 18).
pub struct ChainView { pub provider: Arc<Provider<Http>>, pub flow: Address }
impl ChainView {
    /// numSubmissions on the flow contract (confirm the generated getter
    /// name on contract_interface::ZgsFlow; it is the `numSubmissions` ABI method).
    pub async fn head_submissions(&self) -> Result<u64>;
}

/// Emit one ACL snapshot batch for the stream. Steps:
/// caught-up gate -> snapshot (seq + EffectiveAcl under ONE store read guard) ->
/// emit_acl_ops (skip if 0 ops) -> pre-submit re-check (abort+retry once) ->
/// submit -> resolve seq -> wait_replay -> detection scan -> status.acl_conflicts + ERROR log.
/// Sets/clears status.acl_renewal_in_progress around the submit window.
pub async fn renew_stream_acl(deps: &CycleDeps, chain: &ChainView, stream_id: H256) -> Result<()>;
```

`find_conflicts` matching rule: a window op conflicts when its `(category = op_type & 0xf0, account-or-key identity)` matches something the snapshot emitted — writer-category ops match emitted writers by account; admin-category by account (excluding signer); special-key category by key; special-writer category by (key, account).

- [ ] **Step 1: STD-OPEN.** Title: `ACL snapshot emission with race guards (spec §5)`.

- [ ] **Step 2: Write failing tests** for `find_conflicts`:

```rust
#[test]
fn conflict_matching_by_category_and_identity() {
    let u2 = H160::repeat_byte(2);
    let u3 = H160::repeat_byte(3);
    let emitted = EffectiveAcl {
        admins: vec![], writers: vec![u2],
        special_keys: vec![], special_writers: vec![],
    };
    let window = vec![
        AclOpRow { op_type: AccessControlOps::REVOKE_WRITER_ROLE, key: vec![], account: u2, version: 10 }, // conflict
        AclOpRow { op_type: AccessControlOps::GRANT_WRITER_ROLE, key: vec![], account: u3, version: 11 },  // untouched pair
        AclOpRow { op_type: AccessControlOps::RENOUNCE_WRITER_ROLE, key: vec![], account: u2, version: 12 }, // conflict
    ];
    let c = find_conflicts(&window, &emitted, H160::zero());
    assert_eq!(c.len(), 2);
    assert_eq!(c[0].version, 10);
}
```

- [ ] **Step 3: Run to verify fail. Implement** `find_conflicts` (pure set lookups), then `renew_stream_acl`:

```text
1. status.acl_renewal_in_progress = true (defer-clear on every exit path).
2. Caught-up gate: loop (max 60s): head = chain.head_submissions();
   store.next_tx_seq() >= head && get_stream_replay_progress() + 1 >= head -> proceed;
   else sleep 2s. Timeout -> warn + skip ACL this cycle (values still renew).
3. { let guard = store.read().await;
     snapshot_seq = guard.get_stream_replay_progress().await?;
     acl = guard.get_effective_access_control(stream_id).await?; }   // one guard = one consistent seq
4. Build StreamDataBuilder::new(u64::MAX); n = emit_acl_ops(...); n == 0 -> return Ok.
5. Pre-submit re-check: get_latest_access_control_seq(stream_id) > snapshot_seq
   -> discard, retry from 3 (once); still dirty -> warn + skip.
6. built = builder encode + tags; data = into_upload_data(encoded, cfg.encryption keys);
   dry_run -> log + return. root = sink.submit(data, tags).
7. batch_seq = poll sink.resolve_tx_seq(root) (10s interval, 120s timeout); None -> warn, done
   (detection deferred to next cycle).
8. wait_replay(store, batch_seq, 10min, 2s); reached ->
   window = get_access_control_ops_in_range(stream_id, snapshot_seq, batch_seq);
   conflicts = find_conflicts(&window, &acl, signer);
   for c in conflicts: error!("ACL op overridden by renewal — re-issue it manually: ...");
   status.acl_conflicts extend (map to AclConflict with to_access_control_op_name(c.op_type)).
```

Wire into `run_cycle`: for streams NOT in `acl_disabled`, call `renew_stream_acl(deps, &chain, stream_id)` before `drain_stream`; the service builds one `ChainView` per cycle from `cfg.blockchain_rpc_endpoint` + `cfg.log_contract_address`.

- [ ] **Step 4: Run to verify pass**; workspace builds.

- [ ] **Step 5: Commit + PR** — `feat(renew): ACL snapshot emission with race guards (resolves #N)`. STD-CLOSE.

---

### Task 20: Node wiring — builder, main, RPC context fields

**Files:**
- Modify: `node/src/client/builder.rs` (`with_renew`), `node/src/main.rs` (`start_node`), `node/rpc/src/lib.rs` (Context), `node/rpc/Cargo.toml` (`kv_renew = { path = "../kv_renew" }`)

**Interfaces:**
- Produces:
  - `rpc::Context` gains `pub renew_status: kv_renew::SharedRenewStatus`, `pub renew_trigger: Option<tokio::sync::mpsc::UnboundedSender<()>>`, `pub renew_signer: Option<H160>` (Tasks 21/22 read these).
  - `ClientBuilder::with_renew(self, config: Option<kv_renew::RenewConfig>, live_stream_set, status: kv_renew::SharedRenewStatus, trigger_rx) -> Result<Self, String>` — no-op (info log "renewal disabled") when config is None.
  - `with_rpc` signature gains `renew_status`, `renew_trigger`, `renew_signer` params (main threads them through).

- [ ] **Step 1: STD-OPEN.** Title: `wire kv_renew into node startup and RPC context (spec §4, §8)`.

- [ ] **Step 2: Implement main.rs ordering** (status cell exists BEFORE with_rpc — spec §8):

```rust
let renew_config = config.renew_config()?;
let renew_status: kv_renew::SharedRenewStatus = Default::default();
let (renew_trigger_tx, renew_trigger_rx) = tokio::sync::mpsc::unbounded_channel();
let renew_signer = renew_config.as_ref()
    .map(|c| kv_renew::service::signer_address(&c.private_key))
    .transpose()
    .map_err(|e| format!("bad renew_private_key: {:?}", e))?;

ClientBuilder::default()
    .with_runtime_context(context)
    .with_rocksdb_store(&storage_config).await?
    .merge_streams(&stream_config).await?
    .with_rpc(rpc_config, stream_config.stream_set.clone(),
              renew_status.clone(),
              renew_config.as_ref().map(|_| renew_trigger_tx.clone()),
              renew_signer).await?
    .with_stream(&stream_config).await?
    .with_log_sync(log_sync_config).await?
    .with_renew(renew_config, stream_config.stream_set.clone(), renew_status, renew_trigger_rx).await?
    .build()
```

`with_renew` body: `Some(cfg)` → clone store/executor via the `require!` macro pattern and `kv_renew::service::spawn_renewer(executor, store, live_stream_set, cfg, status, trigger_rx)`.

- [ ] **Step 3: Build + run existing tests** — `cargo build --workspace && cargo test --workspace` (compile-level task; behavior is covered by Task 24).

- [ ] **Step 4: Commit + PR** — `feat(node): wire renewal service into startup (resolves #N)`. STD-CLOSE.

---

### Task 21: kv_getRenewStatus RPC

**Files:**
- Modify: `node/rpc/src/kv_rpc_server/api.rs`, `impl.rs`

**Interfaces:**
- Produces: `#[method(name = "getRenewStatus")] async fn get_renew_status(&self) -> RpcResult<kv_renew::RenewStatus>;` — returns a clone of the shared cell (plus `stuck_keys` already maintained by the service).

- [ ] **Step 1: STD-OPEN.** Title: `kv_getRenewStatus RPC (spec §8)`.

- [ ] **Step 2: Write failing test** (rpc crate has serde_json dev-dep):

```rust
#[tokio::test]
async fn renew_status_rpc_returns_shared_cell() {
    let ctx = test_context().await; // reuse/extend the existing admin e2e test harness setup
    ctx.renew_status.write().await.keys_renewed = 5;
    let s = KeyValueRpcServerImpl { ctx: ctx.clone() }.get_renew_status().await.unwrap();
    assert_eq!(s.keys_renewed, 5);
}
```

(If `node/rpc/tests/admin_add_stream_e2e.rs` builds a full server, follow its pattern; otherwise construct `Context` directly in a unit test in `impl.rs`.)

- [ ] **Step 3: Run to verify fail. Implement:**

```rust
async fn get_renew_status(&self) -> RpcResult<kv_renew::RenewStatus> {
    Ok(self.ctx.renew_status.read().await.clone())
}
```

- [ ] **Step 4: Run to verify pass.** **Commit + PR** — `feat(rpc): kv_getRenewStatus (resolves #N)`. STD-CLOSE.

---

### Task 22: admin_renewNow RPC with EIP-712 auth

**Files:**
- Modify: `node/rpc/src/admin_rpc_server/eip712.rs`, `api.rs`, `impl.rs`, `mod.rs`

**Interfaces:**
- Produces:
  - `eip712::RENEW_NOW_PURPOSE = "renew-now"`; `renew_now_digest(wallet: Address, issued_at: u64, chain_id: u64) -> [u8; 32]` over struct `RenewNow(string purpose,address wallet,uint256 issuedAt)` (same 3-field domain as RegisterStream); `recover_renew_now_signer(wallet, issued_at, chain_id, signature)`.
  - `#[method(name = "renewNow")] async fn renew_now(&self, wallet: H160, issued_at: u64, signature: String) -> RpcResult<bool>` — checks: `|now - issued_at| <= 300`; recovered signer == wallet; wallet == `ctx.renew_signer` (renewal admin); then sends `()` on `renew_trigger`. Returns false when a cycle is already running (send still succeeds; the service ignores re-entry) — return Ok(true) on successful trigger send, error otherwise.

- [ ] **Step 1: STD-OPEN.** Title: `admin_renewNow with EIP-712 auth (spec §8)`.

- [ ] **Step 2: Write failing tests** (mirror the existing eip712 tests with `LocalWallet`):

```rust
#[tokio::test]
async fn renew_now_signature_roundtrip() {
    let wallet = test_wallet(); // existing helper
    let issued_at = 1_755_000_000u64;
    let digest = renew_now_digest(wallet.address(), issued_at, 31337);
    let sig = wallet.sign_hash(H256::from(digest)).unwrap();
    let rec = recover_renew_now_signer(wallet.address(), issued_at, 31337, &sig).unwrap();
    assert_eq!(rec, wallet.address());
    // different issuedAt -> different digest
    assert_ne!(digest, renew_now_digest(wallet.address(), issued_at + 1, 31337));
}
```

- [ ] **Step 3: Run to verify fail. Implement** eip712 additions (copy the RegisterStream trio, swapping the typehash string and `Token::Uint(U256::from(issued_at))` for the streamId token), then the server method following `add_stream`'s recover-and-compare structure. Freshness uses the service's `unix_now()` equivalent locally. Wallet mismatch or missing `renew_trigger`/`renew_signer` → `error::invalid_params` / "renewal disabled" error.

- [ ] **Step 4: Run to verify pass** (`cargo test -p rpc`). **Commit + PR** — `feat(rpc): admin_renewNow with EIP-712 auth (resolves #N)`. STD-CLOSE.

---

### Task 23: Documentation — README + config_example + IMPORTANT notice

**Files:**
- Modify: `README.md` (new "Data Lifetime Renewal" section after Configuration)
- Modify: `run/config_example.toml` (new section)

- [ ] **Step 1: STD-OPEN.** Title: `document the renewal service and the role-change notice`.

- [ ] **Step 2: config_example.toml section** (verbatim):

```toml
#######################################################################
###                 Data Lifetime Renewal Options                   ###
#######################################################################

# The KV node can renew the storage lifetime of aging values by re-uploading
# them. Renewal runs when renew_private_key is set (and renew_enabled is not
# turned off). The key MUST be the stream admin's key and pays real fees.
# Prefer the ZGS_KV_RENEW_PRIVATE_KEY environment variable over this file.
#
# IMPORTANT: do not perform role-change operations (grants, revokes,
# renounces, special-key flips) while a renewal cycle is running — they may
# be silently overridden by the renewal snapshot. Check
# kv_getRenewStatus.aclRenewalInProgress first. If a change lands during the
# window anyway, the node logs an ERROR and reports it in kv_getRenewStatus;
# re-issue the change manually.

# renew_enabled = true
# renew_private_key = ""
# renew_max_age_secs = 15552000        # 180 days
# renew_cycle_interval_secs = 604800   # 7 days
# renew_batch_max_bytes = 8388608
# renew_batch_max_keys = 1000
# renew_pause_between_batches_ms = 2000
# renew_startup_delay_secs = 300
# renew_expected_replica = 1
# renew_stream_ids = []                # empty = every monitored stream
# renew_dry_run = false                # scan and log, submit nothing
# renew_max_attempts = 3
```

- [ ] **Step 3: README section** — condensed: what renewal does (re-upload stale values + effective ACL state weekly), deployment model (admin runs the node, single admin recommended, admin key = renew key, grant write access to users via SDK as usual), the IMPORTANT notice (same text as above), `kv_getRenewStatus` / `admin_renewNow`, dry-run guidance for first run on old streams, and "run the renewer on one node per stream — two nodes both pay".

- [ ] **Step 4: Commit + PR** — `docs: renewal service configuration and role-change notice (resolves #N)`. STD-CLOSE.

---

### Task 24: Integration test — tests/kv_renew_test.py

**Files:**
- Create: `tests/kv_renew_test.py` (register in `tests/test_all.py` if the runner uses an explicit list)

**Interfaces:**
- Consumes: `KVTestFramework`, `setup_kv_node(index, stream_ids, updated_config)`, helpers from `utility/kv.py` (`create_kv_data`, `to_stream_id`), `utility/submission.py`, `config/node_config.py` (`GENESIS_ACCOUNT`), and the node RPCs `kv_getValue` (returns `version`), `kv_getRenewStatus`.

- [ ] **Step 1: STD-OPEN.** Title: `integration test: lifetime renewal end to end`.

- [ ] **Step 2: Write the test** (modeled on `kv_put_get_test.py`):

```python
#!/usr/bin/env python3
import time
from kv_test_framework.test_framework import KVTestFramework
from utility.kv import to_stream_id, create_kv_data, rand_write
from utility.submission import submit_data
from kv_utility.submission import create_submission
from utility.utils import assert_equal, wait_until
from config.node_config import GENESIS_ACCOUNT, TX_PARAMS


class KVRenewTest(KVTestFramework):
    def setup_params(self):
        self.num_blockchain_nodes = 1
        self.num_nodes = 1

    def run_test(self):
        stream_id = to_stream_id(0)
        self.setup_kv_node(0, [stream_id], updated_config={
            "zgs_node_urls": ",".join([node.rpc_url for node in self.nodes]),
            "renew_private_key": GENESIS_ACCOUNT.key[2:] if GENESIS_ACCOUNT.key.startswith("0x") else GENESIS_ACCOUNT.key,
            "renew_max_age_secs": 1,          # everything is stale immediately
            "renew_cycle_interval_secs": 5,   # fast cycles instead of admin_renewNow signing
            "renew_startup_delay_secs": 1,
            "renew_pause_between_batches_ms": 100,
        })
        kv = self.kv_nodes[0]

        # 1. write one key through the normal path (genesis account = first
        #    writer = auto admin), wait for replay
        writes = [rand_write(stream_id, b"renew-me")]
        chunk_data, tags = create_kv_data(1, [], writes, [])
        submissions, root = create_submission(chunk_data, tags)
        self.contract.submit(submissions, tx_prarams=TX_PARAMS)
        wait_until(lambda: self.contract.num_submissions() == 1)
        submit_data(self.nodes[0], chunk_data)
        wait_until(lambda: kv.kv_get_trasanction_result(0) == "Commit")

        v0 = kv.kv_get_value(stream_id, b"renew-me")["version"]

        # 2. the renewer must re-upload it: version advances past the original
        wait_until(lambda: kv.kv_get_value(stream_id, b"renew-me")["version"] > v0,
                   timeout=180)

        # 3. status reflects the work
        status = kv.rpc.kv_getRenewStatus()
        assert status["keysRenewed"] >= 1, status
        assert_equal(status["keysSkippedPermission"], 0)

        # 4. renewal is idempotent-ish: a later cycle with everything fresh
        #    (max_age 1s means it will renew again — just assert no stuck keys)
        assert_equal(len(status["stuckKeys"]), 0)


if __name__ == "__main__":
    KVRenewTest().main()
```

Adapt helper names to the framework's actual surface (`kv_get_value`, `kv_get_trasanction_result`, `contract.submit` — copy exact call shapes from `kv_put_get_test.py` while writing; the framework passes unknown `updated_config` keys straight into the node's TOML).

- [ ] **Step 3: Run** — `cd tests && python kv_renew_test.py` (requires the framework's local chain + storage node binaries; see `tests/Makefile`). Iterate until green.

- [ ] **Step 4: Two follow-up scenarios from the spec's test list** go into the SAME file as extra test methods once the happy path is green (keep the PR focused; if they push it past ~150 lines, split them into a `test:` follow-up PR + issue):
  - *Permission skip:* second stream whose first write comes from a non-genesis account (so that account is admin, not the renew signer); assert its key's version does NOT advance and `keysSkippedPermission >= 1`.
  - *Encrypted stream:* node configured with `encryption_key`; write via `encrypt_kv_data` (see `utility/kv.py`); after renewal, `kv_getValue` still returns the plaintext (proving the renewal file was re-encrypted).
  - The spec's fresh-node ACL replay scenario (new KV node syncing only renewal files reconstructs permissions) needs expiring the original files, which the local framework cannot simulate — record it as a deferred issue titled `e2e: renewal survives original-file expiry` and reference the spec.

- [ ] **Step 5: Commit + PR** — `test: end-to-end lifetime renewal (resolves #N)`. STD-CLOSE.

---

## Self-Review Notes (already applied)

- Task 10's RPC-dedup is explicitly optional to keep the PR ~100 lines; `read_pair_value` is the deliverable.
- Task 15 owns the SDK rev bump so no earlier task needs the new methods.
- `verify_renewed` uses `get_latest_version_before(_, _, u64::MAX) > pre_seq` — no schema addition needed for verification.
- Dry-run must not loop forever (drain would rescan the same stale keys): one pass per stream, stated in Task 17.
- Spec §5's "batch_seq resolve fails" path: detection deferred to next cycle (Task 19 step list line 7).
- Type conversions between `ethereum_types` and ethers re-exports are called out where they bite (Tasks 15, 18).
