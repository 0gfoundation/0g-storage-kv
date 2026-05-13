# Admin RPC: addStream Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an `admin_addStream` JSON-RPC method to the 0g-storage-kv node that lets a privileged caller (the application backend) register a new stream id at runtime. The KV node persists the registration so it survives restarts and uses it as the source of truth for which streams to monitor.

**Architecture:**
- The monitored stream set becomes runtime-mutable via interior mutability: `StreamConfig.stream_set` changes from `HashSet<H256>` to `Arc<RwLock<HashSet<H256>>>`. Both the running `StreamDataFetcher` / `StreamReplayer` and the new admin RPC handler read from the same shared cell.
- Persistence reuses the existing `t_misc.stream_ids` SSZ blob — no schema migration. `StreamManager::initialize` is updated to merge config-defined ids with DB-persisted ids on startup (preserving streams added at runtime in earlier sessions).
- A new RPC namespace `admin` is introduced as a sibling module under `node/rpc/src/admin_rpc_server/`, mounted on the same HTTP listener as `kv_*`. No auth at the node — operators firewall the endpoint.
- The admin RPC is idempotent: re-registering an existing stream returns success without mutation.

**Tech Stack:** Rust, jsonrpsee, tokio, ssz, rusqlite (existing). No new dependencies.

**Out of scope for v1:** signature verification (lives in the backend, not the node), removing a registered stream, replaying historical state for runtime-added streams (assumes streams are added at-or-after creation).

---

## File Structure

**Create:**
- `node/rpc/src/admin_rpc_server/mod.rs` — re-exports
- `node/rpc/src/admin_rpc_server/api.rs` — `AdminRpc` trait
- `node/rpc/src/admin_rpc_server/impl.rs` — `AdminRpcServerImpl`

**Modify:**
- `node/stream/src/config.rs` — change `stream_set` type
- `node/src/config/convert.rs` — wrap initial set in `Arc<RwLock<...>>`
- `node/stream/src/stream_manager/mod.rs` — async lock reads + merge logic in `initialize`
- `node/stream/src/stream_manager/stream_replayer.rs` — async lock read at line 227 + 10 test fixtures
- `node/rpc/src/lib.rs` — add `live_stream_set` to `Context`, mount admin RPC
- `node/rpc/src/kv_rpc_server/api.rs` (and possibly `mod.rs`) — re-export needed types
- `node/src/client/builder.rs` — pass live set into `Context`, reorder so `with_stream` runs before `with_rpc`
- `node/src/main.rs` — reorder `with_stream` before `with_rpc`

---

## Task 1: Make `StreamConfig.stream_set` runtime-mutable

**Files:**
- Modify: `node/stream/src/config.rs`
- Modify: `node/src/config/convert.rs`
- Modify: `node/stream/src/stream_manager/mod.rs:100`
- Modify: `node/stream/src/stream_manager/stream_replayer.rs:227` and all `stream_set: HashSet::from(...)` test fixtures

This task is a pure type refactor — no behavior change. After it lands, `cargo test -p stream` should pass unchanged.

- [ ] **Step 1: Change the field type in StreamConfig**

In `node/stream/src/config.rs`, replace the file contents:

```rust
use std::collections::HashSet;
use std::sync::Arc;

use ethereum_types::H256;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct Config {
    pub stream_ids: Vec<H256>,
    pub stream_set: Arc<RwLock<HashSet<H256>>>,
    pub encryption_key: Option<[u8; 32]>,
    pub wallet_private_key: Option<[u8; 32]>,
    pub max_download_retries: usize,
    pub download_timeout_ms: u64,
    pub download_retry_interval_ms: u64,
    pub retry_wait_ms: u64,
}
```

`Clone` still derives — cloning the `Arc` shares the same inner cell, which is what we want.

- [ ] **Step 2: Update the convert site to wrap the initial set**

In `node/src/config/convert.rs`, modify the `stream_config` method. Add `use std::sync::Arc;` and `use tokio::sync::RwLock;` at the top of the file if not present, then change line 39 and line 61:

```rust
        let stream_set = Arc::new(RwLock::new(HashSet::from_iter(
            stream_ids.iter().cloned(),
        )));
```

(no other changes — `stream_set` is still passed by value into the `StreamConfig` constructor at line 61, the `Arc` is what's moved.)

- [ ] **Step 3: Update the two non-test reader sites to take a read lock**

In `node/stream/src/stream_manager/mod.rs`, change `skippable` (around line 100):

```rust
        for id in tx.stream_ids.iter() {
            if !config.stream_set.read().await.contains(id) {
                return Ok((false, false));
            }
            if !can_write && store.read().await.can_write(tx.sender, *id, tx.seq).await? {
                can_write = true;
            }
        }
```

In `node/stream/src/stream_manager/stream_replayer.rs:227`, change:

```rust
            if !self.config.stream_set.read().await.contains(&stream_read.stream_id) {
                return Ok(Some(ReplayResult::TagsMismatch));
            }
```

- [ ] **Step 4: Update test fixtures in stream_replayer.rs**

There are exactly 10 test fixtures that construct `StreamConfig { ... stream_set: HashSet::from([stream_id]), ... }`. They are at lines 1033, 1079, 1125, 1169, 1211, 1263, 1313, 1383, 1456, 1518 (line numbers approximate; grep to find them).

For each occurrence, replace:

```rust
            stream_set: HashSet::from([stream_id]),
```

with:

```rust
            stream_set: Arc::new(RwLock::new(HashSet::from([stream_id]))),
```

Add the necessary imports near the top of the test module if not present:

```rust
use std::sync::Arc;
use tokio::sync::RwLock;
```

(These imports likely already exist in the `super`-scope; verify before adding.)

Use `replace_all` via the Edit tool to do all 10 sites in one call:

```bash
# verify count first
grep -c "stream_set: HashSet::from" node/stream/src/stream_manager/stream_replayer.rs
# expect: 10
```

- [ ] **Step 5: Build and run stream tests**

Run: `cargo test -p stream`
Expected: all existing tests pass. No new tests in this task.

- [ ] **Step 6: Commit**

```bash
git add node/stream/src/config.rs node/src/config/convert.rs node/stream/src/stream_manager/
git commit -m "refactor: make StreamConfig.stream_set interior-mutable for runtime updates"
```

---

## Task 2: Merge persisted stream ids on startup

**Files:**
- Modify: `node/stream/src/stream_manager/mod.rs` (`StreamManager::initialize`)

Today, `initialize` treats config as canonical: if config introduces a new id, `reset_stream_sync` replaces the DB-persisted set with config's set. That throws away any stream registered at runtime in a previous session. After this task, the DB-persisted set is preserved and unioned with config; `reset_stream_sync` is only triggered when *config* introduces something new (the historical-replay reason for reset still applies in that case), and the value passed is the merged union.

Also: at the end of initialize, the live `stream_set` cell is replaced with the merged set (so the running fetcher/replayer see runtime-added streams from prior sessions).

- [ ] **Step 1: Write the test for the merge behavior**

Add at the bottom of `node/stream/src/stream_manager/mod.rs` (a new `#[cfg(test)] mod tests` module). The test uses an in-memory store directly (no fetcher/replayer spawn — we just verify the side effects of `initialize`-equivalent merge logic).

Because `StreamManager::initialize` also constructs fetcher/replayer (which need network), we extract the merge into a private helper `merge_persisted_streams(config, store)` and test that helper. The helper returns nothing — it mutates `config.stream_set` and the store.

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use ethereum_types::H256;
    use ssz::Encode;
    use std::collections::HashSet;
    use std::sync::Arc;
    use storage_with_stream::StoreManager;
    use tokio::sync::RwLock;

    fn h(b: u8) -> H256 {
        H256::from([b; 32])
    }

    async fn make_store() -> Arc<RwLock<dyn storage_with_stream::Store>> {
        Arc::new(RwLock::new(StoreManager::memorydb().await.unwrap()))
    }

    fn make_config(ids: Vec<H256>) -> StreamConfig {
        StreamConfig {
            stream_ids: ids.clone(),
            stream_set: Arc::new(RwLock::new(HashSet::from_iter(ids.iter().cloned()))),
            encryption_key: None,
            wallet_private_key: None,
            max_download_retries: 0,
            download_timeout_ms: 1000,
            download_retry_interval_ms: 100,
            retry_wait_ms: 100,
        }
    }

    #[tokio::test]
    async fn merge_preserves_runtime_added_streams() {
        let store = make_store().await;
        // simulate a previous run that persisted [a, b] (b is runtime-added)
        let persisted = vec![h(0xa), h(0xb)];
        store
            .write()
            .await
            .update_stream_ids(persisted.as_ssz_bytes())
            .await
            .unwrap();

        // config only mentions [a]; b should NOT be lost
        let config = make_config(vec![h(0xa)]);
        merge_persisted_streams(&config, store.clone()).await.unwrap();

        let live: HashSet<H256> = config.stream_set.read().await.clone();
        assert!(live.contains(&h(0xa)));
        assert!(live.contains(&h(0xb)));
        let db: HashSet<H256> = store
            .read()
            .await
            .get_holding_stream_ids()
            .await
            .unwrap()
            .into_iter()
            .collect();
        assert_eq!(db, HashSet::from([h(0xa), h(0xb)]));
    }

    #[tokio::test]
    async fn merge_resets_when_config_adds_new() {
        let store = make_store().await;
        // pretend sync has progressed
        store
            .write()
            .await
            .update_stream_data_sync_progress(0, 100)
            .await
            .unwrap();
        let persisted = vec![h(0xa)];
        store
            .write()
            .await
            .update_stream_ids(persisted.as_ssz_bytes())
            .await
            .unwrap();

        // config introduces b — reset is required
        let config = make_config(vec![h(0xa), h(0xb)]);
        merge_persisted_streams(&config, store.clone()).await.unwrap();

        let progress = store.read().await.get_stream_data_sync_progress().await.unwrap();
        assert_eq!(progress, 0, "reset should zero data_sync_progress");
        let live: HashSet<H256> = config.stream_set.read().await.clone();
        assert_eq!(live, HashSet::from([h(0xa), h(0xb)]));
    }

    #[tokio::test]
    async fn merge_no_reset_when_config_unchanged() {
        let store = make_store().await;
        store
            .write()
            .await
            .update_stream_data_sync_progress(0, 100)
            .await
            .unwrap();
        let persisted = vec![h(0xa)];
        store
            .write()
            .await
            .update_stream_ids(persisted.as_ssz_bytes())
            .await
            .unwrap();

        let config = make_config(vec![h(0xa)]);
        merge_persisted_streams(&config, store.clone()).await.unwrap();

        let progress = store.read().await.get_stream_data_sync_progress().await.unwrap();
        assert_eq!(progress, 100, "no reset when config introduces nothing new");
    }
}
```

- [ ] **Step 2: Run the tests to verify failure**

Run: `cargo test -p stream merge_`
Expected: FAIL — `merge_persisted_streams` is undefined.

- [ ] **Step 3: Extract and implement the merge helper**

Replace the body of `StreamManager::initialize` in `node/stream/src/stream_manager/mod.rs` so it delegates to the helper:

```rust
pub(crate) async fn merge_persisted_streams(
    config: &StreamConfig,
    store: Arc<RwLock<dyn Store>>,
) -> Result<()> {
    use storage_with_stream::store::DataStoreRead as _; // silence rust-analyzer; harmless if unused

    let persisted_ids = store.read().await.get_holding_stream_ids().await?;
    let persisted_set: HashSet<H256> = persisted_ids.iter().cloned().collect();
    let config_set: HashSet<H256> = config.stream_ids.iter().cloned().collect();

    // merged = config ∪ persisted (preserves runtime-added streams)
    let mut merged_set = persisted_set.clone();
    merged_set.extend(config_set.iter().cloned());
    let merged_ids: Vec<H256> = merged_set.iter().cloned().collect();

    let config_introduces_new = !config_set.is_subset(&persisted_set);

    if config_introduces_new {
        store
            .write()
            .await
            .reset_stream_sync(merged_ids.as_ssz_bytes())
            .await?;
    } else if merged_set != persisted_set {
        // can only happen if persisted_set was empty before — write the merged
        store
            .write()
            .await
            .update_stream_ids(merged_ids.as_ssz_bytes())
            .await?;
    }

    *config.stream_set.write().await = merged_set;
    Ok(())
}
```

Note: the `use ... as _;` is harmless and not needed for rustc — remove it if you prefer; the supertrait method resolves through `Store`.

Then modify `StreamManager::initialize` to call it:

```rust
    pub async fn initialize(
        config: &StreamConfig,
        store: Arc<RwLock<dyn Store>>,
        indexer_url: Option<String>,
        zgs_nodes: Vec<String>,
        zgs_rpc_timeout: u64,
        task_executor: TaskExecutor,
    ) -> Result<(StreamDataFetcher, StreamReplayer)> {
        merge_persisted_streams(config, store.clone()).await?;

        let fetcher = StreamDataFetcher::new(
            config.clone(),
            store.clone(),
            indexer_url,
            zgs_nodes,
            zgs_rpc_timeout,
            task_executor,
        )
        .await?;
        let replayer = StreamReplayer::new(config.clone(), store.clone()).await?;
        Ok((fetcher, replayer))
    }
```

The old subset/reset block (mod.rs lines 28-53) is removed — `merge_persisted_streams` replaces it.

- [ ] **Step 4: Run the tests**

Run: `cargo test -p stream merge_`
Expected: all three tests PASS.

Also re-run the full test suite to make sure nothing regressed:

Run: `cargo test -p stream`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add node/stream/src/stream_manager/mod.rs
git commit -m "feat(stream): merge persisted stream ids with config on startup"
```

---

## Task 3: Add the admin RPC namespace with `addStream`

**Files:**
- Create: `node/rpc/src/admin_rpc_server/mod.rs`
- Create: `node/rpc/src/admin_rpc_server/api.rs`
- Create: `node/rpc/src/admin_rpc_server/impl.rs`

This task adds the trait, impl, and a unit test. Wiring into the running server is Task 4.

- [ ] **Step 1: Define the trait**

Create `node/rpc/src/admin_rpc_server/api.rs`:

```rust
use ethereum_types::H256;
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;

#[rpc(server, client, namespace = "admin")]
pub trait AdminRpc {
    /// Register a stream id for monitoring. Idempotent: returns Ok(true) if the
    /// stream was already registered, Ok(true) after a successful add. Persisted
    /// across node restarts.
    #[method(name = "addStream")]
    async fn add_stream(&self, stream_id: H256) -> RpcResult<bool>;
}
```

- [ ] **Step 2: Write the impl with one unit test**

Create `node/rpc/src/admin_rpc_server/impl.rs`:

```rust
use std::collections::HashSet;
use std::sync::Arc;

use ethereum_types::H256;
use jsonrpsee::core::{async_trait, RpcResult};
use ssz::Encode;
use tokio::sync::RwLock;

use storage_with_stream::Store;

use super::api::AdminRpcServer;
use crate::error;

pub struct AdminRpcServerImpl {
    pub store: Arc<RwLock<dyn Store>>,
    pub live_stream_set: Arc<RwLock<HashSet<H256>>>,
}

#[async_trait]
impl AdminRpcServer for AdminRpcServerImpl {
    async fn add_stream(&self, stream_id: H256) -> RpcResult<bool> {
        // Fast path: already registered.
        if self.live_stream_set.read().await.contains(&stream_id) {
            return Ok(true);
        }

        // Compute merged set under write lock to serialize concurrent adds.
        let mut live = self.live_stream_set.write().await;
        if live.contains(&stream_id) {
            return Ok(true);
        }
        live.insert(stream_id);
        let merged: Vec<H256> = live.iter().cloned().collect();
        drop(live);

        self.store
            .write()
            .await
            .update_stream_ids(merged.as_ssz_bytes())
            .await
            .map_err(|e| error::internal_error(format!("persist stream id: {:?}", e)))?;

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use storage_with_stream::StoreManager;

    fn h(b: u8) -> H256 {
        H256::from([b; 32])
    }

    async fn fixture() -> AdminRpcServerImpl {
        let store: Arc<RwLock<dyn Store>> =
            Arc::new(RwLock::new(StoreManager::memorydb().await.unwrap()));
        AdminRpcServerImpl {
            store,
            live_stream_set: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    #[tokio::test]
    async fn add_stream_persists_and_updates_live() {
        let svc = fixture().await;
        assert!(svc.add_stream(h(0x1)).await.unwrap());

        // live set updated
        assert!(svc.live_stream_set.read().await.contains(&h(0x1)));

        // DB persisted
        let db_ids = svc
            .store
            .read()
            .await
            .get_holding_stream_ids()
            .await
            .unwrap();
        assert_eq!(db_ids, vec![h(0x1)]);
    }

    #[tokio::test]
    async fn add_stream_is_idempotent() {
        let svc = fixture().await;
        assert!(svc.add_stream(h(0x2)).await.unwrap());
        assert!(svc.add_stream(h(0x2)).await.unwrap());

        let db_ids = svc
            .store
            .read()
            .await
            .get_holding_stream_ids()
            .await
            .unwrap();
        assert_eq!(db_ids, vec![h(0x2)]);
        assert_eq!(svc.live_stream_set.read().await.len(), 1);
    }

    #[tokio::test]
    async fn add_stream_appends_without_dropping_existing() {
        let svc = fixture().await;
        // pre-populate as if a previous run had registered h(0x1)
        svc.live_stream_set.write().await.insert(h(0x1));
        svc.store
            .write()
            .await
            .update_stream_ids(vec![h(0x1)].as_ssz_bytes())
            .await
            .unwrap();

        assert!(svc.add_stream(h(0x2)).await.unwrap());

        let db_ids: HashSet<H256> = svc
            .store
            .read()
            .await
            .get_holding_stream_ids()
            .await
            .unwrap()
            .into_iter()
            .collect();
        assert_eq!(db_ids, HashSet::from([h(0x1), h(0x2)]));
    }
}
```

- [ ] **Step 3: Wire the module**

Create `node/rpc/src/admin_rpc_server/mod.rs`:

```rust
mod api;
mod r#impl;

pub use api::AdminRpcClient;
pub use api::AdminRpcServer;
pub use r#impl::AdminRpcServerImpl;
```

Add the module to `node/rpc/src/lib.rs` after the existing `mod kv_rpc_server;` line:

```rust
mod admin_rpc_server;
```

- [ ] **Step 4: Verify error::internal_error exists**

Check `node/rpc/src/error.rs`:

Run: `grep -n "pub fn internal_error\|pub fn parse_error" node/rpc/src/error.rs`

If `internal_error` does not exist, model it on whatever convention the kv_rpc_server uses for converting `anyhow::Error` to `jsonrpsee` errors — open `node/rpc/src/kv_rpc_server/impl.rs` and grep for the error helper used there. Use that exact helper instead of `error::internal_error` in the impl above.

- [ ] **Step 5: Run the unit tests**

Run: `cargo test -p rpc admin_rpc`
Expected: three tests PASS.

- [ ] **Step 6: Commit**

```bash
git add node/rpc/src/admin_rpc_server/ node/rpc/src/lib.rs
git commit -m "feat(rpc): add admin_addStream method with persistence"
```

---

## Task 4: Wire the admin RPC into the running server

**Files:**
- Modify: `node/rpc/src/lib.rs` — extend `Context`, mount admin module
- Modify: `node/src/client/builder.rs` — pass `live_stream_set` into `Context`
- Modify: `node/src/main.rs` — reorder `with_stream` before `with_rpc`

This task is wiring only. After it lands, an end-to-end RPC call `admin_addStream` works against a running node.

- [ ] **Step 1: Extend rpc::Context**

In `node/rpc/src/lib.rs`, add to `Context`:

```rust
use std::collections::HashSet;
use ethereum_types::H256;
// (add these imports if not already present)

#[derive(Clone)]
pub struct Context {
    pub config: RPCConfig,
    pub shutdown_sender: Sender<ShutdownReason>,
    pub store: Arc<RwLock<dyn Store>>,
    pub live_stream_set: Arc<RwLock<HashSet<H256>>>,
}
```

- [ ] **Step 2: Mount the admin RPC in run_server**

In `node/rpc/src/lib.rs`, replace `run_server`:

```rust
use admin_rpc_server::AdminRpcServer;

pub async fn run_server(ctx: Context) -> Result<HttpServerHandle, Box<dyn Error>> {
    let server = HttpServerBuilder::default()
        .max_response_body_size(ctx.config.max_response_body_in_bytes)
        .build(ctx.config.listen_address)
        .await?;

    let mut module = (kv_rpc_server::KeyValueRpcServerImpl { ctx: ctx.clone() }).into_rpc();
    module.merge(
        (admin_rpc_server::AdminRpcServerImpl {
            store: ctx.store.clone(),
            live_stream_set: ctx.live_stream_set.clone(),
        })
        .into_rpc(),
    )?;

    let addr = server.local_addr()?;
    let handle = server.start(module)?;
    info!("Server started http://{}", addr);

    Ok(handle)
}
```

- [ ] **Step 3: Reorder builder calls so stream is initialized first**

In `node/src/main.rs`, swap the order of `with_stream` and `with_rpc`:

```rust
    ClientBuilder::default()
        .with_runtime_context(context)
        .with_rocksdb_store(&storage_config)
        .await?
        .with_stream(&stream_config)
        .await?
        .with_rpc(rpc_config, stream_config.stream_set.clone())
        .await?
        .with_log_sync(log_sync_config)
        .await?
        .build()
```

- [ ] **Step 4: Update with_rpc to accept the live set**

In `node/src/client/builder.rs`, change `with_rpc` signature and body:

```rust
    pub async fn with_rpc(
        mut self,
        rpc_config: RPCConfig,
        live_stream_set: Arc<RwLock<HashSet<H256>>>,
    ) -> Result<Self, String> {
        self.indexer_url.clone_from(&rpc_config.indexer_url);
        self.zgs_nodes = Some(rpc_config.zgs_nodes.clone());
        self.zgs_rpc_timeout = Some(rpc_config.zgs_rpc_timeout);

        if !rpc_config.enabled {
            return Ok(self);
        }

        let executor = require!("rpc", self, runtime_context).clone().executor;
        let store = require!("stream", self, store).clone();

        let ctx = rpc::Context {
            config: rpc_config,
            shutdown_sender: executor.shutdown_sender(),
            store,
            live_stream_set,
        };

        let rpc_handle = rpc::run_server(ctx)
            .await
            .map_err(|e| format!("Unable to start HTTP RPC server: {:?}", e))?;

        executor.spawn(rpc_handle, "rpc");

        Ok(self)
    }
```

Add the necessary imports at the top of `builder.rs`:

```rust
use std::collections::HashSet;
use ethereum_types::H256;
```

- [ ] **Step 5: Cargo check**

Run: `cargo check -p zgs_kv` (or whichever crate is `node/src` — confirm via `head node/Cargo.toml node/src/Cargo.toml`)

Expected: clean build, no warnings beyond pre-existing.

- [ ] **Step 6: Run the full workspace tests**

Run: `cargo test --workspace`
Expected: all PASS. Watch in particular for stream and rpc crate tests.

- [ ] **Step 7: Commit**

```bash
git add node/rpc/src/lib.rs node/src/client/builder.rs node/src/main.rs
git commit -m "feat: mount admin RPC and plumb live stream set through builder"
```

---

## Task 5: End-to-end smoke test

**Files:**
- Create: `node/rpc/tests/admin_add_stream_e2e.rs` (or inline in lib.rs `#[cfg(test)]`)

A smoke test that boots the HTTP RPC server with an in-memory store, calls `admin_addStream` over JSON-RPC via the generated client, then verifies via `kv_getHoldingStreamIds` that the registration is visible.

- [ ] **Step 1: Write the test**

Create `node/rpc/tests/admin_add_stream_e2e.rs`:

```rust
use std::collections::HashSet;
use std::sync::Arc;

use ethereum_types::H256;
use jsonrpsee::http_client::HttpClientBuilder;
use tokio::sync::RwLock;

use rpc::{run_server, Context, KeyValueRpcClient, RPCConfig};
use storage_with_stream::{Store, StoreManager};
use task_executor::TaskExecutor;

// AdminRpcClient is generated by the proc-macro; pull it in via the
// re-export added in mod.rs:
use rpc::admin_rpc_server::AdminRpcClient;

fn h(b: u8) -> H256 {
    H256::from([b; 32])
}

#[tokio::test(flavor = "multi_thread")]
async fn add_stream_then_visible_via_get_holding_stream_ids() {
    let store: Arc<RwLock<dyn Store>> =
        Arc::new(RwLock::new(StoreManager::memorydb().await.unwrap()));
    let live_stream_set = Arc::new(RwLock::new(HashSet::new()));

    let (shutdown_tx, _shutdown_rx) = futures::channel::mpsc::channel(1);

    let listen_address = "127.0.0.1:0".parse().unwrap();
    let rpc_config = RPCConfig {
        enabled: true,
        listen_address,
        chunks_per_segment: 1024,
        indexer_url: None,
        zgs_nodes: vec![],
        max_query_len_in_bytes: 1024 * 1024,
        max_response_body_in_bytes: 10 * 1024 * 1024,
        zgs_rpc_timeout: 30,
    };

    // bind to ephemeral port; capture local addr from handle
    let ctx = Context {
        config: rpc_config,
        shutdown_sender: shutdown_tx,
        store: store.clone(),
        live_stream_set: live_stream_set.clone(),
    };
    let handle = run_server(ctx).await.unwrap();
    let url = format!("http://{}", handle.local_addr().unwrap());

    let client = HttpClientBuilder::default().build(&url).unwrap();
    AdminRpcClient::add_stream(&client, h(0xab)).await.unwrap();

    let ids = KeyValueRpcClient::get_holding_stream_ids(&client)
        .await
        .unwrap();
    assert_eq!(ids, vec![h(0xab)]);

    handle.stop().unwrap();
}
```

Note: `run_server` currently returns `HttpServerHandle` which exposes `local_addr()` and `stop()`. If `RPCConfig` needs different fields than shown above, adjust to match the canonical struct in `node/rpc/src/config.rs`.

The `rpc::admin_rpc_server::AdminRpcClient` re-export needs to be added to `node/rpc/src/lib.rs`:

```rust
pub use admin_rpc_server::AdminRpcClient;
```

(Alongside the existing `pub use kv_rpc_server::KeyValueRpcClient;`.)

If the test uses `local_addr()` on `HttpServerHandle` and that method does not exist, replace the `0`-port binding with a fixed test port (e.g., 27001) and use that directly in `url`. Verify by checking jsonrpsee 0.16 docs (the version used in this repo — check `Cargo.toml`).

- [ ] **Step 2: Run the test**

Run: `cargo test -p rpc --test admin_add_stream_e2e`
Expected: PASS.

If it fails because `RPCConfig` has a different shape than assumed, open `node/rpc/src/config.rs`, adjust the test fixture, and re-run.

- [ ] **Step 3: Commit**

```bash
git add node/rpc/tests/admin_add_stream_e2e.rs node/rpc/src/lib.rs
git commit -m "test: end-to-end admin_addStream over JSON-RPC"
```

---

## Self-review

**Spec coverage:**
- Idempotent admin RPC: Task 3 (impl + tests) and Task 5 (e2e).
- Persistence across restarts: Task 2 (merge logic) + Task 3 (DB write on add).
- Source-of-truth on KV side, no backend table: nothing to implement, by omission.
- Backend signature verification: out of scope, intentionally not in this plan.

**Type consistency:**
- `Arc<RwLock<HashSet<H256>>>` is the only shared-set type used everywhere.
- Method names match between trait and impl (`add_stream`, `addStream` JSON name).
- `Context.live_stream_set` and `AdminRpcServerImpl.live_stream_set` field names match.

**Placeholders:** none.

---

## Open questions to flag during execution

- **Does `error::internal_error` exist?** Task 3 step 4 instructs the executor to verify and adjust. If the rpc crate uses a different error helper (e.g., `JsonRpseeError::Custom(...)`), prefer that.
- **Does `RPCConfig` have a `chunks_per_segment` field?** The Task 5 fixture assumes the existing fields per `node/rpc/src/config.rs`. Read that file before writing the test fixture and adjust field names if needed.
- **Does `HttpServerHandle::local_addr()` exist in this jsonrpsee version?** If not, fall back to a fixed port. Check `Cargo.toml` for the version.
