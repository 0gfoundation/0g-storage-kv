# `admin_addStream` EIP-712 Wallet-Signature Auth Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the KV node's `admin_addStream` RPC require an EIP-712 wallet signature so the KV node itself enforces "only legitimate signers can register stream ids," removing the need for an unauthenticated firewall as the only protection.

**Architecture:**
- The frontend (`0g-storage-scan-frontend-new`) already signs a `RegisterStream` typed-data payload via `eth_signTypedData_v4`. The Next.js `/api/kv/register` route currently verifies that signature and forwards to KV with the stream id only. After this plan, the KV node verifies the signature itself (recovering the signer and confirming it matches the claimed `wallet`), so the trust boundary moves into the KV process.
- A new `node/rpc/src/admin_rpc_server/eip712.rs` module implements the same domain + struct hashing the frontend uses, modeled after `0g-hot-storage/0g-hot-storage-node/crates/settlement/src/eip712.rs` (manual `domainSeparator` / `structHash` / `keccak256("\x19\x01" || ds || sh)` digest, recovery via `Signature::recover(H256::from(digest))`).
- `chain_id` is a node-side configuration value (not request-side). The frontend's signing chain id must match the configured chain id; mismatches cause signature recovery to return the wrong address and the request is rejected.

**Tech Stack:** Rust, `ethers = "^2"` (already used in `node/stream` and `node/log_entry_sync`), `ethereum-types`. No new external services.

**Out of scope:**
- Replay protection via timestamp/nonce. The current frontend payload has no timestamp; if you want anti-replay later, that's a separate plan that updates the frontend payload first.
- Removing the Next.js route. It can stay for now; after this plan it's redundant but not harmful (verifies once, KV verifies again).
- Auth on any other admin method (none exist yet).

---

## Frontend signing format (source of truth)

From `/Users/peter/ZeroGravity/0g-storage-scan-frontend-new/src/lib/eip712.ts`:

```
Domain (3 fields, NO verifyingContract):
  name: "0G Storage Scan"
  version: "1"
  chainId: <runtime>

Type RegisterStream:
  purpose: string
  wallet: address
  streamId: bytes32

Message (always):
  purpose: "register-stream"
  wallet: <signer address>
  streamId: <bytes32>
```

The Next.js route currently calls KV as `admin_addStream(streamId)` only (`/Users/peter/ZeroGravity/0g-storage-scan-frontend-new/src/app/api/kv/register/route.ts:78`). After this plan, the KV method requires three params; the Next.js route needs a 5-line update to pass them through. **That update is OUT OF SCOPE for this plan** (different repo) — note it as a documentation deliverable for the frontend team.

---

## File Structure

**Create:**
- `node/rpc/src/admin_rpc_server/eip712.rs` — domain separator, struct hash, digest, recovery, tests

**Modify:**
- `node/rpc/Cargo.toml` — add `ethers = "^2"` to `[dependencies]`
- `node/rpc/src/admin_rpc_server/mod.rs` — declare the new module
- `node/rpc/src/admin_rpc_server/api.rs` — change `add_stream` signature
- `node/rpc/src/admin_rpc_server/impl.rs` — verify signature, update existing tests with a signing helper
- `node/rpc/src/lib.rs` — extend `Context` with `chain_id`, pass it through `run_server`
- `node/src/config/mod.rs` — declare `(chain_id, (u64), 0)` config field
- `node/src/config/convert.rs` — read it from `ZgsKVConfig`, thread into `RPCConfig` (or directly to Context construction in builder)
- `node/rpc/src/config.rs` — add `chain_id: u64` field
- `node/src/client/builder.rs` — pass `chain_id` from `rpc_config` into `Context`
- `node/rpc/tests/admin_add_stream_e2e.rs` — sign with a `LocalWallet` and pass through the new params
- `run/config_example.toml` — add the `chain_id` line with a comment

---

## Task 1: Add EIP-712 module with tests

**Files:**
- Create: `node/rpc/src/admin_rpc_server/eip712.rs`
- Modify: `node/rpc/Cargo.toml`
- Modify: `node/rpc/src/admin_rpc_server/mod.rs`

This task adds the EIP-712 hashing/verification primitives in isolation with TDD. No call sites yet — those land in Task 3.

- [ ] **Step 1: Add ethers dep**

In `node/rpc/Cargo.toml`, add to `[dependencies]`:

```toml
ethers = "^2"
```

(Same version as `node/stream` and `node/log_entry_sync`.)

- [ ] **Step 2: Write the failing tests**

Create `node/rpc/src/admin_rpc_server/eip712.rs`:

```rust
use ethers::abi::{encode, Token};
use ethers::types::{Address, Signature, H256, U256};
use ethers::utils::keccak256;

/// EIP-712 domain name. Must match the frontend's `EIP712_DOMAIN_NAME` in
/// `src/lib/eip712.ts`. Drift causes signature recovery to return the wrong
/// address.
pub const DOMAIN_NAME: &str = "0G Storage Scan";
pub const DOMAIN_VERSION: &str = "1";

/// The `purpose` field value the frontend sends in every `RegisterStream`
/// payload. Drift causes the struct hash to differ from what the frontend
/// signed.
pub const REGISTER_STREAM_PURPOSE: &str = "register-stream";

/// Compute the EIP-712 domain separator. The 3-field domain matches the
/// frontend's `Eip712Domain = { name, version, chainId }` — there is no
/// `verifyingContract`, so the domain typehash uses only those three fields.
pub fn domain_separator(chain_id: u64) -> [u8; 32] {
    let domain_typehash =
        keccak256(b"EIP712Domain(string name,string version,uint256 chainId)");

    let encoded = encode(&[
        Token::FixedBytes(domain_typehash.to_vec()),
        Token::FixedBytes(keccak256(DOMAIN_NAME.as_bytes()).to_vec()),
        Token::FixedBytes(keccak256(DOMAIN_VERSION.as_bytes()).to_vec()),
        Token::Uint(U256::from(chain_id)),
    ]);

    keccak256(encoded)
}

/// Compute the EIP-712 struct hash for `RegisterStream(string purpose, address wallet, bytes32 streamId)`.
/// `purpose` is hashed (per EIP-712 string encoding); `wallet` and `streamId`
/// are encoded as `address` and `bytes32` respectively.
pub fn register_stream_struct_hash(wallet: Address, stream_id: [u8; 32]) -> [u8; 32] {
    let typehash =
        keccak256(b"RegisterStream(string purpose,address wallet,bytes32 streamId)");

    let encoded = encode(&[
        Token::FixedBytes(typehash.to_vec()),
        Token::FixedBytes(keccak256(REGISTER_STREAM_PURPOSE.as_bytes()).to_vec()),
        Token::Address(wallet),
        Token::FixedBytes(stream_id.to_vec()),
    ]);

    keccak256(encoded)
}

/// Compute the full EIP-712 digest: `keccak256("\x19\x01" || domainSeparator || structHash)`.
pub fn register_stream_digest(
    wallet: Address,
    stream_id: [u8; 32],
    chain_id: u64,
) -> [u8; 32] {
    let domain = domain_separator(chain_id);
    let struct_h = register_stream_struct_hash(wallet, stream_id);

    let mut payload = Vec::with_capacity(2 + 32 + 32);
    payload.extend_from_slice(b"\x19\x01");
    payload.extend_from_slice(&domain);
    payload.extend_from_slice(&struct_h);

    keccak256(payload)
}

/// Recover the signer of a `RegisterStream` typed-data payload. Returns
/// `Ok(signer)` on a valid signature, `Err` if the signature is malformed.
/// The caller is responsible for asserting the recovered address equals the
/// expected `wallet`.
pub fn recover_register_stream_signer(
    wallet: Address,
    stream_id: [u8; 32],
    chain_id: u64,
    signature: &Signature,
) -> Result<Address, ethers::types::SignatureError> {
    let digest = register_stream_digest(wallet, stream_id, chain_id);
    signature.recover(H256::from(digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::signers::{LocalWallet, Signer};

    fn test_wallet() -> LocalWallet {
        // Hardhat default account #0; a well-known throwaway key.
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            .parse::<LocalWallet>()
            .unwrap()
    }

    fn test_stream_id() -> [u8; 32] {
        [0xab; 32]
    }

    #[test]
    fn domain_separator_is_deterministic() {
        let s1 = domain_separator(16601);
        let s2 = domain_separator(16601);
        assert_eq!(s1, s2);
    }

    #[test]
    fn domain_separator_changes_with_chain_id() {
        let s1 = domain_separator(16601);
        let s2 = domain_separator(1);
        assert_ne!(s1, s2);
    }

    #[test]
    fn struct_hash_changes_with_wallet() {
        let h1 = register_stream_struct_hash(Address::from([0x11; 20]), test_stream_id());
        let h2 = register_stream_struct_hash(Address::from([0x22; 20]), test_stream_id());
        assert_ne!(h1, h2);
    }

    #[test]
    fn struct_hash_changes_with_stream_id() {
        let wallet = Address::from([0x11; 20]);
        let h1 = register_stream_struct_hash(wallet, [0x01; 32]);
        let h2 = register_stream_struct_hash(wallet, [0x02; 32]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn digest_changes_with_chain_id() {
        let wallet = Address::from([0x11; 20]);
        let d1 = register_stream_digest(wallet, test_stream_id(), 16601);
        let d2 = register_stream_digest(wallet, test_stream_id(), 1);
        assert_ne!(d1, d2);
    }

    #[tokio::test]
    async fn sign_and_recover_round_trip() {
        let wallet = test_wallet();
        let stream_id = test_stream_id();
        let chain_id = 16601u64;

        let digest = register_stream_digest(wallet.address(), stream_id, chain_id);
        let signature = wallet.sign_hash(H256::from(digest)).unwrap();

        let recovered =
            recover_register_stream_signer(wallet.address(), stream_id, chain_id, &signature)
                .unwrap();
        assert_eq!(recovered, wallet.address());
    }

    #[tokio::test]
    async fn wrong_chain_id_does_not_recover_to_signer() {
        let wallet = test_wallet();
        let stream_id = test_stream_id();

        // Sign with chain id 16601; verify against chain id 1.
        let digest = register_stream_digest(wallet.address(), stream_id, 16601);
        let signature = wallet.sign_hash(H256::from(digest)).unwrap();

        let recovered =
            recover_register_stream_signer(wallet.address(), stream_id, 1, &signature)
                .unwrap();
        assert_ne!(recovered, wallet.address());
    }

    #[tokio::test]
    async fn signature_from_different_key_does_not_recover_to_expected_wallet() {
        let signer = test_wallet();
        let other_wallet: LocalWallet =
            "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
                .parse()
                .unwrap();

        let stream_id = test_stream_id();
        let chain_id = 16601u64;

        // Signer signs, but we claim the wallet is other_wallet.
        let digest = register_stream_digest(other_wallet.address(), stream_id, chain_id);
        let signature = signer.sign_hash(H256::from(digest)).unwrap();

        let recovered = recover_register_stream_signer(
            other_wallet.address(),
            stream_id,
            chain_id,
            &signature,
        )
        .unwrap();
        // Should recover to signer (not other_wallet), so the equality check
        // at the call site (recovered == claimed wallet) will fail.
        assert_eq!(recovered, signer.address());
        assert_ne!(recovered, other_wallet.address());
    }

    #[tokio::test]
    async fn changing_stream_id_breaks_existing_signature() {
        let wallet = test_wallet();
        let chain_id = 16601u64;

        let digest_a = register_stream_digest(wallet.address(), [0xaa; 32], chain_id);
        let signature = wallet.sign_hash(H256::from(digest_a)).unwrap();

        // Verify the signature against a different stream_id — recovers wrong address.
        let recovered =
            recover_register_stream_signer(wallet.address(), [0xbb; 32], chain_id, &signature)
                .unwrap();
        assert_ne!(recovered, wallet.address());
    }
}
```

- [ ] **Step 3: Wire the module declaration**

Modify `node/rpc/src/admin_rpc_server/mod.rs`. Currently:

```rust
mod api;
mod r#impl;

pub use api::AdminRpcClient;
pub use api::AdminRpcServer;
pub use r#impl::AdminRpcServerImpl;
```

Add a private `mod eip712;` line at the top so `r#impl` can reference it via `super::eip712`:

```rust
mod api;
mod eip712;
mod r#impl;

pub use api::AdminRpcClient;
pub use api::AdminRpcServer;
pub use r#impl::AdminRpcServerImpl;
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p rpc@0.1.0 admin_rpc_server::eip712`
Expected: 8 tests pass:
- `domain_separator_is_deterministic`
- `domain_separator_changes_with_chain_id`
- `struct_hash_changes_with_wallet`
- `struct_hash_changes_with_stream_id`
- `digest_changes_with_chain_id`
- `sign_and_recover_round_trip`
- `wrong_chain_id_does_not_recover_to_signer`
- `signature_from_different_key_does_not_recover_to_expected_wallet`
- `changing_stream_id_breaks_existing_signature`

(That's 9; recount in the test file.)

- [ ] **Step 5: Confirm clean build of the workspace**

Run: `cargo check --workspace`
Expected: no new warnings (other tests not yet updated; `add_stream` impl still compiles against the unchanged trait).

- [ ] **Step 6: Commit**

```bash
git add node/rpc/Cargo.toml node/rpc/src/admin_rpc_server/eip712.rs node/rpc/src/admin_rpc_server/mod.rs
git commit -m "feat(rpc): add EIP-712 RegisterStream domain + recovery primitives"
```

---

## Task 2: Plumb `chain_id` through config

**Files:**
- Modify: `node/src/config/mod.rs` — declare config field
- Modify: `node/rpc/src/config.rs` — add `chain_id: u64` field
- Modify: `node/src/config/convert.rs` — populate the field
- Modify: `run/config_example.toml` — document it

This task threads the configuration value end-to-end without changing any runtime behavior. After this task, `RPCConfig.chain_id` exists and is populated; nothing reads it yet.

- [ ] **Step 1: Read the current config layout**

Read `node/src/config/mod.rs` to see the macro pattern for declaring fields:

```bash
grep -n "stream_ids\|rpc_listen_address\|build_config\|build" node/src/config/mod.rs | head -10
```

Match the existing pattern (likely `build_config!` macro with `(field_name, (Type), default_value)` triples).

- [ ] **Step 2: Add the field declaration**

In `node/src/config/mod.rs`, add a `chain_id` declaration alongside the other RPC-related fields. Default `0` (operators MUST set this for auth to work; document in step 5).

```rust
(chain_id, (u64), 0)
```

(Inserted at the appropriate position in the macro list, near other RPC fields.)

- [ ] **Step 3: Add the field to RPCConfig**

In `node/rpc/src/config.rs`, add `pub chain_id: u64,` at the end of the struct:

```rust
use std::net::SocketAddr;

#[derive(Clone)]
pub struct Config {
    pub enabled: bool,
    pub listen_address: SocketAddr,
    pub chunks_per_segment: usize,
    pub indexer_url: Option<String>,
    pub zgs_nodes: Vec<String>,
    pub max_query_len_in_bytes: u64,
    pub max_response_body_in_bytes: u32,
    pub zgs_rpc_timeout: u64,
    pub chain_id: u64,
}
```

- [ ] **Step 4: Populate in convert.rs**

In `node/src/config/convert.rs`, find `pub fn rpc_config(&self) -> Result<RPCConfig, String>`. Add `chain_id: self.chain_id,` at the end of the `RPCConfig { … }` struct literal:

```rust
        Ok(RPCConfig {
            enabled: self.rpc_enabled,
            listen_address,
            // ... existing fields ...
            zgs_rpc_timeout: self.zgs_rpc_timeout,
            chain_id: self.chain_id,
        })
```

- [ ] **Step 5: Document in example config**

In `run/config_example.toml`, add a documented `chain_id` entry near the other RPC settings. If you can't find an obvious location, add it at the top of the RPC-related block:

```toml
# EVM chain id this KV node is associated with. Used for EIP-712 signature
# verification on the admin RPC. Must match the chain id the frontend uses
# when signing register-stream messages, otherwise registrations are rejected.
chain_id = 16601
```

(Use `16601` as the example — it's the 0g chain id used in `0g-hot-storage`'s tests. Adjust if your deployment differs.)

- [ ] **Step 6: Cargo check**

Run: `cargo check --workspace`
Expected: clean. The new field is declared but unused — no warnings expected because struct-field-add doesn't trigger dead-code lint when the field is `pub`.

- [ ] **Step 7: Commit**

```bash
git add node/src/config/mod.rs node/rpc/src/config.rs node/src/config/convert.rs run/config_example.toml
git commit -m "config: add chain_id for EIP-712 admin auth"
```

---

## Task 3: Require EIP-712 signature on `admin_addStream`

**Files:**
- Modify: `node/rpc/src/admin_rpc_server/api.rs` — change method signature
- Modify: `node/rpc/src/admin_rpc_server/impl.rs` — verify signature, update tests
- Modify: `node/rpc/src/lib.rs` — extend `Context` with `chain_id`, plumb into AdminRpcServerImpl construction
- Modify: `node/src/client/builder.rs` — pass `rpc_config.chain_id` into `Context`

This task changes the wire protocol: callers must now pass `wallet` and a hex `signature` alongside `stream_id`. The Next.js route's call needs a matching update — that's a frontend-repo change tracked separately. After this task, `cargo test --workspace` should be green.

- [ ] **Step 1: Update the trait signature**

In `node/rpc/src/admin_rpc_server/api.rs`, replace the trait body:

```rust
use ethereum_types::{H160, H256};
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;

#[rpc(server, client, namespace = "admin")]
pub trait AdminRpc {
    /// Register a stream id for monitoring. The caller must provide a
    /// hex-encoded EIP-712 signature over the `RegisterStream` typed-data
    /// payload (domain `{ name: "0G Storage Scan", version: "1", chainId: <node config> }`,
    /// message `{ purpose: "register-stream", wallet, streamId }`). The KV
    /// node recovers the signer from the signature and verifies it equals
    /// `wallet`. Idempotent: returns `Ok(true)` whether or not the stream
    /// was already registered. Persisted across node restarts.
    #[method(name = "addStream")]
    async fn add_stream(
        &self,
        stream_id: H256,
        wallet: H160,
        signature: String,
    ) -> RpcResult<bool>;
}
```

The `signature: String` is a hex string with `0x` prefix, as produced by `eth_signTypedData_v4` and forwarded by the frontend route. We parse it server-side via `Signature::from_str`.

- [ ] **Step 2: Extend Context with chain_id**

In `node/rpc/src/lib.rs`, modify `Context`:

```rust
#[derive(Clone)]
pub struct Context {
    pub config: RPCConfig,
    pub shutdown_sender: Sender<ShutdownReason>,
    pub store: Arc<RwLock<dyn Store>>,
    pub live_stream_set: Arc<RwLock<HashSet<H256>>>,
    pub chain_id: u64,
}
```

In `run_server`, pass `chain_id` to `AdminRpcServerImpl`:

```rust
    module.merge(
        (admin_rpc_server::AdminRpcServerImpl {
            store: ctx.store.clone(),
            live_stream_set: ctx.live_stream_set.clone(),
            chain_id: ctx.chain_id,
        })
        .into_rpc(),
    )?;
```

- [ ] **Step 3: Update builder.rs to populate chain_id**

In `node/src/client/builder.rs`, find `with_rpc`. Add `chain_id: rpc_config.chain_id,` to the `rpc::Context` construction:

```rust
        let ctx = rpc::Context {
            config: rpc_config.clone(),
            shutdown_sender: executor.shutdown_sender(),
            store,
            live_stream_set,
            chain_id: rpc_config.chain_id,
        };
```

(If `rpc_config` is moved into `Context.config` before reading `chain_id`, capture `chain_id` first or use `.clone()` as shown.)

Actually, to avoid the clone, capture `chain_id` first:

```rust
        let chain_id = rpc_config.chain_id;
        let ctx = rpc::Context {
            config: rpc_config,
            shutdown_sender: executor.shutdown_sender(),
            store,
            live_stream_set,
            chain_id,
        };
```

- [ ] **Step 4: Update AdminRpcServerImpl with chain_id field and verification logic**

Replace `node/rpc/src/admin_rpc_server/impl.rs` with:

```rust
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;

use ethereum_types::{H160, H256};
use ethers::types::{Address, Signature};
use jsonrpsee::core::{async_trait, RpcResult};
use ssz::Encode;
use tokio::sync::RwLock;

use storage_with_stream::Store;

use super::api::AdminRpcServer;
use super::eip712::recover_register_stream_signer;
use crate::error;

pub struct AdminRpcServerImpl {
    pub store: Arc<RwLock<dyn Store>>,
    pub live_stream_set: Arc<RwLock<HashSet<H256>>>,
    pub chain_id: u64,
}

#[async_trait]
impl AdminRpcServer for AdminRpcServerImpl {
    async fn add_stream(
        &self,
        stream_id: H256,
        wallet: H160,
        signature: String,
    ) -> RpcResult<bool> {
        // Parse the hex signature.
        let signature = Signature::from_str(signature.trim_start_matches("0x"))
            .map_err(|e| error::invalid_params("signature", format!("not valid hex: {:?}", e)))?;

        // Convert ethereum_types::H160 -> ethers::types::Address (same 20 bytes).
        let claimed = Address::from_slice(wallet.as_bytes());

        // Recover the signer from the EIP-712 digest.
        let recovered = recover_register_stream_signer(
            claimed,
            stream_id.to_fixed_bytes(),
            self.chain_id,
            &signature,
        )
        .map_err(|e| {
            error::invalid_params("signature", format!("recovery failed: {:?}", e))
        })?;

        if recovered != claimed {
            return Err(error::invalid_params(
                "signature",
                "recovered signer does not match claimed wallet",
            ));
        }

        // Fast path: already registered.
        if self.live_stream_set.read().await.contains(&stream_id) {
            debug!("admin_addStream idempotent hit for {:?}", stream_id);
            return Ok(true);
        }

        // Hold the live-set write guard across the DB write so that concurrent
        // add_stream calls for different ids are fully serialized — preventing
        // an interleave where a later caller's persisted set overwrites an
        // earlier caller's. Readers (`skippable`, `validate_stream_read_set`)
        // only take read locks, so this briefly blocks new readers but never
        // deadlocks.
        let mut live = self.live_stream_set.write().await;
        if live.contains(&stream_id) {
            debug!("admin_addStream idempotent hit for {:?}", stream_id);
            return Ok(true);
        }
        live.insert(stream_id);
        let merged: Vec<H256> = live.iter().cloned().collect();

        if let Err(e) = self
            .store
            .write()
            .await
            .update_stream_ids(merged.as_ssz_bytes())
            .await
        {
            // Roll back so a retry can re-attempt persistence.
            live.remove(&stream_id);
            error!(
                "admin_addStream persist failed for {:?}: {:?}",
                stream_id, e
            );
            return Err(error::internal_error(format!(
                "persist stream id: {:?}",
                e
            )));
        }

        info!(
            "admin_addStream registered new stream {:?} for wallet {:?}",
            stream_id, claimed
        );
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::signers::{LocalWallet, Signer};
    use ethers::types::H256 as EthersH256;
    use storage_with_stream::StoreManager;

    fn h(b: u8) -> H256 {
        H256::from([b; 32])
    }

    fn test_chain_id() -> u64 {
        16601
    }

    /// Hardhat default account #0 — well-known throwaway key.
    fn test_wallet() -> LocalWallet {
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            .parse()
            .unwrap()
    }

    /// Sign a `RegisterStream` payload as `wallet` and return the wire-format
    /// signature string (`0x`-prefixed hex).
    fn sign_register(wallet: &LocalWallet, stream_id: H256, chain_id: u64) -> String {
        use super::super::eip712::register_stream_digest;
        let digest = register_stream_digest(
            wallet.address(),
            stream_id.to_fixed_bytes(),
            chain_id,
        );
        let sig = wallet.sign_hash(EthersH256::from(digest)).unwrap();
        format!("0x{}", hex::encode(sig.to_vec()))
    }

    async fn fixture() -> AdminRpcServerImpl {
        let store: Arc<RwLock<dyn Store>> =
            Arc::new(RwLock::new(StoreManager::memorydb().await.unwrap()));
        AdminRpcServerImpl {
            store,
            live_stream_set: Arc::new(RwLock::new(HashSet::new())),
            chain_id: test_chain_id(),
        }
    }

    fn h160_from_address(addr: Address) -> H160 {
        H160::from_slice(addr.as_bytes())
    }

    #[tokio::test]
    async fn add_stream_persists_and_updates_live() {
        let svc = fixture().await;
        let wallet = test_wallet();
        let stream_id = h(0x01);
        let sig = sign_register(&wallet, stream_id, test_chain_id());

        assert!(svc
            .add_stream(stream_id, h160_from_address(wallet.address()), sig)
            .await
            .unwrap());

        assert!(svc.live_stream_set.read().await.contains(&stream_id));

        let db_ids = svc
            .store
            .read()
            .await
            .get_holding_stream_ids()
            .await
            .unwrap();
        assert_eq!(db_ids, vec![stream_id]);
    }

    #[tokio::test]
    async fn add_stream_is_idempotent() {
        let svc = fixture().await;
        let wallet = test_wallet();
        let stream_id = h(0x02);
        let sig = sign_register(&wallet, stream_id, test_chain_id());

        assert!(svc
            .add_stream(stream_id, h160_from_address(wallet.address()), sig.clone())
            .await
            .unwrap());
        assert!(svc
            .add_stream(stream_id, h160_from_address(wallet.address()), sig)
            .await
            .unwrap());

        let db_ids = svc
            .store
            .read()
            .await
            .get_holding_stream_ids()
            .await
            .unwrap();
        assert_eq!(db_ids, vec![stream_id]);
        assert_eq!(svc.live_stream_set.read().await.len(), 1);
    }

    #[tokio::test]
    async fn add_stream_appends_without_dropping_existing() {
        let svc = fixture().await;
        let wallet = test_wallet();

        // pre-populate as if a previous run had registered h(0x1).
        svc.live_stream_set.write().await.insert(h(0x01));
        svc.store
            .write()
            .await
            .reset_stream_sync(vec![h(0x01)].as_ssz_bytes())
            .await
            .unwrap();

        let stream_id = h(0x02);
        let sig = sign_register(&wallet, stream_id, test_chain_id());
        assert!(svc
            .add_stream(stream_id, h160_from_address(wallet.address()), sig)
            .await
            .unwrap());

        let db_ids: HashSet<H256> = svc
            .store
            .read()
            .await
            .get_holding_stream_ids()
            .await
            .unwrap()
            .into_iter()
            .collect();
        assert_eq!(db_ids, HashSet::from([h(0x01), h(0x02)]));
    }

    #[tokio::test]
    async fn add_stream_concurrent_different_ids_no_loss() {
        let svc = Arc::new(fixture().await);
        let wallet = test_wallet();
        let claimed_h160 = h160_from_address(wallet.address());

        let s1 = svc.clone();
        let s2 = svc.clone();
        let claimed1 = claimed_h160;
        let claimed2 = claimed_h160;
        let sig1 = sign_register(&wallet, h(0x01), test_chain_id());
        let sig2 = sign_register(&wallet, h(0x02), test_chain_id());

        let (r1, r2) = tokio::join!(
            async move { s1.add_stream(h(0x01), claimed1, sig1).await },
            async move { s2.add_stream(h(0x02), claimed2, sig2).await },
        );
        assert!(r1.unwrap());
        assert!(r2.unwrap());

        let live: HashSet<H256> = svc.live_stream_set.read().await.clone();
        assert_eq!(live, HashSet::from([h(0x01), h(0x02)]));

        let db: HashSet<H256> = svc
            .store
            .read()
            .await
            .get_holding_stream_ids()
            .await
            .unwrap()
            .into_iter()
            .collect();
        assert_eq!(db, HashSet::from([h(0x01), h(0x02)]));
    }

    #[tokio::test]
    async fn add_stream_rejects_signature_from_wrong_wallet() {
        let svc = fixture().await;
        let signer = test_wallet();
        let other_wallet: LocalWallet =
            "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
                .parse()
                .unwrap();
        let stream_id = h(0x03);

        // Signer signs, but caller claims wallet is other_wallet.
        let sig = sign_register(&signer, stream_id, test_chain_id());

        let result = svc
            .add_stream(stream_id, h160_from_address(other_wallet.address()), sig)
            .await;
        assert!(result.is_err(), "must reject mismatched signer/wallet");

        // DB and live set unchanged.
        assert!(svc.live_stream_set.read().await.is_empty());
        assert!(svc
            .store
            .read()
            .await
            .get_holding_stream_ids()
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn add_stream_rejects_signature_for_wrong_stream_id() {
        let svc = fixture().await;
        let wallet = test_wallet();

        // Sign for stream_id A; submit with stream_id B.
        let sig = sign_register(&wallet, h(0xaa), test_chain_id());
        let result = svc
            .add_stream(h(0xbb), h160_from_address(wallet.address()), sig)
            .await;
        assert!(result.is_err(), "must reject signature for wrong stream id");
    }

    #[tokio::test]
    async fn add_stream_rejects_signature_with_wrong_chain_id() {
        // Sign with chain id 1; node configured for 16601.
        let svc = fixture().await;
        let wallet = test_wallet();
        let stream_id = h(0x04);
        let sig = sign_register(&wallet, stream_id, 1);

        let result = svc
            .add_stream(stream_id, h160_from_address(wallet.address()), sig)
            .await;
        assert!(result.is_err(), "must reject signature for wrong chain id");
    }

    #[tokio::test]
    async fn add_stream_rejects_malformed_signature() {
        let svc = fixture().await;
        let wallet = test_wallet();
        let stream_id = h(0x05);

        let result = svc
            .add_stream(
                stream_id,
                h160_from_address(wallet.address()),
                "not-hex".to_string(),
            )
            .await;
        assert!(result.is_err(), "must reject malformed signature");
    }
}
```

Note the `hex::encode(...)` in `sign_register`. The `hex` crate is already a transitive dep via `ethers`, but if rustc complains about it not being in scope, add `hex = "0.4"` to `[dev-dependencies]` of `node/rpc/Cargo.toml`. Verify with `cargo check -p rpc@0.1.0 --tests`.

- [ ] **Step 5: Run unit tests**

Run: `cargo test -p rpc@0.1.0 admin_rpc_server::r#impl::tests`
Expected: 8 tests pass:
- `add_stream_persists_and_updates_live`
- `add_stream_is_idempotent`
- `add_stream_appends_without_dropping_existing`
- `add_stream_concurrent_different_ids_no_loss`
- `add_stream_rejects_signature_from_wrong_wallet`
- `add_stream_rejects_signature_for_wrong_stream_id`
- `add_stream_rejects_signature_with_wrong_chain_id`
- `add_stream_rejects_malformed_signature`

- [ ] **Step 6: Confirm clean workspace build**

Run: `cargo check --workspace`
Expected: clean. The e2e test will be broken at this point (Task 4 fixes it).

- [ ] **Step 7: Run the workspace test suite — expect e2e failure**

Run: `cargo test --workspace`
Expected: all rpc unit tests + storage + stream tests pass; **`admin_add_stream_e2e` integration test FAILS** (the e2e test calls the old single-arg `add_stream`). That's expected — Task 4 fixes it.

- [ ] **Step 8: Commit**

```bash
git add node/rpc/src/admin_rpc_server/api.rs \
        node/rpc/src/admin_rpc_server/impl.rs \
        node/rpc/src/lib.rs \
        node/src/client/builder.rs
git commit -m "feat(rpc): require EIP-712 wallet signature on admin_addStream"
```

If you needed to add `hex` to dev-dependencies, include `node/rpc/Cargo.toml` in the staged files.

---

## Task 4: Update e2e test to sign

**Files:**
- Modify: `node/rpc/tests/admin_add_stream_e2e.rs`

The e2e test currently sends only the stream id. After Task 3, it also needs to send a wallet and a real EIP-712 signature.

- [ ] **Step 1: Update the e2e test**

Replace the contents of `node/rpc/tests/admin_add_stream_e2e.rs` with:

```rust
use std::collections::HashSet;
use std::sync::Arc;

use ethereum_types::{H160, H256};
use ethers::abi::{encode, Token};
use ethers::signers::{LocalWallet, Signer};
use ethers::types::{Address, H256 as EthersH256, U256};
use ethers::utils::keccak256;
use jsonrpsee::http_client::HttpClientBuilder;
use tokio::sync::RwLock;

use rpc::{run_server, AdminRpcClient, Context, KeyValueRpcClient, RPCConfig};
use storage_with_stream::{Store, StoreManager};

const CHAIN_ID: u64 = 16601;

fn h(b: u8) -> H256 {
    H256::from([b; 32])
}

/// Inline copy of the EIP-712 digest computation. Kept here (not a `pub use`
/// from the rpc crate) so the e2e test exercises the canonical wire format
/// independently of the production module — if the production module drifts,
/// this test fails.
fn register_stream_digest(wallet: Address, stream_id: [u8; 32], chain_id: u64) -> [u8; 32] {
    let domain_typehash =
        keccak256(b"EIP712Domain(string name,string version,uint256 chainId)");
    let domain = keccak256(encode(&[
        Token::FixedBytes(domain_typehash.to_vec()),
        Token::FixedBytes(keccak256(b"0G Storage Scan").to_vec()),
        Token::FixedBytes(keccak256(b"1").to_vec()),
        Token::Uint(U256::from(chain_id)),
    ]));
    let typehash =
        keccak256(b"RegisterStream(string purpose,address wallet,bytes32 streamId)");
    let struct_hash = keccak256(encode(&[
        Token::FixedBytes(typehash.to_vec()),
        Token::FixedBytes(keccak256(b"register-stream").to_vec()),
        Token::Address(wallet),
        Token::FixedBytes(stream_id.to_vec()),
    ]));

    let mut payload = Vec::with_capacity(2 + 32 + 32);
    payload.extend_from_slice(b"\x19\x01");
    payload.extend_from_slice(&domain);
    payload.extend_from_slice(&struct_hash);
    keccak256(payload)
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
        chain_id: CHAIN_ID,
    };

    let ctx = Context {
        config: rpc_config,
        shutdown_sender: shutdown_tx,
        store: store.clone(),
        live_stream_set: live_stream_set.clone(),
        chain_id: CHAIN_ID,
    };
    let (handle, addr) = run_server(ctx).await.unwrap();
    let url = format!("http://{}", addr);

    let client = HttpClientBuilder::default().build(&url).unwrap();

    // Sign a real RegisterStream payload.
    let wallet: LocalWallet =
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            .parse()
            .unwrap();
    let stream_id = h(0xab);
    let digest = register_stream_digest(wallet.address(), stream_id.to_fixed_bytes(), CHAIN_ID);
    let sig = wallet.sign_hash(EthersH256::from(digest)).unwrap();
    let sig_hex = format!("0x{}", hex::encode(sig.to_vec()));

    let claimed_wallet = H160::from_slice(wallet.address().as_bytes());
    AdminRpcClient::add_stream(&client, stream_id, claimed_wallet, sig_hex)
        .await
        .unwrap();

    let ids = KeyValueRpcClient::get_holding_stream_ids(&client)
        .await
        .unwrap();
    assert_eq!(ids, vec![stream_id]);

    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn add_stream_rejects_invalid_signature_over_the_wire() {
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
        chain_id: CHAIN_ID,
    };

    let ctx = Context {
        config: rpc_config,
        shutdown_sender: shutdown_tx,
        store: store.clone(),
        live_stream_set: live_stream_set.clone(),
        chain_id: CHAIN_ID,
    };
    let (handle, addr) = run_server(ctx).await.unwrap();
    let url = format!("http://{}", addr);

    let client = HttpClientBuilder::default().build(&url).unwrap();

    // Signer is wallet1, but we claim wallet2 — should be rejected.
    let signer: LocalWallet =
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            .parse()
            .unwrap();
    let other_wallet: LocalWallet =
        "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
            .parse()
            .unwrap();
    let stream_id = h(0xcd);

    let digest =
        register_stream_digest(other_wallet.address(), stream_id.to_fixed_bytes(), CHAIN_ID);
    let sig = signer.sign_hash(EthersH256::from(digest)).unwrap();
    let sig_hex = format!("0x{}", hex::encode(sig.to_vec()));
    let claimed_other = H160::from_slice(other_wallet.address().as_bytes());

    let result = AdminRpcClient::add_stream(&client, stream_id, claimed_other, sig_hex).await;
    assert!(
        result.is_err(),
        "RPC must reject signature from wrong wallet"
    );

    let ids = KeyValueRpcClient::get_holding_stream_ids(&client)
        .await
        .unwrap();
    assert!(
        ids.is_empty(),
        "rejected registration must not appear in get_holding_stream_ids"
    );

    handle.stop().unwrap();
}
```

- [ ] **Step 2: Verify dev-dependencies cover ethers and hex**

Read `node/rpc/Cargo.toml`. The e2e test now uses `ethers::signers::LocalWallet`, `ethers::types::*`, `ethers::utils::keccak256`, and `hex::encode`. Since `ethers` was added in Task 1 to `[dependencies]`, integration tests automatically have access. `hex` is a transitive dep of `ethers`; if rustc complains, add to `[dev-dependencies]`:

```toml
[dev-dependencies]
serde_json = "1.0.127"
hex = "0.4"
```

- [ ] **Step 3: Run the e2e test**

Run: `cargo test -p rpc@0.1.0 --test admin_add_stream_e2e`
Expected: 2 tests pass:
- `add_stream_then_visible_via_get_holding_stream_ids`
- `add_stream_rejects_invalid_signature_over_the_wire`

- [ ] **Step 4: Run the full workspace tests**

Run: `cargo test --workspace`
Expected: all PASS — admin RPC unit tests (8), storage_with_stream (14), stream (14), e2e (2), other crates (0). Total 38+ tests.

- [ ] **Step 5: Commit**

```bash
git add node/rpc/tests/admin_add_stream_e2e.rs
# Include node/rpc/Cargo.toml only if hex was added.
git commit -m "test(rpc): e2e admin_addStream over JSON-RPC with EIP-712 signature"
```

---

## Task 5: Document the wire change for the frontend team

**Files:**
- Create: `docs/admin-add-stream-wire.md` — short markdown doc describing the new wire format

This task is purely documentation. It exists so that whoever updates the Next.js route at `/api/kv/register/route.ts` in `0g-storage-scan-frontend-new` has an unambiguous reference for what params to send.

- [ ] **Step 1: Write the doc**

Create `docs/admin-add-stream-wire.md`:

```markdown
# `admin_addStream` JSON-RPC Wire Format

After [feature/admin-add-stream commit X], the KV node's admin RPC requires a
wallet signature on every `admin_addStream` call. This document describes the
exact wire format so external callers (notably the frontend's
`/api/kv/register` Next.js route) can construct compliant requests.

## Method

`admin_addStream(streamId, wallet, signature)`

| Param | Type | Description |
|---|---|---|
| `streamId` | `0x`-prefixed 32-byte hex (`H256`) | The stream id to register |
| `wallet` | `0x`-prefixed 20-byte hex (`H160`) | The address that signed the typed data |
| `signature` | `0x`-prefixed 65-byte hex string | Output of `eth_signTypedData_v4` |

## Signed payload (EIP-712 typed data)

Domain:

```json
{
  "name": "0G Storage Scan",
  "version": "1",
  "chainId": <node's configured chain_id>
}
```

There is **no** `verifyingContract` in the domain.

Type:

```
RegisterStream(string purpose,address wallet,bytes32 streamId)
```

Message:

```json
{
  "purpose": "register-stream",
  "wallet": "<wallet address>",
  "streamId": "<32-byte hex>"
}
```

## Verification on the KV node

1. Reconstruct the EIP-712 digest from `streamId`, `wallet`, and the node's
   configured `chain_id`.
2. Call `Signature::recover(digest)` on the supplied signature.
3. Reject if the recovered address does not equal the supplied `wallet`.

If `chain_id` differs between signer and verifier, recovery yields a different
address and the request is rejected. The frontend MUST sign with the chain id
that matches the deployed KV node's `chain_id` config field.

## Failure responses

- Malformed signature hex → `-32602` (invalid params).
- Signature recovery error → `-32602` (invalid params).
- Recovered signer ≠ claimed wallet → `-32602` (invalid params).
- DB persistence failure → `-32603` (internal error).

## Idempotency

A second call with the same `streamId` and a valid signature returns
`Ok(true)` without re-persisting. The signature does not need to be the same
as the first call's; any valid signature for that `(wallet, streamId)` pair
suffices.

## Frontend route update needed

The Next.js route at
`0g-storage-scan-frontend-new/src/app/api/kv/register/route.ts:78` currently
sends:

```json
{ "method": "admin_addStream", "params": [streamId] }
```

Update to send:

```json
{ "method": "admin_addStream", "params": [streamId, walletAddr, signature] }
```

The route already has `walletAddr` and `signature` in scope from the request
body (verified just above), so this is a 1-line change to the params array.
```

- [ ] **Step 2: Confirm it renders**

Read it with the file viewer to make sure markdown formatting looks right.

- [ ] **Step 3: Commit**

```bash
git add docs/admin-add-stream-wire.md
git commit -m "docs: wire format for admin_addStream EIP-712 signing"
```

---

## Self-review checklist

**Spec coverage:**
- [x] EIP-712 domain matches frontend (`name`, `version`, `chainId`, no `verifyingContract`) — Task 1.
- [x] `RegisterStream` typehash + struct hash match frontend — Task 1.
- [x] `purpose` field included with value `"register-stream"` — Task 1.
- [x] `chain_id` is config-side, not request-side — Task 2.
- [x] Recovered signer must equal claimed wallet — Task 3.
- [x] Idempotency preserved — Task 3 (existing test paths).
- [x] Concurrent calls safe — Task 3 (existing test exercising it).
- [x] E2E test exercises the wire path with real signature — Task 4.
- [x] Wrong-signer / wrong-stream-id / wrong-chain-id / malformed-sig rejection — Tasks 3 & 4.
- [x] Wire format documented for frontend team — Task 5.

**Type consistency:**
- `add_stream(stream_id: H256, wallet: H160, signature: String)` — used the same way in api.rs (Task 3), impl.rs (Task 3), e2e test (Task 4), and the wire doc (Task 5).
- `chain_id: u64` everywhere.
- `Address` (ethers) and `H160` (ethereum_types) bridged via `Address::from_slice(h.as_bytes())` and `H160::from_slice(addr.as_bytes())` — both 20 bytes, byte-order identical.

**Placeholders:** none. All test code, all SQL, all configs are concrete.

**Out of repo (called out):**
- Frontend Next.js route change (Task 5 doc covers this; the actual code change happens in `0g-storage-scan-frontend-new`).

---

## Open questions to surface during execution

1. **Is `hex` a transitive dev-dep?** Most likely yes via `ethers`, but if rustc complains, add to `[dev-dependencies]`. Documented in Task 3 step 4 and Task 4 step 2.

2. **Cross-language vector verification.** The plan's tests verify that Rust's recovery is internally consistent (round-trip with a `LocalWallet`). It does NOT verify that Rust's digest matches viem's digest byte-for-byte for a given message. The first deployment with the real frontend will surface any cross-language drift. If you want belt-and-suspenders before that, generate a vector by running a Node.js script with viem (using the same domain/types/message + a known private key) and add a Rust test that recovers the expected address from the pasted signature. Out of scope for v1 unless you want to add it as a Task 6.

3. **Should the bare `admin_addStream(stream_id)` form be retained for trusted-network callers?** No — the user explicitly chose "specialized KV with auth required." If a future deployment needs the unauthenticated form, that's a separate config flag (e.g. `admin_auth = "none" | "wallet_signature"`). Not in this plan.
