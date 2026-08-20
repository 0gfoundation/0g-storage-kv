use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ethereum_types::{H160, H256};
use ethers::types::{Address, Signature};
use jsonrpsee::core::{async_trait, RpcResult};
use ssz::Encode;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::RwLock;

use storage_with_stream::Store;

use super::api::AdminRpcServer;
use super::eip712::{recover_register_stream_signer, recover_renew_now_signer};
use crate::error;

/// Freshness window (seconds) for `RenewNow` signatures: `issuedAt` must be
/// within this many seconds of the node's clock in either direction.
const RENEW_NOW_FRESHNESS_SECS: u64 = 300;

pub struct AdminRpcServerImpl {
    pub store: Arc<RwLock<dyn Store>>,
    pub live_stream_set: Arc<RwLock<HashSet<H256>>>,
    pub chain_id: u64,
    pub renew_trigger: Option<UnboundedSender<()>>,
    pub renew_signer: Option<H160>,
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
        .map_err(|e| error::invalid_params("signature", format!("recovery failed: {:?}", e)))?;

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
            // Race-loser path: another caller registered the same id between
            // our fast-path read and this write-lock acquisition. No log —
            // the fast-path debug covers the common idempotent case.
            return Ok(true);
        }
        live.insert(stream_id);
        // Sort so the persisted Vec is deterministic — kv_getHoldingStreamIds
        // returns this Vec verbatim and clients/tests depend on ascending order.
        let mut merged: Vec<H256> = live.iter().cloned().collect();
        merged.sort();

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
            return Err(error::internal_error(format!("persist stream id: {:?}", e)));
        }

        info!(
            "admin_addStream registered new stream {:?} for wallet {:?}",
            stream_id, claimed
        );
        Ok(true)
    }

    async fn renew_now(&self, wallet: H160, issued_at: u64, signature: String) -> RpcResult<bool> {
        // Freshness: reject signatures that are stale or future-dated so a
        // captured signature cannot be replayed later.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now.abs_diff(issued_at) > RENEW_NOW_FRESHNESS_SECS {
            return Err(error::invalid_params("issuedAt", "stale or future-dated"));
        }

        // Parse the hex signature.
        let signature = Signature::from_str(signature.trim_start_matches("0x"))
            .map_err(|e| error::invalid_params("signature", format!("not valid hex: {:?}", e)))?;

        // Convert ethereum_types::H160 -> ethers::types::Address (same 20 bytes).
        let claimed = Address::from_slice(wallet.as_bytes());

        // Recover the signer from the EIP-712 digest.
        let recovered = recover_renew_now_signer(claimed, issued_at, self.chain_id, &signature)
            .map_err(|e| error::invalid_params("signature", format!("recovery failed: {:?}", e)))?;

        if recovered != claimed {
            return Err(error::invalid_params(
                "signature",
                "recovered signer does not match claimed wallet",
            ));
        }

        // The recovered/claimed wallet must be the node's configured renewal signer.
        if self.renew_signer != Some(wallet) {
            return Err(error::invalid_params(
                "wallet",
                "renewal disabled or wallet is not the renewal signer",
            ));
        }

        match &self.renew_trigger {
            Some(trigger) => trigger
                .send(())
                .map(|_| true)
                .map_err(|_| error::internal_error("renewal service not running")),
            None => Err(error::invalid_params("renewal", "renewal disabled")),
        }
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
        use ethers::utils::hex;
        let digest = register_stream_digest(wallet.address(), stream_id.to_fixed_bytes(), chain_id);
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
            renew_trigger: None,
            renew_signer: None,
        }
    }

    /// Sign a `RenewNow` payload as `wallet` and return the wire-format
    /// signature string (`0x`-prefixed hex).
    fn sign_renew_now(wallet: &LocalWallet, issued_at: u64, chain_id: u64) -> String {
        use super::super::eip712::renew_now_digest;
        use ethers::utils::hex;
        let digest = renew_now_digest(wallet.address(), issued_at, chain_id);
        let sig = wallet.sign_hash(EthersH256::from(digest)).unwrap();
        format!("0x{}", hex::encode(sig.to_vec()))
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

        // No state mutation on rejection.
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
    async fn renew_now_sends_trigger_on_valid_signature() {
        let wallet = test_wallet();
        let claimed = h160_from_address(wallet.address());
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        let mut svc = fixture().await;
        svc.renew_trigger = Some(tx);
        svc.renew_signer = Some(claimed);

        let issued_at = now_secs();
        let sig = sign_renew_now(&wallet, issued_at, test_chain_id());

        assert!(svc.renew_now(claimed, issued_at, sig).await.unwrap());
        assert!(
            rx.try_recv().is_ok(),
            "trigger channel must receive a signal"
        );
    }

    #[tokio::test]
    async fn renew_now_rejects_stale_issued_at() {
        let wallet = test_wallet();
        let claimed = h160_from_address(wallet.address());
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();

        let mut svc = fixture().await;
        svc.renew_trigger = Some(tx);
        svc.renew_signer = Some(claimed);

        let issued_at = now_secs() - 301;
        let sig = sign_renew_now(&wallet, issued_at, test_chain_id());

        let result = svc.renew_now(claimed, issued_at, sig).await;
        assert!(result.is_err(), "must reject stale issuedAt");
    }

    #[tokio::test]
    async fn renew_now_rejects_future_issued_at() {
        let wallet = test_wallet();
        let claimed = h160_from_address(wallet.address());
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();

        let mut svc = fixture().await;
        svc.renew_trigger = Some(tx);
        svc.renew_signer = Some(claimed);

        let issued_at = now_secs() + 301;
        let sig = sign_renew_now(&wallet, issued_at, test_chain_id());

        let result = svc.renew_now(claimed, issued_at, sig).await;
        assert!(result.is_err(), "must reject future-dated issuedAt");
    }

    #[tokio::test]
    async fn renew_now_rejects_signature_from_wrong_wallet() {
        let signer = test_wallet();
        let other_wallet: LocalWallet =
            "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
                .parse()
                .unwrap();
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();

        let mut svc = fixture().await;
        svc.renew_trigger = Some(tx);
        svc.renew_signer = Some(h160_from_address(other_wallet.address()));

        let issued_at = now_secs();
        // Signer signs, but caller claims wallet is other_wallet.
        let sig = sign_renew_now(&signer, issued_at, test_chain_id());

        let result = svc
            .renew_now(h160_from_address(other_wallet.address()), issued_at, sig)
            .await;
        assert!(result.is_err(), "must reject mismatched signer/wallet");
    }

    #[tokio::test]
    async fn renew_now_rejects_wallet_that_is_not_the_configured_renew_signer() {
        let wallet = test_wallet();
        let claimed = h160_from_address(wallet.address());
        let other_signer = H160::from([0x42; 20]);
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();

        let mut svc = fixture().await;
        svc.renew_trigger = Some(tx);
        svc.renew_signer = Some(other_signer); // configured signer differs from wallet

        let issued_at = now_secs();
        let sig = sign_renew_now(&wallet, issued_at, test_chain_id());

        let result = svc.renew_now(claimed, issued_at, sig).await;
        assert!(
            result.is_err(),
            "must reject a wallet that is not the configured renewal signer"
        );
    }

    #[tokio::test]
    async fn renew_now_disabled_when_no_renew_signer_or_trigger_configured() {
        // Default fixture has renew_trigger: None, renew_signer: None.
        let wallet = test_wallet();
        let claimed = h160_from_address(wallet.address());
        let svc = fixture().await;

        let issued_at = now_secs();
        let sig = sign_renew_now(&wallet, issued_at, test_chain_id());

        let result = svc.renew_now(claimed, issued_at, sig).await;
        assert!(result.is_err(), "must reject when renewal is disabled");
    }

    #[tokio::test]
    async fn renew_now_errors_when_trigger_receiver_dropped() {
        let wallet = test_wallet();
        let claimed = h160_from_address(wallet.address());
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        drop(rx); // service side gone

        let mut svc = fixture().await;
        svc.renew_trigger = Some(tx);
        svc.renew_signer = Some(claimed);

        let issued_at = now_secs();
        let sig = sign_renew_now(&wallet, issued_at, test_chain_id());

        let result = svc.renew_now(claimed, issued_at, sig).await;
        assert!(
            result.is_err(),
            "must surface an error when the renewal service is not running"
        );
    }
}
