use std::collections::HashSet;
use std::sync::Arc;

use ethereum_types::{H160, H256};
use ethers::abi::{encode, Token};
use ethers::signers::{LocalWallet, Signer};
use ethers::types::{Address, H256 as EthersH256, U256};
use ethers::utils::{hex, keccak256};
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
    let domain_typehash = keccak256(b"EIP712Domain(string name,string version,uint256 chainId)");
    let domain = keccak256(encode(&[
        Token::FixedBytes(domain_typehash.to_vec()),
        Token::FixedBytes(keccak256(b"0G Storage Scan").to_vec()),
        Token::FixedBytes(keccak256(b"1").to_vec()),
        Token::Uint(U256::from(chain_id)),
    ]));
    let typehash = keccak256(b"RegisterStream(string purpose,address wallet,bytes32 streamId)");
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
    let wallet: LocalWallet = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
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
    let signer: LocalWallet = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
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
