use std::collections::HashSet;
use std::sync::Arc;

use ethereum_types::H256;
use jsonrpsee::http_client::HttpClientBuilder;
use tokio::sync::RwLock;

use rpc::{run_server, AdminRpcClient, Context, KeyValueRpcClient, RPCConfig};
use storage_with_stream::{Store, StoreManager};

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

    let ctx = Context {
        config: rpc_config,
        shutdown_sender: shutdown_tx,
        store: store.clone(),
        live_stream_set: live_stream_set.clone(),
    };
    let (handle, addr) = run_server(ctx).await.unwrap();
    let url = format!("http://{}", addr);

    let client = HttpClientBuilder::default().build(&url).unwrap();
    AdminRpcClient::add_stream(&client, h(0xab)).await.unwrap();

    let ids = KeyValueRpcClient::get_holding_stream_ids(&client)
        .await
        .unwrap();
    assert_eq!(ids, vec![h(0xab)]);

    handle.stop().unwrap();
}
