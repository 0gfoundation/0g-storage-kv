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
