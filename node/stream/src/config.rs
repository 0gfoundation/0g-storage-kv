use std::collections::HashSet;

use ethereum_types::H256;

#[derive(Clone)]
pub struct Config {
    pub stream_ids: Vec<H256>,
    pub stream_set: HashSet<H256>,
    pub encryption_key: Option<[u8; 32]>,
    pub max_download_retries: usize,
    pub download_timeout_ms: u64,
    pub download_retry_interval_ms: u64,
    pub retry_wait_ms: u64,
}
