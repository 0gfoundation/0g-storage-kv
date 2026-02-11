use std::collections::HashSet;

use ethereum_types::H256;

#[derive(Clone)]
pub struct Config {
    pub stream_ids: Vec<H256>,
    pub stream_set: HashSet<H256>,
    pub encryption_key: Option<[u8; 32]>,
}
