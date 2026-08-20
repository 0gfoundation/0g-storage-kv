use std::sync::Arc;

use async_trait::async_trait;
use ethereum_types::{H160, H256};
use kv_types::{
    AccessControlSet, KVTransaction, KeyValuePair, RenewAttempt, StaleKey, StreamWriteSet,
};
use shared_types::ChunkArray;

use shared_types::FlowProof;

use storage::log_store::log_manager::ENTRY_SIZE;
use storage::log_store::tx_store::BlockHashAndSubmissionIndex;

use crate::error::Result;

mod data_store;
mod flow_store;
mod sqlite_db_statements;
pub mod store_manager;
mod stream_store;
mod tx_store;

pub use stream_store::to_access_control_op_name;
pub use stream_store::AccessControlOps;

pub trait DataStoreRead {
    fn get_tx_by_seq_number(&self, seq: u64) -> Result<Option<KVTransaction>>;

    fn check_tx_completed(&self, tx_seq: u64) -> Result<bool>;

    fn next_tx_seq(&self) -> u64;

    fn get_first_tx_seq(&self) -> Result<Option<u64>>;

    fn get_sync_progress(&self) -> Result<Option<(u64, H256)>>;

    fn get_block_hashes(&self) -> Result<Vec<(u64, BlockHashAndSubmissionIndex)>>;

    fn get_log_latest_block_number(&self) -> Result<Option<u64>>;

    fn get_chunk_by_flow_index(&self, index: u64, length: u64) -> Result<Option<ChunkArray>>;

    fn get_tx_block_time(&self, tx_seq: u64) -> Result<Option<u64>>;
}

pub trait DataStoreWrite {
    fn put_tx(&mut self, tx: KVTransaction) -> Result<()>;

    fn finalize_tx_with_hash(&mut self, tx_seq: u64, tx_hash: H256) -> Result<bool>;

    fn put_sync_progress(&self, progress: (u64, H256, Option<Option<u64>>)) -> Result<()>;

    fn revert_to(&mut self, tx_seq: u64) -> Result<()>;

    fn delete_block_hash_by_number(&self, block_number: u64) -> Result<()>;

    fn put_log_latest_block_number(&self, block_number: u64) -> Result<()>;

    fn put_first_tx_seq(&self, first_tx_seq: u64) -> Result<()>;

    fn put_chunks_with_tx_hash(
        &self,
        tx_seq: u64,
        tx_hash: H256,
        chunks: ChunkArray,
        maybe_file_proof: Option<FlowProof>,
    ) -> Result<bool>;

    fn put_tx_block_time(&self, tx_seq: u64, ts: u64) -> Result<()>;
}

pub trait Store:
    DataStoreRead + DataStoreWrite + Send + Sync + StreamRead + StreamWrite + 'static
{
}
impl<T: DataStoreRead + DataStoreWrite + Send + Sync + StreamRead + StreamWrite + 'static> Store
    for T
{
}

/// Read the full value bytes for a KV pair out of the local flow store.
/// Ok(None) = data missing locally (tx never downloaded).
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

#[async_trait]
pub trait StreamRead {
    async fn get_holding_stream_ids(&self) -> Result<Vec<H256>>;

    async fn get_stream_data_sync_progress(&self) -> Result<u64>;

    async fn get_stream_replay_progress(&self) -> Result<u64>;

    async fn get_latest_version_before(
        &self,
        stream_id: H256,
        key: Arc<Vec<u8>>,
        before: u64,
    ) -> Result<u64>;

    async fn has_write_permission(
        &self,
        account: H160,
        stream_id: H256,
        key: Arc<Vec<u8>>,
        version: u64,
    ) -> Result<bool>;

    async fn can_write(&self, account: H160, stream_id: H256, version: u64) -> Result<bool>;

    async fn is_new_stream(&self, stream_id: H256, version: u64) -> Result<bool>;

    async fn is_admin(&self, account: H160, stream_id: H256, version: u64) -> Result<bool>;

    async fn is_special_key(
        &self,
        stream_id: H256,
        key: Arc<Vec<u8>>,
        version: u64,
    ) -> Result<bool>;

    async fn is_writer_of_key(
        &self,
        account: H160,
        stream_id: H256,
        key: Arc<Vec<u8>>,
        version: u64,
    ) -> Result<bool>;

    async fn is_writer_of_stream(
        &self,
        account: H160,
        stream_id: H256,
        version: u64,
    ) -> Result<bool>;

    async fn get_stream_key_value(
        &self,
        stream_id: H256,
        key: Arc<Vec<u8>>,
        version: u64,
    ) -> Result<Option<KeyValuePair>>;

    async fn get_next_stream_key_value(
        &self,
        stream_id: H256,
        key: Arc<Vec<u8>>,
        inclusive: bool,
        version: u64,
    ) -> Result<Option<KeyValuePair>>;

    async fn get_prev_stream_key_value(
        &self,
        stream_id: H256,
        key: Arc<Vec<u8>>,
        inclusive: bool,
        version: u64,
    ) -> Result<Option<KeyValuePair>>;

    async fn get_first(&self, stream_id: H256, version: u64) -> Result<Option<KeyValuePair>>;

    async fn get_last(&self, stream_id: H256, version: u64) -> Result<Option<KeyValuePair>>;

    async fn get_stale_stream_keys(
        &self,
        stream_id: H256,
        cutoff: u64,
        cursor: Vec<u8>,
        limit: u64,
    ) -> Result<Vec<StaleKey>>;

    async fn get_renew_attempt(
        &self,
        stream_id: H256,
        key: Vec<u8>,
    ) -> Result<Option<RenewAttempt>>;

    async fn list_stuck_renewals(
        &self,
        min_attempts: u64,
        limit: u64,
    ) -> Result<Vec<(H256, Vec<u8>, RenewAttempt)>>;
}

#[async_trait]
pub trait StreamWrite {
    async fn reset_stream_sync(&self, stream_ids: Vec<u8>) -> Result<()>;

    async fn update_stream_ids(&self, stream_ids: Vec<u8>) -> Result<()>;

    async fn update_stream_data_sync_progress(&self, from: u64, progress: u64) -> Result<u64>;

    async fn update_stream_replay_progress(&self, from: u64, progress: u64) -> Result<u64>;

    async fn put_stream(
        &self,
        tx_seq: u64,
        data_merkle_root: H256,
        result: String,
        commit_data: Option<(StreamWriteSet, AccessControlSet)>,
    ) -> Result<()>;

    async fn get_tx_result(&self, tx_seq: u64) -> Result<Option<String>>;

    async fn revert_stream(&mut self, tx_seq: u64) -> Result<()>;

    async fn record_renew_attempt(
        &self,
        stream_id: H256,
        key: Vec<u8>,
        ts: u64,
        tx_hash: Option<H256>,
        error: Option<String>,
    ) -> Result<()>;

    async fn clear_renew_attempt(&self, stream_id: H256, key: Vec<u8>) -> Result<()>;
}

#[cfg(test)]
mod read_pair_value_tests {
    use super::*;
    use crate::store::store_manager::StoreManager;

    fn make_tx(seq: u64, start_entry_index: u64, size: u64) -> KVTransaction {
        KVTransaction {
            stream_ids: vec![],
            sender: H160::zero(),
            data_merkle_root: H256::zero(),
            merkle_nodes: vec![(1, H256::zero())],
            start_entry_index,
            size,
            seq,
        }
    }

    #[tokio::test]
    async fn read_pair_value_roundtrip_and_missing() {
        let mut store = StoreManager::memorydb().await.unwrap();
        // One entry (256 bytes) of 0xAB seeded at flow index 1 (flow index 0
        // is reserved, see FlowStore::get_entries's batch-0 offset fixup).
        let tx = make_tx(0, 1, ENTRY_SIZE as u64);
        store.put_tx(tx.clone()).unwrap();
        let data = vec![0xABu8; ENTRY_SIZE];
        store
            .put_chunks_with_tx_hash(
                0,
                tx.hash(),
                ChunkArray {
                    data,
                    start_index: 0,
                },
                None,
            )
            .unwrap();

        let base = ENTRY_SIZE as u64; // absolute byte offset of entry 1
        let pair = KeyValuePair {
            stream_id: H256::zero(),
            key: b"k".to_vec(),
            start_index: base + 3,
            end_index: base + 10,
            version: 0,
        };
        assert_eq!(read_pair_value(&store, &pair).unwrap(), Some(vec![0xAB; 7]));

        let missing = KeyValuePair {
            stream_id: H256::zero(),
            key: b"k".to_vec(),
            start_index: 10_000_000,
            end_index: 10_000_005,
            version: 0,
        };
        assert_eq!(read_pair_value(&store, &missing).unwrap(), None);

        let empty = KeyValuePair {
            start_index: 5,
            end_index: 5,
            ..pair
        };
        assert_eq!(read_pair_value(&store, &empty).unwrap(), Some(vec![]));
    }
}
