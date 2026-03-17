use std::sync::Arc;

use async_trait::async_trait;
use ethereum_types::{H160, H256};
use kv_types::{AccessControlSet, KVTransaction, KeyValuePair, StreamWriteSet};
use shared_types::ChunkArray;

use shared_types::FlowProof;

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
}

pub trait Store:
    DataStoreRead + DataStoreWrite + Send + Sync + StreamRead + StreamWrite + 'static
{
}
impl<T: DataStoreRead + DataStoreWrite + Send + Sync + StreamRead + StreamWrite + 'static> Store
    for T
{
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
}
