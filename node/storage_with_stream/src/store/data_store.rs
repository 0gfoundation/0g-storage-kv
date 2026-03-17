use std::{path::Path, sync::Arc, time::Instant};

use anyhow::{anyhow, bail, Result};
use kv_types::KVTransaction;
use kvdb_rocksdb::{Database, DatabaseConfig};
use shared_types::{compute_padded_chunk_size, ChunkArray, FlowProof};

use storage::{
    log_store::{
        log_manager::{bytes_to_entries, ENTRY_SIZE, PORA_CHUNK_SIZE},
        tx_store::BlockHashAndSubmissionIndex,
    },
    H256,
};
use tracing::{debug, instrument, trace};

use super::{
    flow_store::{batch_iter, FlowStore},
    tx_store::TransactionStore,
};

pub const COL_TX: u32 = 0;
pub const COL_ENTRY_BATCH: u32 = 1;
pub const COL_TX_COMPLETED: u32 = 2;
pub const COL_MISC: u32 = 3;
pub const COL_BLOCK_PROGRESS: u32 = 4;
pub const COL_NUM: u32 = 5;

pub struct DataStore {
    flow_store: FlowStore,
    tx_store: TransactionStore,
}

impl DataStore {
    pub fn rocksdb(path: impl AsRef<Path>) -> Result<Self> {
        let mut db_config = DatabaseConfig::with_columns(COL_NUM);
        db_config.enable_statistics = true;
        let db = Arc::new(Database::open(&db_config, path)?);
        Ok(Self {
            flow_store: FlowStore::new(db.clone()),
            tx_store: TransactionStore::new(db.clone())?,
        })
    }

    pub fn memorydb() -> Self {
        let db = Arc::new(kvdb_memorydb::create(COL_NUM));
        Self {
            flow_store: FlowStore::new(db.clone()),
            tx_store: TransactionStore::new(db.clone()).unwrap(),
        }
    }

    #[instrument(skip(self))]
    pub fn put_tx(&self, tx: KVTransaction) -> Result<()> {
        self.tx_store.put_tx(tx)
    }

    pub fn put_sync_progress(&self, progress: (u64, H256, Option<Option<u64>>)) -> Result<()> {
        self.tx_store.put_progress(progress)
    }

    pub fn delete_block_hash_by_number(&self, block_number: u64) -> Result<()> {
        self.tx_store.delete_block_hash_by_number(block_number)
    }

    pub fn put_log_latest_block_number(&self, block_number: u64) -> Result<()> {
        self.tx_store.put_log_latest_block_number(block_number)
    }

    pub fn get_tx_by_seq_number(&self, seq: u64) -> Result<Option<KVTransaction>> {
        self.tx_store.get_tx_by_seq_number(seq)
    }

    pub fn check_tx_completed(&self, tx_seq: u64) -> Result<bool> {
        self.tx_store.check_tx_completed(tx_seq)
    }

    pub fn get_sync_progress(&self) -> Result<Option<(u64, H256)>> {
        self.tx_store.get_progress()
    }

    pub fn get_log_latest_block_number(&self) -> Result<Option<u64>> {
        self.tx_store.get_log_latest_block_number()
    }

    pub fn get_block_hashes(&self) -> Result<Vec<(u64, BlockHashAndSubmissionIndex)>> {
        self.tx_store.get_block_hashes()
    }

    pub fn next_tx_seq(&self) -> u64 {
        self.tx_store.next_tx_seq()
    }

    pub fn put_first_tx_seq(&self, first_tx_seq: u64) -> Result<()> {
        self.tx_store.put_first_tx_seq(first_tx_seq)
    }

    pub fn get_first_tx_seq(&self) -> Result<Option<u64>> {
        self.tx_store.get_first_tx_seq()
    }

    pub fn revert_to(&self, tx_seq: u64) -> Result<()> {
        let start = if tx_seq != u64::MAX { tx_seq + 1 } else { 0 };
        let removed_txs = self.tx_store.remove_tx_after(start)?;
        if !removed_txs.is_empty() {
            let start_index = removed_txs.first().unwrap().start_entry_index;
            self.flow_store.truncate(start_index)?;
        }
        Ok(())
    }

    pub fn finalize_tx_with_hash(&self, tx_seq: u64, tx_hash: H256) -> Result<bool> {
        let _start_time = Instant::now();
        trace!(
            "finalize_tx_with_hash: tx_seq={} tx_hash={:?}",
            tx_seq,
            tx_hash
        );
        let tx = self
            .tx_store
            .get_tx_by_seq_number(tx_seq)?
            .ok_or_else(|| anyhow!("finalize_tx with tx missing: tx_seq={}", tx_seq))?;
        debug!("finalize_tx_with_hash: tx={:?}", tx);
        if tx.hash() != tx_hash {
            return Ok(false);
        }

        let tx_end_index = tx.start_entry_index + bytes_to_entries(tx.size);
        if self.check_data_completed(tx.start_entry_index, tx_end_index)? {
            self.tx_store.finalize_tx(tx_seq)?;
            Ok(true)
        } else {
            bail!("finalize tx hash with data missing: tx_seq={}", tx_seq)
        }
    }

    pub fn check_data_completed(&self, start: u64, end: u64) -> Result<bool> {
        for (batch_start, batch_end) in batch_iter(start, end, PORA_CHUNK_SIZE) {
            if self
                .flow_store
                .get_entries(batch_start, batch_end)?
                .is_none()
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub fn put_chunks_with_tx_hash(
        &self,
        tx_seq: u64,
        tx_hash: H256,
        chunks: ChunkArray,
        _maybe_file_proof: Option<FlowProof>,
    ) -> Result<bool> {
        let tx = self
            .tx_store
            .get_tx_by_seq_number(tx_seq)?
            .ok_or_else(|| anyhow!("put chunks with missing tx: tx_seq={}", tx_seq))?;
        if tx.hash() != tx_hash {
            return Ok(false);
        }
        let (chunks_for_proof, _) = compute_padded_chunk_size(tx.size as usize);
        if chunks.start_index.saturating_mul(ENTRY_SIZE as u64) + chunks.data.len() as u64
            > (chunks_for_proof * ENTRY_SIZE) as u64
        {
            bail!(
                "put chunks with data out of tx range: tx_seq={} start_index={} data_len={}",
                tx_seq,
                chunks.start_index,
                chunks.data.len()
            );
        }
        // TODO: Use another struct to avoid confusion.
        let mut flow_entry_array = chunks;
        flow_entry_array.start_index += tx.start_entry_index;
        self.flow_store.append_entries(flow_entry_array)?;
        Ok(true)
    }

    pub fn get_chunk_by_flow_index(&self, index: u64, length: u64) -> Result<Option<ChunkArray>> {
        let start_flow_index = index;
        let end_flow_index = index + length;
        self.flow_store
            .get_entries(start_flow_index, end_flow_index)
    }
}
