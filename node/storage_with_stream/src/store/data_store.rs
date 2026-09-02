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
pub const COL_TX_TIME: u32 = 5;
pub const COL_NUM: u32 = 6;

/// Materializes any column family up to `target_columns` that an existing
/// on-disk database predates (e.g. `COL_TX_TIME`, added when `COL_NUM` grew
/// from 5 to 6). `kvdb_rocksdb::Database::open` cannot grow an existing
/// database itself: its fallback path reopens with an empty column list,
/// which RocksDB rejects once any column family already exists on disk
/// ("Column families not opened: col4, col3, ..."). A no-op for a database
/// that doesn't exist yet or is already at `target_columns`.
fn ensure_column_families(path: &Path, target_columns: u32) -> Result<()> {
    let probe_opts = rocksdb::Options::default();
    let existing = match rocksdb::DB::list_cf(&probe_opts, path) {
        Ok(cfs) => cfs,
        Err(_) => return Ok(()), // no existing database; nothing to migrate
    };

    let wanted: Vec<String> = (0..target_columns).map(|c| format!("col{}", c)).collect();
    if wanted.iter().all(|name| existing.contains(name)) {
        return Ok(());
    }

    let mut open_opts = rocksdb::Options::default();
    open_opts.create_missing_column_families(true);
    let descriptors = wanted
        .iter()
        .map(|name| rocksdb::ColumnFamilyDescriptor::new(name, rocksdb::Options::default()));
    // Opened only to force RocksDB to create the missing column families on
    // disk, then dropped; the real, tuned open happens right after in `rocksdb()`.
    rocksdb::DB::open_cf_descriptors(&open_opts, path, descriptors)
        .map_err(|e| anyhow!("Unable to create missing column families: {}", e))?;
    Ok(())
}

pub struct DataStore {
    flow_store: FlowStore,
    tx_store: TransactionStore,
}

impl DataStore {
    pub fn rocksdb(path: impl AsRef<Path>) -> Result<Self> {
        ensure_column_families(path.as_ref(), COL_NUM)?;
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

    pub fn put_tx_block_time(&self, tx_seq: u64, ts: u64) -> Result<()> {
        self.tx_store.put_block_time(tx_seq, ts)
    }

    pub fn get_tx_block_time(&self, tx_seq: u64) -> Result<Option<u64>> {
        self.tx_store.get_block_time(tx_seq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Reproduces the upgrade failure: a database created with the
    // pre-`COL_TX_TIME` column count (5) must still open once the code
    // expects 6. `kvdb_rocksdb::Database::open`'s own fallback can't do
    // this on an existing database -- see `ensure_column_families`.
    #[test]
    fn rocksdb_opens_after_column_count_grows() {
        let dir = tempdir::TempDir::new("data_store_migration_test").unwrap();
        let path = dir.path();

        {
            let old_config = DatabaseConfig::with_columns(5);
            Database::open(&old_config, path).expect("initial 5-column open");
        }

        DataStore::rocksdb(path).expect("re-opening with a grown column count must succeed");
    }
}
