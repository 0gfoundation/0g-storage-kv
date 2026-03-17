use crate::error::Error;
use crate::try_option;
use anyhow::{anyhow, Result};
use ethereum_types::H256;
use kv_types::KVTransaction;
use ssz::{Decode, Encode};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use storage::log_store::tx_store::BlockHashAndSubmissionIndex;
use storage::ZgsKeyValueDB;
use tracing::{error, instrument};

use super::data_store::{COL_BLOCK_PROGRESS, COL_MISC, COL_TX, COL_TX_COMPLETED};

const LOG_SYNC_PROGRESS_KEY: &str = "log_sync_progress";
const NEXT_TX_KEY: &str = "next_tx_seq";
const FIRST_TX_SEQ_KEY: &str = "first_tx_seq";
const LOG_LATEST_BLOCK_NUMBER_KEY: &str = "log_latest_block_number_key";

pub enum TxStatus {
    Finalized,
    Pruned,
}

impl From<TxStatus> for u8 {
    fn from(value: TxStatus) -> Self {
        match value {
            TxStatus::Finalized => 0,
            TxStatus::Pruned => 1,
        }
    }
}

impl TryFrom<u8> for TxStatus {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(TxStatus::Finalized),
            1 => Ok(TxStatus::Pruned),
            _ => Err(anyhow!("invalid value for tx status {}", value)),
        }
    }
}

pub struct TransactionStore {
    kvdb: Arc<dyn ZgsKeyValueDB>,
    /// This is always updated before writing the database to ensure no intermediate states.
    next_tx_seq: AtomicU64,
}

impl TransactionStore {
    pub fn new(kvdb: Arc<dyn ZgsKeyValueDB>) -> Result<Self> {
        let next_tx_seq = kvdb
            .get(COL_TX, NEXT_TX_KEY.as_bytes())?
            .map(|a| decode_tx_seq(&a))
            .unwrap_or(Ok(0))?;
        Ok(Self {
            kvdb,
            next_tx_seq: AtomicU64::new(next_tx_seq),
        })
    }

    #[instrument(skip(self))]
    pub fn put_tx(&self, tx: KVTransaction) -> Result<()> {
        let _start_time = Instant::now();

        let mut db_tx = self.kvdb.transaction();
        db_tx.put(COL_TX, &tx.seq.to_be_bytes(), &tx.as_ssz_bytes());
        db_tx.put(COL_TX, NEXT_TX_KEY.as_bytes(), &(tx.seq + 1).to_be_bytes());
        self.next_tx_seq.store(tx.seq + 1, Ordering::SeqCst);
        self.kvdb.write(db_tx)?;
        Ok(())
    }

    pub fn get_tx_by_seq_number(&self, seq: u64) -> Result<Option<KVTransaction>> {
        if seq >= self.next_tx_seq() {
            return Ok(None);
        }
        let value = try_option!(self.kvdb.get(COL_TX, &seq.to_be_bytes())?);
        let tx = KVTransaction::from_ssz_bytes(&value).map_err(Error::from)?;
        Ok(Some(tx))
    }

    pub fn remove_tx_after(&self, min_seq: u64) -> Result<Vec<KVTransaction>> {
        let mut removed_txs = Vec::new();
        let max_seq = self.next_tx_seq();
        let mut db_tx = self.kvdb.transaction();
        for seq in min_seq..max_seq {
            let Some(tx) = self.get_tx_by_seq_number(seq)? else {
                error!(?seq, ?max_seq, "Transaction missing before the end");
                break;
            };
            db_tx.delete(COL_TX, &seq.to_be_bytes());
            db_tx.delete(COL_TX_COMPLETED, &seq.to_be_bytes());
            removed_txs.push(tx);
        }
        db_tx.put(COL_TX, NEXT_TX_KEY.as_bytes(), &min_seq.to_be_bytes());
        self.next_tx_seq.store(min_seq, Ordering::SeqCst);
        self.kvdb.write(db_tx)?;
        Ok(removed_txs)
    }

    #[instrument(skip(self))]
    pub fn finalize_tx(&self, tx_seq: u64) -> Result<()> {
        Ok(self.kvdb.put(
            COL_TX_COMPLETED,
            &tx_seq.to_be_bytes(),
            &[TxStatus::Finalized.into()],
        )?)
    }

    pub fn get_tx_status(&self, tx_seq: u64) -> Result<Option<TxStatus>> {
        let value = try_option!(self.kvdb.get(COL_TX_COMPLETED, &tx_seq.to_be_bytes())?);
        match value.first() {
            Some(v) => Ok(Some(TxStatus::try_from(*v)?)),
            None => Ok(None),
        }
    }

    pub fn check_tx_completed(&self, tx_seq: u64) -> Result<bool> {
        let _start_time = Instant::now();
        let status = self.get_tx_status(tx_seq)?;

        Ok(matches!(status, Some(TxStatus::Finalized)))
    }

    pub fn next_tx_seq(&self) -> u64 {
        self.next_tx_seq.load(Ordering::SeqCst)
    }

    pub fn put_first_tx_seq(&self, first_tx_seq: u64) -> Result<()> {
        Ok(self.kvdb.put(
            COL_MISC,
            FIRST_TX_SEQ_KEY.as_bytes(),
            &first_tx_seq.to_be_bytes(),
        )?)
    }

    pub fn get_first_tx_seq(&self) -> Result<Option<u64>> {
        self.kvdb
            .get(COL_MISC, FIRST_TX_SEQ_KEY.as_bytes())?
            .map(|data| decode_tx_seq(&data))
            .transpose()
    }

    #[instrument(skip(self))]
    pub fn put_progress(&self, progress: (u64, H256, Option<Option<u64>>)) -> Result<()> {
        let mut items = vec![(
            COL_MISC,
            LOG_SYNC_PROGRESS_KEY.as_bytes().to_vec(),
            (progress.0, progress.1).as_ssz_bytes(),
        )];

        if let Some(p) = progress.2 {
            items.push((
                COL_BLOCK_PROGRESS,
                progress.0.to_be_bytes().to_vec(),
                (progress.1, p).as_ssz_bytes(),
            ));
        }
        Ok(self.kvdb.puts(items)?)
    }

    #[instrument(skip(self))]
    pub fn get_progress(&self) -> Result<Option<(u64, H256)>> {
        Ok(Some(
            <(u64, H256)>::from_ssz_bytes(&try_option!(self
                .kvdb
                .get(COL_MISC, LOG_SYNC_PROGRESS_KEY.as_bytes())?))
            .map_err(Error::from)?,
        ))
    }

    #[instrument(skip(self))]
    pub fn put_log_latest_block_number(&self, block_number: u64) -> Result<()> {
        Ok(self.kvdb.put(
            COL_MISC,
            LOG_LATEST_BLOCK_NUMBER_KEY.as_bytes(),
            &block_number.as_ssz_bytes(),
        )?)
    }

    #[instrument(skip(self))]
    pub fn get_log_latest_block_number(&self) -> Result<Option<u64>> {
        Ok(Some(
            <u64>::from_ssz_bytes(&try_option!(self
                .kvdb
                .get(COL_MISC, LOG_LATEST_BLOCK_NUMBER_KEY.as_bytes())?))
            .map_err(Error::from)?,
        ))
    }

    pub fn get_block_hashes(&self) -> Result<Vec<(u64, BlockHashAndSubmissionIndex)>> {
        let mut block_numbers = vec![];
        for r in self.kvdb.iter(COL_BLOCK_PROGRESS) {
            let (key, val) = r?;
            let block_number =
                u64::from_be_bytes(key.as_ref().try_into().map_err(|e| anyhow!("{:?}", e))?);
            let val = <(H256, Option<u64>)>::from_ssz_bytes(val.as_ref()).map_err(Error::from)?;

            block_numbers.push((
                block_number,
                BlockHashAndSubmissionIndex {
                    block_hash: val.0,
                    first_submission_index: val.1,
                },
            ));
        }

        Ok(block_numbers)
    }

    pub fn delete_block_hash_by_number(&self, block_number: u64) -> Result<()> {
        Ok(self
            .kvdb
            .delete(COL_BLOCK_PROGRESS, &block_number.to_be_bytes())?)
    }
}

fn decode_tx_seq(data: &[u8]) -> Result<u64> {
    Ok(u64::from_be_bytes(
        data.try_into().map_err(|e| anyhow!("{:?}", e))?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_store() -> TransactionStore {
        let db = Arc::new(kvdb_memorydb::create(super::super::data_store::COL_NUM));
        TransactionStore::new(db).unwrap()
    }

    #[test]
    fn test_first_tx_seq_not_set() {
        let store = create_test_store();
        assert_eq!(store.get_first_tx_seq().unwrap(), None);
    }

    #[test]
    fn test_first_tx_seq_persist_and_read() {
        let store = create_test_store();
        store.put_first_tx_seq(12345).unwrap();
        assert_eq!(store.get_first_tx_seq().unwrap(), Some(12345));
    }

    #[test]
    fn test_first_tx_seq_zero() {
        let store = create_test_store();
        store.put_first_tx_seq(0).unwrap();
        assert_eq!(store.get_first_tx_seq().unwrap(), Some(0));
    }

    #[test]
    fn test_fresh_db_next_tx_seq_is_zero() {
        let store = create_test_store();
        assert_eq!(store.next_tx_seq(), 0);
    }
}
