use std::{cmp, sync::Arc};

use anyhow::{anyhow, bail, Result};

use shared_types::ChunkArray;
use ssz::{Decode, Encode};
use storage::{
    error::Error,
    log_store::{
        load_chunk::EntryBatchData,
        log_manager::{bytes_to_entries, ENTRY_SIZE},
    },
    ZgsKeyValueDB,
};
use tracing::{error, trace};

use crate::try_option;

use super::data_store::COL_ENTRY_BATCH;

pub const ENTRY_BATCH_SIZE: usize = 1024;

fn try_decode_usize(data: &[u8]) -> Result<usize> {
    Ok(usize::from_be_bytes(
        data.try_into().map_err(|e| anyhow!("{:?}", e))?,
    ))
}

fn decode_batch_index(data: &[u8]) -> Result<usize> {
    try_decode_usize(data)
}

pub struct FlowStore {
    kvdb: Arc<dyn ZgsKeyValueDB>,
}

impl FlowStore {
    pub fn new(kvdb: Arc<dyn ZgsKeyValueDB>) -> Self {
        Self { kvdb }
    }

    pub fn truncate(&self, start_index: u64) -> crate::error::Result<()> {
        let mut tx = self.kvdb.transaction();
        let mut start_batch_index = start_index / ENTRY_BATCH_SIZE as u64;
        let first_batch_offset = start_index as usize % ENTRY_BATCH_SIZE;
        if first_batch_offset != 0 {
            if let Some(mut first_batch) = self.get_entry_batch(start_batch_index)? {
                first_batch.truncate(first_batch_offset);
                if !first_batch.is_empty() {
                    tx.put(
                        COL_ENTRY_BATCH,
                        &start_batch_index.to_be_bytes(),
                        &first_batch.as_ssz_bytes(),
                    );
                } else {
                    tx.delete(COL_ENTRY_BATCH, &start_batch_index.to_be_bytes());
                }
            }

            start_batch_index += 1;
        }
        // TODO: `kvdb` and `kvdb-rocksdb` does not support `seek_to_last` yet.
        // We'll need to fork it or use another wrapper for a better performance in this.
        let end = match self.kvdb.iter(COL_ENTRY_BATCH).last() {
            Some(Ok((k, _))) => decode_batch_index(k.as_ref())?,
            Some(Err(e)) => {
                error!("truncate db error: e={:?}", e);
                return Err(e.into());
            }
            None => {
                // The db has no data, so we can just return;
                return Ok(());
            }
        };
        for batch_index in start_batch_index as usize..=end {
            tx.delete(COL_ENTRY_BATCH, &batch_index.to_be_bytes());
        }
        self.kvdb.write(tx)?;
        Ok(())
    }

    fn get_entry_batch(&self, batch_index: u64) -> Result<Option<EntryBatchData>> {
        let raw = try_option!(self.kvdb.get(COL_ENTRY_BATCH, &batch_index.to_be_bytes())?);
        Ok(Some(
            EntryBatchData::from_ssz_bytes(&raw).map_err(Error::from)?,
        ))
    }

    fn put_entry_batch_list(&self, batch_list: Vec<(u64, EntryBatchData)>) -> Result<()> {
        let mut tx = self.kvdb.transaction();
        for (batch_index, batch) in batch_list {
            tx.put(
                COL_ENTRY_BATCH,
                &batch_index.to_be_bytes(),
                &batch.as_ssz_bytes(),
            );
        }
        self.kvdb.write(tx)?;
        Ok(())
    }

    pub fn append_entries(&self, data: ChunkArray) -> Result<()> {
        trace!("append_entries: {} {}", data.start_index, data.data.len());
        if data.data.len() % ENTRY_SIZE != 0 {
            bail!("append_entries: invalid data size, len={}", data.data.len());
        }
        let mut batch_list = Vec::new();
        for (start_entry_index, end_entry_index) in batch_iter(
            data.start_index,
            data.start_index + bytes_to_entries(data.data.len() as u64),
            ENTRY_BATCH_SIZE,
        ) {
            let chunk = data
                .sub_array(start_entry_index, end_entry_index)
                .expect("in range");

            let chunk_index = chunk.start_index / ENTRY_BATCH_SIZE as u64;

            let mut batch = self
                .get_entry_batch(chunk_index)?
                .unwrap_or_else(EntryBatchData::new);
            let start_byte = (chunk.start_index % ENTRY_BATCH_SIZE as u64) as usize * ENTRY_SIZE;
            // check data existence
            if chunk.data.is_empty() || batch.get(start_byte, chunk.data.len()).is_some() {
                continue;
            }
            batch.insert_data(
                (chunk.start_index % ENTRY_BATCH_SIZE as u64) as usize * ENTRY_SIZE,
                chunk.data,
            )?;

            batch_list.push((chunk_index, batch));
        }

        self.put_entry_batch_list(batch_list)
    }

    pub fn get_entries(&self, index_start: u64, index_end: u64) -> Result<Option<ChunkArray>> {
        if index_end <= index_start {
            bail!(
                "invalid entry index: start={} end={}",
                index_start,
                index_end
            );
        }
        let mut data = Vec::with_capacity((index_end - index_start) as usize * ENTRY_SIZE);
        for (start_entry_index, end_entry_index) in
            batch_iter(index_start, index_end, ENTRY_BATCH_SIZE)
        {
            let chunk_index = start_entry_index / ENTRY_BATCH_SIZE as u64;
            let mut offset = start_entry_index - chunk_index * ENTRY_BATCH_SIZE as u64;
            let mut length = end_entry_index - start_entry_index;

            // Tempfix: for first chunk, its offset is always 1
            if chunk_index == 0 && offset == 0 {
                offset = 1;
                length -= 1;
            }

            let entry_batch = try_option!(self.get_entry_batch(chunk_index)?);
            let entry_batch_data = try_option!(
                entry_batch.get(offset as usize * ENTRY_SIZE, length as usize * ENTRY_SIZE)
            );
            data.append(&mut entry_batch_data.to_vec());
        }
        Ok(Some(ChunkArray {
            data,
            start_index: index_start,
        }))
    }
}

pub fn batch_iter(start: u64, end: u64, batch_size: usize) -> Vec<(u64, u64)> {
    let mut list = Vec::new();
    for i in (start / batch_size as u64 * batch_size as u64..end).step_by(batch_size) {
        let batch_start = cmp::max(start, i);
        let batch_end = cmp::min(end, i + batch_size as u64);
        list.push((batch_start, batch_end));
    }
    list
}
