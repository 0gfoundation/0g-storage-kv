use crate::stream_manager::error::ParseError;
use crate::stream_manager::skippable;
use crate::StreamConfig;
use anyhow::{bail, Result};
use ethereum_types::{H160, H256};
use kv_types::{
    AccessControl, AccessControlSet, KVTransaction, StreamRead, StreamReadSet, StreamWrite,
    StreamWriteSet,
};
use ssz::Decode;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::str;
use std::{cmp, sync::Arc, time::Duration};
use storage_with_stream::error::Error;
use storage_with_stream::log_store::log_manager::ENTRY_SIZE;
use storage_with_stream::store::to_access_control_op_name;
use storage_with_stream::AccessControlOps;
use storage_with_stream::Store;
use tokio::sync::RwLock;

use zg_storage_client::transfer::encryption::ENCRYPTION_HEADER_SIZE;

use super::RETRY_WAIT_MS;

const MAX_LOAD_ENTRY_SIZE: u64 = 10;
const STREAM_ID_SIZE: u64 = 32;
const STREAM_KEY_LEN_SIZE: u64 = 3;
const SET_LEN_SIZE: u64 = 4;
const DATA_LEN_SIZE: u64 = 8;
const VERSION_SIZE: u64 = 8;
const ACCESS_CONTROL_OP_TYPE_SIZE: u64 = 1;
const ADDRESS_SIZE: u64 = 20;
const MAX_SIZE_LEN: u32 = 65536;

enum ReplayResult {
    Commit(u64, StreamWriteSet, AccessControlSet),
    DataParseError(String),
    VersionConfliction,
    TagsMismatch,
    SenderNoWritePermission,
    WritePermissionDenied(H256, Arc<Vec<u8>>),
    AccessControlPermissionDenied(u8, H256, Arc<Vec<u8>>, H160),
    DataUnavailable,
}

fn truncated_key(key: &[u8]) -> String {
    if key.is_empty() {
        return "NONE".to_owned();
    }
    let key_str = str::from_utf8(key).unwrap_or("UNKNOWN");
    match key_str.char_indices().nth(32) {
        None => key_str.to_owned(),
        Some((idx, _)) => key_str[0..idx].to_owned(),
    }
}

impl fmt::Display for ReplayResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ReplayResult::Commit(_, _, _) => write!(f, "Commit"),
            ReplayResult::DataParseError(e) => write!(f, "DataParseError: {}", e),
            ReplayResult::VersionConfliction => write!(f, "VersionConfliction"),
            ReplayResult::TagsMismatch => write!(f, "TagsMismatch"),
            ReplayResult::SenderNoWritePermission => write!(f, "SenderNoWritePermission"),
            ReplayResult::WritePermissionDenied(stream_id, key) => write!(
                f,
                "WritePermissionDenied: stream: {:?}, key: {}",
                stream_id,
                truncated_key(key),
            ),
            ReplayResult::AccessControlPermissionDenied(op_type, stream_id, key, account) => {
                write!(
                    f,
                    "AccessControlPermissionDenied: operation: {}, stream: {:?}, key: {}, account: {:?}",
                    to_access_control_op_name(*op_type),
                    stream_id,
                    truncated_key(key),
                    account
                )
            }
            ReplayResult::DataUnavailable => write!(f, "DataUnavailable"),
        }
    }
}

struct StreamReader<'a> {
    store: Arc<RwLock<dyn Store>>,
    tx: &'a KVTransaction,
    tx_size_in_entry: u64,
    current_position: u64, // the index of next entry to read
    buffer: Vec<u8>,       // buffered data
}

impl<'a> StreamReader<'a> {
    pub fn new(store: Arc<RwLock<dyn Store>>, tx: &'a KVTransaction) -> Self {
        Self {
            store,
            tx,
            tx_size_in_entry: if tx.size % ENTRY_SIZE as u64 == 0 {
                tx.size / ENTRY_SIZE as u64
            } else {
                tx.size / ENTRY_SIZE as u64 + 1
            },
            current_position: 0,
            buffer: vec![],
        }
    }

    pub fn current_position_in_bytes(&self) -> u64 {
        (self.current_position + self.tx.start_entry_index) * (ENTRY_SIZE as u64)
            - (self.buffer.len() as u64)
    }

    async fn load(&mut self, length: u64) -> Result<()> {
        match self
            .store
            .read()
            .await
            .get_chunk_by_flow_index(self.current_position + self.tx.start_entry_index, length)?
        {
            Some(mut x) => {
                self.buffer.append(&mut x.data);
                self.current_position += length;
                Ok(())
            }
            None => {
                bail!(ParseError::PartialDataAvailable);
            }
        }
    }

    // read next ${size} bytes from the stream
    pub async fn next(&mut self, size: u64) -> Result<Vec<u8>> {
        if (self.buffer.len() as u64)
            + (self.tx_size_in_entry - self.current_position) * (ENTRY_SIZE as u64)
            < size
        {
            bail!(ParseError::InvalidData);
        }
        while (self.buffer.len() as u64) < size {
            self.load(cmp::min(
                self.tx_size_in_entry - self.current_position,
                MAX_LOAD_ENTRY_SIZE,
            ))
            .await?;
        }
        Ok(self.buffer.drain(0..(size as usize)).collect())
    }

    pub async fn skip(&mut self, mut size: u64) -> Result<()> {
        if (self.buffer.len() as u64) >= size {
            self.buffer.drain(0..(size as usize));
            return Ok(());
        }
        size -= self.buffer.len() as u64;
        self.buffer.clear();
        let entries_to_skip = size / (ENTRY_SIZE as u64);
        self.current_position += entries_to_skip;
        if self.current_position > self.tx_size_in_entry {
            bail!(ParseError::InvalidData);
        }
        size -= entries_to_skip * (ENTRY_SIZE as u64);
        if size > 0 {
            self.next(size).await?;
        }
        Ok(())
    }
}

pub struct StreamReplayer {
    config: StreamConfig,
    store: Arc<RwLock<dyn Store>>,
}

impl StreamReplayer {
    pub async fn new(config: StreamConfig, store: Arc<RwLock<dyn Store>>) -> Result<Self> {
        Ok(Self { config, store })
    }

    async fn parse_version(&self, stream_reader: &mut StreamReader<'_>) -> Result<u64> {
        Ok(u64::from_be_bytes(
            stream_reader.next(VERSION_SIZE).await?.try_into().unwrap(),
        ))
    }

    async fn parse_key(&self, stream_reader: &mut StreamReader<'_>) -> Result<Vec<u8>> {
        let mut key_size_in_bytes = vec![0x0; (8 - STREAM_KEY_LEN_SIZE) as usize];
        key_size_in_bytes.append(&mut stream_reader.next(STREAM_KEY_LEN_SIZE).await?);
        let key_size = u64::from_be_bytes(key_size_in_bytes.try_into().unwrap());
        // key should not be empty
        if key_size == 0 {
            bail!(ParseError::InvalidData);
        }
        stream_reader.next(key_size).await
    }

    async fn parse_stream_read_set(
        &self,
        stream_reader: &mut StreamReader<'_>,
    ) -> Result<StreamReadSet> {
        let size = u32::from_be_bytes(stream_reader.next(SET_LEN_SIZE).await?.try_into().unwrap());
        if size > MAX_SIZE_LEN {
            bail!(ParseError::ListTooLong);
        }
        let mut stream_read_set = StreamReadSet {
            stream_reads: vec![],
        };
        for _ in 0..(size as usize) {
            stream_read_set.stream_reads.push(StreamRead {
                stream_id: H256::from_ssz_bytes(&stream_reader.next(STREAM_ID_SIZE).await?)
                    .map_err(Error::from)?,
                key: Arc::new(self.parse_key(stream_reader).await?),
            });
        }
        Ok(stream_read_set)
    }

    async fn validate_stream_read_set(
        &self,
        stream_read_set: &StreamReadSet,
        tx: &KVTransaction,
        version: u64,
    ) -> Result<Option<ReplayResult>> {
        for stream_read in stream_read_set.stream_reads.iter() {
            if !self.config.stream_set.contains(&stream_read.stream_id) {
                return Ok(Some(ReplayResult::TagsMismatch));
            }
            // check version confiction
            if self
                .store
                .read()
                .await
                .get_latest_version_before(stream_read.stream_id, stream_read.key.clone(), tx.seq)
                .await?
                > version
            {
                return Ok(Some(ReplayResult::VersionConfliction));
            }
        }
        Ok(None)
    }

    async fn parse_stream_write_set(
        &self,
        stream_reader: &mut StreamReader<'_>,
    ) -> Result<StreamWriteSet> {
        let size = u32::from_be_bytes(stream_reader.next(SET_LEN_SIZE).await?.try_into().unwrap());
        if size > MAX_SIZE_LEN {
            bail!(ParseError::ListTooLong);
        }
        // load metadata
        let mut stream_write_metadata = vec![];
        for _ in 0..(size as usize) {
            let stream_id = H256::from_ssz_bytes(&stream_reader.next(STREAM_ID_SIZE).await?)
                .map_err(Error::from)?;
            let key = Arc::new(self.parse_key(stream_reader).await?);
            let data_size =
                u64::from_be_bytes(stream_reader.next(DATA_LEN_SIZE).await?.try_into().unwrap());
            stream_write_metadata.push((stream_id, key, data_size));
        }
        // use a hashmap to filter out the duplicate writes on same key, only the last one is reserved
        let mut start_index = stream_reader.current_position_in_bytes();
        let mut stream_writes = HashMap::new();
        for (stream_id, key, data_size) in stream_write_metadata.iter() {
            let end_index = start_index + data_size;
            stream_writes.insert(
                (stream_id, key.clone()),
                StreamWrite {
                    stream_id: *stream_id,
                    key: key.clone(),
                    start_index,
                    end_index,
                },
            );
            start_index = end_index;
        }
        // skip the write data
        stream_reader
            .skip(start_index - stream_reader.current_position_in_bytes())
            .await?;
        Ok(StreamWriteSet {
            stream_writes: stream_writes.into_values().collect(),
        })
    }

    async fn validate_stream_write_set(
        &self,
        stream_write_set: &StreamWriteSet,
        tx: &KVTransaction,
        version: u64,
    ) -> Result<Option<ReplayResult>> {
        let stream_set = HashSet::<H256>::from_iter(tx.stream_ids.iter().cloned());
        let store_read = self.store.read().await;
        for stream_write in stream_write_set.stream_writes.iter() {
            if !stream_set.contains(&stream_write.stream_id) {
                // the write set in data is conflict with tx tags
                return Ok(Some(ReplayResult::TagsMismatch));
            }
            // check version confiction
            if store_read
                .get_latest_version_before(stream_write.stream_id, stream_write.key.clone(), tx.seq)
                .await?
                > version
            {
                return Ok(Some(ReplayResult::VersionConfliction));
            }
            // check write permission
            if !(store_read
                .has_write_permission(
                    tx.sender,
                    stream_write.stream_id,
                    stream_write.key.clone(),
                    tx.seq,
                )
                .await?)
            {
                return Ok(Some(ReplayResult::WritePermissionDenied(
                    stream_write.stream_id,
                    stream_write.key.clone(),
                )));
            }
        }
        Ok(None)
    }

    async fn parse_access_control_data(
        &self,
        tx: &KVTransaction,
        stream_reader: &mut StreamReader<'_>,
    ) -> Result<AccessControlSet> {
        let size = u32::from_be_bytes(stream_reader.next(SET_LEN_SIZE).await?.try_into().unwrap());
        if size > MAX_SIZE_LEN {
            bail!(ParseError::ListTooLong);
        }
        // use a hashmap to filter out the useless operations
        // all operations can be categorized by op_type & 0xf0
        // for each category, except GRANT_ADMIN_ROLE, only the last operation of each account is reserved
        let mut access_ops = HashMap::new();
        // pad GRANT_ADMIN_ROLE prefix to handle the first write to new stream
        let mut is_admin = HashSet::new();
        let store_read = self.store.read().await;
        for id in &tx.stream_ids {
            if store_read.is_new_stream(*id, tx.seq).await? {
                let op_meta = (
                    AccessControlOps::GRANT_ADMIN_ROLE & 0xf0,
                    *id,
                    Arc::new(vec![]),
                    tx.sender,
                );
                access_ops.insert(
                    op_meta,
                    AccessControl {
                        op_type: AccessControlOps::GRANT_ADMIN_ROLE,
                        stream_id: *id,
                        key: Arc::new(vec![]),
                        account: tx.sender,
                        operator: H160::zero(),
                    },
                );
                is_admin.insert(*id);
            } else if store_read.is_admin(tx.sender, *id, tx.seq).await? {
                is_admin.insert(*id);
            }
        }
        drop(store_read);
        // ops in transaction
        for _ in 0..(size as usize) {
            let op_type = u8::from_be_bytes(
                stream_reader
                    .next(ACCESS_CONTROL_OP_TYPE_SIZE)
                    .await?
                    .try_into()
                    .unwrap(),
            );
            // parse operation data
            let stream_id = H256::from_ssz_bytes(&stream_reader.next(STREAM_ID_SIZE).await?)
                .map_err(Error::from)?;
            let mut account = H160::zero();
            let mut key = Arc::new(vec![]);
            match op_type {
                // stream_id + account
                AccessControlOps::GRANT_ADMIN_ROLE
                | AccessControlOps::GRANT_WRITER_ROLE
                | AccessControlOps::REVOKE_WRITER_ROLE => {
                    account = H160::from_ssz_bytes(&stream_reader.next(ADDRESS_SIZE).await?)
                        .map_err(Error::from)?;
                }
                // stream_id + key
                AccessControlOps::SET_KEY_TO_NORMAL | AccessControlOps::SET_KEY_TO_SPECIAL => {
                    key = Arc::new(self.parse_key(stream_reader).await?);
                }
                // stream_id + key + account
                AccessControlOps::GRANT_SPECIAL_WRITER_ROLE
                | AccessControlOps::REVOKE_SPECIAL_WRITER_ROLE => {
                    key = Arc::new(self.parse_key(stream_reader).await?);
                    account = H160::from_ssz_bytes(&stream_reader.next(ADDRESS_SIZE).await?)
                        .map_err(Error::from)?;
                }
                // renounce type
                AccessControlOps::RENOUNCE_ADMIN_ROLE | AccessControlOps::RENOUNCE_WRITER_ROLE => {
                    account = tx.sender;
                }
                AccessControlOps::RENOUNCE_SPECIAL_WRITER_ROLE => {
                    key = Arc::new(self.parse_key(stream_reader).await?);
                    account = tx.sender;
                }
                // unexpected type
                _ => {
                    bail!(ParseError::InvalidData);
                }
            }
            let op_meta = (op_type & 0xf0, stream_id, key.clone(), account);
            if op_type != AccessControlOps::GRANT_ADMIN_ROLE
                || (!access_ops.contains_key(&op_meta) && account != tx.sender)
            {
                access_ops.insert(
                    op_meta,
                    AccessControl {
                        op_type,
                        stream_id,
                        key: key.clone(),
                        account,
                        operator: tx.sender,
                    },
                );
            }
        }
        Ok(AccessControlSet {
            access_controls: access_ops.into_values().collect(),
            is_admin,
        })
    }

    async fn validate_access_control_set(
        &self,
        access_control_set: &mut AccessControlSet,
        tx: &KVTransaction,
    ) -> Result<Option<ReplayResult>> {
        // validate
        let store_read = self.store.read().await;
        let stream_set = HashSet::<H256>::from_iter(tx.stream_ids.iter().cloned());
        for access_control in &access_control_set.access_controls {
            if !stream_set.contains(&access_control.stream_id) {
                // the write set in data is conflict with tx tags
                return Ok(Some(ReplayResult::TagsMismatch));
            }
            match access_control.op_type {
                AccessControlOps::GRANT_ADMIN_ROLE
                | AccessControlOps::SET_KEY_TO_NORMAL
                | AccessControlOps::SET_KEY_TO_SPECIAL
                | AccessControlOps::REVOKE_WRITER_ROLE
                | AccessControlOps::REVOKE_SPECIAL_WRITER_ROLE => {
                    if !access_control_set
                        .is_admin
                        .contains(&access_control.stream_id)
                    {
                        return Ok(Some(ReplayResult::AccessControlPermissionDenied(
                            access_control.op_type,
                            access_control.stream_id,
                            access_control.key.clone(),
                            access_control.account,
                        )));
                    }
                }
                AccessControlOps::GRANT_WRITER_ROLE => {
                    if !access_control_set
                        .is_admin
                        .contains(&access_control.stream_id)
                        && !store_read
                            .is_writer_of_stream(tx.sender, access_control.stream_id, tx.seq)
                            .await?
                    {
                        return Ok(Some(ReplayResult::AccessControlPermissionDenied(
                            access_control.op_type,
                            access_control.stream_id,
                            access_control.key.clone(),
                            access_control.account,
                        )));
                    }
                }
                AccessControlOps::GRANT_SPECIAL_WRITER_ROLE => {
                    if !access_control_set
                        .is_admin
                        .contains(&access_control.stream_id)
                        && !store_read
                            .is_writer_of_key(
                                tx.sender,
                                access_control.stream_id,
                                access_control.key.clone(),
                                tx.seq,
                            )
                            .await?
                    {
                        return Ok(Some(ReplayResult::AccessControlPermissionDenied(
                            access_control.op_type,
                            access_control.stream_id,
                            access_control.key.clone(),
                            access_control.account,
                        )));
                    }
                }
                _ => {}
            }
        }
        Ok(None)
    }

    async fn replay(&self, tx: &KVTransaction) -> Result<ReplayResult> {
        if !self.store.read().await.check_tx_completed(tx.seq)? {
            return Ok(ReplayResult::DataUnavailable);
        }
        let mut stream_reader = StreamReader::new(self.store.clone(), tx);
        // Skip encryption header if encryption is configured
        if self.config.encryption_key.is_some() {
            stream_reader.skip(ENCRYPTION_HEADER_SIZE as u64).await?;
        }
        // parse and validate
        let version = self.parse_version(&mut stream_reader).await?;
        let stream_read_set = match self.parse_stream_read_set(&mut stream_reader).await {
            Ok(x) => x,
            Err(e) => match e.downcast_ref::<ParseError>() {
                Some(ParseError::InvalidData | ParseError::ListTooLong) => {
                    return Ok(ReplayResult::DataParseError(e.to_string()));
                }
                Some(ParseError::PartialDataAvailable) | None => {
                    return Err(e);
                }
            },
        };
        if let Some(result) = self
            .validate_stream_read_set(&stream_read_set, tx, version)
            .await?
        {
            // validation error in stream read set
            return Ok(result);
        }
        let stream_write_set = match self.parse_stream_write_set(&mut stream_reader).await {
            Ok(x) => x,
            Err(e) => match e.downcast_ref::<ParseError>() {
                Some(ParseError::InvalidData | ParseError::ListTooLong) => {
                    return Ok(ReplayResult::DataParseError(e.to_string()));
                }
                Some(ParseError::PartialDataAvailable) | None => {
                    return Err(e);
                }
            },
        };
        if let Some(result) = self
            .validate_stream_write_set(&stream_write_set, tx, version)
            .await?
        {
            // validation error in stream write set
            return Ok(result);
        }
        let mut access_control_set =
            match self.parse_access_control_data(tx, &mut stream_reader).await {
                Ok(x) => x,
                Err(e) => match e.downcast_ref::<ParseError>() {
                    Some(ParseError::InvalidData | ParseError::ListTooLong) => {
                        return Ok(ReplayResult::DataParseError(e.to_string()));
                    }
                    Some(ParseError::PartialDataAvailable) | None => {
                        return Err(e);
                    }
                },
            };
        if let Some(result) = self
            .validate_access_control_set(&mut access_control_set, tx)
            .await?
        {
            // there is confliction in access control set
            return Ok(result);
        }
        Ok(ReplayResult::Commit(
            tx.seq,
            stream_write_set,
            access_control_set,
        ))
    }

    pub async fn run(&self) {
        let mut tx_seq;
        match self.store.read().await.get_stream_replay_progress().await {
            Ok(progress) => {
                tx_seq = progress;
            }
            Err(e) => {
                error!("get stream replay progress error: e={:?}", e);
                return;
            }
        }
        let mut check_replay_progress = false;
        loop {
            if check_replay_progress {
                match self.store.read().await.get_stream_replay_progress().await {
                    Ok(progress) => {
                        if tx_seq != progress {
                            debug!("reorg happend: tx_seq {}, progress {}", tx_seq, progress);
                            tx_seq = progress;
                        }
                    }
                    Err(e) => {
                        error!("get stream replay progress error: e={:?}", e);
                    }
                }

                check_replay_progress = false;
            }

            info!("checking tx with sequence number {:?}..", tx_seq);
            let maybe_tx = self.store.read().await.get_tx_by_seq_number(tx_seq);
            match maybe_tx {
                Ok(Some(tx)) => {
                    let (stream_matched, can_write) =
                        match skippable(&tx, &self.config, self.store.clone()).await {
                            Ok(ok) => ok,
                            Err(e) => {
                                error!("check skippable error: e={:?}", e);
                                check_replay_progress = true;
                                continue;
                            }
                        };
                    // replay data
                    if stream_matched && can_write {
                        info!("replaying data of tx with sequence number {:?}..", tx.seq);
                        match self.replay(&tx).await {
                            Ok(result) => {
                                let result_str = result.to_string();
                                match result {
                                    ReplayResult::Commit(
                                        tx_seq,
                                        stream_write_set,
                                        access_control_set,
                                    ) => {
                                        match self
                                            .store
                                            .write()
                                            .await
                                            .put_stream(
                                                tx_seq,
                                                tx.data_merkle_root,
                                                result_str.clone(),
                                                Some((stream_write_set, access_control_set)),
                                            )
                                            .await
                                        {
                                            Ok(_) => {
                                                info!(
                                                    "tx with sequence number {:?} commit.",
                                                    tx.seq
                                                );
                                            }
                                            Err(e) => {
                                                error!("stream replay result finalization error: e={:?}", e);
                                                check_replay_progress = true;
                                                continue;
                                            }
                                        }
                                    }
                                    ReplayResult::DataUnavailable => {
                                        // data not available
                                        info!("data of tx with sequence number {:?} is not available yet, wait..", tx.seq);
                                        tokio::time::sleep(Duration::from_millis(RETRY_WAIT_MS))
                                            .await;
                                        check_replay_progress = true;
                                        continue;
                                    }
                                    _ => {
                                        match self
                                            .store
                                            .write()
                                            .await
                                            .put_stream(
                                                tx.seq,
                                                tx.data_merkle_root,
                                                result_str.clone(),
                                                None,
                                            )
                                            .await
                                        {
                                            Ok(_) => {
                                                info!(
                                                    "tx with sequence number {:?} reverted with reason {:?}",
                                                    tx.seq, result_str
                                                );
                                            }
                                            Err(e) => {
                                                error!("stream replay result finalization error: e={:?}", e);
                                                check_replay_progress = true;
                                                continue;
                                            }
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                error!("replay stream data error: e={:?}", e);
                                tokio::time::sleep(Duration::from_millis(RETRY_WAIT_MS)).await;
                                check_replay_progress = true;
                                continue;
                            }
                        }
                    } else if stream_matched {
                        info!(
                            "tx {:?} is in stream but sender has no write permission.",
                            tx.seq
                        );
                        let result_str = ReplayResult::SenderNoWritePermission.to_string();
                        match self
                            .store
                            .write()
                            .await
                            .put_stream(tx.seq, tx.data_merkle_root, result_str.clone(), None)
                            .await
                        {
                            Ok(_) => {
                                info!(
                                    "tx with sequence number {:?} reverted with reason {:?}",
                                    tx.seq, result_str
                                );
                            }
                            Err(e) => {
                                error!("stream replay result finalization error: e={:?}", e);
                                check_replay_progress = true;
                                continue;
                            }
                        }
                    } else {
                        info!("tx {:?} is not in stream, skipped.", tx.seq);
                    }
                    // parse success
                    // update progress, get next tx_seq to sync
                    match self
                        .store
                        .write()
                        .await
                        .update_stream_replay_progress(tx_seq, tx_seq + 1)
                        .await
                    {
                        Ok(next_tx_seq) => {
                            tx_seq = next_tx_seq;
                        }
                        Err(e) => {
                            error!("update stream replay progress error: e={:?}", e);
                        }
                    }
                }
                Ok(None) => {
                    tokio::time::sleep(Duration::from_millis(RETRY_WAIT_MS)).await;
                    check_replay_progress = true;
                }
                Err(e) => {
                    error!("stream replay error: e={:?}", e);
                    tokio::time::sleep(Duration::from_millis(RETRY_WAIT_MS)).await;
                    check_replay_progress = true;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared_types::ChunkArray;
    use storage_with_stream::StoreManager;
    use zg_storage_client::transfer::encryption::{crypt_at, EncryptionHeader};

    /// Build KV binary format data with one write entry.
    /// Format: version(8) + read_set(4) + write_set_count(4) + [stream_id(32) + key_len(3) + key + data_len(8)] + value_data + access_control(4)
    fn build_kv_data(stream_id: H256, key: &[u8], value: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        // Version: u64 BE = 1
        data.extend_from_slice(&1u64.to_be_bytes());
        // Read set count: u32 BE = 0
        data.extend_from_slice(&0u32.to_be_bytes());
        // Write set count: u32 BE = 1
        data.extend_from_slice(&1u32.to_be_bytes());
        // Write metadata:
        //   stream_id: 32 bytes
        data.extend_from_slice(stream_id.as_bytes());
        //   key_len: 3 bytes (last 3 bytes of u64 BE)
        let key_len_bytes = (key.len() as u64).to_be_bytes();
        data.extend_from_slice(&key_len_bytes[5..8]);
        //   key
        data.extend_from_slice(key);
        //   data_len: u64 BE
        data.extend_from_slice(&(value.len() as u64).to_be_bytes());
        // Write data
        data.extend_from_slice(value);
        // Access control count: u32 BE = 0
        data.extend_from_slice(&0u32.to_be_bytes());
        data
    }

    /// Pad data to 256-byte entry boundary.
    fn pad_to_entries(data: &[u8]) -> Vec<u8> {
        let padded_len = ((data.len() + ENTRY_SIZE - 1) / ENTRY_SIZE) * ENTRY_SIZE;
        let mut padded = data.to_vec();
        padded.resize(padded_len, 0);
        padded
    }

    /// Create a memorydb store with a single tx containing the given data.
    /// Returns the store and the tx for use in tests.
    async fn setup_store_with_data(
        data: &[u8],
        stream_id: H256,
    ) -> (Arc<RwLock<dyn Store>>, KVTransaction) {
        let store_manager = StoreManager::memorydb().await.unwrap();
        let store: Arc<RwLock<dyn Store>> = Arc::new(RwLock::new(store_manager));
        let padded = pad_to_entries(data);
        let tx = KVTransaction {
            stream_ids: vec![stream_id],
            sender: H160::zero(),
            data_merkle_root: H256::zero(),
            merkle_nodes: vec![(1, H256::zero())],
            start_entry_index: 1, // avoid flow store batch-0 offset-0 issue
            size: data.len() as u64,
            seq: 0,
        };
        let tx_hash = tx.hash();
        {
            let mut s = store.write().await;
            s.put_tx(tx.clone()).unwrap();
            assert!(s
                .put_chunks_with_tx_hash(
                    0,
                    tx_hash,
                    ChunkArray {
                        data: padded,
                        start_index: 0, // relative to tx start
                    },
                    None,
                )
                .unwrap());
            assert!(s.finalize_tx_with_hash(0, tx_hash).unwrap());
        }
        (store, tx)
    }

    #[tokio::test]
    async fn test_stream_reader_plain() {
        let stream_id = H256::from_low_u64_be(1);
        let key = b"mykey";
        let value = b"hello world";
        let kv_data = build_kv_data(stream_id, key, value);

        let (store, tx) = setup_store_with_data(&kv_data, stream_id).await;

        let mut reader = StreamReader::new(store.clone(), &tx);

        // Read version
        let version =
            u64::from_be_bytes(reader.next(VERSION_SIZE).await.unwrap().try_into().unwrap());
        assert_eq!(version, 1);

        // Read read-set count
        let read_set_count =
            u32::from_be_bytes(reader.next(SET_LEN_SIZE).await.unwrap().try_into().unwrap());
        assert_eq!(read_set_count, 0);

        // Read write-set count
        let write_set_count =
            u32::from_be_bytes(reader.next(SET_LEN_SIZE).await.unwrap().try_into().unwrap());
        assert_eq!(write_set_count, 1);

        // Read stream_id
        let sid_bytes = reader.next(STREAM_ID_SIZE).await.unwrap();
        assert_eq!(H256::from_slice(&sid_bytes), stream_id);

        // Read key_len (3-byte big-endian)
        let mut key_len_padded = vec![0u8; 5];
        key_len_padded.extend_from_slice(&reader.next(STREAM_KEY_LEN_SIZE).await.unwrap());
        let key_len = u64::from_be_bytes(key_len_padded.try_into().unwrap());
        assert_eq!(key_len, 5);

        // Read key
        let read_key = reader.next(key_len).await.unwrap();
        assert_eq!(read_key, key.to_vec());

        // Read data_len
        let data_size = u64::from_be_bytes(
            reader
                .next(DATA_LEN_SIZE)
                .await
                .unwrap()
                .try_into()
                .unwrap(),
        );
        assert_eq!(data_size, value.len() as u64);

        // Read value data
        let read_value = reader.next(data_size).await.unwrap();
        assert_eq!(read_value, value.to_vec());
    }

    #[tokio::test]
    async fn test_stream_reader_encrypted_header_skip() {
        let stream_id = H256::from_low_u64_be(1);
        let key = b"mykey";
        let value = b"hello world";
        let kv_data = build_kv_data(stream_id, key, value);

        // Prepend encryption header (simulating decrypt-before-store)
        let header = EncryptionHeader::new();
        let mut stored_data = header.to_bytes().to_vec();
        stored_data.extend_from_slice(&kv_data);

        let (store, tx) = setup_store_with_data(&stored_data, stream_id).await;
        let mut reader = StreamReader::new(store.clone(), &tx);

        // Skip encryption header
        reader.skip(ENCRYPTION_HEADER_SIZE as u64).await.unwrap();

        // Should now read the KV data correctly
        let version =
            u64::from_be_bytes(reader.next(VERSION_SIZE).await.unwrap().try_into().unwrap());
        assert_eq!(version, 1);

        let read_set_count =
            u32::from_be_bytes(reader.next(SET_LEN_SIZE).await.unwrap().try_into().unwrap());
        assert_eq!(read_set_count, 0);

        let write_set_count =
            u32::from_be_bytes(reader.next(SET_LEN_SIZE).await.unwrap().try_into().unwrap());
        assert_eq!(write_set_count, 1);

        // Read stream_id
        let sid_bytes = reader.next(STREAM_ID_SIZE).await.unwrap();
        assert_eq!(H256::from_slice(&sid_bytes), stream_id);
    }

    #[tokio::test]
    async fn test_replay_plain_data() {
        let stream_id = H256::from_low_u64_be(1);
        let key = b"mykey";
        let value = b"hello world";
        let kv_data = build_kv_data(stream_id, key, value);

        let (store, tx) = setup_store_with_data(&kv_data, stream_id).await;

        let config = StreamConfig {
            stream_ids: vec![stream_id],
            stream_set: HashSet::from([stream_id]),
            encryption_key: None,
        };

        let replayer = StreamReplayer::new(config, store).await.unwrap();
        let result = replayer.replay(&tx).await.unwrap();

        match result {
            ReplayResult::Commit(seq, write_set, _acl) => {
                assert_eq!(seq, 0);
                assert_eq!(write_set.stream_writes.len(), 1);
                let sw = &write_set.stream_writes[0];
                assert_eq!(sw.stream_id, stream_id);
                assert_eq!(*sw.key, key.to_vec());
                // tx starts at entry 1 = byte 256
                // metadata before value: version(8) + read_count(4) + write_count(4)
                //   + stream_id(32) + key_len(3) + key(5) + data_len(8) = 64 bytes
                // value starts at byte 256 + 64 = 320
                assert_eq!(sw.start_index, 320);
                assert_eq!(sw.end_index, 320 + value.len() as u64);
            }
            _ => panic!("expected Commit result"),
        }
    }

    #[tokio::test]
    async fn test_replay_encrypted_data() {
        let stream_id = H256::from_low_u64_be(1);
        let key = b"mykey";
        let value = b"hello world";
        let kv_data = build_kv_data(stream_id, key, value);

        // Simulate decrypt-before-store: header + plaintext KV data
        let header = EncryptionHeader::new();
        let mut stored_data = header.to_bytes().to_vec();
        stored_data.extend_from_slice(&kv_data);

        let (store, tx) = setup_store_with_data(&stored_data, stream_id).await;

        let config = StreamConfig {
            stream_ids: vec![stream_id],
            stream_set: HashSet::from([stream_id]),
            encryption_key: Some([0x42u8; 32]),
        };

        let replayer = StreamReplayer::new(config, store).await.unwrap();
        let result = replayer.replay(&tx).await.unwrap();

        match result {
            ReplayResult::Commit(seq, write_set, _acl) => {
                assert_eq!(seq, 0);
                assert_eq!(write_set.stream_writes.len(), 1);
                let sw = &write_set.stream_writes[0];
                assert_eq!(sw.stream_id, stream_id);
                assert_eq!(*sw.key, key.to_vec());
                // tx starts at entry 1 = byte 256
                // header(17) skipped, then metadata(64) before value
                // value starts at byte 256 + 17 + 64 = 337
                assert_eq!(sw.start_index, 337);
                assert_eq!(sw.end_index, 337 + value.len() as u64);
            }
            _ => panic!("expected Commit result"),
        }
    }

    #[tokio::test]
    async fn test_replay_encrypted_cross_entry_boundary() {
        let stream_id = H256::from_low_u64_be(1);
        let key = b"mykey";
        // 200-byte value: total stored = header(17) + kv_overhead(68) + 200 = 285 bytes → 2 entries
        let value = vec![0xAB; 200];
        let kv_data = build_kv_data(stream_id, key, &value);

        let header = EncryptionHeader::new();
        let mut stored_data = header.to_bytes().to_vec();
        stored_data.extend_from_slice(&kv_data);
        assert!(stored_data.len() > ENTRY_SIZE && stored_data.len() <= 2 * ENTRY_SIZE);

        let (store, tx) = setup_store_with_data(&stored_data, stream_id).await;

        let config = StreamConfig {
            stream_ids: vec![stream_id],
            stream_set: HashSet::from([stream_id]),
            encryption_key: Some([0x42u8; 32]),
        };

        let replayer = StreamReplayer::new(config, store).await.unwrap();
        let result = replayer.replay(&tx).await.unwrap();

        match result {
            ReplayResult::Commit(seq, write_set, _acl) => {
                assert_eq!(seq, 0);
                assert_eq!(write_set.stream_writes.len(), 1);
                let sw = &write_set.stream_writes[0];
                assert_eq!(sw.stream_id, stream_id);
                assert_eq!(*sw.key, key.to_vec());
                assert_eq!(sw.end_index - sw.start_index, value.len() as u64);
            }
            other => panic!("expected Commit, got {}", other),
        }
    }

    #[tokio::test]
    async fn test_replay_encrypted_at_segment_boundary() {
        let stream_id = H256::from_low_u64_be(1);
        let key = b"mykey";
        // One segment = 1024 entries × 256 bytes = 262144 bytes
        // Overhead = header(17) + kv_overhead(68) = 85 bytes
        // Value sized so total = exactly one segment
        let value = vec![0xCD; 262144 - 85];
        let kv_data = build_kv_data(stream_id, key, &value);

        let header = EncryptionHeader::new();
        let mut stored_data = header.to_bytes().to_vec();
        stored_data.extend_from_slice(&kv_data);
        assert_eq!(stored_data.len(), 1024 * ENTRY_SIZE);

        let (store, tx) = setup_store_with_data(&stored_data, stream_id).await;

        let config = StreamConfig {
            stream_ids: vec![stream_id],
            stream_set: HashSet::from([stream_id]),
            encryption_key: Some([0x42u8; 32]),
        };

        let replayer = StreamReplayer::new(config, store).await.unwrap();
        let result = replayer.replay(&tx).await.unwrap();

        match result {
            ReplayResult::Commit(seq, write_set, _acl) => {
                assert_eq!(seq, 0);
                assert_eq!(write_set.stream_writes.len(), 1);
                let sw = &write_set.stream_writes[0];
                assert_eq!(sw.stream_id, stream_id);
                assert_eq!(*sw.key, key.to_vec());
                assert_eq!(sw.end_index - sw.start_index, value.len() as u64);
            }
            other => panic!("expected Commit, got {}", other),
        }
    }

    #[tokio::test]
    async fn test_replay_encrypted_over_segment() {
        let stream_id = H256::from_low_u64_be(1);
        let key = b"mykey";
        // 1.5 segments = 393216 bytes total, value = 393216 - 85 overhead
        let value = vec![0xEF; 393216 - 85];
        let kv_data = build_kv_data(stream_id, key, &value);

        let header = EncryptionHeader::new();
        let mut stored_data = header.to_bytes().to_vec();
        stored_data.extend_from_slice(&kv_data);
        assert!(stored_data.len() > 1024 * ENTRY_SIZE);

        let (store, tx) = setup_store_with_data(&stored_data, stream_id).await;

        let config = StreamConfig {
            stream_ids: vec![stream_id],
            stream_set: HashSet::from([stream_id]),
            encryption_key: Some([0x42u8; 32]),
        };

        let replayer = StreamReplayer::new(config, store).await.unwrap();
        let result = replayer.replay(&tx).await.unwrap();

        match result {
            ReplayResult::Commit(seq, write_set, _acl) => {
                assert_eq!(seq, 0);
                assert_eq!(write_set.stream_writes.len(), 1);
                let sw = &write_set.stream_writes[0];
                assert_eq!(sw.stream_id, stream_id);
                assert_eq!(*sw.key, key.to_vec());
                assert_eq!(sw.end_index - sw.start_index, value.len() as u64);
            }
            other => panic!("expected Commit, got {}", other),
        }
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_store_roundtrip() {
        let stream_id = H256::from_low_u64_be(1);
        let key = b"mykey";
        let value = b"hello world";
        let kv_data = build_kv_data(stream_id, key, value);
        let encryption_key = [0x42u8; 32];

        // Encrypt the KV data (simulating what uploader does)
        let header = EncryptionHeader::new();
        let mut encrypted = kv_data.clone();
        crypt_at(&encryption_key, &header.nonce, 0, &mut encrypted);
        assert_ne!(encrypted, kv_data, "encrypted should differ from plaintext");

        // Decrypt (simulating what data fetcher does before storing)
        let mut decrypted = encrypted.clone();
        crypt_at(&encryption_key, &header.nonce, 0, &mut decrypted);
        assert_eq!(decrypted, kv_data, "decrypted should match original");

        // Store: header bytes (unchanged) + decrypted plaintext
        let mut stored_data = header.to_bytes().to_vec();
        stored_data.extend_from_slice(&decrypted);

        let (store, tx) = setup_store_with_data(&stored_data, stream_id).await;

        let config = StreamConfig {
            stream_ids: vec![stream_id],
            stream_set: HashSet::from([stream_id]),
            encryption_key: Some(encryption_key),
        };

        let replayer = StreamReplayer::new(config, store.clone()).await.unwrap();
        let result = replayer.replay(&tx).await.unwrap();

        match result {
            ReplayResult::Commit(seq, write_set, _acl) => {
                assert_eq!(seq, 0);
                assert_eq!(write_set.stream_writes.len(), 1);
                let sw = &write_set.stream_writes[0];
                assert_eq!(sw.stream_id, stream_id);
                assert_eq!(*sw.key, key.to_vec());

                // Read the actual value bytes from the flow store
                let start_entry = sw.start_index / ENTRY_SIZE as u64;
                let end_entry = (sw.end_index + ENTRY_SIZE as u64 - 1) / ENTRY_SIZE as u64;
                let chunk = store
                    .read()
                    .await
                    .get_chunk_by_flow_index(start_entry, end_entry - start_entry)
                    .unwrap()
                    .unwrap();
                let offset = (sw.start_index % ENTRY_SIZE as u64) as usize;
                let len = (sw.end_index - sw.start_index) as usize;
                let stored_value = &chunk.data[offset..offset + len];
                assert_eq!(stored_value, value, "stored value should match original");
            }
            _ => panic!("expected Commit result"),
        }
    }
}
