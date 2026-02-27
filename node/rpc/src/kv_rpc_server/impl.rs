use std::sync::Arc;

use crate::error;
use crate::types::KeyValueSegment;
use crate::types::ValueSegment;
use crate::Context;
use ethereum_types::H160;
use kv_types::KeyValuePair;
use storage_with_stream::log_store::log_manager::ENTRY_SIZE;
use zgs_rpc::types::Segment;

use super::api::KeyValueRpcServer;
use ethereum_types::H256;
use jsonrpsee::core::async_trait;
use jsonrpsee::core::RpcResult;
pub struct KeyValueRpcServerImpl {
    pub ctx: Context,
}

impl KeyValueRpcServerImpl {
    async fn get_value_segment(
        &self,
        pair: KeyValuePair,
        start_index: u64,
        len: u64,
    ) -> RpcResult<Option<ValueSegment>> {
        if len == 0 {
            return Ok(Some(ValueSegment {
                version: pair.version,
                data: vec![],
                size: pair.end_index - pair.start_index,
            }));
        }
        if start_index > pair.end_index - pair.start_index {
            return Err(error::invalid_params(
                "start_index",
                "start index is greater than value length",
            ));
        }
        let start_byte_index = pair.start_index + start_index;
        let end_byte_index = std::cmp::min(start_byte_index + len, pair.end_index);
        let start_entry_index = start_byte_index / ENTRY_SIZE as u64;
        let end_entry_index = if end_byte_index % ENTRY_SIZE as u64 == 0 {
            end_byte_index / ENTRY_SIZE as u64
        } else {
            end_byte_index / ENTRY_SIZE as u64 + 1
        };
        if let Some(entry_array) = self
            .ctx
            .store
            .read()
            .await
            .get_chunk_by_flow_index(start_entry_index, end_entry_index - start_entry_index)?
        {
            return Ok(Some(ValueSegment {
                version: pair.version,
                data: entry_array.data[(start_byte_index as usize
                    - start_entry_index as usize * ENTRY_SIZE)
                    ..(end_byte_index as usize - start_entry_index as usize * ENTRY_SIZE)]
                    .to_vec(),
                size: pair.end_index - pair.start_index,
            }));
        }
        Err(error::internal_error("key data is missing"))
    }

    async fn get_key_value_segment(
        &self,
        pair: KeyValuePair,
        start_index: u64,
        len: u64,
    ) -> RpcResult<Option<KeyValueSegment>> {
        if len == 0 {
            return Ok(Some(KeyValueSegment {
                version: pair.version,
                key: pair.key,
                data: vec![],
                size: pair.end_index - pair.start_index,
            }));
        }
        if start_index > pair.end_index - pair.start_index {
            return Err(error::invalid_params(
                "start_index",
                "start index is greater than value length",
            ));
        }
        let start_byte_index = pair.start_index + start_index;
        let end_byte_index = std::cmp::min(start_byte_index + len, pair.end_index);
        let start_entry_index = start_byte_index / ENTRY_SIZE as u64;
        let end_entry_index = if end_byte_index % ENTRY_SIZE as u64 == 0 {
            end_byte_index / ENTRY_SIZE as u64
        } else {
            end_byte_index / ENTRY_SIZE as u64 + 1
        };
        if let Some(entry_array) = self
            .ctx
            .store
            .read()
            .await
            .get_chunk_by_flow_index(start_entry_index, end_entry_index - start_entry_index)?
        {
            return Ok(Some(KeyValueSegment {
                version: pair.version,
                key: pair.key,
                data: entry_array.data[(start_byte_index as usize
                    - start_entry_index as usize * ENTRY_SIZE)
                    ..(end_byte_index as usize - start_entry_index as usize * ENTRY_SIZE)]
                    .to_vec(),
                size: pair.end_index - pair.start_index,
            }));
        }
        Err(error::internal_error("key data is missing"))
    }
}

#[async_trait]
impl KeyValueRpcServer for KeyValueRpcServerImpl {
    async fn get_status(&self) -> RpcResult<bool> {
        debug!("kv_getStatus()");

        Ok(true)
    }

    async fn get_value(
        &self,
        stream_id: H256,
        key: Segment,
        start_index: u64,
        len: u64,
        version: Option<u64>,
    ) -> RpcResult<Option<ValueSegment>> {
        debug!("kv_getValue()");

        if len > self.ctx.config.max_query_len_in_bytes {
            return Err(error::invalid_params("len", "query length too large"));
        }

        if key.0.is_empty() {
            return Err(error::invalid_params("key", "key is empty"));
        }

        let before_version = version.unwrap_or(u64::MAX);

        let store_read = self.ctx.store.read().await;
        if let Some(pair) = store_read
            .get_stream_key_value(stream_id, Arc::new(key.0), before_version)
            .await?
        {
            if pair.end_index == pair.start_index {
                return Ok(Some(ValueSegment {
                    version: pair.version,
                    data: vec![],
                    size: 0,
                }));
            }
            drop(store_read);
            return self.get_value_segment(pair, start_index, len).await;
        }
        Ok(Some(ValueSegment {
            version: 0,
            data: vec![],
            size: 0,
        }))
    }

    async fn get_next(
        &self,
        stream_id: H256,
        key: Segment,
        start_index: u64,
        len: u64,
        inclusive: bool,
        version: Option<u64>,
    ) -> RpcResult<Option<KeyValueSegment>> {
        debug!("kv_getNext()");

        if len > self.ctx.config.max_query_len_in_bytes {
            return Err(error::invalid_params("len", "query length too large"));
        }

        if key.0.is_empty() {
            return Err(error::invalid_params("key", "key is empty"));
        }

        let before_version = version.unwrap_or(u64::MAX);

        let store_read = self.ctx.store.read().await;
        let mut next_key = Arc::new(key.0);
        while let Some(pair) = store_read
            .get_next_stream_key_value(stream_id, next_key.clone(), inclusive, before_version)
            .await?
        {
            // skip deleted keys
            // TODO: resolve this in sql statements?
            if pair.end_index == pair.start_index {
                next_key = Arc::new(pair.key);
                continue;
            }
            drop(store_read);
            return self.get_key_value_segment(pair, start_index, len).await;
        }
        Ok(None)
    }

    async fn get_prev(
        &self,
        stream_id: H256,
        key: Segment,
        start_index: u64,
        len: u64,
        inclusive: bool,
        version: Option<u64>,
    ) -> RpcResult<Option<KeyValueSegment>> {
        debug!("kv_getPrev()");

        if len > self.ctx.config.max_query_len_in_bytes {
            return Err(error::invalid_params("len", "query length too large"));
        }

        if key.0.is_empty() {
            return Err(error::invalid_params("key", "key is empty"));
        }

        let before_version = version.unwrap_or(u64::MAX);

        let store_read = self.ctx.store.read().await;
        let mut next_key = Arc::new(key.0);
        while let Some(pair) = store_read
            .get_prev_stream_key_value(stream_id, next_key.clone(), inclusive, before_version)
            .await?
        {
            // skip deleted keys
            // TODO: resolve this in sql statements?
            if pair.end_index == pair.start_index {
                next_key = Arc::new(pair.key);
                continue;
            }
            drop(store_read);
            return self.get_key_value_segment(pair, start_index, len).await;
        }
        Ok(None)
    }

    async fn get_first(
        &self,
        stream_id: H256,
        start_index: u64,
        len: u64,
        version: Option<u64>,
    ) -> RpcResult<Option<KeyValueSegment>> {
        debug!("kv_getFirst()");

        if len > self.ctx.config.max_query_len_in_bytes {
            return Err(error::invalid_params("len", "query length too large"));
        }

        let before_version = version.unwrap_or(u64::MAX);

        let store_read = self.ctx.store.read().await;

        let mut result = store_read.get_first(stream_id, before_version).await?;
        while let Some(pair) = result {
            // skip deleted keys
            // TODO: resolve this in sql statements?
            if pair.end_index == pair.start_index {
                result = store_read
                    .get_next_stream_key_value(stream_id, Arc::new(pair.key), false, before_version)
                    .await?;
                continue;
            }
            drop(store_read);
            return self.get_key_value_segment(pair, start_index, len).await;
        }
        Ok(None)
    }

    async fn get_last(
        &self,
        stream_id: H256,
        start_index: u64,
        len: u64,
        version: Option<u64>,
    ) -> RpcResult<Option<KeyValueSegment>> {
        debug!("kv_getLast()");

        if len > self.ctx.config.max_query_len_in_bytes {
            return Err(error::invalid_params("len", "query length too large"));
        }

        let before_version = version.unwrap_or(u64::MAX);

        let store_read = self.ctx.store.read().await;

        let mut result = store_read.get_last(stream_id, before_version).await?;
        while let Some(pair) = result {
            // skip deleted keys
            // TODO: resolve this in sql statements?
            if pair.end_index == pair.start_index {
                result = store_read
                    .get_prev_stream_key_value(stream_id, Arc::new(pair.key), false, before_version)
                    .await?;
                continue;
            }
            drop(store_read);
            return self.get_key_value_segment(pair, start_index, len).await;
        }
        Ok(None)
    }

    async fn get_trasanction_result(&self, tx_seq: u64) -> RpcResult<Option<String>> {
        debug!("kv_getTransactionResult()");

        Ok(self.ctx.store.read().await.get_tx_result(tx_seq).await?)
    }

    async fn get_holding_stream_ids(&self) -> RpcResult<Vec<H256>> {
        debug!("kv_getHoldingStreamIds()");

        Ok(self.ctx.store.read().await.get_holding_stream_ids().await?)
    }

    async fn has_write_permission(
        &self,
        account: H160,
        stream_id: H256,
        key: Segment,
        version: Option<u64>,
    ) -> RpcResult<bool> {
        debug!("kv_hasWritePermission()");

        if key.0.is_empty() {
            return Err(error::invalid_params("key", "key is empty"));
        }

        let before_version = version.unwrap_or(u64::MAX);

        Ok(self
            .ctx
            .store
            .read()
            .await
            .has_write_permission(account, stream_id, Arc::new(key.0), before_version)
            .await?)
    }

    async fn is_admin(
        &self,
        account: H160,
        stream_id: H256,
        version: Option<u64>,
    ) -> RpcResult<bool> {
        debug!("kv_isAdmin()");

        let before_version = version.unwrap_or(u64::MAX);

        Ok(self
            .ctx
            .store
            .read()
            .await
            .is_admin(account, stream_id, before_version)
            .await?)
    }

    async fn is_special_key(
        &self,
        stream_id: H256,
        key: Segment,
        version: Option<u64>,
    ) -> RpcResult<bool> {
        debug!("kv_isSpecialKey()");

        if key.0.is_empty() {
            return Err(error::invalid_params("key", "key is empty"));
        }

        let before_version = version.unwrap_or(u64::MAX);

        Ok(self
            .ctx
            .store
            .read()
            .await
            .is_special_key(stream_id, Arc::new(key.0), before_version)
            .await?)
    }

    async fn is_writer_of_key(
        &self,
        account: H160,
        stream_id: H256,
        key: Segment,
        version: Option<u64>,
    ) -> RpcResult<bool> {
        debug!("kv_isWriterOfKey()");

        if key.0.is_empty() {
            return Err(error::invalid_params("key", "key is empty"));
        }

        let before_version = version.unwrap_or(u64::MAX);

        Ok(self
            .ctx
            .store
            .read()
            .await
            .is_writer_of_key(account, stream_id, Arc::new(key.0), before_version)
            .await?)
    }

    async fn is_writer_of_stream(
        &self,
        account: H160,
        stream_id: H256,
        version: Option<u64>,
    ) -> RpcResult<bool> {
        debug!("kv_isWriterOfStream()");

        let before_version = version.unwrap_or(u64::MAX);

        Ok(self
            .ctx
            .store
            .read()
            .await
            .is_writer_of_stream(account, stream_id, before_version)
            .await?)
    }
}
