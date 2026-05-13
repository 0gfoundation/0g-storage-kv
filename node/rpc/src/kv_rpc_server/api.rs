use ethereum_types::{H160, H256};
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use zgs_rpc::types::Segment;

use crate::types::{KeyValueSegment, ReplayProgress, ValueSegment};

#[rpc(server, client, namespace = "kv")]
pub trait KeyValueRpc {
    #[method(name = "getStatus")]
    async fn get_status(&self) -> RpcResult<bool>;

    #[method(name = "getValue")]
    async fn get_value(
        &self,
        stream_id: H256,
        key: Segment,
        start_index: u64,
        len: u64,
        version: Option<u64>,
    ) -> RpcResult<Option<ValueSegment>>;

    #[method(name = "getNext")]
    async fn get_next(
        &self,
        stream_id: H256,
        key: Segment,
        start_index: u64,
        len: u64,
        inclusive: bool,
        version: Option<u64>,
    ) -> RpcResult<Option<KeyValueSegment>>;

    #[method(name = "getPrev")]
    async fn get_prev(
        &self,
        stream_id: H256,
        key: Segment,
        start_index: u64,
        len: u64,
        inclusive: bool,
        version: Option<u64>,
    ) -> RpcResult<Option<KeyValueSegment>>;

    #[method(name = "getFirst")]
    async fn get_first(
        &self,
        stream_id: H256,
        start_index: u64,
        len: u64,
        version: Option<u64>,
    ) -> RpcResult<Option<KeyValueSegment>>;

    #[method(name = "getLast")]
    async fn get_last(
        &self,
        stream_id: H256,
        start_index: u64,
        len: u64,
        version: Option<u64>,
    ) -> RpcResult<Option<KeyValueSegment>>;

    #[method(name = "getTransactionResult")]
    async fn get_trasanction_result(&self, tx_seq: u64) -> RpcResult<Option<String>>;

    #[method(name = "getHoldingStreamIds")]
    async fn get_holding_stream_ids(&self) -> RpcResult<Vec<H256>>;

    /// Returns this node's stream-replay progress. See
    /// `crate::types::ReplayProgress` for field semantics.
    ///
    /// Downstream callers (notably an S3 gateway caching the
    /// (bucket,key)→root namespace) use this to detect cache lag
    /// after an out-of-band write: when a Flow `Submit` event for
    /// seq N is observed on-chain, the caller polls this RPC and
    /// reads from KV once `applied_seq >= N`.
    #[method(name = "getReplayProgress")]
    async fn get_replay_progress(&self) -> RpcResult<ReplayProgress>;

    #[method(name = "hasWritePermission")]
    async fn has_write_permission(
        &self,
        account: H160,
        stream_id: H256,
        key: Segment,
        version: Option<u64>,
    ) -> RpcResult<bool>;

    #[method(name = "isAdmin")]
    async fn is_admin(
        &self,
        account: H160,
        stream_id: H256,
        version: Option<u64>,
    ) -> RpcResult<bool>;

    #[method(name = "isSpecialKey")]
    async fn is_special_key(
        &self,
        stream_id: H256,
        key: Segment,
        version: Option<u64>,
    ) -> RpcResult<bool>;

    #[method(name = "isWriterOfKey")]
    async fn is_writer_of_key(
        &self,
        account: H160,
        stream_id: H256,
        key: Segment,
        version: Option<u64>,
    ) -> RpcResult<bool>;

    #[method(name = "isWriterOfStream")]
    async fn is_writer_of_stream(
        &self,
        account: H160,
        stream_id: H256,
        version: Option<u64>,
    ) -> RpcResult<bool>;
}
