use ethereum_types::H256;
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;

#[rpc(server, client, namespace = "admin")]
pub trait AdminRpc {
    /// Register a stream id for monitoring. Idempotent: returns Ok(true) if the
    /// stream was already registered, Ok(true) after a successful add. Persisted
    /// across node restarts.
    #[method(name = "addStream")]
    async fn add_stream(&self, stream_id: H256) -> RpcResult<bool>;
}
