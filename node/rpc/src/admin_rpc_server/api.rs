use ethereum_types::{H160, H256};
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;

#[rpc(server, client, namespace = "admin")]
pub trait AdminRpc {
    /// Register a stream id for monitoring. The caller must provide a
    /// hex-encoded EIP-712 signature over the `RegisterStream` typed-data
    /// payload (domain `{ name: "0G Storage Scan", version: "1", chainId: <node config> }`,
    /// message `{ purpose: "register-stream", wallet, streamId }`). The KV
    /// node recovers the signer from the signature and verifies it equals
    /// `wallet`. Idempotent: returns `Ok(true)` whether or not the stream
    /// was already registered. Persisted across node restarts.
    #[method(name = "addStream")]
    async fn add_stream(&self, stream_id: H256, wallet: H160, signature: String)
        -> RpcResult<bool>;

    /// Trigger an immediate renewal cycle. The caller must provide a
    /// hex-encoded EIP-712 signature over the `RenewNow` typed-data payload
    /// (domain `{ name: "0G Storage Scan", version: "1", chainId: <node config> }`,
    /// message `{ purpose: "renew-now", wallet, issuedAt }`). `issuedAt` (unix
    /// seconds) must be within 300 seconds of the node's clock so a captured
    /// signature cannot be replayed later. The recovered signer must equal
    /// `wallet`, and `wallet` must equal the node's configured renewal
    /// signer. Returns `Ok(true)` once the trigger has been sent to the
    /// renewal service (a cycle already running ignores the re-entrant
    /// trigger and simply continues).
    #[method(name = "renewNow")]
    async fn renew_now(&self, wallet: H160, issued_at: u64, signature: String) -> RpcResult<bool>;
}
