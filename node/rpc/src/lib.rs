#[macro_use]
extern crate tracing;

mod admin_rpc_server;
mod config;
mod error;
mod kv_rpc_server;
pub mod types;

use admin_rpc_server::AdminRpcServer;
use ethereum_types::H256;
use futures::channel::mpsc::Sender;
pub use jsonrpsee::http_client::HttpClient;
use jsonrpsee::http_client::HttpClientBuilder;
use jsonrpsee::http_server::{HttpServerBuilder, HttpServerHandle};
use kv_rpc_server::KeyValueRpcServer;
use std::collections::HashSet;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use storage_with_stream::Store;
use task_executor::ShutdownReason;
use tokio::sync::RwLock;

pub use admin_rpc_server::AdminRpcClient;
pub use config::Config as RPCConfig;
pub use kv_rpc_server::KeyValueRpcClient;

/// A wrapper around all the items required to spawn the HTTP server.
///
/// The server will gracefully handle the case where any fields are `None`.
#[derive(Clone)]
pub struct Context {
    pub config: RPCConfig,
    pub shutdown_sender: Sender<ShutdownReason>,
    pub store: Arc<RwLock<dyn Store>>,
    pub live_stream_set: Arc<RwLock<HashSet<H256>>>,
}

pub fn build_client(url: &String, timeout: u64) -> Result<HttpClient, Box<dyn Error>> {
    Ok(HttpClientBuilder::default()
        .request_timeout(Duration::from_secs(timeout))
        .build(url)?)
}

pub async fn run_server(ctx: Context) -> Result<(HttpServerHandle, SocketAddr), Box<dyn Error>> {
    let server = HttpServerBuilder::default()
        .max_response_body_size(ctx.config.max_response_body_in_bytes)
        .build(ctx.config.listen_address)
        .await?;

    let mut module = (kv_rpc_server::KeyValueRpcServerImpl { ctx: ctx.clone() }).into_rpc();
    module.merge(
        (admin_rpc_server::AdminRpcServerImpl {
            store: ctx.store.clone(),
            live_stream_set: ctx.live_stream_set.clone(),
        })
        .into_rpc(),
    )?;

    let addr = server.local_addr()?;
    let handle = server.start(module)?;
    info!("Server started http://{}", addr);

    Ok((handle, addr))
}
