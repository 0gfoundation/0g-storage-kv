#[macro_use]
extern crate tracing;

mod cli;
mod client;
mod config;
mod log;

use client::{Client, ClientBuilder, RuntimeContext};
use config::ZgsKVConfig;
use std::error::Error;

async fn start_node(context: RuntimeContext, config: ZgsKVConfig) -> Result<Client, String> {
    let storage_config = config.storage_config()?;
    let rpc_config = config.rpc_config()?;
    let log_sync_config = config.log_sync_config()?;
    let stream_config = config.stream_config()?;
    let renew_config = config.renew_config()?;

    // Built before `with_rpc` (spec §8) so the RPC context always has a
    // status cell to read from and a trigger channel to send into, whether
    // or not the renewal service ends up running.
    let renew_status: kv_renew::SharedRenewStatus = Default::default();
    let (renew_trigger_tx, renew_trigger_rx) = tokio::sync::mpsc::unbounded_channel();
    let renew_signer = renew_config
        .as_ref()
        .map(|c| kv_renew::service::signer_address(&c.private_key))
        .transpose()
        .map_err(|e| format!("bad renew_private_key: {:?}", e))?;

    ClientBuilder::default()
        .with_runtime_context(context)
        .with_rocksdb_store(&storage_config)
        .await?
        .merge_streams(&stream_config)
        .await?
        .with_rpc(
            rpc_config,
            stream_config.stream_set.clone(),
            renew_status.clone(),
            renew_config.as_ref().map(|_| renew_trigger_tx.clone()),
            renew_signer,
        )
        .await?
        .with_stream(&stream_config)
        .await?
        .with_log_sync(log_sync_config)
        .await?
        .with_renew(
            renew_config,
            stream_config.stream_set.clone(),
            renew_status,
            renew_trigger_rx,
        )
        .await?
        .build()
}

fn main() -> Result<(), Box<dyn Error>> {
    // enable backtraces
    std::env::set_var("RUST_BACKTRACE", "1");

    // runtime environment
    let mut environment = client::EnvironmentBuilder::new()
        .multi_threaded_tokio_runtime()?
        .build()?;

    let context = environment.core_context();
    let executor = context.executor.clone();

    // CLI, config, and logs
    let matches = cli::cli_app().get_matches();
    let config = ZgsKVConfig::parse(&matches)?;
    log::configure(&config.log_config_file, executor.clone());

    // start services
    executor.clone().spawn(
        async move {
            info!("Starting services...");
            if let Err(e) = start_node(context.clone(), config).await {
                error!(reason = %e, "Failed to start zgs kv node");
                // Ignore the error since it always occurs during normal operation when
                // shutting down.
                let _ =
                    executor
                        .shutdown_sender()
                        .try_send(task_executor::ShutdownReason::Failure(
                            "Failed to start zgs kv node",
                        ));
            } else {
                info!("Services started");
            }
        },
        "zgs_kv_node",
    );

    // Block this thread until we get a ctrl-c or a task sends a shutdown signal.
    let shutdown_reason = environment.block_until_shutdown_requested()?;
    info!(reason = ?shutdown_reason, "Shutting down...");

    environment.fire_signal();

    // Shutdown the environment once all tasks have completed.
    environment.shutdown_on_idle();

    match shutdown_reason {
        task_executor::ShutdownReason::Success(_) => Ok(()),
        task_executor::ShutdownReason::Failure(msg) => Err(msg.to_string().into()),
    }
}
