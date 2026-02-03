mod error;
mod stream_data_fetcher;
mod stream_replayer;

use crate::StreamConfig;
use anyhow::Result;
use ethereum_types::H256;
use kv_types::KVTransaction;
use ssz::Encode;
use std::{collections::HashSet, sync::Arc};
use storage_with_stream::Store;
use task_executor::TaskExecutor;
use tokio::sync::RwLock;

use self::{stream_data_fetcher::StreamDataFetcher, stream_replayer::StreamReplayer};

pub struct StreamManager;

pub const RETRY_WAIT_MS: u64 = 1000;

impl StreamManager {
    pub async fn initialize(
        config: &StreamConfig,
        store: Arc<RwLock<dyn Store>>,
        indexer_url: Option<String>,
        zgs_nodes: Vec<String>,
        zgs_rpc_timeout: u64,
        task_executor: TaskExecutor,
    ) -> Result<(StreamDataFetcher, StreamReplayer)> {
        // initialize
        let holding_stream_ids = store.read().await.get_holding_stream_ids().await?;
        let holding_stream_set: HashSet<H256> =
            HashSet::from_iter(holding_stream_ids.iter().cloned());
        // ensure current stream id set is a subset of streams maintained in db
        let mut reseted = false;
        for id in config.stream_ids.iter() {
            if !holding_stream_set.contains(id) {
                // new stream id, replay from start
                store
                    .write()
                    .await
                    .reset_stream_sync(config.stream_ids.as_ssz_bytes())
                    .await?;
                reseted = true;
                break;
            }
        }
        // is a subset, update stream ids in db
        if !reseted && config.stream_ids.len() != holding_stream_ids.len() {
            store
                .write()
                .await
                .update_stream_ids(config.stream_ids.as_ssz_bytes())
                .await?;
        }

        // spawn data sync and stream replay threads
        let fetcher = StreamDataFetcher::new(
            config.clone(),
            store.clone(),
            indexer_url,
            zgs_nodes,
            zgs_rpc_timeout,
            task_executor,
        )
        .await?;
        let replayer = StreamReplayer::new(config.clone(), store.clone()).await?;
        Ok((fetcher, replayer))
    }

    pub fn spawn(
        fetcher: StreamDataFetcher,
        replayer: StreamReplayer,
        executor: TaskExecutor,
    ) -> Result<()> {
        executor.spawn(
            async move { Box::pin(fetcher.run()).await },
            "stream data fetcher",
        );

        executor.spawn(
            async move { Box::pin(replayer.run()).await },
            "stream data replayer",
        );
        Ok(())
    }
}

// returns bool pair (stream_matched, can_write)
async fn skippable(
    tx: &KVTransaction,
    config: &StreamConfig,
    store: Arc<RwLock<dyn Store>>,
) -> Result<(bool, bool)> {
    if tx.stream_ids.is_empty() {
        Ok((false, false))
    } else {
        let replay_progress = store.read().await.get_stream_replay_progress().await?;
        // if replayer is not up-to-date, always make can_write be true
        let mut can_write = replay_progress < tx.seq;
        for id in tx.stream_ids.iter() {
            if !config.stream_set.contains(id) {
                return Ok((false, false));
            }
            if !can_write && store.read().await.can_write(tx.sender, *id, tx.seq).await? {
                can_write = true;
            }
        }
        Ok((true, can_write))
    }
}
