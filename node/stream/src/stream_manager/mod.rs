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

impl StreamManager {
    pub async fn initialize(
        config: &StreamConfig,
        store: Arc<RwLock<dyn Store>>,
        indexer_url: Option<String>,
        zgs_nodes: Vec<String>,
        zgs_rpc_timeout: u64,
        task_executor: TaskExecutor,
    ) -> Result<(StreamDataFetcher, StreamReplayer)> {
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
            if !config.stream_set.read().await.contains(id) {
                return Ok((false, false));
            }
            if !can_write && store.read().await.can_write(tx.sender, *id, tx.seq).await? {
                can_write = true;
            }
        }
        Ok((true, can_write))
    }
}

pub async fn merge_persisted_streams(
    config: &StreamConfig,
    store: Arc<RwLock<dyn Store>>,
) -> Result<()> {
    let persisted_ids = store.read().await.get_holding_stream_ids().await?;
    let persisted_set: HashSet<H256> = persisted_ids.iter().cloned().collect();
    let config_set: HashSet<H256> = config.stream_ids.iter().cloned().collect();

    // merged = config ∪ persisted (preserves runtime-added streams)
    let mut merged_set = persisted_set.clone();
    merged_set.extend(config_set.iter().cloned());
    let merged_ids: Vec<H256> = merged_set.iter().cloned().collect();

    let config_introduces_new = !config_set.is_subset(&persisted_set);

    if config_introduces_new {
        store
            .write()
            .await
            .reset_stream_sync(merged_ids.as_ssz_bytes())
            .await?;
    } else if merged_set != persisted_set {
        store
            .write()
            .await
            .update_stream_ids(merged_ids.as_ssz_bytes())
            .await?;
    }

    *config.stream_set.write().await = merged_set;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethereum_types::H256;
    use ssz::Encode;
    use std::collections::HashSet;
    use std::sync::Arc;
    use storage_with_stream::StoreManager;
    use tokio::sync::RwLock;

    fn h(b: u8) -> H256 {
        H256::from([b; 32])
    }

    async fn make_store() -> Arc<RwLock<dyn storage_with_stream::Store>> {
        Arc::new(RwLock::new(StoreManager::memorydb().await.unwrap()))
    }

    fn make_config(ids: Vec<H256>) -> StreamConfig {
        StreamConfig {
            stream_ids: ids.clone(),
            stream_set: Arc::new(RwLock::new(HashSet::from_iter(ids.iter().cloned()))),
            encryption_key: None,
            wallet_private_key: None,
            max_download_retries: 0,
            download_timeout_ms: 1000,
            download_retry_interval_ms: 100,
            retry_wait_ms: 100,
        }
    }

    // Seeds the t_misc row with the given persisted stream ids. Uses
    // reset_stream_sync because update_stream_ids is a plain UPDATE that
    // no-ops when the row does not yet exist (t_misc has no default row
    // after create_tables_if_not_exist).
    async fn seed_persisted(
        store: &Arc<RwLock<dyn storage_with_stream::Store>>,
        persisted: Vec<H256>,
    ) {
        store
            .write()
            .await
            .reset_stream_sync(persisted.as_ssz_bytes())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn merge_preserves_runtime_added_streams() {
        let store = make_store().await;
        // simulate a previous run that persisted [a, b] (b is runtime-added)
        seed_persisted(&store, vec![h(0xa), h(0xb)]).await;

        // config only mentions [a]; b should NOT be lost
        let config = make_config(vec![h(0xa)]);
        merge_persisted_streams(&config, store.clone())
            .await
            .unwrap();

        let live: HashSet<H256> = config.stream_set.read().await.clone();
        assert!(live.contains(&h(0xa)));
        assert!(live.contains(&h(0xb)));
        let db: HashSet<H256> = store
            .read()
            .await
            .get_holding_stream_ids()
            .await
            .unwrap()
            .into_iter()
            .collect();
        assert_eq!(db, HashSet::from([h(0xa), h(0xb)]));
    }

    #[tokio::test]
    async fn merge_resets_when_config_adds_new() {
        let store = make_store().await;
        // seed persisted [a] then pretend sync has progressed
        seed_persisted(&store, vec![h(0xa)]).await;
        store
            .write()
            .await
            .update_stream_data_sync_progress(0, 100)
            .await
            .unwrap();

        // config introduces b — reset is required
        let config = make_config(vec![h(0xa), h(0xb)]);
        merge_persisted_streams(&config, store.clone())
            .await
            .unwrap();

        let progress = store
            .read()
            .await
            .get_stream_data_sync_progress()
            .await
            .unwrap();
        assert_eq!(progress, 0, "reset should zero data_sync_progress");
        let live: HashSet<H256> = config.stream_set.read().await.clone();
        assert_eq!(live, HashSet::from([h(0xa), h(0xb)]));
    }

    #[tokio::test]
    async fn merge_no_reset_when_config_unchanged() {
        let store = make_store().await;
        seed_persisted(&store, vec![h(0xa)]).await;
        store
            .write()
            .await
            .update_stream_data_sync_progress(0, 100)
            .await
            .unwrap();

        let config = make_config(vec![h(0xa)]);
        merge_persisted_streams(&config, store.clone())
            .await
            .unwrap();

        let progress = store
            .read()
            .await
            .get_stream_data_sync_progress()
            .await
            .unwrap();
        assert_eq!(progress, 100, "no reset when config introduces nothing new");
    }
}
