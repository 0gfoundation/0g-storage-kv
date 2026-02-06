use crate::{stream_manager::skippable, StreamConfig};
use anyhow::{anyhow, bail, Result};
use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use jsonrpsee::rpc_params;
use kv_types::KVTransaction;
use serde_json::Value;
use shared_types::ChunkArray;
use std::{
    cmp,
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::Duration,
};
use zgs_rpc::ZgsRPCClient;

use storage_with_stream::{log_store::log_manager::ENTRY_SIZE, Store};
use task_executor::TaskExecutor;
use tokio::sync::{
    mpsc::{self, UnboundedSender},
    RwLock,
};
use zgs_storage::config::{all_shards_available, ShardConfig};

const RETRY_WAIT_MS: u64 = 1000;
const ENTRIES_PER_SEGMENT: usize = 1024;
const MAX_DOWNLOAD_TASK: usize = 5;
const MAX_RETRY: usize = 5;

#[derive(Clone, Debug)]
struct LocationCandidate {
    url: String,
    shard_config: Option<ShardConfig>,
}

pub struct StreamDataFetcher {
    config: StreamConfig,
    store: Arc<RwLock<dyn Store>>,
    indexer_client: HttpClient,
    static_node_urls: Vec<String>,
    zgs_rpc_timeout: u64,
    task_executor: TaskExecutor,
}

#[allow(clippy::too_many_arguments)]
async fn download_with_proof(
    clients: Arc<Vec<HttpClient>>,
    client_index: usize,
    tx: Arc<KVTransaction>,
    start_index: usize,
    end_index: usize,
    store: Arc<RwLock<dyn Store>>,
    sender: UnboundedSender<Result<(), (usize, usize, bool)>>,
) {
    let mut fail_cnt = 0;
    let mut index = client_index;
    while fail_cnt < clients.len() {
        let seg_index = start_index / ENTRIES_PER_SEGMENT;
        debug!(
            "download_with_proof for tx_seq: {}, start_index: {}, end_index {} from client #{}",
            tx.seq, start_index, end_index, index
        );
        match clients[index]
            .download_segment_with_proof_by_tx_seq(tx.seq, seg_index)
            .await
        {
            Ok(Some(segment)) => {
                if segment.data.len() % ENTRY_SIZE != 0
                    || segment.data.len() / ENTRY_SIZE != end_index - start_index
                {
                    debug!("invalid data length");
                    if let Err(e) = sender.send(Err((start_index, end_index, true))) {
                        error!("send error: {:?}", e);
                    }

                    return;
                }

                if segment.root != tx.data_merkle_root {
                    debug!("invalid file root");
                    if let Err(e) = sender.send(Err((start_index, end_index, true))) {
                        error!("send error: {:?}", e);
                    }

                    return;
                }

                if let Err(e) = segment.validate(ENTRIES_PER_SEGMENT) {
                    debug!("validate segment with error: {:?}", e);

                    if let Err(e) = sender.send(Err((start_index, end_index, true))) {
                        error!("send error: {:?}", e);
                    }
                    return;
                }

                if let Err(e) = store.write().await.put_chunks_with_tx_hash(
                    tx.seq,
                    tx.hash(),
                    ChunkArray {
                        data: segment.data,
                        start_index: (segment.index * ENTRIES_PER_SEGMENT) as u64,
                    },
                    None,
                ) {
                    debug!("put segment with error: {:?}", e);

                    if let Err(e) = sender.send(Err((start_index, end_index, true))) {
                        error!("send error: {:?}", e);
                    }
                    return;
                }

                debug!("download start_index {:?} successful", start_index);
                if let Err(e) = sender.send(Ok(())) {
                    error!("send error: {:?}", e);
                }

                return;
            }
            Ok(None) => {
                debug!(
                    "tx_seq {}, start_index {}, end_index {}, client #{} response is none",
                    tx.seq, start_index, end_index, index
                );
                fail_cnt += 1;
                index = (index + 1) % clients.len();
                tokio::time::sleep(Duration::from_millis(RETRY_WAIT_MS)).await;
            }
            Err(e) => {
                warn!(
                    "tx_seq {}, start_index {}, end_index {}, client #{} response error: {:?}",
                    tx.seq, start_index, end_index, index, e
                );
                fail_cnt += 1;
                index = (index + 1) % clients.len();
                tokio::time::sleep(Duration::from_millis(RETRY_WAIT_MS)).await;
            }
        }
    }

    if let Err(e) = sender.send(Err((start_index, end_index, false))) {
        error!("send error: {:?}", e);
    }
}

impl StreamDataFetcher {
    pub async fn new(
        config: StreamConfig,
        store: Arc<RwLock<dyn Store>>,
        indexer_url: Option<String>,
        zgs_nodes: Vec<String>,
        zgs_rpc_timeout: u64,
        task_executor: TaskExecutor,
    ) -> Result<Self> {
        let indexer_client = match indexer_url {
            Some(url) if !url.is_empty() => HttpClientBuilder::default()
                .request_timeout(Duration::from_secs(zgs_rpc_timeout))
                .build(url)?,
            _ => HttpClientBuilder::default()
                .request_timeout(Duration::from_secs(zgs_rpc_timeout))
                .build("http://127.0.0.1:0")?,
        };
        Ok(Self {
            config,
            store,
            indexer_client,
            static_node_urls: zgs_nodes,
            zgs_rpc_timeout,
            task_executor,
        })
    }

    fn parse_shard_config(config: &Value) -> Option<ShardConfig> {
        let obj = config.as_object()?;
        let shard_id = obj
            .get("shardId")
            .or_else(|| obj.get("shard_id"))
            .and_then(|v| v.as_u64())? as usize;
        let num_shard = obj
            .get("numShard")
            .or_else(|| obj.get("num_shard"))
            .and_then(|v| v.as_u64())? as usize;
        let config = ShardConfig {
            shard_id,
            num_shard,
        };
        if config.validate().is_err() {
            return None;
        }
        Some(config)
    }

    fn select_download_nodes(
        candidates: Vec<LocationCandidate>,
        root_hex: &str,
    ) -> Result<Vec<String>> {
        let mut urls = Vec::new();
        let mut with_config = Vec::new();
        let mut without_config = Vec::new();

        for candidate in candidates {
            if let Some(config) = candidate.shard_config {
                with_config.push((candidate.url, config));
            } else {
                without_config.push(candidate.url);
            }
        }

        if with_config.is_empty() {
            urls.extend(without_config);
            if urls.is_empty() {
                bail!("indexer returned no locations for root {}", root_hex);
            }
            urls.sort();
            urls.dedup();
            return Ok(urls);
        }

        let mut selected_urls = Vec::new();
        let mut selected_configs = Vec::new();
        let mut covered = false;
        for (url, config) in with_config {
            selected_urls.push(url);
            selected_configs.push(config);
            if all_shards_available(selected_configs.clone()) {
                covered = true;
                break;
            }
        }

        if !covered {
            bail!(
                "file not found or shards incomplete, no shard-covered node set for root {}",
                root_hex
            );
        }

        selected_urls.sort();
        selected_urls.dedup();
        Ok(selected_urls)
    }

    async fn fetch_locations(&self, root_hex: String) -> Result<Vec<String>> {
        if !self.static_node_urls.is_empty() {
            return Ok(self.static_node_urls.clone());
        }
        let locations: Vec<Value> = self
            .indexer_client
            .request("indexer_getFileLocations", rpc_params![root_hex.clone()])
            .await?;
        let mut candidates = Vec::new();
        for loc in locations {
            match loc {
                Value::String(url) => candidates.push(LocationCandidate {
                    url,
                    shard_config: None,
                }),
                Value::Object(map) => {
                    if let Some(url) = map
                        .get("URL")
                        .or_else(|| map.get("url"))
                        .and_then(|v| v.as_str())
                    {
                        let shard_config = map.get("config").and_then(Self::parse_shard_config);
                        candidates.push(LocationCandidate {
                            url: url.to_string(),
                            shard_config,
                        });
                    }
                }
                _ => {}
            }
        }
        Self::select_download_nodes(candidates, &root_hex)
    }

    fn build_clients(&self, urls: &[String]) -> Result<Vec<HttpClient>> {
        urls.iter()
            .map(|url| {
                HttpClientBuilder::default()
                    .request_timeout(Duration::from_secs(self.zgs_rpc_timeout))
                    .build(url)
                    .map_err(|e| anyhow!("failed to build zgs client {}: {:?}", url, e))
            })
            .collect()
    }

    fn spawn_download_task(
        &self,
        client_index: &mut usize,
        tx: Arc<KVTransaction>,
        start_index: usize,
        end_index: usize,
        sender: &UnboundedSender<Result<(), (usize, usize, bool)>>,
        clients: Arc<Vec<HttpClient>>,
    ) {
        debug!(
            "downloading start_index {:?}, end_index: {:?} from client index: {}",
            start_index, end_index, client_index
        );

        self.task_executor.spawn(
            download_with_proof(
                clients.clone(),
                *client_index,
                tx,
                start_index,
                end_index,
                self.store.clone(),
                sender.clone(),
            ),
            "download segment",
        );

        // round robin client
        *client_index = (*client_index + 1) % clients.len();
    }

    async fn sync_data(&self, tx: &KVTransaction) -> Result<()> {
        if self.store.read().await.check_tx_completed(tx.seq)? {
            return Ok(());
        }
        let root_hex = format!("{:#x}", tx.data_merkle_root);
        let urls = self.fetch_locations(root_hex).await?;
        let clients = Arc::new(self.build_clients(&urls)?);
        let tx_size_in_entry = if tx.size % ENTRY_SIZE as u64 == 0 {
            tx.size / ENTRY_SIZE as u64
        } else {
            tx.size / ENTRY_SIZE as u64 + 1
        };

        let mut pending_entries = VecDeque::new();
        let mut task_counter = 0;
        let mut client_index = 0;
        let (sender, mut rx) = mpsc::unbounded_channel();
        let tx = Arc::new(tx.clone());

        for i in (0..tx_size_in_entry).step_by(ENTRIES_PER_SEGMENT * MAX_DOWNLOAD_TASK) {
            let tasks_end_index = cmp::min(
                tx_size_in_entry,
                i + (ENTRIES_PER_SEGMENT * MAX_DOWNLOAD_TASK) as u64,
            );
            debug!(
                "task_start_index: {:?}, tasks_end_index: {:?}, tx_size_in_entry: {:?}, root: {:?}",
                i, tasks_end_index, tx_size_in_entry, tx.data_merkle_root
            );
            for j in (i..tasks_end_index).step_by(ENTRIES_PER_SEGMENT) {
                let task_end_index = cmp::min(tasks_end_index, j + ENTRIES_PER_SEGMENT as u64);
                pending_entries.push_back((j as usize, task_end_index as usize));
            }
        }

        // spawn download tasks
        while task_counter < MAX_DOWNLOAD_TASK && !pending_entries.is_empty() {
            let (start_index, end_index) = pending_entries.pop_front().unwrap();
            self.spawn_download_task(
                &mut client_index,
                tx.clone(),
                start_index,
                end_index,
                &sender,
                clients.clone(),
            );
            task_counter += 1;
        }

        let mut failed_tasks = HashMap::new();
        while task_counter > 0 {
            if let Some(ret) = rx.recv().await {
                match ret {
                    Ok(_) => {
                        if let Some((start_index, end_index)) = pending_entries.pop_front() {
                            self.spawn_download_task(
                                &mut client_index,
                                tx.clone(),
                                start_index,
                                end_index,
                                &sender,
                                clients.clone(),
                            );
                        } else {
                            task_counter -= 1;
                        }
                    }
                    Err((start_index, end_index, data_err)) => {
                        warn!("Download data of tx_seq {:?}, start_index {:?}, end_index {:?}, failed",tx.seq, start_index, end_index);

                        match failed_tasks.get_mut(&start_index) {
                            Some(c) => {
                                if data_err {
                                    *c += 1;
                                }

                                if *c == clients.len() * MAX_RETRY {
                                    bail!(anyhow!(format!("Download segment failed, start_index {:?}, end_index: {:?}", start_index, end_index)));
                                }
                            }
                            _ => {
                                failed_tasks.insert(start_index, 1);
                            }
                        }

                        self.spawn_download_task(
                            &mut client_index,
                            tx.clone(),
                            start_index,
                            end_index,
                            &sender,
                            clients.clone(),
                        );
                    }
                }
            }
        }

        self.store
            .write()
            .await
            .finalize_tx_with_hash(tx.seq, tx.hash())?;
        Ok(())
    }

    pub async fn run(&self) {
        let mut tx_seq;
        match self
            .store
            .read()
            .await
            .get_stream_data_sync_progress()
            .await
        {
            Ok(progress) => {
                tx_seq = progress;
            }
            Err(e) => {
                error!("get stream data sync progress error: e={:?}", e);
                return;
            }
        }

        let mut check_sync_progress = false;
        loop {
            if check_sync_progress {
                match self
                    .store
                    .read()
                    .await
                    .get_stream_data_sync_progress()
                    .await
                {
                    Ok(progress) => {
                        if tx_seq != progress {
                            debug!("reorg happened: tx_seq {}, progress {}", tx_seq, progress);
                            tx_seq = progress;
                        }
                    }
                    Err(e) => {
                        error!("get stream data sync progress error: e={:?}", e);
                    }
                }

                check_sync_progress = false;
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
                                check_sync_progress = true;
                                continue;
                            }
                        };
                    info!(
                        "tx: {:?}, stream_matched: {:?}, can_write: {:?}",
                        tx_seq, stream_matched, can_write
                    );
                    if stream_matched && can_write {
                        // sync data
                        info!("syncing data of tx with sequence number {:?}..", tx.seq);
                        match self.sync_data(&tx).await {
                            Ok(()) => {
                                info!("data of tx with sequence number {:?} synced.", tx.seq);
                            }
                            Err(e) => {
                                error!("stream data sync error: e={:?}", e);
                                check_sync_progress = true;
                                continue;
                            }
                        }
                    } else if stream_matched {
                        // stream not matched, go to next tx
                        info!(
                            "sender of tx {:?} has no write permission, skipped.",
                            tx.seq
                        );
                    } else {
                        // stream not matched, go to next tx
                        info!("tx {:?} is not in stream, skipped.", tx.seq);
                    }
                    // update progress, get next tx_seq to sync
                    match self
                        .store
                        .write()
                        .await
                        .update_stream_data_sync_progress(tx_seq, tx_seq + 1)
                        .await
                    {
                        Ok(next_tx_seq) => {
                            tx_seq = next_tx_seq;
                        }
                        Err(e) => {
                            error!("update stream data sync progress error: e={:?}", e);
                        }
                    }
                }
                Ok(None) => {
                    tokio::time::sleep(Duration::from_millis(RETRY_WAIT_MS)).await;
                    check_sync_progress = true;
                }
                Err(e) => {
                    error!("stream data sync error: e={:?}", e);
                    tokio::time::sleep(Duration::from_millis(RETRY_WAIT_MS)).await;
                    check_sync_progress = true;
                }
            }
        }
    }
}
