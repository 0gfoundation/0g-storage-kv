use crate::{stream_manager::skippable, StreamConfig};
use anyhow::{anyhow, bail, Result};
use kv_types::KVTransaction;
use shared_types::ChunkArray;
use std::{
    cmp,
    collections::{HashSet, VecDeque},
    sync::{Arc, Mutex},
    time::Duration,
};
use zg_storage_client::common::shard::select;
use zg_storage_client::indexer::client::IndexerClient;
use zg_storage_client::node::client_zgs::ZgsClient;
use zg_storage_client::node::types::{FileInfo, Transaction as SdkTransaction};
use zg_storage_client::transfer::downloader::DownloadContext;

use storage_with_stream::{log_store::log_manager::ENTRY_SIZE, Store};
use task_executor::TaskExecutor;
use tokio::sync::{
    mpsc::{self, UnboundedSender},
    RwLock,
};

const ENTRIES_PER_SEGMENT: usize = 1024;
const MAX_DOWNLOAD_TASK: usize = 5;
const SEGMENT_DOWNLOAD_RETRIES: usize = 5;
const HEALTH_CHECK_TIMEOUT_SECS: u64 = 2;

struct DownloadTaskParams {
    ctx: Arc<DownloadContext>,
    tx: Arc<KVTransaction>,
    segment_index: u64,
    start_entry: usize,
    end_entry: usize,
    sender: UnboundedSender<Result<()>>,
    retry_wait_ms: u64,
}

pub struct StreamDataFetcher {
    config: StreamConfig,
    store: Arc<RwLock<dyn Store>>,
    indexer_client: Option<IndexerClient>,
    static_clients: Vec<(String, ZgsClient)>,
    dead_urls: Mutex<HashSet<String>>,
    task_executor: TaskExecutor,
}

async fn download_with_proof(params: DownloadTaskParams, store: Arc<RwLock<dyn Store>>) {
    let DownloadTaskParams {
        ctx,
        tx,
        segment_index,
        start_entry,
        end_entry,
        sender,
        retry_wait_ms,
    } = params;

    let mut last_err = None;
    for attempt in 0..SEGMENT_DOWNLOAD_RETRIES {
        debug!(
            "download_with_proof for tx_seq: {}, segment: {}, entries: [{}, {}) attempt {}",
            tx.seq, segment_index, start_entry, end_entry, attempt
        );

        match ctx.download_segment_padded(segment_index, true).await {
            Ok(data) => {
                if data.len() % ENTRY_SIZE != 0
                    || data.len() / ENTRY_SIZE != end_entry - start_entry
                {
                    last_err = Some(anyhow!(
                        "invalid data length: got {} entries, expected {}",
                        data.len() / ENTRY_SIZE,
                        end_entry - start_entry
                    ));
                } else {
                    match store.write().await.put_chunks_with_tx_hash(
                        tx.seq,
                        tx.hash(),
                        ChunkArray {
                            data,
                            start_index: segment_index * ENTRIES_PER_SEGMENT as u64,
                        },
                        None,
                    ) {
                        Ok(_) => {
                            debug!("download segment {} successful", segment_index);
                            if let Err(e) = sender.send(Ok(())) {
                                error!("send error: {:?}", e);
                            }
                            return;
                        }
                        Err(e) => {
                            last_err = Some(anyhow!(e));
                        }
                    }
                }
            }
            Err(e) => {
                last_err = Some(anyhow!(
                    "tx_seq {}, segment {}, download error: {:?}",
                    tx.seq,
                    segment_index,
                    e
                ));
            }
        }

        tokio::time::sleep(Duration::from_millis(retry_wait_ms)).await;
    }

    if let Err(e) = sender.send(Err(last_err.unwrap_or_else(|| anyhow!("download failed")))) {
        error!("send error: {:?}", e);
    }
}

/// Convert a KVTransaction to an SDK FileInfo for use with DownloadContext.
fn kv_tx_to_file_info(tx: &KVTransaction) -> FileInfo {
    FileInfo {
        tx: SdkTransaction {
            stream_ids: vec![],
            data: vec![],
            data_merkle_root: tx.data_merkle_root,
            start_entry_index: tx.start_entry_index,
            size: tx.size,
            seq: tx.seq,
        },
        finalized: true,
        is_cached: false,
        uploaded_seg_num: 0,
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
        // Initialize SDK's global RPC config with the KV's timeout setting
        zg_storage_client::common::options::init_global_config(
            None,
            None,
            false,
            5,
            Duration::from_secs(5),
            Duration::from_secs(zgs_rpc_timeout),
        )
        .await?;

        let indexer_client = match indexer_url {
            Some(url) if !url.is_empty() => Some(IndexerClient::new(&url).await?),
            _ => None,
        };

        let mut static_clients = Vec::new();
        for url in &zgs_nodes {
            let client = ZgsClient::new(url).await?;
            static_clients.push((url.clone(), client));
        }

        Ok(Self {
            config,
            store,
            indexer_client,
            static_clients,
            dead_urls: Mutex::new(HashSet::new()),
            task_executor,
        })
    }

    /// Health-check static clients and mark unreachable ones as dead.
    async fn update_dead_nodes(&self) {
        let timeout = Duration::from_secs(HEALTH_CHECK_TIMEOUT_SECS);
        for (url, client) in &self.static_clients {
            match tokio::time::timeout(timeout, client.get_status()).await {
                Ok(Ok(_)) => {
                    self.dead_urls.lock().unwrap().remove(url);
                }
                _ => {
                    warn!("Node {} is unreachable, marking as dead", url);
                    self.dead_urls.lock().unwrap().insert(url.clone());
                }
            }
        }
    }

    /// Fetch alive storage clients, retrying until at least one is available.
    /// For indexer mode: re-queries indexer and filters dead nodes before shard
    /// selection so the algorithm picks a valid replication from alive nodes.
    async fn fetch_clients(&self, root: ethers::types::H256) -> Vec<ZgsClient> {
        loop {
            if !self.static_clients.is_empty() {
                let dead = self.dead_urls.lock().unwrap().clone();
                let alive: Vec<ZgsClient> = self
                    .static_clients
                    .iter()
                    .filter(|(url, _)| !dead.contains(url))
                    .map(|(_, client)| client.clone())
                    .collect();
                if !alive.is_empty() {
                    return alive;
                }
                // All static nodes marked dead — clear and return all to retry
                warn!("All static nodes marked as dead, clearing dead set and retrying");
                self.dead_urls.lock().unwrap().clear();
                tokio::time::sleep(Duration::from_millis(self.config.retry_wait_ms)).await;
                continue;
            }

            let indexer = match self.indexer_client.as_ref() {
                Some(c) => c,
                None => {
                    error!("No indexer client and no static nodes configured");
                    tokio::time::sleep(Duration::from_millis(self.config.retry_wait_ms)).await;
                    continue;
                }
            };

            let mut locations = match indexer.get_file_locations(root).await {
                Ok(Some(locs)) if !locs.is_empty() => locs,
                Ok(_) => {
                    info!("File not found on indexer for root {:?}, retrying", root);
                    tokio::time::sleep(Duration::from_millis(self.config.retry_wait_ms)).await;
                    continue;
                }
                Err(e) => {
                    warn!("Indexer query failed: {:?}, retrying", e);
                    tokio::time::sleep(Duration::from_millis(self.config.retry_wait_ms)).await;
                    continue;
                }
            };

            // Filter out dead nodes before shard selection
            {
                let dead = self.dead_urls.lock().unwrap();
                locations.retain(|node| !dead.contains(&node.url));
            }

            let (selected, covered) = select(&mut locations, 1, true);
            if !covered {
                warn!(
                    "Shards not fully covered after filtering dead nodes for root {:?}, \
                     clearing dead set and retrying",
                    root
                );
                self.dead_urls.lock().unwrap().clear();
                tokio::time::sleep(Duration::from_millis(self.config.retry_wait_ms)).await;
                continue;
            }

            let mut clients = Vec::new();
            for node in &selected {
                match ZgsClient::new_with_shard_config(&node.url, node.config.clone()).await {
                    Ok(client) => clients.push(client),
                    Err(e) => {
                        warn!("Failed to create client for node {}: {:?}", node.url, e);
                        self.dead_urls.lock().unwrap().insert(node.url.clone());
                    }
                }
            }

            if !clients.is_empty() {
                return clients;
            }

            warn!("No reachable nodes after selection, retrying");
            tokio::time::sleep(Duration::from_millis(self.config.retry_wait_ms)).await;
        }
    }

    fn spawn_download_task(&self, params: DownloadTaskParams) {
        debug!(
            "downloading segment {:?}, entries: [{:?}, {:?})",
            params.segment_index, params.start_entry, params.end_entry
        );

        let store = self.store.clone();
        self.task_executor
            .spawn(download_with_proof(params, store), "download segment");
    }

    async fn sync_data(&self, tx: &KVTransaction, clients: Vec<ZgsClient>) -> Result<()> {
        if self.store.read().await.check_tx_completed(tx.seq)? {
            return Ok(());
        }

        let file_info = kv_tx_to_file_info(tx);

        // Build DownloadContext with optional encryption
        let ctx = {
            let base = DownloadContext::new(clients, 1, file_info, tx.data_merkle_root)?;
            if let Some(key) = &self.config.encryption_key {
                base.with_encryption(*key)
            } else {
                base
            }
        };
        let ctx = Arc::new(ctx);

        let tx_size_in_entry = if tx.size % ENTRY_SIZE as u64 == 0 {
            tx.size / ENTRY_SIZE as u64
        } else {
            tx.size / ENTRY_SIZE as u64 + 1
        };

        let tx = Arc::new(tx.clone());

        // If encrypted, download segment 0 first to parse the encryption header
        let start_entry = if self.config.encryption_key.is_some() {
            let first_seg_entries = cmp::min(ENTRIES_PER_SEGMENT as u64, tx_size_in_entry);
            let data = ctx.download_segment_padded(0, true).await?;

            if data.len() / ENTRY_SIZE != first_seg_entries as usize {
                bail!(
                    "Segment 0 data length mismatch: got {} entries, expected {}",
                    data.len() / ENTRY_SIZE,
                    first_seg_entries
                );
            }

            self.store.write().await.put_chunks_with_tx_hash(
                tx.seq,
                tx.hash(),
                ChunkArray {
                    data,
                    start_index: 0,
                },
                None,
            )?;

            first_seg_entries
        } else {
            0
        };

        let mut pending_entries = VecDeque::new();
        let mut task_counter = 0;
        let (sender, mut rx) = mpsc::unbounded_channel();

        for i in (start_entry..tx_size_in_entry).step_by(ENTRIES_PER_SEGMENT * MAX_DOWNLOAD_TASK) {
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
            let segment_index = start_index as u64 / ENTRIES_PER_SEGMENT as u64;
            self.spawn_download_task(DownloadTaskParams {
                ctx: ctx.clone(),
                tx: tx.clone(),
                segment_index,
                start_entry: start_index,
                end_entry: end_index,
                sender: sender.clone(),
                retry_wait_ms: self.config.retry_wait_ms,
            });
            task_counter += 1;
        }

        while task_counter > 0 {
            if let Some(ret) = rx.recv().await {
                match ret {
                    Ok(_) => {
                        if let Some((start_index, end_index)) = pending_entries.pop_front() {
                            let segment_index = start_index as u64 / ENTRIES_PER_SEGMENT as u64;
                            self.spawn_download_task(DownloadTaskParams {
                                ctx: ctx.clone(),
                                tx: tx.clone(),
                                segment_index,
                                start_entry: start_index,
                                end_entry: end_index,
                                sender: sender.clone(),
                                retry_wait_ms: self.config.retry_wait_ms,
                            });
                        } else {
                            task_counter -= 1;
                        }
                    }
                    Err(e) => {
                        bail!("Download failed for tx_seq {:?}: {:?}", tx.seq, e);
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
        let mut consecutive_failures: usize = 0;
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
                            consecutive_failures = 0;
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
                        // Health-check nodes before download to avoid slow
                        // timeouts against unreachable nodes
                        self.update_dead_nodes().await;
                        info!("syncing data of tx with sequence number {:?}..", tx.seq);

                        // Step 1: Wait for file locations with timeout
                        let fetch_timeout = Duration::from_millis(self.config.download_timeout_ms);
                        let fetch_result = tokio::time::timeout(
                            fetch_timeout,
                            self.fetch_clients(tx.data_merkle_root),
                        )
                        .await;

                        let sync_err = match fetch_result {
                            Ok(clients) => {
                                // Step 2: Download without overall timeout;
                                // individual RPCs have their own timeout.
                                match self.sync_data(&tx, clients).await {
                                    Ok(()) => {
                                        info!(
                                            "data of tx with sequence number {:?} synced.",
                                            tx.seq
                                        );
                                        self.dead_urls.lock().unwrap().clear();
                                        None
                                    }
                                    Err(e) => Some(e),
                                }
                            }
                            Err(_) => Some(anyhow!(
                                "Timed out waiting for file location for tx {:?}",
                                tx_seq
                            )),
                        };
                        if let Some(e) = sync_err {
                            // Health-check nodes and mark dead ones
                            self.update_dead_nodes().await;

                            consecutive_failures += 1;
                            if self.config.max_download_retries > 0
                                && consecutive_failures >= self.config.max_download_retries
                            {
                                warn!(
                                    "tx {:?} download failed after {} attempts, skipping: e={:?}",
                                    tx_seq, consecutive_failures, e
                                );
                                consecutive_failures = 0;
                                // fall through to advance progress
                            } else {
                                error!(
                                    "stream data sync error (attempt {}/{}): e={:?}",
                                    consecutive_failures, self.config.max_download_retries, e
                                );
                                tokio::time::sleep(Duration::from_millis(
                                    self.config.download_retry_interval_ms,
                                ))
                                .await;
                                check_sync_progress = true;
                                continue;
                            }
                        }
                    } else if stream_matched {
                        info!(
                            "sender of tx {:?} has no write permission, skipped.",
                            tx.seq
                        );
                    } else {
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
                            consecutive_failures = 0;
                        }
                        Err(e) => {
                            error!("update stream data sync progress error: e={:?}", e);
                        }
                    }
                }
                Ok(None) => {
                    tokio::time::sleep(Duration::from_millis(self.config.retry_wait_ms)).await;
                    check_sync_progress = true;
                }
                Err(e) => {
                    error!("stream data sync error: e={:?}", e);
                    tokio::time::sleep(Duration::from_millis(self.config.retry_wait_ms)).await;
                    check_sync_progress = true;
                }
            }
        }
    }
}
