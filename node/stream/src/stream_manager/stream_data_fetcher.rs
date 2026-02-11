use crate::{stream_manager::skippable, StreamConfig};
use anyhow::{anyhow, bail, Result};
use kv_types::KVTransaction;
use shared_types::ChunkArray;
use std::{
    cmp,
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::Duration,
};
use zg_storage_client::common::shard::select;
use zg_storage_client::core::dataflow::padded_segment_root;
use zg_storage_client::indexer::client::IndexerClient;
use zg_storage_client::node::client_zgs::ZgsClient;
use zg_storage_client::transfer::encryption::{crypt_at, EncryptionHeader, ENCRYPTION_HEADER_SIZE};

use storage_with_stream::{log_store::log_manager::ENTRY_SIZE, Store};
use task_executor::TaskExecutor;
use tokio::sync::{
    mpsc::{self, UnboundedSender},
    RwLock,
};

const RETRY_WAIT_MS: u64 = 1000;
const ENTRIES_PER_SEGMENT: usize = 1024;
const MAX_DOWNLOAD_TASK: usize = 5;
const MAX_RETRY: usize = 5;

struct DownloadTaskParams {
    tx: Arc<KVTransaction>,
    start_index: usize,
    end_index: usize,
    sender: UnboundedSender<Result<(), (usize, usize, bool)>>,
    clients: Arc<Vec<ZgsClient>>,
    encryption: Option<([u8; 32], EncryptionHeader)>,
}

pub struct StreamDataFetcher {
    config: StreamConfig,
    store: Arc<RwLock<dyn Store>>,
    indexer_client: Option<IndexerClient>,
    static_clients: Vec<ZgsClient>,
    task_executor: TaskExecutor,
}

#[allow(clippy::too_many_arguments)]
async fn download_with_proof(
    clients: Arc<Vec<ZgsClient>>,
    client_index: usize,
    tx: Arc<KVTransaction>,
    start_index: usize,
    end_index: usize,
    store: Arc<RwLock<dyn Store>>,
    sender: UnboundedSender<Result<(), (usize, usize, bool)>>,
    encryption: Option<([u8; 32], EncryptionHeader)>,
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
            .download_segment_with_proof_by_tx_seq(tx.seq, seg_index as u64)
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

                let (seg_root, num_segs) = padded_segment_root(
                    segment.index as u64,
                    &segment.data,
                    segment.file_size as u64,
                );
                if let Err(e) = segment.proof.validate_hash(
                    segment.root,
                    seg_root,
                    segment.index as u64,
                    num_segs,
                ) {
                    debug!("validate segment with error: {:?}", e);
                    if let Err(e) = sender.send(Err((start_index, end_index, true))) {
                        error!("send error: {:?}", e);
                    }
                    return;
                }

                // Decrypt segment data before storing if encryption is configured
                let data = if let Some((key, header)) = &encryption {
                    let segment_size_bytes = ENTRIES_PER_SEGMENT * ENTRY_SIZE;
                    let data_offset = (seg_index * segment_size_bytes) as u64
                        - ENCRYPTION_HEADER_SIZE as u64;
                    let mut data = segment.data;
                    crypt_at(key, &header.nonce, data_offset, &mut data);
                    data
                } else {
                    segment.data
                };

                if let Err(e) = store.write().await.put_chunks_with_tx_hash(
                    tx.seq,
                    tx.hash(),
                    ChunkArray {
                        data,
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
            static_clients.push(ZgsClient::new(url).await?);
        }

        Ok(Self {
            config,
            store,
            indexer_client,
            static_clients,
            task_executor,
        })
    }

    async fn fetch_clients(&self, root: ethers::types::H256) -> Result<Vec<ZgsClient>> {
        if !self.static_clients.is_empty() {
            return Ok(self.static_clients.clone());
        }

        let indexer = self
            .indexer_client
            .as_ref()
            .ok_or_else(|| anyhow!("No indexer client and no static nodes configured"))?;

        let locations = indexer.get_file_locations(root).await?;
        let mut locations =
            locations.ok_or_else(|| anyhow!("File not found on indexer for root {:?}", root))?;

        let (selected, covered) = select(&mut locations, 1, true);
        if !covered {
            bail!("File not found or shards incomplete for root {:?}", root);
        }

        let mut clients = Vec::new();
        for node in selected {
            match ZgsClient::new(&node.url).await {
                Ok(client) => clients.push(client),
                Err(e) => {
                    warn!("Failed to create client for node {}: {:?}", node.url, e);
                    continue;
                }
            }
        }

        if clients.is_empty() {
            bail!("No reachable nodes found for root {:?}", root);
        }

        Ok(clients)
    }

    fn spawn_download_task(&self, client_index: &mut usize, params: DownloadTaskParams) {
        debug!(
            "downloading start_index {:?}, end_index: {:?} from client index: {}",
            params.start_index, params.end_index, client_index
        );

        self.task_executor.spawn(
            download_with_proof(
                params.clients.clone(),
                *client_index,
                params.tx,
                params.start_index,
                params.end_index,
                self.store.clone(),
                params.sender,
                params.encryption,
            ),
            "download segment",
        );

        // round robin client
        *client_index = (*client_index + 1) % params.clients.len();
    }

    /// Download segment 0 first to extract the encryption header, decrypt it, and store it.
    /// Returns the parsed EncryptionHeader for use by subsequent segment downloads.
    async fn download_first_segment_encrypted(
        &self,
        clients: &Arc<Vec<ZgsClient>>,
        tx: &Arc<KVTransaction>,
        key: &[u8; 32],
        end_index: usize,
    ) -> Result<EncryptionHeader> {
        for attempt in 0..clients.len() * MAX_RETRY {
            let client_idx = attempt % clients.len();
            match clients[client_idx]
                .download_segment_with_proof_by_tx_seq(tx.seq, 0)
                .await
            {
                Ok(Some(segment)) => {
                    if segment.data.len() % ENTRY_SIZE != 0
                        || segment.data.len() / ENTRY_SIZE != end_index
                    {
                        warn!("Invalid data length for segment 0");
                        continue;
                    }
                    if segment.root != tx.data_merkle_root {
                        warn!("Invalid file root for segment 0");
                        continue;
                    }
                    let (seg_root, num_segs) =
                        padded_segment_root(0, &segment.data, segment.file_size as u64);
                    if let Err(e) =
                        segment
                            .proof
                            .validate_hash(segment.root, seg_root, 0, num_segs)
                    {
                        warn!("Proof validation failed for segment 0: {:?}", e);
                        continue;
                    }

                    if segment.data.len() < ENCRYPTION_HEADER_SIZE {
                        bail!("Segment 0 too short for encryption header");
                    }
                    let header = EncryptionHeader::parse(&segment.data)?;

                    // Decrypt: skip header bytes, decrypt the rest at data offset 0
                    let mut data = segment.data;
                    crypt_at(key, &header.nonce, 0, &mut data[ENCRYPTION_HEADER_SIZE..]);

                    self.store.write().await.put_chunks_with_tx_hash(
                        tx.seq,
                        tx.hash(),
                        ChunkArray {
                            data,
                            start_index: 0,
                        },
                        None,
                    )?;

                    return Ok(header);
                }
                Ok(None) => {
                    tokio::time::sleep(Duration::from_millis(RETRY_WAIT_MS)).await;
                }
                Err(e) => {
                    warn!("Error downloading segment 0: {:?}", e);
                    tokio::time::sleep(Duration::from_millis(RETRY_WAIT_MS)).await;
                }
            }
        }
        bail!("Failed to download segment 0 for encryption header after all retries");
    }

    async fn sync_data(&self, tx: &KVTransaction) -> Result<()> {
        if self.store.read().await.check_tx_completed(tx.seq)? {
            return Ok(());
        }
        let clients = Arc::new(self.fetch_clients(tx.data_merkle_root).await?);
        let tx_size_in_entry = if tx.size % ENTRY_SIZE as u64 == 0 {
            tx.size / ENTRY_SIZE as u64
        } else {
            tx.size / ENTRY_SIZE as u64 + 1
        };

        let tx = Arc::new(tx.clone());

        // If encrypted, download segment 0 first to get the encryption header
        let (encryption, start_entry) = if let Some(key) = &self.config.encryption_key {
            let first_seg_entries = cmp::min(ENTRIES_PER_SEGMENT as u64, tx_size_in_entry);
            let header = self
                .download_first_segment_encrypted(
                    &clients,
                    &tx,
                    key,
                    first_seg_entries as usize,
                )
                .await?;
            (Some((*key, header)), first_seg_entries)
        } else {
            (None, 0)
        };

        let mut pending_entries = VecDeque::new();
        let mut task_counter = 0;
        let mut client_index = 0;
        let (sender, mut rx) = mpsc::unbounded_channel();

        for i in
            (start_entry..tx_size_in_entry).step_by(ENTRIES_PER_SEGMENT * MAX_DOWNLOAD_TASK)
        {
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
                DownloadTaskParams {
                    tx: tx.clone(),
                    start_index,
                    end_index,
                    sender: sender.clone(),
                    clients: clients.clone(),
                    encryption: encryption.clone(),
                },
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
                                DownloadTaskParams {
                                    tx: tx.clone(),
                                    start_index,
                                    end_index,
                                    sender: sender.clone(),
                                    clients: clients.clone(),
                                    encryption: encryption.clone(),
                                },
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
                            DownloadTaskParams {
                                tx: tx.clone(),
                                start_index,
                                end_index,
                                sender: sender.clone(),
                                clients: clients.clone(),
                                encryption: encryption.clone(),
                            },
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
