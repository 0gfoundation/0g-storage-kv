//! Uploads a batch payload for renewal, forcing a fresh on-chain submission
//! (`skip_tx: false`) so the file's log entry is re-anchored even when the
//! same data already lives on storage nodes. See spec §4 step 6.

use anyhow::{bail, Result};
use async_trait::async_trait;
use ethereum_types::H256;
use ethers::types::U256;
use std::sync::Arc;
use zg_storage_client::cmd::upload::{FinalityRequirement, UploadOption};
use zg_storage_client::common::blockchain::rpc::must_new_web3;
use zg_storage_client::core::dataflow::{merkle_tree, IterableData};
use zg_storage_client::indexer::client::IndexerClient;
use zg_storage_client::node::client_zgs::{must_new_zgs_clients, ZgsClient};
use zg_storage_client::transfer::uploader::{Uploader, Web3Client};

use crate::RenewConfig;

/// Sink Tasks 17/19 upload renewal batches through; a mock implementation
/// drives their unit tests without touching the network.
#[async_trait]
pub trait BatchSink: Send + Sync {
    /// Uploads; returns the file's merkle root. "Already finalized" counts as success.
    async fn submit(&self, data: Arc<dyn IterableData>, tags: Vec<u8>) -> Result<H256>;
    /// Root -> tx seq via storage-node file info (None until nodes have logged it).
    async fn resolve_tx_seq(&self, root: H256) -> Result<Option<u64>>;
}

/// Uploads renewal batches via the storage SDK, always forcing a fresh
/// on-chain submission (`skip_tx: false`) regardless of whether the data
/// already sits on storage nodes — that resubmission is the entire point of
/// renewal.
pub struct RenewUploader {
    web3: Web3Client,
    indexer: Option<IndexerClient>,
    zgs_node_urls: Vec<String>,
    expected_replica: u64,
}

impl RenewUploader {
    pub async fn new(cfg: &RenewConfig) -> Result<Self> {
        let web3 = must_new_web3(&cfg.blockchain_rpc_endpoint, &hex::encode(cfg.private_key)).await;

        let indexer = match &cfg.indexer_url {
            Some(url) if !url.is_empty() => Some(IndexerClient::new(url).await?),
            _ => None,
        };

        Ok(Self {
            web3,
            indexer,
            zgs_node_urls: cfg.zgs_node_urls.clone(),
            expected_replica: cfg.expected_replica,
        })
    }

    /// Selects storage-node clients: via the indexer's shard selection when
    /// configured, otherwise the statically configured node URLs.
    async fn clients(&self) -> Result<Vec<ZgsClient>> {
        if let Some(indexer) = &self.indexer {
            return indexer
                .select_nodes(self.expected_replica as usize, &[])
                .await;
        }
        if !self.zgs_node_urls.is_empty() {
            return Ok(must_new_zgs_clients(&self.zgs_node_urls).await);
        }
        bail!("RenewUploader: no indexer_url or zgs_node_urls configured")
    }
}

#[async_trait]
impl BatchSink for RenewUploader {
    async fn submit(&self, data: Arc<dyn IterableData>, tags: Vec<u8>) -> Result<H256> {
        let tree = merkle_tree(data.clone()).await?;
        let root = H256::from_slice(tree.root().as_ref());
        let clients = self.clients().await?;

        let opt = UploadOption {
            tags,
            finality_required: FinalityRequirement::TransactionPacked,
            task_size: 10,
            expected_replica: self.expected_replica,
            skip_tx: false, // THE point of renewal: always submit on-chain
            fee: U256::zero(),
            nonce: U256::zero(),
        };

        let uploader = Uploader::new(self.web3.clone(), clients).await?;
        match uploader.upload(data, &opt).await {
            Ok(_) => Ok(root),
            Err(e) if is_already_finalized_err(&format!("{:?}", e)) => {
                info!(
                    "segments already on nodes for {:?}; tx submitted, counting as success",
                    root
                );
                Ok(root)
            }
            Err(e) => Err(e),
        }
    }

    async fn resolve_tx_seq(&self, root: H256) -> Result<Option<u64>> {
        let clients = self.clients().await?;
        for client in &clients {
            if let Some(info) = client.get_file_info(root).await? {
                return Ok(Some(info.tx.seq));
            }
        }
        Ok(None)
    }
}

/// Matches storage/chain error text indicating the file was already
/// uploaded/finalized — treated as renewal success rather than failure.
pub fn is_already_finalized_err(msg: &str) -> bool {
    let m = msg.to_lowercase();
    m.contains("already") && (m.contains("finaliz") || m.contains("exist"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn already_finalized_matcher() {
        assert!(is_already_finalized_err("file already exists on node"));
        assert!(is_already_finalized_err("Transaction already finalized"));
        assert!(!is_already_finalized_err("connection refused"));
    }
}
