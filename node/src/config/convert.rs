#![allow(clippy::field_reassign_with_default)]

use std::{collections::HashSet, str::FromStr, time::Duration};

use crate::ZgsKVConfig;
use ethereum_types::H256;
use http::Uri;
use log_entry_sync::{CacheConfig, ContractAddress, LogSyncConfig};
use rpc::RPCConfig;
use storage_with_stream::{log_store::log_manager::LogConfig, LogStorageConfig, StorageConfig};
use stream::StreamConfig;

impl ZgsKVConfig {
    pub fn storage_config(&self) -> Result<StorageConfig, String> {
        let mut log_config = LogConfig::default();
        log_config.flow.merkle_node_cache_capacity = self.merkle_node_cache_capacity;
        Ok(StorageConfig {
            log_config: LogStorageConfig {
                db_dir: self.db_dir.clone().into(),
                log_config,
            },
            kv_db_file: self.kv_db_file.clone().into(),
        })
    }

    pub fn stream_config(&self) -> Result<StreamConfig, String> {
        let mut stream_ids: Vec<H256> = vec![];
        for id in &self.stream_ids {
            stream_ids.push(
                H256::from_str(id)
                    .map_err(|e| format!("Unable to parse stream id: {:?}, error: {:?}", id, e))?,
            );
        }
        stream_ids.sort();
        stream_ids.dedup();
        if stream_ids.is_empty() {
            error!("{}", format!("stream ids is empty"))
        }
        let stream_set = HashSet::from_iter(stream_ids.iter().cloned());
        let encryption_key = if self.encryption_key.is_empty() {
            None
        } else {
            Some(parse_encryption_key(&self.encryption_key)?)
        };
        Ok(StreamConfig {
            stream_ids,
            stream_set,
            encryption_key,
            max_download_retries: self.max_download_retries,
            download_timeout_ms: self.download_timeout_ms,
            download_retry_interval_ms: self.download_retry_interval_ms,
        })
    }

    pub fn rpc_config(&self) -> Result<RPCConfig, String> {
        let listen_address = self
            .rpc_listen_address
            .parse::<std::net::SocketAddr>()
            .map_err(|e| format!("Unable to parse rpc_listen_address: {:?}", e))?;
        if self.indexer_url.is_empty() && self.zgs_node_urls.is_empty() {
            return Err("either indexer_url or zgs_node_urls must be set".to_string());
        }
        if !self.indexer_url.is_empty() {
            self.indexer_url
                .parse::<Uri>()
                .map_err(|e| format!("Invalid indexer_url: {}", e))?;
        }

        Ok(RPCConfig {
            enabled: self.rpc_enabled,
            listen_address,
            chunks_per_segment: self.rpc_chunks_per_segment,
            indexer_url: if self.indexer_url.is_empty() {
                None
            } else {
                Some(self.indexer_url.clone())
            },
            zgs_nodes: if self.zgs_node_urls.is_empty() {
                Vec::new()
            } else {
                to_zgs_nodes(self.zgs_node_urls.clone())
                    .map_err(|e| format!("failed to parse zgs_node_urls: {}", e))?
            },
            max_query_len_in_bytes: self.max_query_len_in_bytes,
            max_response_body_in_bytes: self.max_response_body_in_bytes,
            zgs_rpc_timeout: self.zgs_rpc_timeout,
        })
    }

    pub fn log_sync_config(&self) -> Result<LogSyncConfig, String> {
        let contract_address = self
            .log_contract_address
            .parse::<ContractAddress>()
            .map_err(|e| format!("Unable to parse log_contract_address: {:?}", e))?;
        let cache_config = CacheConfig {
            // 100 MB.
            max_data_size: self.max_cache_data_size,
            // This should be enough if we have about one Zgs tx per block.
            tx_seq_ttl: self.cache_tx_seq_ttl,
        };
        Ok(LogSyncConfig::new(
            self.blockchain_rpc_endpoint.clone(),
            contract_address,
            self.log_sync_start_block_number,
            self.confirmation_block_count,
            cache_config,
            self.log_page_size,
            self.rate_limit_retries,
            self.timeout_retries,
            self.initial_backoff,
            self.recover_query_delay,
            self.default_finalized_block_count,
            self.remove_finalized_block_interval_minutes,
            self.watch_loop_wait_time_ms,
            self.force_log_sync_from_start_block_number,
            Duration::from_secs(self.blockchain_rpc_timeout_secs),
        ))
    }
}

fn parse_encryption_key(hex_str: &str) -> Result<[u8; 32], String> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    if hex_str.len() != 64 {
        return Err(format!(
            "encryption_key must be 64 hex chars (32 bytes), got {} chars",
            hex_str.len()
        ));
    }
    let mut key = [0u8; 32];
    for i in 0..32 {
        key[i] = u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("Invalid hex in encryption_key at position {}: {}", i * 2, e))?;
    }
    Ok(key)
}

// zgs_node_urls can be used as a static node list; otherwise indexer_url is used.
pub fn to_zgs_nodes(zgs_node_urls: String) -> Result<Vec<String>, String> {
    if zgs_node_urls.is_empty() {
        return Err("zgs_node_urls is empty".to_string());
    }

    zgs_node_urls
        .split(',')
        .map(|url| {
            url.parse::<Uri>()
                .map_err(|e| format!("Invalid URL: {}", e))?;

            Ok(url.to_owned())
        })
        .collect()
}
