#![allow(clippy::field_reassign_with_default)]

use std::{collections::HashSet, str::FromStr, sync::Arc, time::Duration};

use crate::ZgsKVConfig;
use ethereum_types::H256;
use http::Uri;
use log_entry_sync::{CacheConfig, ContractAddress, LogSyncConfig};
use rpc::RPCConfig;
use storage_with_stream::{log_store::log_manager::LogConfig, LogStorageConfig, StorageConfig};
use stream::StreamConfig;
use tokio::sync::RwLock;

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
        let stream_set = Arc::new(RwLock::new(HashSet::from_iter(stream_ids.iter().cloned())));
        let encryption_key = if self.encryption_key.is_empty() {
            None
        } else {
            Some(parse_32byte_hex(&self.encryption_key, "encryption_key")?)
        };
        let wallet_private_key = if self.wallet_private_key.is_empty() {
            None
        } else {
            Some(parse_32byte_hex(
                &self.wallet_private_key,
                "wallet_private_key",
            )?)
        };
        if encryption_key.is_some() && wallet_private_key.is_some() {
            return Err(
                "encryption_key (v1 symmetric) and wallet_private_key (v2 ECIES) are mutually exclusive; configure at most one"
                    .to_string(),
            );
        }
        Ok(StreamConfig {
            stream_ids,
            stream_set,
            encryption_key,
            wallet_private_key,
            max_download_retries: self.max_download_retries,
            download_timeout_ms: self.download_timeout_ms,
            download_retry_interval_ms: self.download_retry_interval_ms,
            retry_wait_ms: self.retry_wait_ms,
        })
    }

    // Wired into the client's renew loop startup by a later task; unused for now.
    #[allow(dead_code)]
    pub fn renew_config(&self) -> Result<Option<kv_renew::RenewConfig>, String> {
        let key_hex = std::env::var("ZGS_KV_RENEW_PRIVATE_KEY")
            .unwrap_or_else(|_| self.renew_private_key.clone());
        if !self.renew_enabled || key_hex.is_empty() {
            return Ok(None);
        }
        let private_key = parse_32byte_hex(&key_hex, "renew_private_key")?;

        let mut stream_ids = Vec::new();
        for id in &self.renew_stream_ids {
            stream_ids.push(
                H256::from_str(id).map_err(|e| format!("bad renew_stream_id {}: {:?}", id, e))?,
            );
        }

        let stream_cfg = self.stream_config()?; // reuse parsed encryption keys
        Ok(Some(kv_renew::RenewConfig {
            private_key,
            max_age_secs: self.renew_max_age_secs,
            cycle_interval_secs: self.renew_cycle_interval_secs,
            batch_max_bytes: self.renew_batch_max_bytes,
            batch_max_keys: self.renew_batch_max_keys,
            pause_between_batches_ms: self.renew_pause_between_batches_ms,
            startup_delay_secs: self.renew_startup_delay_secs,
            expected_replica: self.renew_expected_replica,
            stream_ids,
            dry_run: self.renew_dry_run,
            max_attempts: self.renew_max_attempts,
            blockchain_rpc_endpoint: self.blockchain_rpc_endpoint.clone(),
            log_contract_address: self.log_contract_address.clone(),
            indexer_url: if self.indexer_url.is_empty() {
                None
            } else {
                Some(self.indexer_url.clone())
            },
            zgs_node_urls: if self.zgs_node_urls.is_empty() {
                Vec::new()
            } else {
                to_zgs_nodes(self.zgs_node_urls.clone())?
            },
            encryption_key: stream_cfg.encryption_key,
            wallet_private_key: stream_cfg.wallet_private_key,
        }))
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
            chain_id: self.chain_id,
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

fn parse_32byte_hex(hex_str: &str, field_name: &str) -> Result<[u8; 32], String> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    if hex_str.len() != 64 {
        return Err(format!(
            "{} must be 64 hex chars (32 bytes), got {} chars",
            field_name,
            hex_str.len()
        ));
    }
    let mut key = [0u8; 32];
    for i in 0..32 {
        key[i] = u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("Invalid hex in {} at position {}: {}", field_name, i * 2, e))?;
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

#[cfg(test)]
mod renew_config_tests {
    use crate::config::RawConfiguration;
    use crate::ZgsKVConfig;

    fn cfg_with(key: &str) -> ZgsKVConfig {
        let mut raw = RawConfiguration::default();
        raw.renew_private_key = key.to_string();
        raw.indexer_url = "http://indexer".to_string();
        ZgsKVConfig { raw_conf: raw }
    }

    #[test]
    fn no_key_means_disabled() {
        assert!(cfg_with("").renew_config().unwrap().is_none());
    }

    #[test]
    fn kill_switch_wins() {
        let mut c = cfg_with(&"11".repeat(32));
        c.raw_conf.renew_enabled = false;
        assert!(c.renew_config().unwrap().is_none());
    }

    #[test]
    fn key_enables_and_parses() {
        let c = cfg_with(&"11".repeat(32));
        let rc = c.renew_config().unwrap().unwrap();
        assert_eq!(rc.private_key, [0x11u8; 32]);
        assert_eq!(rc.max_age_secs, 15552000);
    }

    #[test]
    fn bad_key_is_an_error() {
        assert!(cfg_with("nothex").renew_config().is_err());
    }
}
