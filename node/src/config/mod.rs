mod config_macro;

mod convert;
use config_macro::*;
use std::ops::Deref;

build_config! {
    // stream
    (stream_ids, (Vec<String>), vec![])

    // log sync
    (blockchain_rpc_endpoint, (String), "http://127.0.0.1:8545".to_string())
    (log_contract_address, (String), "".to_string())
    (log_sync_start_block_number, (u64), 0)
    (force_log_sync_from_start_block_number, (bool), false)
    (confirmation_block_count, (u64), 3)
    (log_page_size, (u64), 999)
    (max_cache_data_size, (usize), 100 * 1024 * 1024) // 100 MB
    (cache_tx_seq_ttl, (usize), 500)

    (rate_limit_retries, (u32), 100)
    (timeout_retries, (u32), 100)
    (initial_backoff, (u64), 500)
    (recover_query_delay, (u64), 50)

    (default_finalized_block_count, (u64), 100)
    (remove_finalized_block_interval_minutes, (u64), 30)
    (watch_loop_wait_time_ms, (u64), 500)

    (blockchain_rpc_timeout_secs, (u64), 120)


    // rpc
    (rpc_enabled, (bool), true)
    (rpc_listen_address, (String), "127.0.0.1:5678".to_string())
    (rpc_chunks_per_segment, (usize), 1024)
    (indexer_url, (String), "".to_string())
    (zgs_node_urls, (String), "".to_string())
    (max_query_len_in_bytes, (u64), 1024 * 256) // 256 KB
    (max_response_body_in_bytes, (u32), 1024 * 1024 * 30) // 30MB
    (zgs_rpc_timeout, (u64), 5) // 5 seconds

    // db
    (db_dir, (String), "db".to_string())
    (merkle_node_cache_capacity, (usize), 32 * 1024 * 1024)

    (kv_db_file, (String), "kv.DB".to_string())

    // misc
    (log_config_file, (String), "log_config".to_string())
}

#[derive(Debug)]
pub struct ZgsKVConfig {
    pub raw_conf: RawConfiguration,
}

impl Deref for ZgsKVConfig {
    type Target = RawConfiguration;

    fn deref(&self) -> &Self::Target {
        &self.raw_conf
    }
}

impl ZgsKVConfig {
    pub fn parse(matches: &clap::ArgMatches) -> Result<ZgsKVConfig, String> {
        Ok(ZgsKVConfig {
            raw_conf: RawConfiguration::parse(matches)?,
        })
    }
}
