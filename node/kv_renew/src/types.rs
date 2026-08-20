use ethereum_types::{H160, H256};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct RenewConfig {
    pub private_key: [u8; 32],
    pub max_age_secs: u64,
    pub cycle_interval_secs: u64,
    pub batch_max_bytes: usize,
    pub batch_max_keys: usize,
    pub pause_between_batches_ms: u64,
    pub startup_delay_secs: u64,
    pub expected_replica: u64,
    pub stream_ids: Vec<H256>, // empty = every live stream
    pub dry_run: bool,
    pub max_attempts: u64,
    pub blockchain_rpc_endpoint: String,
    pub log_contract_address: String,
    pub indexer_url: Option<String>,
    pub zgs_node_urls: Vec<String>,
    pub encryption_key: Option<[u8; 32]>,
    pub wallet_private_key: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RenewStatus {
    pub cycle_running: bool,
    pub acl_renewal_in_progress: bool,
    pub dry_run: bool,
    pub last_cycle_start: Option<u64>,
    pub last_cycle_end: Option<u64>,
    pub keys_scanned: u64,
    pub keys_renewed: u64,
    pub keys_skipped_permission: u64,
    pub keys_skipped_missing: u64,
    pub bytes_uploaded: u64,
    pub stuck_keys: Vec<StuckKey>,
    pub acl_conflicts: Vec<AclConflict>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StuckKey {
    pub stream_id: H256,
    pub key: String, // 0x-hex
    pub attempts: u64,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AclConflict {
    pub stream_id: H256,
    pub op: String,
    pub account: H160,
    pub key: String,
    pub version: u64,
}

pub type SharedRenewStatus = std::sync::Arc<tokio::sync::RwLock<RenewStatus>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_serializes_camel_case() {
        let s = RenewStatus {
            acl_renewal_in_progress: true,
            ..Default::default()
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["aclRenewalInProgress"], true);
        assert!(v.get("acl_renewal_in_progress").is_none());
    }
}
