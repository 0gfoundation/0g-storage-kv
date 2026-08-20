use ethereum_types::{H160, H256};

use serde::{Deserialize, Serialize};
use shared_types::{DataRoot, Transaction, TxID};
use ssz::Encode;
use ssz_derive::{Decode as DeriveDecode, Encode as DeriveEncode};
use std::collections::HashSet;
use tiny_keccak::{Hasher, Keccak};

use std::sync::Arc;

// SHA256("STREAM")
// df2ff3bb0af36c6384e6206552a4ed807f6f6a26e7d0aa6bff772ddc9d4307aa
pub const STREAM_DOMAIN: H256 = H256([
    223, 47, 243, 187, 10, 243, 108, 99, 132, 230, 32, 101, 82, 164, 237, 128, 127, 111, 106, 38,
    231, 208, 170, 107, 255, 119, 45, 220, 157, 67, 7, 170,
]);

pub fn submission_topic_to_stream_ids(topic: Vec<u8>) -> Vec<H256> {
    if topic.is_empty() || topic.len() % 32 != 0 || H256::from_slice(&topic[..32]) != STREAM_DOMAIN
    {
        return vec![];
    }

    let mut stream_ids = Vec::new();
    for i in (32..topic.len()).step_by(32) {
        stream_ids.push(H256::from_slice(&topic[i..i + 32]))
    }
    stream_ids
}

#[derive(Clone, Debug, Eq, PartialEq, DeriveDecode, DeriveEncode, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KVTransaction {
    pub stream_ids: Vec<H256>,
    pub sender: H160,
    pub data_merkle_root: DataRoot,
    /// `(subtree_depth, subtree_root)`
    pub merkle_nodes: Vec<(usize, DataRoot)>,

    pub start_entry_index: u64,
    pub size: u64,
    pub seq: u64,
}

impl KVTransaction {
    pub fn num_entries_of_node(depth: usize) -> usize {
        1 << (depth - 1)
    }

    pub fn num_entries_of_list(merkle_nodes: &[(usize, DataRoot)]) -> usize {
        merkle_nodes.iter().fold(0, |size, &(depth, _)| {
            size + Transaction::num_entries_of_node(depth)
        })
    }

    pub fn num_entries(&self) -> usize {
        Self::num_entries_of_list(&self.merkle_nodes)
    }

    pub fn hash(&self) -> H256 {
        let bytes = self.as_ssz_bytes();
        let mut h = Keccak::v256();
        let mut e = H256::zero();
        h.update(&bytes);
        h.finalize(e.as_mut());
        e
    }

    pub fn id(&self) -> TxID {
        TxID {
            seq: self.seq,
            hash: self.hash(),
        }
    }

    pub fn start_entry_index(&self) -> u64 {
        self.start_entry_index
    }
}

#[derive(Debug)]
pub struct StreamRead {
    pub stream_id: H256,
    pub key: Arc<Vec<u8>>,
}

#[derive(Debug)]
pub struct StreamReadSet {
    pub stream_reads: Vec<StreamRead>,
}

#[derive(Debug)]
pub struct StreamWrite {
    pub stream_id: H256,
    pub key: Arc<Vec<u8>>,
    // start index in bytes
    pub start_index: u64,
    // end index in bytes
    pub end_index: u64,
}

#[derive(Debug)]
pub struct StreamWriteSet {
    pub stream_writes: Vec<StreamWrite>,
}

#[derive(Debug)]
pub struct AccessControlSet {
    pub access_controls: Vec<AccessControl>,
    pub is_admin: HashSet<H256>,
}

#[derive(Debug)]
pub struct AccessControl {
    pub op_type: u8,
    pub stream_id: H256,
    pub key: Arc<Vec<u8>>,
    pub account: H160,
    pub operator: H160,
}

#[derive(Debug)]
pub struct KeyValuePair {
    pub stream_id: H256,
    pub key: Vec<u8>,
    pub start_index: u64,
    pub end_index: u64,
    pub version: u64,
}

#[derive(Debug, Clone)]
pub struct StaleKey {
    pub stream_id: H256,
    pub key: Vec<u8>,
    pub version: u64,
    pub start_index: u64,
    pub end_index: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RenewAttempt {
    pub attempts: u64,
    pub last_attempt_ts: u64,
    pub last_tx_hash: Option<H256>,
    pub last_error: Option<String>,
}

/// A stream's effective access-control state as of some version: the
/// groupwise-latest winner per (account) for admins/writers and per
/// (key)/(key, account) for special keys/special writers. See spec §5.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EffectiveAcl {
    pub admins: Vec<H160>,
    pub writers: Vec<H160>,
    pub special_keys: Vec<Vec<u8>>,
    pub special_writers: Vec<(Vec<u8>, H160)>,
}

/// A single `t_access_control` row surfaced by
/// `get_access_control_ops_in_range`, in replay order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclOpRow {
    pub op_type: u8,
    pub key: Vec<u8>,
    pub account: H160,
    pub version: u64,
}
