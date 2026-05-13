use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValueSegment {
    // key version
    pub version: u64,
    // data
    #[serde(with = "base64")]
    pub data: Vec<u8>,
    // value total size
    pub size: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyValueSegment {
    // key version
    pub version: u64,
    // key
    #[serde(with = "base64")]
    pub key: Vec<u8>,
    // data
    #[serde(with = "base64")]
    pub data: Vec<u8>,
    // value total size
    pub size: u64,
}

/// Per-node stream replay progress. Returned by `kv_getReplayProgress`
/// so downstream consumers (e.g. an S3 gateway maintaining a local
/// namespace cache) can answer "has this node folded tx-seq N yet?"
/// without speculative reads.
///
/// `applied_seq` is monotonic across all streams the node watches —
/// the replayer processes tx-seqs in order regardless of which
/// stream(s) a given tx affects, so `applied_seq >= N` means every
/// tx up to N has been classified (applied, skipped, or reverted).
///
/// `first_tx_seq` is set when the node started syncing from a block
/// past genesis (bootstrap hole). Callers with a seq below
/// `first_tx_seq` know that tx is permanently outside this node's
/// window and should not be waited on.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplayProgress {
    pub applied_seq: u64,
    pub first_tx_seq: Option<u64>,
}

mod base64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        let base64 = base64::encode(v);
        String::serialize(&base64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let base64 = String::deserialize(d)?;
        base64::decode(base64.as_bytes()).map_err(serde::de::Error::custom)
    }
}
