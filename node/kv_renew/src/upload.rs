//! Uploads a batch payload for renewal, forcing a fresh on-chain submission
//! (`skip_tx: false`) so the file's log entry is re-anchored even when the
//! same data already lives on storage nodes. See spec §4 step 6.

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
