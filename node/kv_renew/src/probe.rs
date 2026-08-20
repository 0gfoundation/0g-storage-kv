use anyhow::Result;

/// Binary search for the largest block whose timestamp is <= `target_ts`,
/// bounded by `[lo, hi]`. Generic over `ts_of` so this unit-tests without a
/// live chain; network callers pass a closure that fetches
/// `provider.get_block(n)` and returns its timestamp.
pub async fn bisect_block_at<F, Fut>(_lo: u64, _hi: u64, _target_ts: u64, _ts_of: F) -> Result<u64>
where
    F: Fn(u64) -> Fut,
    Fut: std::future::Future<Output = Result<u64>>,
{
    todo!()
}

#[cfg(test)]
mod tests {
    use super::bisect_block_at;

    #[tokio::test]
    async fn bisect_finds_boundary_block() {
        // block n has timestamp n*10
        let ts_of = |n: u64| async move { Ok::<u64, anyhow::Error>(n * 10) };
        assert_eq!(bisect_block_at(0, 1000, 505, ts_of).await.unwrap(), 50);
        assert_eq!(bisect_block_at(0, 1000, 500, ts_of).await.unwrap(), 50);
        assert_eq!(bisect_block_at(0, 1000, 5, ts_of).await.unwrap(), 0);
        assert_eq!(bisect_block_at(0, 1000, 99999, ts_of).await.unwrap(), 1000);
    }
}
