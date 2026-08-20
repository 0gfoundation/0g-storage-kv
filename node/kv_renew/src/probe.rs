use crate::clock::PiecewiseClock;
use anyhow::Result;
use contract_interface::ZgsFlow;
use ethers::providers::{Http, Middleware, Provider};
use ethers::types::Address;
use std::sync::Arc;

/// Default age points (in seconds before "now") used to seed the backfill
/// clock: 6 and 12 months.
pub const DEFAULT_AGE_POINTS_SECS: [u64; 2] = [15_552_000, 31_104_000];

/// Binary search for the largest block whose timestamp is <= `target_ts`,
/// bounded by `[lo, hi]`. Generic over `ts_of` so this unit-tests without a
/// live chain; network callers pass a closure that fetches
/// `provider.get_block(n)` and returns its timestamp.
pub async fn bisect_block_at<F, Fut>(
    mut lo: u64,
    mut hi: u64,
    target_ts: u64,
    ts_of: F,
) -> Result<u64>
where
    F: Fn(u64) -> Fut,
    Fut: std::future::Future<Output = Result<u64>>,
{
    if ts_of(hi).await? <= target_ts {
        return Ok(hi);
    }
    if ts_of(lo).await? > target_ts {
        return Ok(lo);
    }
    while lo + 1 < hi {
        let mid = lo + (hi - lo) / 2;
        if ts_of(mid).await? <= target_ts {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    Ok(lo)
}

/// Scans `Submit` events forward from `from_block` in `page`-sized windows
/// (bounded by the current chain head) and returns the `submission_index`
/// of the first event found. Returns `Ok(None)` once the scan passes the
/// head without finding any submission.
///
/// Network path — exercised by Task 24's integration test, not unit-tested
/// here.
pub async fn first_submission_at_or_after(
    provider: Arc<Provider<Http>>,
    flow: Address,
    from_block: u64,
    page: u64,
) -> Result<Option<u64>> {
    let head = provider.get_block_number().await?.as_u64();
    let contract = ZgsFlow::new(flow, provider.clone());

    let mut window_start = from_block;
    while window_start <= head {
        let window_end = window_start
            .saturating_add(page.saturating_sub(1))
            .min(head);
        let events = contract
            .submit_filter()
            .from_block(window_start)
            .to_block(window_end)
            .query()
            .await?;
        if let Some(first) = events.first() {
            return Ok(Some(first.submission_index.as_u64()));
        }
        window_start = window_end + 1;
    }
    Ok(None)
}

/// Builds a [`PiecewiseClock`] by probing the chain for the block/submission
/// boundary at each age (in seconds before `now`) in `age_points_secs`, then
/// always anchoring the clock with `(next_tx_seq, now)` so the most recent
/// version maps to the current time regardless of what the probes found.
///
/// Network path — exercised by Task 24's integration test, not unit-tested
/// here.
pub async fn build_clock(
    provider: Arc<Provider<Http>>,
    flow: Address,
    age_points_secs: &[u64],
    next_tx_seq: u64,
    now: u64,
) -> Result<PiecewiseClock> {
    let head = provider.get_block_number().await?.as_u64();
    let mut points = Vec::with_capacity(age_points_secs.len() + 1);

    for &age in age_points_secs {
        let target = now.saturating_sub(age);

        let block = {
            let provider = provider.clone();
            bisect_block_at(0, head, target, move |n| {
                let provider = provider.clone();
                async move {
                    let block = provider
                        .get_block(n)
                        .await?
                        .ok_or_else(|| anyhow::anyhow!("missing block {n}"))?;
                    Ok(block.timestamp.as_u64())
                }
            })
            .await?
        };

        if let Some(seq) =
            first_submission_at_or_after(provider.clone(), flow, block, 10_000).await?
        {
            points.push((seq, target));
        }
    }

    points.push((next_tx_seq, now));
    Ok(PiecewiseClock::new(points))
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
