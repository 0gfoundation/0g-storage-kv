/// Maps a stream version to a unix timestamp via clamped linear
/// interpolation over a set of (version, unix_ts) sample points.
///
/// Used to backfill `updated_at`/`created_at` timestamps for KV rows that
/// were written before block-time stamping existed (see spec §3).
pub struct PiecewiseClock {
    points: Vec<(u64, u64)>,
}

impl PiecewiseClock {
    /// Builds a clock from `points`, sorting them by version and dropping
    /// duplicate versions. Panics if `points` is empty — callers (Task 18)
    /// never construct an empty clock.
    pub fn new(mut points: Vec<(u64, u64)>) -> Self {
        assert!(
            !points.is_empty(),
            "PiecewiseClock::new requires at least one (version, ts) point"
        );
        points.sort();
        points.dedup_by_key(|p| p.0);
        Self { points }
    }

    /// Returns the interpolated unix timestamp for `version`, clamped to the
    /// first/last sample point's timestamp when `version` falls outside the
    /// sampled range.
    pub fn time_at(&self, version: u64) -> u64 {
        match self.points.binary_search_by_key(&version, |p| p.0) {
            Ok(i) => self.points[i].1,
            Err(0) => self.points[0].1,
            Err(i) if i == self.points.len() => self.points[i - 1].1,
            Err(i) => {
                let (v0, t0) = self.points[i - 1];
                let (v1, t1) = self.points[i];
                t0 + (t1 - t0) * (version - v0) / (v1 - v0)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PiecewiseClock;

    #[test]
    fn interpolates_between_points() {
        let c = PiecewiseClock::new(vec![(100, 1000), (200, 2000)]);
        assert_eq!(c.time_at(150), 1500);
    }

    #[test]
    fn clamps_outside_range_and_sorts_input() {
        let c = PiecewiseClock::new(vec![(200, 2000), (100, 1000)]);
        assert_eq!(c.time_at(50), 1000);
        assert_eq!(c.time_at(500), 2000);
    }

    #[test]
    fn single_point_is_constant() {
        let c = PiecewiseClock::new(vec![(10, 42)]);
        assert_eq!(c.time_at(0), 42);
        assert_eq!(c.time_at(99), 42);
    }
}
