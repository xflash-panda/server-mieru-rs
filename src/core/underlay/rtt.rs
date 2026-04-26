use std::time::Duration;

const MIN_RTO: Duration = Duration::from_millis(200);
const MAX_RTO: Duration = Duration::from_secs(60);
const INITIAL_RTO: Duration = Duration::from_secs(1);

pub struct RttEstimator {
    srtt: Duration,
    rttvar: Duration,
    rto: Duration,
    has_measurement: bool,
}

impl RttEstimator {
    pub fn new() -> Self {
        Self {
            srtt: Duration::ZERO,
            rttvar: Duration::ZERO,
            rto: INITIAL_RTO,
            has_measurement: false,
        }
    }

    pub fn rto(&self) -> Duration {
        self.rto
    }

    pub fn srtt(&self) -> Duration {
        self.srtt
    }

    /// Update RTT estimate with a new measurement (RFC 6298).
    pub fn update(&mut self, rtt: Duration) {
        if !self.has_measurement {
            // First measurement
            self.srtt = rtt;
            self.rttvar = rtt / 2;
            self.has_measurement = true;
        } else {
            // RTTVAR = 3/4 * RTTVAR + 1/4 * |SRTT - R'|
            let diff = self.srtt.abs_diff(rtt);
            self.rttvar = self.rttvar * 3 / 4 + diff / 4;
            // SRTT = 7/8 * SRTT + 1/8 * R'
            self.srtt = self.srtt * 7 / 8 + rtt / 8;
        }
        // RTO = SRTT + 4*RTTVAR, clamped to [MIN_RTO, MAX_RTO]
        let rto = self.srtt + self.rttvar * 4;
        self.rto = rto.max(MIN_RTO).min(MAX_RTO);
    }

    /// Double the RTO on timeout, capped at MAX_RTO.
    pub fn on_timeout(&mut self) {
        self.rto = (self.rto * 2).min(MAX_RTO);
    }
}

impl Default for RttEstimator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_rto() {
        let est = RttEstimator::new();
        assert_eq!(est.rto(), Duration::from_secs(1));
    }

    #[test]
    fn test_first_measurement_sets_srtt() {
        let mut est = RttEstimator::new();
        est.update(Duration::from_millis(100));
        assert_eq!(est.srtt(), Duration::from_millis(100));
    }

    #[test]
    fn test_first_measurement_rto() {
        let mut est = RttEstimator::new();
        est.update(Duration::from_millis(100));
        // srtt=100ms, rttvar=50ms, rto = 100 + 4*50 = 300ms
        assert_eq!(est.rto(), Duration::from_millis(300));
    }

    #[test]
    fn test_subsequent_measurement_adjusts_srtt() {
        let mut est = RttEstimator::new();
        est.update(Duration::from_millis(100));
        est.update(Duration::from_millis(200));
        // srtt = 7/8 * 100 + 1/8 * 200 = 87.5 + 25 = 112.5ms
        // Duration arithmetic preserves sub-ms precision: 112ms 500µs
        assert_eq!(est.srtt(), Duration::from_micros(112_500));
    }

    #[test]
    fn test_rto_minimum_clamp() {
        let mut est = RttEstimator::new();
        // Very small RTT: srtt=1ms, rttvar=0ms, rto = 1 + 4*0 = 1ms → clamped to 200ms
        est.update(Duration::from_micros(100));
        assert!(est.rto() >= Duration::from_millis(200));
    }

    #[test]
    fn test_on_timeout_doubles_rto() {
        let mut est = RttEstimator::new();
        est.update(Duration::from_millis(100));
        let rto_before = est.rto();
        est.on_timeout();
        assert_eq!(est.rto(), rto_before * 2);
    }

    #[test]
    fn test_on_timeout_caps_at_max() {
        let mut est = RttEstimator::new();
        // Repeatedly double until we hit the cap
        for _ in 0..30 {
            est.on_timeout();
        }
        assert_eq!(est.rto(), Duration::from_secs(60));
    }
}
