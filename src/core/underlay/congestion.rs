use std::time::Instant;

const CUBIC_C: f64 = 0.4;
const CUBIC_BETA: f64 = 0.7;
const INITIAL_CWND: f64 = 10.0;

pub struct CubicCongestion {
    pub cwnd: f64,
    pub ssthresh: f64,
    pub w_max: f64,
    pub epoch_start: Option<Instant>,
    pub k: f64,
}

impl CubicCongestion {
    pub fn new() -> Self {
        Self {
            cwnd: INITIAL_CWND,
            ssthresh: f64::INFINITY,
            w_max: 0.0,
            epoch_start: None,
            k: 0.0,
        }
    }

    pub fn window(&self) -> u32 {
        self.cwnd.max(1.0) as u32
    }

    pub fn can_send(&self, inflight: u32) -> bool {
        inflight < self.window()
    }

    pub fn on_ack(&mut self, now: Instant) {
        if self.cwnd < self.ssthresh {
            // Slow start
            self.cwnd += 1.0;
        } else {
            // Congestion avoidance: CUBIC curve W(t) = C*(t-K)^3 + W_max
            let epoch_start = self.epoch_start.get_or_insert(now);
            let t = now.duration_since(*epoch_start).as_secs_f64();
            let w_cubic = CUBIC_C * (t - self.k).powi(3) + self.w_max;
            let increment = ((w_cubic - self.cwnd) / self.cwnd).max(1.0 / self.cwnd);
            self.cwnd += increment;
        }
    }

    pub fn on_loss(&mut self) {
        self.w_max = self.cwnd;
        self.ssthresh = (self.cwnd * CUBIC_BETA).max(1.0);
        self.cwnd = self.ssthresh;
        self.k = (self.w_max * (1.0 - CUBIC_BETA) / CUBIC_C).cbrt();
        self.epoch_start = None;
    }
}

impl Default for CubicCongestion {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn test_initial_window() {
        let cc = CubicCongestion::new();
        assert_eq!(cc.window(), 10);
    }

    #[test]
    fn test_can_send_below_window() {
        let cc = CubicCongestion::new();
        assert!(cc.can_send(0));
        assert!(cc.can_send(9));
        assert!(!cc.can_send(10));
    }

    #[test]
    fn test_slow_start_increases_cwnd() {
        let mut cc = CubicCongestion::new();
        let initial = cc.cwnd;
        let now = Instant::now();
        cc.on_ack(now);
        assert!(
            cc.cwnd > initial,
            "cwnd should grow after ACK in slow start"
        );
    }

    #[test]
    fn test_on_loss_reduces_cwnd() {
        let mut cc = CubicCongestion::new();
        let initial = cc.cwnd;
        cc.on_loss();
        assert!(cc.cwnd < initial, "cwnd should shrink after loss");
    }

    #[test]
    fn test_on_loss_sets_ssthresh() {
        let mut cc = CubicCongestion::new();
        cc.on_loss();
        assert!(
            cc.ssthresh.is_finite(),
            "ssthresh should be finite after loss"
        );
    }

    #[test]
    fn test_congestion_avoidance_slower_than_slow_start() {
        let acks = 20;
        let now = Instant::now();

        // Measure slow start growth: keep ssthresh at infinity
        let mut ss = CubicCongestion::new();
        for i in 0..acks {
            ss.on_ack(now + Duration::from_millis(i * 100));
        }
        let ss_growth = ss.cwnd - INITIAL_CWND;

        // Measure CA growth: trigger loss first to enter CA
        let mut ca = CubicCongestion::new();
        ca.on_loss(); // sets ssthresh below current cwnd, enters CA on next ack
        let ca_start = ca.cwnd;
        for i in 0..acks {
            ca.on_ack(now + Duration::from_millis(i * 100));
        }
        let ca_growth = ca.cwnd - ca_start;

        assert!(
            ca_growth < ss_growth,
            "CA growth ({ca_growth}) should be less than SS growth ({ss_growth})"
        );
    }

    #[test]
    fn test_window_never_zero() {
        let mut cc = CubicCongestion::new();
        for _ in 0..100 {
            cc.on_loss();
            assert!(
                cc.window() >= 1,
                "window must never be zero, got {}",
                cc.window()
            );
        }
    }
}
