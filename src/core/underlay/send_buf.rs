use std::collections::BTreeMap;
use std::time::{Duration, Instant};

pub struct SentSegment {
    pub payload: Vec<u8>,
    pub sent_at: Instant,
    pub retransmit_count: u32,
}

pub struct SendBuf {
    buf: BTreeMap<u32, SentSegment>,
    next_seq: u32,
}

impl SendBuf {
    pub fn new() -> Self {
        Self {
            buf: BTreeMap::new(),
            next_seq: 0,
        }
    }

    /// Assign next_seq to this payload, insert it, advance next_seq, return assigned seq.
    pub fn enqueue(&mut self, payload: Vec<u8>, now: Instant) -> u32 {
        let seq = self.next_seq;
        self.buf.insert(
            seq,
            SentSegment {
                payload,
                sent_at: now,
                retransmit_count: 0,
            },
        );
        self.next_seq = self.next_seq.wrapping_add(1);
        seq
    }

    /// Remove all segments with seq < ack_seq.
    /// Return RTT sample from the last removed segment if it had retransmit_count == 0 (Karn's algorithm).
    pub fn ack(&mut self, ack_seq: u32, now: Instant) -> Option<Duration> {
        let seqs_to_remove: Vec<u32> = self.buf.range(..ack_seq).map(|(&seq, _)| seq).collect();

        let mut rtt_sample: Option<Duration> = None;
        for seq in seqs_to_remove {
            if let Some(seg) = self.buf.remove(&seq)
                && seg.retransmit_count == 0
            {
                rtt_sample = Some(now.duration_since(seg.sent_at));
            }
        }
        rtt_sample
    }

    /// Return seq numbers where now - sent_at >= rto.
    pub fn retransmit_due(&self, rto: Duration, now: Instant) -> Vec<u32> {
        self.buf
            .iter()
            .filter(|(_, seg)| now.duration_since(seg.sent_at) >= rto)
            .map(|(&seq, _)| seq)
            .collect()
    }

    /// Update sent_at=now and increment retransmit_count for the given seq.
    pub fn mark_retransmitted(&mut self, seq: u32, now: Instant) {
        if let Some(seg) = self.buf.get_mut(&seq) {
            seg.sent_at = now;
            seg.retransmit_count += 1;
        }
    }

    /// Get the payload for a given seq.
    pub fn get(&self, seq: u32) -> Option<&[u8]> {
        self.buf.get(&seq).map(|seg| seg.payload.as_slice())
    }

    /// Number of unacknowledged segments in flight.
    pub fn inflight(&self) -> u32 {
        self.buf.len() as u32
    }

    /// Next sequence number to be assigned.
    pub fn next_seq(&self) -> u32 {
        self.next_seq
    }
}

impl Default for SendBuf {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_enqueue_assigns_sequential_ids() {
        let mut sb = SendBuf::new();
        let now = Instant::now();
        let s0 = sb.enqueue(vec![0], now);
        let s1 = sb.enqueue(vec![1], now);
        let s2 = sb.enqueue(vec![2], now);
        assert_eq!(s0, 0);
        assert_eq!(s1, 1);
        assert_eq!(s2, 2);
        assert_eq!(sb.inflight(), 3);
    }

    #[test]
    fn test_ack_removes_segments() {
        let mut sb = SendBuf::new();
        let now = Instant::now();
        sb.enqueue(vec![0], now);
        sb.enqueue(vec![1], now);
        sb.enqueue(vec![2], now);
        // ack(2) removes seq 0 and 1, leaves seq 2
        sb.ack(2, now);
        assert_eq!(sb.inflight(), 1);
    }

    #[test]
    fn test_ack_returns_rtt_sample() {
        let mut sb = SendBuf::new();
        let t0 = Instant::now();
        sb.enqueue(vec![42], t0);
        thread::sleep(Duration::from_millis(50));
        let t1 = Instant::now();
        let rtt = sb.ack(1, t1);
        assert!(rtt.is_some());
        assert!(rtt.unwrap() >= Duration::from_millis(50));
    }

    #[test]
    fn test_ack_no_rtt_for_retransmitted() {
        let mut sb = SendBuf::new();
        let t0 = Instant::now();
        sb.enqueue(vec![42], t0);
        sb.mark_retransmitted(0, t0);
        let t1 = Instant::now();
        let rtt = sb.ack(1, t1);
        assert!(rtt.is_none());
    }

    #[test]
    fn test_retransmit_due() {
        let mut sb = SendBuf::new();
        let t0 = Instant::now();
        sb.enqueue(vec![0], t0);
        sb.enqueue(vec![1], t0);
        let t_check = t0 + Duration::from_millis(150);
        let rto = Duration::from_millis(100);
        let due = sb.retransmit_due(rto, t_check);
        assert_eq!(due.len(), 2);
        assert!(due.contains(&0));
        assert!(due.contains(&1));
    }

    #[test]
    fn test_retransmit_not_due_yet() {
        let mut sb = SendBuf::new();
        let t0 = Instant::now();
        sb.enqueue(vec![0], t0);
        let t_check = t0 + Duration::from_millis(50);
        let rto = Duration::from_millis(100);
        let due = sb.retransmit_due(rto, t_check);
        assert!(due.is_empty());
    }

    #[test]
    fn test_mark_retransmitted() {
        let mut sb = SendBuf::new();
        let t0 = Instant::now();
        sb.enqueue(vec![0], t0);
        let t1 = t0 + Duration::from_millis(150);
        sb.mark_retransmitted(0, t1);
        // Just after retransmit, not due yet with rto=100ms
        let t_check = t1 + Duration::from_millis(50);
        let rto = Duration::from_millis(100);
        let due = sb.retransmit_due(rto, t_check);
        assert!(due.is_empty());
    }

    #[test]
    fn test_get_payload() {
        let mut sb = SendBuf::new();
        let now = Instant::now();
        sb.enqueue(b"hello".to_vec(), now);
        assert_eq!(sb.get(0), Some(b"hello".as_ref()));
        assert_eq!(sb.get(1), None);
    }
}
