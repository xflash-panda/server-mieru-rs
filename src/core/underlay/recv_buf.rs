use std::collections::BTreeMap;

pub struct RecvBuf {
    buf: BTreeMap<u32, Vec<u8>>,
    next_deliver_seq: u32,
    max_entries: usize,
}

impl RecvBuf {
    pub fn new(max_entries: usize) -> Self {
        Self {
            buf: BTreeMap::new(),
            next_deliver_seq: 0,
            max_entries,
        }
    }

    /// Insert a packet with the given sequence number and payload.
    /// Returns true if the packet was accepted, false if rejected.
    pub fn insert(&mut self, seq: u32, payload: Vec<u8>) -> bool {
        // Reject already-delivered sequences
        if seq < self.next_deliver_seq {
            return false;
        }
        // Reject duplicates
        if self.buf.contains_key(&seq) {
            return false;
        }
        // Reject if at capacity
        if self.buf.len() >= self.max_entries {
            return false;
        }
        self.buf.insert(seq, payload);
        true
    }

    /// Drain all contiguous ready packets starting from next_deliver_seq.
    pub fn drain_ready(&mut self) -> Vec<Vec<u8>> {
        let mut result = Vec::new();
        while let Some(payload) = self.buf.remove(&self.next_deliver_seq) {
            result.push(payload);
            self.next_deliver_seq = self.next_deliver_seq.wrapping_add(1);
        }
        result
    }

    /// Returns the next sequence number expected for delivery.
    pub fn next_expected_seq(&self) -> u32 {
        self.next_deliver_seq
    }

    /// Returns the number of packets currently buffered.
    pub fn buffered_count(&self) -> usize {
        self.buf.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_order_delivery() {
        let mut rb = RecvBuf::new(16);
        assert!(rb.insert(0, vec![0]));
        assert!(rb.insert(1, vec![1]));
        assert!(rb.insert(2, vec![2]));
        let drained = rb.drain_ready();
        assert_eq!(drained, vec![vec![0], vec![1], vec![2]]);
        assert_eq!(rb.next_expected_seq(), 3);
        assert_eq!(rb.buffered_count(), 0);
    }

    #[test]
    fn test_out_of_order_buffering() {
        let mut rb = RecvBuf::new(16);
        assert!(rb.insert(2, vec![2]));
        let drained = rb.drain_ready();
        assert!(drained.is_empty());
        assert_eq!(rb.next_expected_seq(), 0);

        assert!(rb.insert(0, vec![0]));
        let drained = rb.drain_ready();
        assert_eq!(drained, vec![vec![0]]);
        assert_eq!(rb.next_expected_seq(), 1);

        assert!(rb.insert(1, vec![1]));
        let drained = rb.drain_ready();
        assert_eq!(drained, vec![vec![1], vec![2]]);
        assert_eq!(rb.next_expected_seq(), 3);
    }

    #[test]
    fn test_duplicate_rejected() {
        let mut rb = RecvBuf::new(16);
        assert!(rb.insert(0, vec![0]));
        assert!(!rb.insert(0, vec![0]));
        assert_eq!(rb.buffered_count(), 1);
    }

    #[test]
    fn test_already_delivered_rejected() {
        let mut rb = RecvBuf::new(16);
        assert!(rb.insert(0, vec![0]));
        rb.drain_ready();
        assert_eq!(rb.next_expected_seq(), 1);
        assert!(!rb.insert(0, vec![0]));
    }

    #[test]
    fn test_capacity_limit() {
        let mut rb = RecvBuf::new(3);
        assert!(rb.insert(0, vec![0]));
        assert!(rb.insert(1, vec![1]));
        assert!(rb.insert(2, vec![2]));
        assert!(!rb.insert(3, vec![3]));
        assert_eq!(rb.buffered_count(), 3);
    }

    #[test]
    fn test_empty_drain() {
        let mut rb = RecvBuf::new(16);
        let drained = rb.drain_ready();
        assert!(drained.is_empty());
    }

    #[test]
    fn test_gap_then_fill() {
        let mut rb = RecvBuf::new(16);
        assert!(rb.insert(0, vec![0]));
        assert!(rb.insert(1, vec![1]));
        assert!(rb.insert(3, vec![3]));
        assert!(rb.insert(5, vec![5]));

        let drained = rb.drain_ready();
        assert_eq!(drained, vec![vec![0], vec![1]]);
        assert_eq!(rb.next_expected_seq(), 2);
        assert_eq!(rb.buffered_count(), 2); // 3 and 5 remain

        assert!(rb.insert(2, vec![2]));
        let drained = rb.drain_ready();
        assert_eq!(drained, vec![vec![2], vec![3]]);
        assert_eq!(rb.next_expected_seq(), 4);
        assert_eq!(rb.buffered_count(), 1); // 5 remains
    }
}
