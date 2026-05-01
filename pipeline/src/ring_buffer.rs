use std::{
    cell::UnsafeCell,
    mem::MaybeUninit,
    sync::atomic::{AtomicUsize, Ordering},
};
use syscallmind_common::SyscallTraceEvent;

const RING_BUFFER_SIZE: usize = 1024;

/// Lock-free single-producer single-consumer ring buffer.
pub struct RingBuffer {
    slots: Box<[UnsafeCell<MaybeUninit<SyscallTraceEvent>>; RING_BUFFER_SIZE]>,
    head: AtomicUsize,
    tail: AtomicUsize,
}

// SAFETY: SyscallTraceEvent is Copy. Head is only advanced by the consumer;
// tail only by the producer. The UnsafeCell slots are accessed at disjoint
// indices, so no aliasing occurs.
unsafe impl Send for RingBuffer {}
unsafe impl Sync for RingBuffer {}

impl RingBuffer {
    pub fn new() -> Self {
        // SAFETY: MaybeUninit<T> does not require initialization.
        let slots = unsafe {
            let mut arr: [UnsafeCell<MaybeUninit<SyscallTraceEvent>>; RING_BUFFER_SIZE] =
                MaybeUninit::uninit().assume_init();
            for slot in arr.iter_mut() {
                *slot = UnsafeCell::new(MaybeUninit::uninit());
            }
            Box::new(arr)
        };
        Self {
            slots,
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
        }
    }

    /// Push an event. Returns `false` if the buffer is full.
    pub fn push(&self, event: SyscallTraceEvent) -> bool {
        let tail = self.tail.load(Ordering::Relaxed);
        let next_tail = (tail + 1) % RING_BUFFER_SIZE;
        if next_tail == self.head.load(Ordering::Acquire) {
            return false; // full
        }
        // SAFETY: tail is exclusively modified by this function (single-producer).
        unsafe {
            (*self.slots[tail].get()).write(event);
        }
        self.tail.store(next_tail, Ordering::Release);
        true
    }

    /// Pop an event. Returns `None` if the buffer is empty.
    pub fn pop(&self) -> Option<SyscallTraceEvent> {
        let head = self.head.load(Ordering::Relaxed);
        if head == self.tail.load(Ordering::Acquire) {
            return None; // empty
        }
        // SAFETY: head index was fully written by push before tail advanced.
        let event = unsafe { (*self.slots[head].get()).assume_init_read() };
        self.head.store((head + 1) % RING_BUFFER_SIZE, Ordering::Release);
        Some(event)
    }

    pub fn len(&self) -> usize {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Relaxed);
        (tail + RING_BUFFER_SIZE - head) % RING_BUFFER_SIZE
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn capacity(&self) -> usize {
        RING_BUFFER_SIZE - 1
    }
}

impl Default for RingBuffer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syscallmind_common::{zero_pubkey, zero_tx_id};

    fn event(id: u32) -> SyscallTraceEvent {
        SyscallTraceEvent {
            program_id: zero_pubkey(),
            syscall_id: id,
            args_hash: id as u64,
            timestamp_ns: 0,
            slot: 1,
            transaction_id: zero_tx_id(),
            depth: 0,
        }
    }

    #[test]
    fn push_and_pop() {
        let rb = RingBuffer::new();
        assert!(rb.push(event(1)));
        assert!(rb.push(event(2)));
        assert_eq!(rb.len(), 2);
        assert_eq!(rb.pop().unwrap().syscall_id, 1);
        assert_eq!(rb.pop().unwrap().syscall_id, 2);
        assert!(rb.pop().is_none());
    }

    #[test]
    fn full_returns_false() {
        let rb = RingBuffer::new();
        for i in 0..rb.capacity() {
            assert!(rb.push(event(i as u32)));
        }
        assert!(!rb.push(event(9999)));
    }

    #[test]
    fn empty_is_none() {
        let rb = RingBuffer::new();
        assert!(rb.pop().is_none());
        assert!(rb.is_empty());
    }

    #[test]
    fn ordering_preserved() {
        let rb = RingBuffer::new();
        for i in 0..10u32 {
            rb.push(event(i));
        }
        for i in 0..10u32 {
            assert_eq!(rb.pop().unwrap().syscall_id, i);
        }
    }
}
