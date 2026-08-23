//! Host admission: memory/CPU reservations and CI slot cap.

use std::sync::atomic::{AtomicU32, Ordering};

/// Default concurrent CI/maintain/review containers.
pub const DEFAULT_JOB_SLOTS: u32 = 2;

/// Reserved floor in MiB for loomd + Surreal + Caddy.
pub const RESERVED_MIB: u64 = 2048;

/// Admission state for ephemeral jobs.
#[derive(Debug)]
pub struct Admission {
    slots: AtomicU32,
    max_slots: u32,
    host_memory_mib: u64,
}

impl Admission {
    /// Creates admission with a host memory cap (slice).
    #[must_use]
    pub const fn new(host_memory_mib: u64, max_slots: u32) -> Self {
        Self {
            slots: AtomicU32::new(0),
            max_slots,
            host_memory_mib,
        }
    }

    /// Default 64 GiB slice, 2 slots.
    #[must_use]
    pub const fn default_slice() -> Self {
        Self::new(64 * 1024, DEFAULT_JOB_SLOTS)
    }

    /// Tries to take a job slot.
    pub fn try_acquire_slot(&self) -> bool {
        loop {
            let current = self.slots.load(Ordering::SeqCst);
            if current >= self.max_slots {
                return false;
            }
            if self
                .slots
                .compare_exchange(current, current + 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return true;
            }
        }
    }

    /// Releases a job slot.
    pub fn release_slot(&self) {
        loop {
            let current = self.slots.load(Ordering::SeqCst);
            let next = current.saturating_sub(1);
            if self
                .slots
                .compare_exchange(current, next, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return;
            }
        }
    }

    /// True when `needed_mib` plus the reserved floor fits in the slice.
    #[must_use]
    pub fn fits(&self, needed_mib: u64) -> bool {
        needed_mib.saturating_add(RESERVED_MIB) <= self.host_memory_mib
    }
}

impl Default for Admission {
    fn default() -> Self {
        Self::default_slice()
    }
}

/// Default memory reservation for a language pack, in MiB.
#[must_use]
pub fn pack_memory_mib(pack: Option<crate::pack::PackKind>) -> u64 {
    match pack {
        Some(crate::pack::PackKind::Node | crate::pack::PackKind::Python) => 512,
        Some(crate::pack::PackKind::Rust) => 1024,
        Some(crate::pack::PackKind::Go | crate::pack::PackKind::Unknown) | None => 256,
    }
}
