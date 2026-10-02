//! Startup-only retry policy shared by the native owner and synthetic tests.
pub(crate) const MAX_STARTUP_ATTEMPTS: u8 = 3;
pub(crate) fn retry_startup(
    attempt: u8,
    reached_ready: bool,
    cleanup_complete: bool,
    connected: bool,
) -> bool {
    attempt < MAX_STARTUP_ATTEMPTS && !reached_ready && cleanup_complete && connected
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fully_torn_down_startup_failure_has_a_small_retry_budget() {
        assert!(retry_startup(1, false, true, true));
        assert!(retry_startup(2, false, true, true));
        assert!(!retry_startup(MAX_STARTUP_ATTEMPTS, false, true, true));
    }
    #[test]
    fn runtime_failure_requires_thread_exit_not_reinitialization() {
        assert!(!retry_startup(1, true, true, true));
    }
    #[test]
    fn incomplete_cleanup_or_disconnected_consumer_cannot_retry() {
        assert!(!retry_startup(1, false, false, true));
        assert!(!retry_startup(1, false, true, false));
    }
}

pub(crate) fn claim_monitor(started: &std::sync::atomic::AtomicBool) -> bool {
    started
        .compare_exchange(
            false,
            true,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        )
        .is_ok()
}

#[cfg(test)]
mod ownership_tests {
    #[test]
    fn only_one_native_owner_can_start_in_a_process() {
        let started = std::sync::atomic::AtomicBool::new(false);
        assert!(super::claim_monitor(&started));
        assert!(!super::claim_monitor(&started));
    }
}
