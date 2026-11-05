//! Deterministic WASI: a virtual clock, seeded randomness, captured output,
//! and sleeps that advance virtual time instead of waiting.
//!
//! Virtual time = guest instructions (fuel) × ns per instruction
//!              + host call latencies (from manifest or plan)
//!              + WASI sleeps
//!              + a small step for every clock read.
//! The guest part is brought up to date before every guest-to-host call, and
//! each clock read adds a step, so a loop that watches the clock sees time
//! move without real waiting.

use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rand::rngs::StdRng;
use rand::{SeedableRng, TryRng};
use serde::Serialize;

/// Nanoseconds a clock read advances virtual time.
pub const CLOCK_READ_STEP_NS: u64 = 1_000;
/// Monotonic clocks start here, not at zero, like real ones.
const MONOTONIC_START_NS: u64 = 1_000_000_000_000;

#[derive(Debug, Default, Clone, Serialize)]
pub struct ClockState {
    /// Unix time at the start of the run, in ns.
    pub base_wall_ns: u64,
    pub guest_ns: u64,
    pub host_ns: u64,
    pub sleep_ns: u64,
    pub wall_reads: u64,
    pub monotonic_reads: u64,
    pub sleeps: u64,
}

impl ClockState {
    pub fn elapsed_ns(&self) -> u64 {
        self.guest_ns
            .saturating_add(self.host_ns)
            .saturating_add(self.sleep_ns)
            .saturating_add(self.wall_reads.saturating_add(self.monotonic_reads).saturating_mul(CLOCK_READ_STEP_NS))
    }
}

#[derive(Clone)]
pub struct VirtualClock(pub Arc<Mutex<ClockState>>);

impl VirtualClock {
    pub fn new(base_wall_ns: u64) -> Self {
        VirtualClock(Arc::new(Mutex::new(ClockState { base_wall_ns, ..Default::default() })))
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut ClockState) -> R) -> R {
        f(&mut self.0.lock().unwrap_or_else(|e| e.into_inner()))
    }

    pub fn monotonic_now(&self) -> u64 {
        self.with(|c| MONOTONIC_START_NS.saturating_add(c.elapsed_ns()))
    }
}

pub struct WallClock(pub VirtualClock);
pub struct MonotonicClock(pub VirtualClock);

impl wasmtime_wasi::HostWallClock for WallClock {
    fn resolution(&self) -> Duration {
        Duration::from_nanos(CLOCK_READ_STEP_NS)
    }
    fn now(&self) -> Duration {
        self.0.with(|c| {
            c.wall_reads = c.wall_reads.saturating_add(1);
            Duration::from_nanos(c.base_wall_ns.saturating_add(c.elapsed_ns()))
        })
    }
}

impl wasmtime_wasi::HostMonotonicClock for MonotonicClock {
    fn resolution(&self) -> u64 {
        CLOCK_READ_STEP_NS
    }
    fn now(&self) -> u64 {
        self.0.with(|c| {
            c.monotonic_reads = c.monotonic_reads.saturating_add(1);
            MONOTONIC_START_NS.saturating_add(c.elapsed_ns())
        })
    }
}

/// A seeded generator that counts what the guest draws.
pub struct CountingRng {
    inner: StdRng,
    pub drawn: Arc<Mutex<u64>>,
}

impl CountingRng {
    pub fn new(seed: u64, drawn: Arc<Mutex<u64>>) -> Self {
        CountingRng { inner: StdRng::seed_from_u64(seed), drawn }
    }
    fn count(&self, n: usize) {
        *self.drawn.lock().unwrap_or_else(|e| e.into_inner()) += n as u64;
    }
}

impl TryRng for CountingRng {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        self.count(4);
        self.inner.try_next_u32()
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        self.count(8);
        self.inner.try_next_u64()
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        self.count(dst.len());
        self.inner.try_fill_bytes(dst)
    }
}

/// A pollable that is ready at once.
pub struct Ready;

#[async_trait::async_trait]
impl wasmtime_wasi::p2::Pollable for Ready {
    async fn ready(&mut self) {}
}

/// `YYYY-MM-DDTHH:MM:SS` (or `YYYY-MM-DD`) → Unix seconds (UTC).
pub fn parse_datetime(s: &str) -> Option<i64> {
    let (date, time) = s.split_once(['T', ' ']).unwrap_or((s, "00:00:00"));
    let number = |text: &str, width: usize| -> Option<i64> {
        if text.len() != width || !text.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        text.parse().ok()
    };
    let parts: Vec<_> = date.split('-').collect();
    let [year, month, day] = parts.as_slice() else { return None };
    let (y, m, day) = (number(year, 4)?, number(month, 2)?, number(day, 2)?);
    if y == 0 || !(1..=12).contains(&m) || !(1..=31).contains(&day) {
        return None;
    }
    let days = days_from_civil(y, m, day);
    if civil_from_days(days) != (y, m, day) {
        return None;
    }
    let time = time.strip_suffix('Z').unwrap_or(time);
    let parts: Vec<_> = time.split(':').collect();
    let (h, mi, sec) = match parts.as_slice() {
        [h, mi] => (number(h, 2)?, number(mi, 2)?, 0),
        [h, mi, sec] => (number(h, 2)?, number(mi, 2)?, number(sec, 2)?),
        _ => return None,
    };
    if h >= 24 || mi >= 60 || sec >= 60 {
        return None;
    }
    Some(days * 86_400 + h * 3600 + mi * 60 + sec)
}

/// Unix seconds → (`YYYY-MM-DD`, `HH:MM`, `HH:MM:SS`).
pub fn format_datetime(secs: i64) -> (String, String, String) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    (format!("{y:04}-{m:02}-{d:02}"), format!("{h:02}:{mi:02}"), format!("{h:02}:{mi:02}:{s:02}"))
}

// Howard Hinnant's civil date algorithms.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_round_trip() {
        let t = parse_datetime("2026-11-02T10:15:30").unwrap();
        assert_eq!(format_datetime(t), ("2026-11-02".into(), "10:15".into(), "10:15:30".into()));
        assert_eq!(parse_datetime("1970-01-01"), Some(0));
        assert_eq!(format_datetime(parse_datetime("2024-02-29").unwrap()).0, "2024-02-29");
        assert!(parse_datetime("2026-13-01").is_none());
    }

    #[test]
    fn invalid_calendar_dates_and_malformed_times_are_rejected() {
        for text in [
            "2026-02-29",
            "2026-04-31",
            "0000-01-01",
            "2026-11-02-extra",
            "2026-11-02Tbad",
            "2026-11-02T10:xx:00",
            "2026-11-02T24:00:00",
            "2026-11-02T10:60:00",
            "2026-11-02T10:00:60",
            "2026-11-02T10:00:00:01",
            "2026-11-02T10:00:00ZZ",
            "9223372036854775807-01-01",
            "2026-11-02T9223372036854775807:00:00",
        ] {
            assert_eq!(parse_datetime(text), None, "accepted {text}");
        }
        let expected = parse_datetime("2026-11-02T10:15:00").unwrap();
        for text in ["2026-11-02T10:15", "2026-11-02 10:15:00", "2026-11-02T10:15:00Z"] {
            assert_eq!(parse_datetime(text), Some(expected), "rejected {text}");
        }
    }

    #[test]
    fn calendar_parsing_agrees_with_an_independent_calendar() {
        for year in [1, 4, 100, 400, 1900, 1970, 2000, 2024, 9999] {
            for month in 1..=12 {
                for day in 1..=31 {
                    let text = format!("{year:04}-{month:02}-{day:02}T23:59:59");
                    let expected = chrono::NaiveDate::from_ymd_opt(year, month, day).map(|date| date.and_hms_opt(23, 59, 59).unwrap().and_utc().timestamp());
                    assert_eq!(parse_datetime(&text), expected, "{text}");
                }
            }
        }
    }

    #[test]
    fn virtual_time_saturates_without_wrapping_or_panicking() {
        let state = ClockState { guest_ns: u64::MAX, host_ns: 1, sleep_ns: 1, wall_reads: u64::MAX, monotonic_reads: 1, ..Default::default() };
        assert_eq!(state.elapsed_ns(), u64::MAX);
        let clock = VirtualClock::new(u64::MAX);
        clock.with(|c| c.sleep_ns = u64::MAX);
        assert_eq!(clock.monotonic_now(), u64::MAX);
        assert_eq!(wasmtime_wasi::HostWallClock::now(&WallClock(clock.clone())), Duration::from_nanos(u64::MAX));
        assert_eq!(wasmtime_wasi::HostMonotonicClock::now(&MonotonicClock(clock)), u64::MAX);
    }
}
