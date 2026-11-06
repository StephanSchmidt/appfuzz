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

use crate::natural::Natural;
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
    #[serde(serialize_with = "crate::wide::serialize_signed")]
    pub base_wall_ns: i128,
    pub guest_ns: Natural,
    pub host_ns: Natural,
    pub sleep_ns: Natural,
    pub wall_reads: u64,
    pub monotonic_reads: u64,
    pub sleeps: u64,
    /// The Duration-only SDK adapter could not represent a negative wall read.
    /// Execution rejects it at the host return boundary, before guest code resumes.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub before_epoch_read: bool,
}

impl ClockState {
    pub fn wall_ns(&self) -> Option<Natural> {
        let elapsed = self.elapsed_ns();
        if self.base_wall_ns >= 0 {
            return Some(Natural::from(self.base_wall_ns as u128) + elapsed);
        }
        let before_epoch = Natural::from(self.base_wall_ns.unsigned_abs());
        (elapsed >= before_epoch).then(|| elapsed - before_epoch)
    }
    pub fn read_wall_ns(&mut self) -> Option<Natural> {
        self.wall_reads = self.wall_reads.saturating_add(1);
        self.wall_ns()
    }
    pub fn until_wall_ns(&self, target: u64) -> Natural {
        if self.base_wall_ns < 0 {
            (Natural::from(target) + Natural::from(self.base_wall_ns.unsigned_abs())).saturating_sub(&self.elapsed_ns())
        } else {
            Natural::from(target).saturating_sub(&self.wall_ns().expect("nonnegative wall origin"))
        }
    }
    pub fn elapsed_ns(&self) -> Natural {
        self.guest_ns.clone()
            + self.host_ns.clone()
            + self.sleep_ns.clone()
            + (Natural::from(self.wall_reads) + Natural::from(self.monotonic_reads)) * CLOCK_READ_STEP_NS
    }
}

#[derive(Clone)]
pub struct VirtualClock(pub Arc<Mutex<ClockState>>);

impl VirtualClock {
    pub fn new(base_wall_ns: impl Into<i128>) -> Self {
        VirtualClock(Arc::new(Mutex::new(ClockState { base_wall_ns: base_wall_ns.into(), ..Default::default() })))
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut ClockState) -> R) -> R {
        f(&mut self.0.lock().unwrap_or_else(|e| e.into_inner()))
    }

    pub fn monotonic_now(&self) -> u64 {
        self.with(|c| (Natural::from(MONOTONIC_START_NS) + c.elapsed_ns()).saturating_u64())
    }
}

pub struct WallClock(pub VirtualClock);
pub struct MonotonicClock(pub VirtualClock);

impl wasmtime_wasi::HostWallClock for WallClock {
    fn resolution(&self) -> Duration {
        Duration::from_nanos(CLOCK_READ_STEP_NS)
    }
    fn now(&self) -> Duration {
        self.0.with(|c| match c.read_wall_ns() {
            Some(now) => now.duration(),
            None => {
                c.before_epoch_read = true;
                Duration::ZERO
            }
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
            (Natural::from(MONOTONIC_START_NS) + c.elapsed_ns()).saturating_u64()
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
    fn signed_wall_origins_and_epoch_crossing_remain_exact() {
        let mut state = ClockState { base_wall_ns: -1_000_000_000, ..Default::default() };
        assert_eq!(state.wall_ns(), None);
        assert_eq!(state.until_wall_ns(0), 1_000_000_000);
        state.sleep_ns = 1_000_000_000u64.into();
        assert_eq!(state.wall_ns(), Some(0u64.into()));
        assert_eq!(state.read_wall_ns(), Some(1000u64.into()));
        assert_eq!(state.until_wall_ns(5000), 4000);
        let extreme = ClockState { base_wall_ns: i128::MIN, ..Default::default() };
        assert_eq!(extreme.until_wall_ns(u64::MAX), Natural::from(i128::MIN.unsigned_abs()) + Natural::from(u64::MAX));
        for value in [i128::MIN, -1, 0, i64::MAX as i128, u64::MAX as i128, i128::MAX] {
            let state = ClockState { base_wall_ns: value, ..Default::default() };
            let wire = serde_json::to_value(state).unwrap();
            assert_eq!(wire["base_wall_ns"].is_number(), value >= i128::from(i64::MIN) && value <= i128::from(u64::MAX));
            if let Some(text) = wire["base_wall_ns"].as_str() {
                assert_eq!(text, value.to_string());
            }
        }
    }
    #[test]
    fn guest_clocks_saturate_while_internal_time_keeps_advancing() {
        let state = ClockState {
            guest_ns: u64::MAX.into(),
            host_ns: 1u64.into(),
            sleep_ns: 1u64.into(),
            wall_reads: u64::MAX,
            monotonic_reads: 1,
            ..Default::default()
        };
        assert_eq!(state.elapsed_ns(), Natural::from(u64::MAX) + Natural::from(2u64) + (Natural::from(u64::MAX) + Natural::from(1u64)) * CLOCK_READ_STEP_NS);
        let clock = VirtualClock::new(u64::MAX);
        clock.with(|c| c.sleep_ns = u64::MAX.into());
        assert_eq!(clock.monotonic_now(), u64::MAX);
        assert_eq!(wasmtime_wasi::HostWallClock::now(&WallClock(clock.clone())), (Natural::from(u64::MAX) * 2 + Natural::from(CLOCK_READ_STEP_NS)).duration());
        assert_eq!(wasmtime_wasi::HostMonotonicClock::now(&MonotonicClock(clock)), u64::MAX);
    }
}
