//! Exact nonnegative counters. Ordinary values stay inline; large virtual times
//! retain every nanosecond rather than clipping to a guest ABI's integer width.
use num_bigint::BigUint;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use std::{
    cmp::Ordering,
    fmt,
    iter::Sum,
    ops::{Add, AddAssign, Div, Mul, Sub},
};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Repr {
    Small(u128),
    Big(BigUint),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Natural(Repr);

impl Default for Natural {
    fn default() -> Self {
        Self::from(0u64)
    }
}
impl Natural {
    fn big(&self) -> BigUint {
        match &self.0 {
            Repr::Small(n) => (*n).into(),
            Repr::Big(n) => n.clone(),
        }
    }
    fn normalized(n: BigUint) -> Self {
        let digits = n.to_u64_digits();
        if digits.len() <= 2 {
            Self::from(u128::from(digits.first().copied().unwrap_or(0)) | (u128::from(digits.get(1).copied().unwrap_or(0)) << 64))
        } else {
            Self(Repr::Big(n))
        }
    }
    pub fn parse(text: &str) -> Option<Self> {
        if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        Some(text.parse::<u128>().map(Self::from).unwrap_or_else(|_| Self::normalized(BigUint::parse_bytes(text.as_bytes(), 10).expect("decimal digits"))))
    }
    /// Multiply the shortest round-tripping decimal of a configured finite
    /// float, flooring only the final product to whole units.
    pub fn from_scaled_f64(value: f64, factor: u64) -> Self {
        Rate::new(value).apply(&factor.into())
    }
    pub fn from_scaled_product(values: &[f64], factor: u64) -> Self {
        let mut rate = Rate { coefficient: Natural::from(factor), exponent: 0 };
        for value in values {
            let other = Rate::new(*value);
            rate.coefficient = rate.coefficient.product(&other.coefficient);
            rate.exponent += other.exponent;
        }
        rate.apply(&1u64.into())
    }
    fn product(&self, rhs: &Self) -> Self {
        if let (Repr::Small(a), Repr::Small(b)) = (&self.0, &rhs.0)
            && let Some(n) = a.checked_mul(*b)
        {
            return Self::from(n);
        }
        Self::normalized(self.big() * rhs.big())
    }
    pub fn scaled(&self, factor: f64) -> Self {
        Rate::new(factor).apply(self)
    }
    pub fn is_zero(&self) -> bool {
        matches!(self.0, Repr::Small(0))
    }
    pub fn saturating_u64(&self) -> u64 {
        match self.0 {
            Repr::Small(n) => n.min(u128::from(u64::MAX)) as u64,
            Repr::Big(_) => u64::MAX,
        }
    }
    pub fn duration(&self) -> std::time::Duration {
        let seconds = self.clone() / 1_000_000_000;
        if seconds > u64::MAX {
            return std::time::Duration::MAX;
        }
        let nanos = match &self.0 {
            Repr::Small(n) => (n % 1_000_000_000) as u32,
            Repr::Big(n) => (n % 1_000_000_000u32).to_u32_digits().first().copied().unwrap_or(0),
        };
        std::time::Duration::new(seconds.saturating_u64(), nanos)
    }
    pub fn saturating_sub(&self, rhs: &Self) -> Self {
        if self < rhs { Self::default() } else { self.clone() - rhs.clone() }
    }
    /// Approximate ratio for statistical fitting; counters themselves stay exact.
    pub fn ratio(&self, other: &Self) -> f64 {
        if let (Repr::Small(a), Repr::Small(b)) = (&self.0, &other.0) {
            return *a as f64 / *b as f64;
        }
        let Some((a, ae)) = self.scientific() else {
            return if other.is_zero() { f64::NAN } else { 0.0 };
        };
        let Some((b, be)) = other.scientific() else {
            return f64::INFINITY;
        };
        format!("{}e{}", a / b, ae - be).parse().expect("scientific ratio")
    }
    pub(crate) fn scientific(&self) -> Option<(f64, i64)> {
        if self.is_zero() {
            return None;
        }
        let text = self.to_string();
        let digits = text.len().min(17);
        let mantissa = text[..digits].parse::<f64>().expect("counter digits") / 10f64.powi(digits as i32 - 1);
        Some((mantissa, text.len() as i64 - 1))
    }
    pub fn ms_text(&self) -> String {
        let mut text = self.to_string();
        if text.len() <= 6 {
            text = format!("{:0>7}", text);
        }
        text.insert(text.len() - 6, '.');
        text
    }
    pub fn ms(&self) -> f64 {
        if let Repr::Small(n) = self.0 {
            return n as f64 / 1_000_000.0;
        }
        self.ms_text().parse().expect("nonnegative decimal")
    }
    pub fn ms_json(&self) -> Value {
        let text = self.ms_text();
        let value = self.ms();
        if let Some(number) = serde_json::Number::from_f64(value)
            && crate::value_contract::Decimal::parse(&text)
                .expect("integer milliseconds")
                .cmp(&crate::value_contract::Decimal::parse(&number.to_string()).expect("finite number"))
                .is_eq()
        {
            Value::Number(number)
        } else {
            Value::String(text)
        }
    }
    pub fn exceeds_ms(&self, limit: f64) -> bool {
        if limit.is_nan() || limit == f64::INFINITY {
            return false;
        }
        if limit < 0.0 {
            return true;
        }
        self > &Self::from_scaled_f64(limit, 1_000_000)
    }
}
/// A rate compiled once per run, so clock synchronization needs no decimal parsing.
#[derive(Clone, Debug)]
pub(crate) struct Rate {
    coefficient: Natural,
    exponent: i32,
}
impl Rate {
    pub(crate) fn new(value: f64) -> Self {
        assert!(value.is_finite() && value >= 0.0, "finite nonnegative counter rate");
        if value == 0.0 {
            return Self { coefficient: Natural::default(), exponent: 0 };
        }
        let text = value.to_string();
        let (mantissa, exponent) = text.split_once(['e', 'E']).map_or((text.as_str(), 0), |(m, e)| (m, e.parse::<i32>().expect("float exponent")));
        let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
        Self { coefficient: Natural::parse(&format!("{whole}{fraction}")).expect("float digits"), exponent: exponent - fraction.len() as i32 }
    }
    pub(crate) fn apply(&self, factor: &Natural) -> Natural {
        let product = self.coefficient.product(factor);
        if let Repr::Small(n) = product.0 {
            if let Some(scale) = 10u128.checked_pow(self.exponent.unsigned_abs()) {
                if self.exponent < 0 {
                    return Natural::from(n / scale);
                }
                if let Some(n) = n.checked_mul(scale) {
                    return Natural::from(n);
                }
            } else if self.exponent < 0 || n == 0 {
                return Natural::default();
            }
        }
        let mut product = product.big();
        let scale = BigUint::from(10u32).pow(self.exponent.unsigned_abs());
        if self.exponent >= 0 {
            product *= scale;
        } else {
            product /= scale;
        }
        Natural::normalized(product)
    }
}
impl fmt::Display for Natural {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Repr::Small(n) => n.fmt(f),
            Repr::Big(n) => n.fmt(f),
        }
    }
}
impl From<u128> for Natural {
    fn from(n: u128) -> Self {
        Self(Repr::Small(n))
    }
}
impl From<u64> for Natural {
    fn from(n: u64) -> Self {
        Self::from(u128::from(n))
    }
}
impl From<u32> for Natural {
    fn from(n: u32) -> Self {
        Self::from(u128::from(n))
    }
}
impl From<usize> for Natural {
    fn from(n: usize) -> Self {
        Self::from(n as u128)
    }
}
impl From<&Natural> for Natural {
    fn from(n: &Natural) -> Self {
        n.clone()
    }
}
impl Add for Natural {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        if let (Repr::Small(a), Repr::Small(b)) = (&self.0, &rhs.0)
            && let Some(n) = a.checked_add(*b)
        {
            return Self::from(n);
        }
        Self::normalized(self.big() + rhs.big())
    }
}
impl AddAssign for Natural {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.clone() + rhs;
    }
}
impl Sub for Natural {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        if let (Repr::Small(a), Repr::Small(b)) = (&self.0, &rhs.0) {
            return Self::from(a.checked_sub(*b).expect("nonnegative counter difference"));
        }
        Self::normalized(self.big() - rhs.big())
    }
}
impl Div<u64> for Natural {
    type Output = Self;
    fn div(self, rhs: u64) -> Self {
        match self.0 {
            Repr::Small(n) => Self::from(n / u128::from(rhs)),
            Repr::Big(n) => Self::normalized(n / rhs),
        }
    }
}
impl Mul<u64> for Natural {
    type Output = Self;
    fn mul(self, rhs: u64) -> Self {
        if let Repr::Small(n) = self.0
            && let Some(n) = n.checked_mul(u128::from(rhs))
        {
            return Self::from(n);
        }
        Self::normalized(self.big() * rhs)
    }
}
impl Sum for Natural {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::default(), |a, b| a + b)
    }
}
impl Serialize for Natural {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            Repr::Small(n) if n <= u128::from(u64::MAX) => s.serialize_u64(n as u64),
            _ => s.serialize_str(&self.to_string()),
        }
    }
}
impl<'de> Deserialize<'de> for Natural {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Wire {
            Number(u64),
            Decimal(String),
        }
        match Wire::deserialize(d)? {
            Wire::Number(n) => Ok(n.into()),
            Wire::Decimal(s) => Self::parse(&s).ok_or_else(|| serde::de::Error::custom("nonnegative decimal integer required")),
        }
    }
}
macro_rules! compare_integer { ($($t:ty),*) => {$ (
    impl PartialEq<$t> for Natural { fn eq(&self,rhs:&$t)->bool { self==&Self::from(*rhs as u128) } }
    impl PartialOrd<$t> for Natural { fn partial_cmp(&self,rhs:&$t)->Option<Ordering> { Some(self.cmp(&Self::from(*rhs as u128))) } }
)*}; }
compare_integer!(u32, u64, u128, usize);
impl PartialEq<i32> for Natural {
    fn eq(&self, rhs: &i32) -> bool {
        *rhs >= 0 && self == &Self::from(*rhs as u128)
    }
}
impl PartialOrd<i32> for Natural {
    fn partial_cmp(&self, rhs: &i32) -> Option<Ordering> {
        Some(if *rhs < 0 { Ordering::Greater } else { self.cmp(&Self::from(*rhs as u128)) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn counter_arithmetic_matches_integer_operations_and_crosses_inline_boundaries() {
        for a in [0u128, 1, 2, 99, 1 << 64, u128::MAX / 4] {
            for b in [0u128, 1, 13, u128::MAX / 4] {
                let (a, b) = (Natural::from(a), Natural::from(b));
                assert_eq!((a.clone() + b.clone()) - b.clone(), a);
                assert_eq!(a.saturating_sub(&b) + b.clone(), a.clone().max(b));
            }
        }
        let max = Natural::from(u128::MAX);
        let wide = max.clone() + Natural::from(1u64);
        assert_eq!(wide.to_string(), "340282366920938463463374607431768211456");
        assert!(wide > max);
        assert_eq!(wide.clone() - Natural::from(1u64), max);
        assert_eq!(wide.clone() / 2, Natural::from(1u128 << 127));
        assert_eq!(wide.clone() * 2, wide.clone() + wide);
        assert_eq!(Natural::from(0u64), 0);
        assert!(Natural::default() > -1);
    }
    #[test]
    fn configured_decimal_rates_do_not_overflow_or_round_across_a_nanosecond() {
        for (rate, factor, expected) in [
            (0.5, 5, "2"),
            (0.1, 1_000_000, "100000"),
            (0.3333333333333333, 3, "0"),
            (1e30, 1_000_000, "1000000000000000000000000000000000000"),
            (f64::MIN_POSITIVE, u64::MAX, "0"),
            (-0.0, u64::MAX, "0"),
        ] {
            assert_eq!(Natural::from_scaled_f64(rate, factor).to_string(), expected, "{rate} * {factor}");
        }
        let huge = Natural::from_scaled_f64(f64::MAX, 1_000_000);
        assert!(huge > u128::MAX);
        assert_eq!(huge.clone() / 1_000_000, Natural::from_scaled_f64(f64::MAX, 1));
        assert!(!huge.exceeds_ms(f64::MAX));
        assert!((huge.clone() + Natural::from(1u64)).exceeds_ms(f64::MAX));
        assert!(huge.ms().is_finite());
        assert!((huge * 2).ms_json().is_string());
    }
    #[test]
    fn wire_values_and_millisecond_text_preserve_exact_counters() {
        for text in ["0", "1", "1000", "1000000", "18446744073709551615", "18446744073709551616", "340282366920938463463374607431768211456"] {
            let value = Natural::parse(text).unwrap();
            let wire = serde_json::to_value(&value).unwrap();
            assert_eq!(wire.is_number(), value <= u64::MAX);
            assert_eq!(serde_json::from_value::<Natural>(wire).unwrap(), value);
        }
        assert_eq!(Natural::from(1u64).ms_text(), "0.000001");
        assert_eq!(Natural::from(1_000_001u64).ms_text(), "1.000001");
        for value in [json!(-1), json!(1.5), json!("-1"), json!("+1"), json!("1e3"), json!("")] {
            assert!(serde_json::from_value::<Natural>(value).is_err());
        }
    }
    #[test]
    fn statistical_ratios_do_not_divide_two_infinities() {
        let denominator = Natural::parse(&format!("1{}", "0".repeat(400))).unwrap();
        let numerator = Natural::parse(&format!("5{}", "0".repeat(399))).unwrap();
        assert_eq!(numerator.ratio(&denominator), 0.5);
        assert_eq!(denominator.ratio(&numerator), 2.0);
        assert_eq!(Natural::default().ratio(&denominator), 0.0);
        assert!(denominator.ratio(&Natural::default()).is_infinite());
        assert!(Natural::default().ratio(&Natural::default()).is_nan());
        assert_eq!(Natural::from(u128::MAX).ratio(&Natural::from(u128::MAX)), 1.0);
    }
    #[test]
    fn wall_clock_uses_the_seconds_width_while_monotonic_clock_uses_nanoseconds() {
        let value = Natural::from(u64::MAX) * 2;
        assert_eq!(value.saturating_u64(), u64::MAX);
        assert_eq!(value.duration(), std::time::Duration::new(36_893_488_147, 419_103_230));
        assert_eq!(Natural::from_scaled_f64(f64::MAX, 1_000_000).duration(), std::time::Duration::MAX);
    }
}
