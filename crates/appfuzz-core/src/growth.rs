//! Fitting growth laws to measurements: `calls = 3 + 28·n`.

use crate::natural::Natural;
use serde::{Serialize, Serializer, ser::SerializeStruct};
use serde_json::{Value, json};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Class {
    Constant,
    Log,
    Linear,
    NLogN,
    Quadratic,
    Cubic,
    Exponential,
    /// Grows, then stops at a cap (`min(n, 20)`): `a` is the cap.
    Capped,
}

impl Class {
    fn f(self, n: f64) -> f64 {
        match self {
            Class::Constant => 0.0,
            Class::Log => n.max(1.0).log2(),
            Class::Linear => n,
            Class::NLogN => n * n.max(1.0).log2(),
            Class::Quadratic => n * n,
            Class::Cubic => n * n * n,
            Class::Exponential => 2f64.powf(n.min(1000.0)),
            Class::Capped => 0.0,
        }
    }
    fn term(self) -> &'static str {
        match self {
            Class::Constant => "",
            Class::Log => "log₂n",
            Class::Linear => "n",
            Class::NLogN => "n·log₂n",
            Class::Quadratic => "n²",
            Class::Cubic => "n³",
            Class::Exponential => "2ⁿ",
            Class::Capped => "",
        }
    }
    /// Grows faster than linear.
    pub fn superlinear(self) -> bool {
        matches!(self, Class::NLogN | Class::Quadratic | Class::Cubic | Class::Exponential)
    }
}

const ORDER: [Class; 7] = [Class::Constant, Class::Log, Class::Linear, Class::NLogN, Class::Quadratic, Class::Cubic, Class::Exponential];

#[derive(Debug, Clone)]
pub struct Law {
    pub class: Class,
    pub a: f64,
    pub b: f64,
    /// `3 + 28·n`
    pub text: String,
    /// 1 − residual / variance.
    pub fit: f64,
    /// Used when raw coefficients cannot fit f64. The model is
    /// y = y_scale * (a + b * f(n) / x_scale).
    pub normalization: Option<Normalization>,
    /// Optional exact unit for a curve fitted to fractions of a time maximum.
    /// Its a/b coefficients describe those fractions, before rescaling to ms.
    pub time_scale_ns: Option<Natural>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Normalization {
    pub a: f64,
    pub b: f64,
    pub x_scale: f64,
    pub y_scale: f64,
}

// Rescale a fitted coefficient without overflowing intermediate products.
fn product(numerators: &[f64], denominators: &[f64]) -> (f64, String) {
    scaled_product(numerators, denominators, 0)
}
fn scaled_product(numerators: &[f64], denominators: &[f64], extra_exponent: i64) -> (f64, String) {
    if numerators.contains(&0.0) {
        return (0.0, "0".into());
    }
    let mut mantissa = 1.0;
    let mut exponent = extra_exponent;
    for (factors, divide) in [(numerators, false), (denominators, true)] {
        for value in factors {
            let text = format!("{value:e}");
            let (m, e) = text.split_once('e').expect("finite scientific notation");
            let m = m.parse::<f64>().expect("mantissa");
            let e = e.parse::<i64>().expect("exponent");
            if divide {
                mantissa /= m;
                exponent -= e;
            } else {
                mantissa *= m;
                exponent += e;
            }
        }
    }
    while mantissa.abs() >= 10.0 {
        mantissa /= 10.0;
        exponent += 1;
    }
    while mantissa.abs() < 1.0 {
        mantissa *= 10.0;
        exponent -= 1;
    }
    let text = format!("{mantissa}e{exponent}");
    (text.parse().expect("scientific number"), text)
}

impl Serialize for Law {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let coefficient = |raw: f64, slope: bool| -> Value {
            if raw.is_finite() && (raw != 0.0 || self.normalization.is_none()) {
                return json!(raw);
            }
            let Some(n) = &self.normalization else { return json!(raw) };
            let (value, text) = if slope { product(&[n.b, n.y_scale], &[n.x_scale]) } else { product(&[n.a, n.y_scale], &[]) };
            if value.is_finite() && (value != 0.0 || text == "0") { json!(value) } else { json!(text) }
        };
        let mut state = serializer.serialize_struct("Law", 5 + usize::from(self.normalization.is_some()) + usize::from(self.time_scale_ns.is_some()))?;
        state.serialize_field("class", &self.class)?;
        state.serialize_field("a", &coefficient(self.a, false))?;
        state.serialize_field("b", &coefficient(self.b, true))?;
        state.serialize_field("text", &self.text)?;
        state.serialize_field("fit", &self.fit)?;
        if let Some(n) = &self.normalization {
            state.serialize_field("normalization", n)?;
        }
        if let Some(scale) = &self.time_scale_ns {
            state.serialize_field("time_scale_ns", scale)?;
        }
        state.end()
    }
}

impl Law {
    pub fn eval(&self, n: f64) -> f64 {
        let value = self.unscaled_eval(n);
        if let Some(scale) = &self.time_scale_ns {
            if !value.is_finite() {
                return value;
            }
            return scale.scientific().map_or(0.0, |(mantissa, exponent)| scaled_product(&[value, mantissa], &[], exponent - 6).0);
        }
        value
    }
    fn unscaled_eval(&self, n: f64) -> f64 {
        let x = self.class.f(n);
        if let Some(model) = &self.normalization {
            if !x.is_finite() {
                return model.b.mul_add(x, model.a) * model.y_scale;
            }
            let normalized = model.b.mul_add(x / model.x_scale, model.a);
            if normalized.is_finite() {
                return normalized * model.y_scale;
            }
            return product(&[model.b, x, model.y_scale], &[model.x_scale]).0 + product(&[model.a, model.y_scale], &[]).0;
        }
        self.b.mul_add(x, self.a)
    }

    pub fn increasing(&self) -> bool {
        self.normalization.as_ref().map_or(self.b > 0.0, |n| n.b > 0.0)
    }

    /// Smallest n ≥ 0 (up to `max_n`) where the law exceeds `limit`.
    pub fn breaking_point(&self, limit: f64, max_n: u64) -> Option<u64> {
        if limit.is_nan() {
            return None;
        }
        let limit = self.time_scale_ns.as_ref().filter(|_| limit.is_finite()).map_or(limit, |scale| {
            let ratio = Natural::from_scaled_f64(limit.abs(), 1_000_000).ratio(scale);
            if limit < 0.0 { -ratio } else { ratio }
        });
        if self.class == Class::Capped {
            // Only a measured break counts for a capped law.
            return None;
        }
        if !self.increasing() || self.class == Class::Constant {
            return (self.unscaled_eval(0.0) > limit).then_some(0);
        }
        if self.unscaled_eval(0.0) > limit {
            return Some(0);
        }
        if max_n == 0 {
            return None;
        }
        let (mut lo, mut hi) = (0u64, 1u64);
        while self.unscaled_eval(hi as f64) <= limit {
            if hi >= max_n {
                return None;
            }
            lo = hi;
            hi = hi.saturating_mul(2).min(max_n);
        }
        while hi - lo > 1 {
            let mid = lo + (hi - lo) / 2;
            if self.unscaled_eval(mid as f64) > limit { hi = mid } else { lo = mid }
        }
        Some(hi)
    }
}

fn round(x: f64) -> String {
    if x == 0.0 || (x.abs() >= 1.0 && (x - x.round()).abs() < 1e-6) {
        format!("{:.0}", x.round())
    } else if x.abs() >= 100.0 {
        format!("{:.0}", x)
    } else if x.abs() >= 0.01 {
        format!("{:.2}", x)
    } else {
        format!("{x:.2e}")
    }
}

/// Fits `y = a + b·f(n)` for each class and returns the simplest one that
/// fits about as well as the best. Needs at least 3 points.
pub fn fit(points: &[(f64, f64)]) -> Option<Law> {
    if points.len() < 3 || points.iter().any(|(n, y)| !n.is_finite() || !y.is_finite()) {
        return None;
    }
    // A plateau at the end after growth: the app caps it.
    let n = points.len();
    let last = points[n - 1].1;
    if points[n - 2].1 == last && points[0].1 < last && n >= 4 {
        let plateau = points.iter().position(|p| p.1 == last).unwrap_or(n - 1);
        let before = &points[..plateau];
        let inner = if before.len() >= 3 { fit(before).map(|l| format!("{} up to n = {}, then ", l.text, before[plateau - 1].0)) } else { None };
        return Some(Law {
            class: Class::Capped,
            a: last,
            b: 1.0,
            text: format!("{}capped at {}", inner.unwrap_or_default(), round(last)),
            fit: 1.0,
            normalization: None,
            time_scale_ns: None,
        });
    }
    // Growing faster than linear needs growth at most steps: a single jump
    // (memory pages, a buffer doubling) fits 2^n perfectly but is a step.
    let rises = points.windows(2).filter(|w| w[1].1 > w[0].1 * 1.01).count();
    let steady = rises * 2 >= n - 1;
    let y_scale = points.iter().map(|p| p.1.abs()).fold(0.0, f64::max).max(f64::MIN_POSITIVE);
    let ys: Vec<f64> = points.iter().map(|p| p.1 / y_scale).collect();
    let mean_y = ys.iter().sum::<f64>() / points.len() as f64;
    let var: f64 = ys.iter().map(|y| (y - mean_y).powi(2)).sum();
    let mut fits: Vec<Law> = Vec::new();
    for class in ORDER {
        if class.superlinear() && !steady {
            continue;
        }
        let mut xs: Vec<f64> = points.iter().map(|p| class.f(p.0)).collect();
        if xs.iter().any(|x| !x.is_finite()) {
            continue;
        }
        let x_scale = xs.iter().map(|x| x.abs()).fold(1.0, f64::max);
        for x in &mut xs {
            *x /= x_scale;
        }
        let (mut a, b) = if class == Class::Constant {
            (mean_y, 0.0)
        } else {
            let mx = xs.iter().sum::<f64>() / xs.len() as f64;
            let sxx: f64 = xs.iter().map(|x| (x - mx).powi(2)).sum();
            if sxx == 0.0 {
                continue;
            }
            let sxy: f64 = xs.iter().zip(&ys).map(|(x, y)| (x - mx) * (y - mean_y)).sum();
            let b = sxy / sxx;
            (mean_y - b * mx, b)
        };
        // Suppress intercept noise below the precision of the normalized fit.
        if a.abs() < 1e-14 {
            a = 0.0;
        }
        let res: f64 = xs.iter().zip(&ys).map(|(x, y)| (y - b.mul_add(*x, a)).powi(2)).sum();
        let fit = if var == 0.0 { 1.0 } else { 1.0 - res / var };
        if !fit.is_finite() {
            continue;
        }
        let (raw_a, text_a) = product(&[a, y_scale], &[]);
        let (raw_b, text_b) = product(&[b, y_scale], &[x_scale]);
        let coefficient_text = |value: f64, text: String| if value.is_finite() && (value != 0.0 || text == "0") { round(value) } else { text };
        let a_text = coefficient_text(raw_a, text_a);
        let b_text = coefficient_text(raw_b.abs(), text_b.trim_start_matches('-').to_string());
        let text = if class == Class::Constant || b == 0.0 {
            a_text
        } else if a == 0.0 {
            format!("{}{}·{}", if b < 0.0 { "−" } else { "" }, b_text, class.term())
        } else {
            format!("{} {} {}·{}", a_text, if b < 0.0 { "−" } else { "+" }, b_text, class.term())
        };
        let normalization = (!raw_a.is_finite() || !raw_b.is_finite() || (raw_a == 0.0 && a != 0.0) || (raw_b == 0.0 && b != 0.0)).then_some(Normalization {
            a,
            b,
            x_scale,
            y_scale,
        });
        fits.push(Law { class, a: raw_a, b: raw_b, text, fit, normalization, time_scale_ns: None });
    }
    let best = fits.iter().map(|l| l.fit).fold(f64::MIN, f64::max);
    // Simplest class within a small margin of the best fit; a decreasing
    // law is never "superlinear".
    fits.into_iter().find(|l| l.fit >= best - 0.002 && !(l.class.superlinear() && l.b < 0.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pts(f: impl Fn(f64) -> f64) -> Vec<(f64, f64)> {
        [1.0, 2.0, 4.0, 8.0, 16.0].iter().map(|&n| (n, f(n))).collect()
    }

    #[test]
    fn finds_laws() {
        let l = fit(&pts(|n| 3.0 + 28.0 * n)).unwrap();
        assert_eq!(l.class, Class::Linear);
        assert_eq!(l.text, "3 + 28·n");
        assert_eq!(l.breaking_point(100.0, 1 << 20), Some(4));
        assert_eq!(fit(&pts(|_| 5.0)).unwrap().class, Class::Constant);
        assert_eq!(fit(&pts(|n| n * n + 1.0)).unwrap().class, Class::Quadratic);
        assert_eq!(fit(&pts(|n| 7.0 * n * n.log2())).unwrap().class, Class::NLogN);
        let capped = fit(&pts(|n| n.min(4.0))).unwrap();
        assert_eq!(capped.class, Class::Capped);
        assert_eq!(capped.breaking_point(1.0, 100), None);
        // Memory in pages: flat, then one jump.
        let step = fit(&[(1.0, 1.0e6), (2.0, 1.0e6), (4.0, 1.0e6), (8.0, 1.0e6), (16.0, 1.0e6), (32.0, 1.07e6)]).unwrap();
        assert!(!step.class.superlinear(), "{step:?}");
    }
}
