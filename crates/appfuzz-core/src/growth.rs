//! Fitting growth laws to measurements: `calls = 3 + 28·n`.

use serde::Serialize;

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

const ORDER: [Class; 7] =
    [Class::Constant, Class::Log, Class::Linear, Class::NLogN, Class::Quadratic, Class::Cubic, Class::Exponential];

#[derive(Debug, Clone, Serialize)]
pub struct Law {
    pub class: Class,
    pub a: f64,
    pub b: f64,
    /// `3 + 28·n`
    pub text: String,
    /// 1 − residual / variance.
    pub fit: f64,
}

impl Law {
    pub fn eval(&self, n: f64) -> f64 {
        self.a + self.b * self.class.f(n)
    }

    /// Smallest n ≥ 0 (up to `max_n`) where the law exceeds `limit`.
    pub fn breaking_point(&self, limit: f64, max_n: u64) -> Option<u64> {
        if self.class == Class::Capped {
            // Only a measured break counts for a capped law.
            return None;
        }
        if self.b <= 0.0 || self.class == Class::Constant {
            return (self.a > limit).then_some(0);
        }
        let (mut lo, mut hi) = (0u64, 1u64);
        while self.eval(hi as f64) <= limit {
            if hi >= max_n {
                return None;
            }
            lo = hi;
            hi = (hi * 2).min(max_n);
        }
        if self.eval(lo as f64) > limit {
            return Some(lo);
        }
        while hi - lo > 1 {
            let mid = (lo + hi) / 2;
            if self.eval(mid as f64) > limit { hi = mid } else { lo = mid }
        }
        Some(hi)
    }
}

fn round(x: f64) -> String {
    if (x - x.round()).abs() < 1e-6 {
        format!("{}", x.round() as i64)
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
    if points.len() < 3 {
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
        });
    }
    // Growing faster than linear needs growth at most steps: a single jump
    // (memory pages, a buffer doubling) fits 2^n perfectly but is a step.
    let rises = points.windows(2).filter(|w| w[1].1 > w[0].1 * 1.01).count();
    let steady = rises * 2 >= n - 1;
    let mean_y = points.iter().map(|p| p.1).sum::<f64>() / points.len() as f64;
    let var: f64 = points.iter().map(|p| (p.1 - mean_y).powi(2)).sum();
    let mut fits: Vec<Law> = Vec::new();
    for class in ORDER {
        if class.superlinear() && !steady {
            continue;
        }
        let xs: Vec<f64> = points.iter().map(|p| class.f(p.0)).collect();
        if xs.iter().any(|x| !x.is_finite()) {
            continue;
        }
        let (a, b) = if class == Class::Constant {
            (mean_y, 0.0)
        } else {
            let mx = xs.iter().sum::<f64>() / xs.len() as f64;
            let sxx: f64 = xs.iter().map(|x| (x - mx).powi(2)).sum();
            if sxx == 0.0 {
                continue;
            }
            let sxy: f64 = xs.iter().zip(points).map(|(x, p)| (x - mx) * (p.1 - mean_y)).sum();
            let b = sxy / sxx;
            (mean_y - b * mx, b)
        };
        let res: f64 = xs.iter().zip(points).map(|(x, p)| (p.1 - a - b * x).powi(2)).sum();
        let fit = if var == 0.0 { 1.0 } else { 1.0 - res / var };
        let text = if class == Class::Constant || b.abs() < 1e-9 {
            round(a)
        } else if a.abs() < 1e-6 {
            format!("{}·{}", round(b), class.term())
        } else {
            format!("{} {} {}·{}", round(a), if b < 0.0 { "−" } else { "+" }, round(b.abs()), class.term())
        };
        fits.push(Law { class, a, b, text, fit });
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
