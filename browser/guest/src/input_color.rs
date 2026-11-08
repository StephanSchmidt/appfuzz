//! Color well parsing and serialization stay native, outside page intrinsics.
//! CSS tokenization/grammar comes from Servo's parser; Linebender supplies
//! color-space conversions. Unsupported expressions are reported explicitly.
use color::{ColorSpaceTag as Space, DynamicColor, Flags, HueDirection, Missing};
use cssparser::{ParseError, Parser, ToCss, Token};
use cssparser_color::{AngleOrNumber, Color, ColorParser, NumberOrPercentage};
use std::cell::Cell;
type Result<T> = std::result::Result<T, ParseError<()>>;
fn invalid<T>() -> Result<T> {
    Err(ParseError::unexpected_token())
}
#[derive(Clone, Copy)]
struct Quantity {
    value: f64,
    percent: i8,
    angle: i8,
}
impl Quantity {
    fn number(value: f64) -> Self {
        Self { value, percent: 0, angle: 0 }
    }
    fn same(self, other: Self) -> bool {
        self.percent == other.percent && self.angle == other.angle
    }
}
struct Components<'a> {
    unsupported: &'a Cell<bool>,
    numeric_percentage: bool,
}
impl Components<'_> {
    fn value(&self, input: &mut Parser, depth: u8) -> Result<Quantity> {
        if depth >= 64 {
            self.unsupported.set(true);
            return invalid();
        }
        Ok(match input.next()?.clone() {
            Token::Number { value, .. } => Quantity::number(value as f64),
            Token::Percentage { unit_value, .. } => Quantity { value: unit_value as f64, percent: 1, angle: 0 },
            Token::Dimension { value, unit, .. } => {
                let factor = match unit.to_ascii_lowercase().as_str() {
                    "deg" => 1.,
                    "grad" => 0.9,
                    "turn" => 360.,
                    "rad" => 180. / std::f64::consts::PI,
                    _ => return invalid(),
                };
                Quantity { value: value as f64 * factor, percent: 0, angle: 1 }
            }
            Token::Ident(name) if depth > 0 => Quantity::number(match name.to_ascii_lowercase().as_str() {
                "pi" => std::f64::consts::PI,
                "e" => std::f64::consts::E,
                "infinity" => f64::INFINITY,
                "-infinity" => f64::NEG_INFINITY,
                "nan" => f64::NAN,
                _ => return invalid(),
            }),
            Token::ParenthesisBlock if depth > 0 => input.parse_nested_block(|p| self.sum(p, depth + 1))?,
            Token::Function(name) => input.parse_nested_block(|p| self.function(p, &name.to_ascii_lowercase(), depth + 1))?,
            _ => return invalid(),
        })
    }
    fn product(&self, input: &mut Parser, depth: u8) -> Result<Quantity> {
        let mut left = self.value(input, depth)?;
        while let Ok(op) = input.try_parse(|p| match p.next()? {
            Token::Delim(c @ ('*' | '/')) => Ok(*c),
            _ => Err(cssparser::BasicParseError::unexpected_token()),
        }) {
            let right = self.value(input, depth)?;
            if op == '*' {
                left.value *= right.value;
                left.percent += right.percent;
                left.angle += right.angle;
            } else {
                left.value /= right.value;
                left.percent -= right.percent;
                left.angle -= right.angle;
            }
            if left.percent.abs() > 16 || left.angle.abs() > 16 {
                self.unsupported.set(true);
                return invalid();
            }
        }
        Ok(left)
    }
    fn sum(&self, input: &mut Parser, depth: u8) -> Result<Quantity> {
        let mut left = self.product(input, depth)?;
        loop {
            let state = input.state();
            let mut space = false;
            let op = loop {
                match input.next_including_whitespace() {
                    Ok(Token::WhiteSpace(_)) => space = true,
                    Ok(Token::Delim(c @ ('+' | '-'))) if space => break *c,
                    _ => {
                        input.reset(&state);
                        return Ok(left);
                    }
                }
            };
            if !matches!(input.next_including_whitespace()?, Token::WhiteSpace(_)) {
                return invalid();
            }
            let right = self.product(input, depth)?;
            if !left.same(right) {
                return invalid();
            }
            if op == '+' {
                left.value += right.value;
            } else {
                left.value -= right.value;
            }
        }
    }
    fn function(&self, input: &mut Parser, name: &str, depth: u8) -> Result<Quantity> {
        if name == "calc" {
            return self.sum(input, depth);
        }
        if matches!(name, "min" | "max" | "clamp" | "abs" | "sign") {
            let mut args = input.parse_comma_separated(|p| self.sum(p, depth))?;
            if args.is_empty() {
                return invalid();
            }
            let first = args[0];
            if args.iter().any(|v| !first.same(*v)) {
                return invalid();
            }
            let mut value = first;
            match name {
                "abs" if args.len() == 1 => value.value = value.value.abs(),
                "sign" if args.len() == 1 => {
                    value = Quantity::number(if value.value == 0. || value.value.is_nan() { value.value } else { value.value.signum() });
                }
                "clamp" if args.len() == 3 => {
                    let upper = if args[1].value.is_nan() || args[2].value.is_nan() { f64::NAN } else { args[1].value.min(args[2].value) };
                    value.value = if value.value.is_nan() || upper.is_nan() { f64::NAN } else { value.value.max(upper) };
                }
                "min" | "max" => {
                    for next in args.drain(1..) {
                        value.value = if value.value.is_nan() || next.value.is_nan() {
                            f64::NAN
                        } else if name == "min" {
                            value.value.min(next.value)
                        } else {
                            value.value.max(next.value)
                        };
                    }
                }
                _ => return invalid(),
            }
            return Ok(value);
        }
        if matches!(
            name,
            "round" | "mod" | "rem" | "sin" | "cos" | "tan" | "asin" | "acos" | "atan" | "atan2" | "pow" | "sqrt" | "hypot" | "log" | "exp" | "progress"
        ) {
            self.unsupported.set(true);
        }
        invalid()
    }
}
fn resolved(value: f64) -> f32 {
    if value.is_nan() { 0. } else { value as f32 }
}
impl<'i> ColorParser<'i> for Components<'_> {
    type Output = Color;
    type Error = ();
    fn parse_number(&self, input: &mut Parser) -> Result<f32> {
        let q = self.value(input, 0)?;
        if q.percent == 0 && q.angle == 0 { Ok(resolved(q.value)) } else { invalid() }
    }
    fn parse_percentage(&self, input: &mut Parser) -> Result<f32> {
        let q = self.value(input, 0)?;
        if q.percent == 1 && q.angle == 0 {
            Ok(resolved(q.value))
        } else if self.numeric_percentage && q.percent == 0 && q.angle == 0 {
            Ok(resolved(q.value / 100.))
        } else {
            invalid()
        }
    }
    fn parse_number_or_percentage(&self, input: &mut Parser) -> Result<NumberOrPercentage> {
        let q = self.value(input, 0)?;
        if q.percent == 0 && q.angle == 0 {
            Ok(NumberOrPercentage::Number { value: resolved(q.value) })
        } else if q.percent == 1 && q.angle == 0 {
            Ok(NumberOrPercentage::Percentage { unit_value: resolved(q.value) })
        } else {
            invalid()
        }
    }
    fn parse_angle_or_number(&self, input: &mut Parser) -> Result<AngleOrNumber> {
        let q = self.value(input, 0)?;
        if q.percent != 0 {
            return invalid();
        }
        let degrees = if q.value.is_finite() { resolved(q.value) } else { 0. };
        if q.angle == 0 {
            Ok(AngleOrNumber::Number { value: degrees })
        } else if q.angle == 1 {
            Ok(AngleOrNumber::Angle { degrees })
        } else {
            invalid()
        }
    }
}
fn dynamic(cs: Space, parts: [Option<f32>; 4]) -> DynamicColor {
    let mut missing = Missing::EMPTY;
    for (i, part) in parts.iter().enumerate() {
        if part.is_none() {
            missing.insert(i);
        }
    }
    DynamicColor { cs, flags: Flags::from_missing(missing), components: parts.map(|v| v.unwrap_or(0.)) }
}
fn rgba(r: f32, g: f32, b: f32, a: f32) -> DynamicColor {
    dynamic(Space::Srgb, [Some(r), Some(g), Some(b), Some(a)])
}
fn converted(value: Color) -> DynamicColor {
    use cssparser::color::PredefinedColorSpace as P;
    match value {
        Color::CurrentColor => rgba(0., 0., 0., 1.),
        Color::Rgba(v) => rgba(v.red as f32 / 255., v.green as f32 / 255., v.blue as f32 / 255., v.alpha),
        Color::Hsl(v) => dynamic(Space::Hsl, [v.hue, v.saturation.map(|v| v * 100.), v.lightness.map(|v| v * 100.), v.alpha]),
        Color::Hwb(v) => dynamic(Space::Hwb, [v.hue, v.whiteness.map(|v| v * 100.), v.blackness.map(|v| v * 100.), v.alpha]),
        Color::Lab(v) => dynamic(Space::Lab, [v.lightness, v.a, v.b, v.alpha]),
        Color::Lch(v) => dynamic(Space::Lch, [v.lightness, v.chroma, v.hue, v.alpha]),
        Color::Oklab(v) => dynamic(Space::Oklab, [v.lightness, v.a, v.b, v.alpha]),
        Color::Oklch(v) => dynamic(Space::Oklch, [v.lightness, v.chroma, v.hue, v.alpha]),
        Color::ColorFunction(v) => {
            let cs = match v.color_space {
                P::Srgb => Space::Srgb,
                P::SrgbLinear => Space::LinearSrgb,
                P::DisplayP3 | P::DisplayP3Linear => Space::DisplayP3,
                P::A98Rgb => Space::A98Rgb,
                P::ProphotoRgb => Space::ProphotoRgb,
                P::Rec2020 => Space::Rec2020,
                P::XyzD50 => Space::XyzD50,
                P::XyzD65 => Space::XyzD65,
            };
            let mut result = dynamic(cs, [v.c1, v.c2, v.c3, v.alpha]);
            if v.color_space == P::DisplayP3Linear {
                let encoded = dynamic(Space::LinearSrgb, [v.c1, v.c2, v.c3, v.alpha]).convert(Space::Srgb);
                result.components = encoded.components;
            }
            result
        }
    }
}
fn parse(input: &mut Parser, unsupported: &Cell<bool>, depth: u8) -> Result<DynamicColor> {
    if depth >= 64 {
        unsupported.set(true);
        return invalid();
    }
    let state = input.state();
    // System colors depend on a platform palette and user preferences.
    if let Ok(Token::Ident(name)) = input.next().cloned()
        && matches!(
            name.to_ascii_lowercase().as_str(),
            "accentcolor"
                | "accentcolortext"
                | "activetext"
                | "buttonborder"
                | "buttonface"
                | "buttontext"
                | "canvas"
                | "canvastext"
                | "field"
                | "fieldtext"
                | "graytext"
                | "highlight"
                | "highlighttext"
                | "linktext"
                | "mark"
                | "marktext"
                | "selecteditem"
                | "selecteditemtext"
                | "visitedtext"
                | "activeborder"
                | "activecaption"
                | "appworkspace"
                | "background"
                | "buttonhighlight"
                | "buttonshadow"
                | "captiontext"
                | "inactiveborder"
                | "inactivecaption"
                | "inactivecaptiontext"
                | "infobackground"
                | "infotext"
                | "menu"
                | "menutext"
                | "scrollbar"
                | "threeddarkshadow"
                | "threedface"
                | "threedhighlight"
                | "threedlightshadow"
                | "threedshadow"
                | "window"
                | "windowframe"
                | "windowtext"
        )
    {
        unsupported.set(true);
    }
    input.reset(&state);
    if let Ok(Token::Function(name)) = input.next().cloned() {
        if name.eq_ignore_ascii_case("color-mix") {
            return input.parse_nested_block(|p| mix(p, unsupported, depth + 1));
        }
        if matches!(name.to_ascii_lowercase().as_str(), "light-dark" | "contrast-color" | "device-cmyk" | "alpha") {
            unsupported.set(true);
        }
        let relative = matches!(name.to_ascii_lowercase().as_str(), "rgb" | "rgba" | "hsl" | "hsla" | "hwb" | "lab" | "lch" | "oklab" | "oklch" | "color");
        let _ = input.parse_nested_block(|p| -> Result<()> {
            if matches!(p.next(),Ok(Token::Ident(v)) if relative && v.eq_ignore_ascii_case("from") || name.eq_ignore_ascii_case("color") && v.starts_with("--"))
            {
                unsupported.set(true);
            }
            Ok(())
        });
    }
    input.reset(&state);
    // Numeric saturation/lightness and whiteness/blackness use modern syntax.
    // The legacy comma form still requires percentages.
    let modern = input
        .try_parse(|p| -> Result<bool> {
            p.expect_function_matching("hsl").or_else(|_| {
                p.reset(&state);
                p.expect_function_matching("hsla").or_else(|_| {
                    p.reset(&state);
                    p.expect_function_matching("hwb")
                })
            })?;
            p.parse_nested_block(|p| {
                while let Ok(token) = p.next() {
                    if matches!(token, Token::Comma) {
                        return Ok(false);
                    }
                }
                Ok(true)
            })
        })
        .unwrap_or(false);
    input.reset(&state);
    cssparser_color::parse_color_with(&Components { unsupported, numeric_percentage: modern }, input).map(converted)
}
fn space(name: &str) -> Option<Space> {
    Some(match name {
        "srgb" => Space::Srgb,
        "srgb-linear" => Space::LinearSrgb,
        "display-p3" => Space::DisplayP3,
        "a98-rgb" => Space::A98Rgb,
        "prophoto-rgb" => Space::ProphotoRgb,
        "rec2020" => Space::Rec2020,
        "xyz" | "xyz-d65" => Space::XyzD65,
        "xyz-d50" => Space::XyzD50,
        "lab" => Space::Lab,
        "lch" => Space::Lch,
        "oklab" => Space::Oklab,
        "oklch" => Space::Oklch,
        "hsl" => Space::Hsl,
        "hwb" => Space::Hwb,
        _ => return None,
    })
}
fn mix(input: &mut Parser, unsupported: &Cell<bool>, depth: u8) -> Result<DynamicColor> {
    let specified = input.try_parse(|p| p.expect_ident_matching("in")).is_ok();
    let cs = if specified {
        let name = input.expect_ident()?.to_ascii_lowercase();
        space(&name).ok_or_else(ParseError::unexpected_token)?
    } else {
        Space::Oklab
    };
    let mut hue = HueDirection::Shorter;
    if let Some(direction) = if specified { input.try_parse(|p| p.expect_ident_cloned()).ok() } else { None } {
        hue = match direction.to_ascii_lowercase().as_str() {
            "shorter" => HueDirection::Shorter,
            "longer" => HueDirection::Longer,
            "increasing" => HueDirection::Increasing,
            "decreasing" => HueDirection::Decreasing,
            _ => return invalid(),
        };
        input.expect_ident_matching("hue")?;
        if !matches!(cs, Space::Hsl | Space::Hwb | Space::Lch | Space::Oklch) {
            return invalid();
        }
    }
    if specified {
        input.expect_comma()?;
    }
    let colors = input.parse_comma_separated(|p| {
        let mut weight = p.try_parse(|p| Components { unsupported, numeric_percentage: false }.parse_percentage(p)).ok();
        let c = parse(p, unsupported, depth)?;
        if weight.is_none() {
            weight = p.try_parse(|p| Components { unsupported, numeric_percentage: false }.parse_percentage(p)).ok();
        }
        if weight.is_some_and(|w| !(0. ..=1.).contains(&w)) {
            return invalid();
        }
        Ok((c, weight))
    })?;
    if colors.is_empty() {
        return invalid();
    }
    let specified_sum: f32 = colors.iter().filter_map(|(_, w)| *w).sum();
    let omitted = colors.iter().filter(|(_, w)| w.is_none()).count();
    let default_weight = if omitted == 0 { 0. } else { (1. - specified_sum).max(0.) / omitted as f32 };
    let total = specified_sum + default_weight * omitted as f32;
    let mut result = colors[0].0;
    let mut accumulated = colors[0].1.unwrap_or(default_weight);
    for (next, weight) in colors.iter().skip(1) {
        let weight = weight.unwrap_or(default_weight);
        let sum = accumulated + weight;
        result = result.interpolate(*next, cs, hue).eval(if sum > 0. { weight / sum } else { 0.5 });
        accumulated = sum;
    }
    result = result.convert(cs);
    result.components[3] *= total.min(1.);
    Ok(result)
}
fn byte(value: f32) -> u8 {
    (value * 255.).round().clamp(0., 255.) as u8
}
fn number(value: f32) -> String {
    if value == 0. { "0".into() } else { value.to_css_string() }
}
pub(crate) fn sanitize(value: &str, alpha: bool, p3: bool) -> (String, bool) {
    let unsupported = Cell::new(false);
    let mut c = Parser::new(value).parse_entirely(|p| parse(p, &unsupported, 0)).unwrap_or_else(|_| rgba(0., 0., 0., 1.));
    if !alpha {
        c.components[3] = 1.;
    }
    // Missing components become zero when used as a standalone color.
    c.flags = Flags::default();
    c = c.convert(if p3 { Space::DisplayP3 } else { Space::Srgb });
    if c.components.iter().any(|v| !v.is_finite()) {
        // sRGB infinities can be clamped directly. Conversion through another
        // space can produce NaNs, which cannot silently become valid evidence.
        if p3 || c.components.iter().any(|v| v.is_nan()) {
            unsupported.set(true);
        }
        for v in &mut c.components {
            if v.is_nan() {
                *v = 0.;
            }
        }
    }
    if !p3 {
        let [r, g, b, a] = c.components.map(byte);
        if !alpha {
            return (format!("#{r:02x}{g:02x}{b:02x}"), unsupported.get());
        }
        c.components = [r as f32 / 255., g as f32 / 255., b as f32 / 255., a as f32 / 255.];
    }
    let [r, g, b, a] = c.components;
    if ![r, g, b, a].iter().all(|v| v.is_finite()) {
        return ("color(display-p3 0 0 0)".into(), true);
    }
    let suffix = if a == 1. { String::new() } else { format!(" / {}", number(a)) };
    (format!("color({} {} {} {}{})", if p3 { "display-p3" } else { "srgb" }, number(r), number(g), number(b), suffix), unsupported.get())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn css_colors_and_strict_legacy_grammar() {
        for (source, expected) in [
            ("#abc", "#aabbcc"),
            (" RED\n", "#ff0000"),
            ("r\\65 d", "#ff0000"),
            ("/**/red/**/", "#ff0000"),
            ("oklch(.7 .2 30)", "#ff614d"),
            ("rgb(1, 2%, 3)", "#000000"),
            ("rgb(1% 2 3%)", "#030208"),
            ("hsl(120,100,50)", "#000000"),
            ("var(--x)", "#000000"),
        ] {
            assert_eq!(sanitize(source, false, false), (expected.into(), false), "{source}");
        }
    }
    #[test]
    fn limited_srgb_quantizes_all_channels() {
        assert_eq!(sanitize("rgb(.49 .5 1.5 / .5)", true, false), ("color(srgb 0 0.00392157 0.00784314 / 0.501961)".into(), false));
        assert_eq!(sanitize("#abcd", false, false), ("#aabbcc".into(), false));
    }
    #[test]
    fn display_p3_preserves_extended_components_and_alpha() {
        let value = "color(display-p3 1.84 -0.19 0.72 / 0.6)";
        assert_eq!(sanitize(value, true, true), (value.into(), false));
        assert_eq!(sanitize(value, false, true), ("color(display-p3 1.84 -0.19 0.72)".into(), false));
    }
    #[test]
    fn css_math_dimensions_precedence_and_whitespace() {
        for (source, expected) in [
            ("rgb(calc(2 * (30 + 10)) 0 0)", "#500000"),
            ("rgb(calc(100% / 2) 0% 0%)", "#800000"),
            ("hsl(calc(.25turn + 90deg) 100% 50%)", "#00ffff"),
            ("rgb(clamp(0,200,100) 0 0)", "#640000"),
            ("rgb(calc(10-2) 0 0)", "#000000"),
            ("rgb(calc(1 + 20%) 0 0)", "#000000"),
            ("rgb(calc(1px) 0 0)", "#000000"),
        ] {
            assert_eq!(sanitize(source, false, false), (expected.into(), false), "{source}");
        }
    }
    #[test]
    fn nonfinite_channels_do_not_panic_or_serialize_nan() {
        for (source, expected) in
            [("rgb(calc(1 / 0) 0 0)", "#ff0000"), ("rgb(calc(0 / 0) 0 0)", "#000000"), ("color(srgb 1e999 0 0)", "#ff0000"), ("hsl(1e999 100% 50%)", "#ff0000")]
        {
            assert_eq!(sanitize(source, false, false), (expected.into(), false), "{source}");
        }
        let (value, unsupported) = sanitize("color(srgb 1e999 0 0)", true, true);
        assert!(unsupported);
        assert!(!value.contains("NaN") && !value.contains("inf"));
    }
    #[test]
    fn mix_uses_premultiplied_alpha_and_weights() {
        assert_eq!(sanitize("color-mix(in srgb,red,blue)", false, false), ("#800080".into(), false));
        assert_eq!(sanitize("color-mix(in srgb,transparent 50%,red)", true, false), ("color(srgb 1 0 0 / 0.501961)".into(), false));
        // CSS Color 5 keeps the mixed components at alpha 0; HTML then forces opacity.
        assert_eq!(sanitize("color-mix(in srgb,red 0%,blue 0%)", false, false), ("#800080".into(), false));
    }
    #[test]
    fn unimplemented_context_and_math_are_explicit() {
        for source in
            ["rgb(from red r g b)", "light-dark(red,blue)", "rgb(sqrt(4) 0 0)", "contrast-color(red)", "device-cmyk(0 1 1 0)", "color(--custom 1 0 0)"]
        {
            assert!(sanitize(source, false, false).1, "{source}");
        }
    }
    #[test]
    fn system_colors_are_not_silently_treated_as_invalid_text() {
        for source in ["Canvas", "LinkText", "ButtonFace", "Window", "AccentColor"] {
            assert!(sanitize(source, false, false).1, "{source}");
        }
        assert_eq!(sanitize("var(--x)", false, false), ("#000000".into(), false));
    }
    #[test]
    fn expression_depth_is_bounded() {
        let source = format!("rgb({}1{} 0 0)", "calc(".repeat(100), ")".repeat(100));
        assert!(sanitize(&source, false, false).1);
    }
}
