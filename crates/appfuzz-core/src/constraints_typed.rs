//! Apply platform guarantees with the WIT type available: repairs must remain
//! representable, and growing an empty list needs a typed element generator.
use super::{Constraint, Decimal, integer_json};
use crate::value::{GenOpts, Generator, json_to_val, val_to_json};
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use wasmtime::component::Type;

fn segments(path: &str) -> Vec<&str> {
    path.split('.').filter(|s| !s.is_empty()).collect()
}

fn list_element(ty: &Type) -> Option<Type> {
    match ty {
        Type::List(l) => Some(l.ty()),
        Type::FixedLengthList(l) => Some(l.ty()),
        _ => None,
    }
}

fn selected_type(ty: &Type, path: &[&str], c: &Constraint) -> Result<Type> {
    match ty {
        Type::Option(o) => return selected_type(&o.ty(), path, c),
        Type::Result(r) => return selected_type(&r.ok().context("a value guarantee needs a successful result payload")?, path, c),
        _ => {}
    }
    if let Some(inner) = list_element(ty) {
        if path.is_empty() && matches!(c, Constraint::Len(..) | Constraint::Unique(_)) {
            return Ok(ty.clone());
        }
        if !path.is_empty()
            && let Type::Tuple(tuple) = &inner
        {
            let parts: Vec<_> = tuple.types().collect();
            if parts.len() == 2 && parts[0] == Type::String {
                return selected_type(&parts[1], &path[1..], c);
            }
        }
        return selected_type(&inner, path, c);
    }
    if path.is_empty() {
        return Ok(ty.clone());
    }
    if let Type::Record(record) = ty {
        let field = record.fields().find(|f| f.name == path[0]).context("value guarantee names an unknown field")?;
        return selected_type(&field.ty, &path[1..], c);
    }
    bail!("value guarantee path does not exist in WIT")
}

fn integer_limits(ty: &Type) -> Option<(i128, i128)> {
    Some(match ty {
        Type::U8 => (0, u8::MAX.into()),
        Type::U16 => (0, u16::MAX.into()),
        Type::U32 => (0, u32::MAX.into()),
        Type::U64 => (0, u64::MAX.into()),
        Type::S8 => (i8::MIN.into(), i8::MAX.into()),
        Type::S16 => (i16::MIN.into(), i16::MAX.into()),
        Type::S32 => (i32::MIN.into(), i32::MAX.into()),
        Type::S64 => (i64::MIN.into(), i64::MAX.into()),
        _ => return None,
    })
}

fn integer_range(c: &Constraint, ty: &Type) -> Result<Constraint> {
    let Constraint::Range(lo, hi) = c else { return Ok(c.clone()) };
    let Some((mut min, mut max)) = integer_limits(ty) else { return Ok(c.clone()) };
    let lower = Decimal::parse(&min.to_string()).unwrap();
    let upper = Decimal::parse(&max.to_string()).unwrap();
    if let Some(lo) = lo {
        if lo.cmp(&upper).is_gt() {
            bail!("range has no value representable by this WIT integer");
        }
        if lo.cmp(&lower).is_gt() {
            min = lo.rounded_integer(true).context("unrepresentable integer lower bound")?;
        }
    }
    if let Some(hi) = hi {
        if hi.cmp(&lower).is_lt() {
            bail!("range has no value representable by this WIT integer");
        }
        if hi.cmp(&upper).is_lt() {
            max = hi.rounded_integer(false).context("unrepresentable integer upper bound")?;
        }
    }
    if min > max {
        bail!("range has no value representable by this WIT integer");
    }
    Ok(Constraint::Range(Some(Decimal::parse(&min.to_string()).unwrap()), Some(Decimal::parse(&max.to_string()).unwrap())))
}

fn repair_scalar(value: &Value, ty: &Type, c: &Constraint, seed: u64) -> Result<Value> {
    let adjusted = integer_range(c, ty)?;
    if let Ok(converted) = json_to_val(value, ty) {
        let normalized = val_to_json(&converted);
        if c.holds(&normalized) {
            return Ok(normalized);
        }
    }
    if let Constraint::Enum(choices) = c {
        for i in 0..choices.len() {
            let text = &choices[((seed % choices.len() as u64) as usize + i) % choices.len()];
            let candidate = if integer_limits(ty).is_some() {
                Decimal::parse(text).and_then(|n| {
                    let integer = n.rounded_integer(true)?;
                    n.cmp(&Decimal::parse(&integer.to_string())?).is_eq().then(|| integer_json(integer)).flatten()
                })
            } else if matches!(ty, Type::Float32 | Type::Float64) {
                text.parse::<serde_json::Number>().ok().map(Value::Number)
            } else {
                Some(json!(text))
            };
            if let Some(candidate) = candidate
                && let Ok(converted) = json_to_val(&candidate, ty)
            {
                let normalized = val_to_json(&converted);
                if c.holds(&normalized) {
                    return Ok(normalized);
                }
            }
        }
        bail!("enum has no value representable by this WIT type");
    }
    let candidate = adjusted.conform(value, seed);
    if let Ok(converted) = json_to_val(&candidate, ty) {
        let normalized = val_to_json(&converted);
        if c.holds(&normalized) {
            return Ok(normalized);
        }
        if let Type::Float32 = ty
            && let Some(number) = candidate.as_f64()
        {
            let number = number as f32;
            for n in [number.next_up(), number.next_down()] {
                let normalized = json!(n as f64);
                if n.is_finite() && c.holds(&normalized) {
                    return Ok(normalized);
                }
            }
        }
    }
    bail!("cannot produce a WIT value that keeps the platform guarantee {c}")
}

pub(crate) fn validate_type(ty: &Type, path: &str, c: &Constraint) -> Result<()> {
    if !path.is_empty() && path.split('.').any(str::is_empty) {
        bail!("value guarantee path contains an empty segment");
    }
    let selected = selected_type(ty, &segments(path), c)?;
    match c {
        Constraint::Len(lo, hi) => match &selected {
            Type::String | Type::List(_) => {}
            Type::FixedLengthList(l) if lo.is_none_or(|n| l.len() as usize >= n) && hi.is_none_or(|n| l.len() as usize <= n) => {}
            _ => bail!("length guarantee is incompatible with the selected WIT type"),
        },
        Constraint::Unique(fields) => {
            let inner = list_element(&selected).context("unique guarantee needs a WIT list")?;
            if !fields.is_empty() {
                let Type::Record(record) = inner else { bail!("unique fields need a list of records") };
                if fields.iter().any(|name| !record.fields().any(|f| f.name == name)) {
                    bail!("unique guarantee names an unknown record field");
                }
            }
        }
        Constraint::Format(_) if selected == Type::String => {}
        Constraint::Format(_) => bail!("format guarantee needs WIT text"),
        Constraint::Range(..) | Constraint::Enum(_) => {
            if !matches!(
                selected,
                Type::String
                    | Type::Enum(_)
                    | Type::U8
                    | Type::U16
                    | Type::U32
                    | Type::U64
                    | Type::S8
                    | Type::S16
                    | Type::S32
                    | Type::S64
                    | Type::Float32
                    | Type::Float64
            ) || matches!(c, Constraint::Range(..)) && matches!(selected, Type::Enum(_))
            {
                bail!("numeric/enum guarantee is incompatible with the selected WIT type");
            }
            let mut generator = Generator::new(1, GenOpts::default());
            repair_scalar(&generator.gen_json(&selected), &selected, c, 1)?;
        }
    }
    Ok(())
}

fn visit(value: &mut Value, ty: &Type, path: &[&str], c: &Constraint, generator: &mut Generator, seed: u64, repair: bool) -> Result<()> {
    match ty {
        Type::Option(o) => {
            if value.is_null() {
                return Ok(());
            }
            let wrapped = value.as_object().is_some_and(|o| o.len() == 1 && o.contains_key("some"));
            let value = if wrapped { value.get_mut("some").unwrap() } else { value };
            return visit(value, &o.ty(), path, c, generator, seed, repair);
        }
        Type::Result(r) => {
            let Some(payload) = value.get_mut("ok") else { return Ok(()) };
            return visit(payload, &r.ok().context("missing successful payload type")?, path, c, generator, seed, repair);
        }
        _ => {}
    }
    if let Some(inner) = list_element(ty) {
        if path.is_empty() && matches!(c, Constraint::Len(..) | Constraint::Unique(_)) {
            if repair {
                if let Constraint::Len(Some(min), _) = c {
                    let array = value.as_array_mut().context("expected a list for a length guarantee")?;
                    if array.is_empty() {
                        array.extend((0..*min).map(|_| generator.gen_json(&inner)));
                    }
                }
                if matches!(c, Constraint::Unique(_)) {
                    for element in value.as_array_mut().context("unique guarantee needs a list")? {
                        *element = val_to_json(&json_to_val(element, &inner)?);
                    }
                }
                *value = c.conform(value, seed);
            }
        } else {
            let array = value.as_array_mut().context("expected WIT list")?;
            for element in array {
                if !path.is_empty()
                    && let Type::Tuple(tuple) = &inner
                {
                    let parts: Vec<_> = tuple.types().collect();
                    if parts.len() == 2 && parts[0] == Type::String {
                        if element.get(0).and_then(Value::as_str) == Some(path[0]) {
                            visit(element.get_mut(1).context("expected a key/value pair")?, &parts[1], &path[1..], c, generator, seed, repair)?;
                        }
                        continue;
                    }
                }
                visit(element, &inner, path, c, generator, seed, repair)?;
            }
            return Ok(());
        }
    } else if let Some((head, rest)) = path.split_first() {
        let Type::Record(record) = ty else { bail!("guarantee path does not exist") };
        let field = record.fields().find(|f| f.name == *head).context("unknown guarantee field")?;
        let key = if value.get(field.name).is_some() { field.name.to_string() } else { field.name.replace('-', "_") };
        return visit(value.get_mut(&key).context("guarantee field absent from host response")?, &field.ty, rest, c, generator, seed, repair);
    } else if repair {
        *value = repair_scalar(value, ty, c, seed)?;
    }
    if !c.holds(value) {
        bail!("host response violates platform guarantee {c}");
    }
    Ok(())
}

pub(crate) fn conform_host(value: &mut Value, ty: &Type, constraints: &[(String, Constraint)], seed: u64) -> Result<()> {
    let mut generator = Generator::new(seed, GenOpts::default());
    for (path, c) in constraints.iter().filter(|(_, c)| !matches!(c, Constraint::Unique(_))) {
        visit(value, ty, &segments(path), c, &mut generator, seed, true).with_context(|| format!("values {path:?}: {c}"))?;
    }
    let mut unique: Vec<_> = constraints.iter().filter(|(_, c)| matches!(c, Constraint::Unique(_))).collect();
    unique.sort_by_key(|(path, _)| std::cmp::Reverse(segments(path).len()));
    for (path, c) in unique {
        visit(value, ty, &segments(path), c, &mut generator, seed, true).with_context(|| format!("values {path:?}: {c}"))?;
    }
    let mut normalized = val_to_json(&json_to_val(value, ty)?);
    for (path, c) in constraints {
        visit(&mut normalized, ty, &segments(path), c, &mut generator, seed, false).with_context(|| format!("values {path:?}: {c}"))?;
    }
    Ok(())
}

pub(crate) fn conform_request_typed(args: &mut [Value], app: &crate::harness::App, export: &str, seed: u64) -> Result<()> {
    let Some(entry) = &app.manifest.entry else { return Ok(()) };
    if entry.values.is_empty() || !crate::harness::fn_key_eq(&entry.export, export) {
        return Ok(());
    }
    let (_, ty) = app.export(export)?.ty.params().next().context("request guarantees need an argument")?;
    let request = args.first_mut().context("missing request argument")?;
    let constraints: Vec<_> = entry.values.iter().map(|(path, c)| (path.clone(), c.clone())).collect();
    conform_host(request, &ty, &constraints, seed)
}
