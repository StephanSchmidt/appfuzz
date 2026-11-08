// HTML input value sanitization. Keep the parsers and arithmetic private:
// page replacements of Number, RegExp.exec, Math or String must not change
// the values a native control accepts or submits.
import { eventAttribute } from './dom-state.js';
const num = Number, str = String, bigint = BigInt, finite = Number.isFinite;
const exec = Function.call.bind(RegExp.prototype.exec);
const slice = Function.call.bind(String.prototype.slice);
const floor = Math.floor, min = Math.min;
const FLOAT = /^-?(?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$/;
const DECIMAL = /^(-?)([0-9]+)(?:\.([0-9]+))?(?:e([+-]?[0-9]+))?$/;
const DATE = /^([0-9]{4,})-([0-9]{2})-([0-9]{2})$/;
const MONTH = /^([0-9]{4,})-([0-9]{2})$/;
const WEEK = /^([0-9]{4,})-W([0-9]{2})$/;
const TIME = /^([0-9]{2}):([0-9]{2})(?::([0-9]{2})(?:\.([0-9]{1,3}))?)?$/;
const DATETIME = /^([0-9]{4,}-[0-9]{2}-[0-9]{2})[T ]([0-9:.]+)$/;
function full(pattern, value) {
  const result = exec(pattern, value);
  // JavaScript's $ also matches before a final newline, which HTML forbids.
  return result && result[0].length === value.length ? result : null;
}
export function inputNumber(value) {
  if (value === null || !full(FLOAT, value)) return null;
  const result = num(value); return finite(result) ? result : null;
}
function decimal(value) {
  const parts = exec(DECIMAL, str(value)), fraction = parts[3] || '';
  return { coefficient: bigint(parts[1] + parts[2] + fraction), exponent: num(parts[4] || 0) - fraction.length };
}
function scale(value, exponent) { return value.coefficient * 10n ** bigint(value.exponent - exponent); }
function floorDiv(a, b) { const q = a / b; return a % b < 0n ? q - 1n : q; }
function rangeValue(node, value) {
  const declaredMin = inputNumber(eventAttribute(node, 'min'));
  const lower = declaredMin ?? 0, upper = inputNumber(eventAttribute(node, 'max')) ?? 100;
  let current = inputNumber(value);
  if (current === null) current = upper < lower ? lower : lower / 2 + upper / 2;
  if (current < lower) current = lower;
  if (current > upper) current = upper;
  if (upper < lower) return str(lower);
  const stepText = eventAttribute(node, 'step');
  if (stepText && full(/^[aA][nN][yY]$/, stepText)) return str(current);
  const declaredStep = inputNumber(stepText), step = declaredStep !== null && declaredStep > 0 ? declaredStep : 1;
  const base = declaredMin ?? inputNumber(eventAttribute(node, 'value')) ?? 0;
  // Work on the decimal values represented by the doubles. Floating point
  // remainder loses ties such as 0.15 on a 0.1 grid and leaks long artifacts
  // into submitted values. The common exponent is bounded by finite doubles.
  const v = decimal(current), b = decimal(base), s = decimal(step), lo = decimal(lower), hi = decimal(upper);
  const exponent = min(v.exponent, b.exponent, s.exponent, lo.exponent, hi.exponent);
  const V = scale(v, exponent), B = scale(b, exponent), S = scale(s, exponent), L = scale(lo, exponent), H = scale(hi, exponent);
  const below = B + floorDiv(V - B, S) * S, above = below + S;
  const belowValid = below >= L && below <= H, aboveValid = above >= L && above <= H;
  let chosen;
  if (belowValid && aboveValid) chosen = V - below < above - V ? below : above;
  else if (belowValid) chosen = below;
  else if (aboveValid) chosen = above;
  else return str(current); // No step-aligned value exists in the range.
  return str(num(str(chosen) + 'e' + exponent));
}
// Calendar validity is independent of Date's TimeClip limit. A 400-year
// residue suffices for Gregorian leap years and ISO week counts; accumulate
// it without rounding very long positive year spellings through Number.
function yearResidue(value) {
  let residue = 0, positive = false;
  for (let i = 0; i < value.length; i++) { const digit = num(value[i]); residue = (residue * 10 + digit) % 400; if (digit) positive = true; }
  return positive ? residue : -1;
}
function leap(year) { return year % 4 === 0 && (year % 100 !== 0 || year === 0); }
function validDate(value) {
  const m = full(DATE, value); if (!m) return false;
  const year = yearResidue(m[1]), month = num(m[2]), day = num(m[3]);
  if (year < 0 || month < 1 || month > 12 || day < 1) return false;
  const days = month === 2 ? (leap(year) ? 29 : 28) : (month === 4 || month === 6 || month === 9 || month === 11 ? 30 : 31);
  return day <= days;
}
function validMonth(value) { const m = full(MONTH, value); return !!m && yearResidue(m[1]) >= 0 && num(m[2]) >= 1 && num(m[2]) <= 12; }
function validWeek(value) {
  const m = full(WEEK, value); if (!m) return false;
  const year = yearResidue(m[1]), week = num(m[2]); if (year < 0 || week < 1 || week > 53) return false;
  const previous = (year + 399) % 400;
  const january = (1 + previous * 365 + floor(previous / 4) - floor(previous / 100) + floor(previous / 400)) % 7;
  return week <= (january === 4 || january === 3 && leap(year) ? 53 : 52);
}
function timeParts(value) {
  const m = full(TIME, value);
  return m && num(m[1]) < 24 && num(m[2]) < 60 && (!m[3] || num(m[3]) < 60) ? m : null;
}
function localDateTime(value) {
  const parts = full(DATETIME, value); if (!parts || !validDate(parts[1])) return '';
  const t = timeParts(parts[2]); if (!t) return '';
  let fraction = t[4] || '';
  while (fraction.length && fraction[fraction.length - 1] === '0') fraction = slice(fraction, 0, -1);
  return parts[1] + 'T' + t[1] + ':' + t[2] + (num(t[3] || 0) || fraction ? ':' + t[3] + (fraction ? '.' + fraction : '') : '');
}
export function sanitizeInputDomain(node, type, value) {
  if (type === 'number') return inputNumber(value) === null ? '' : value;
  if (type === 'range') return rangeValue(node, value);
  if (type === 'date') return validDate(value) ? value : '';
  if (type === 'month') return validMonth(value) ? value : '';
  if (type === 'week') return validWeek(value) ? value : '';
  if (type === 'time') return timeParts(value) ? value : '';
  if (type === 'datetime-local') return localDateTime(value);
  return value;
}
export function representativeInputValue(type) {
  if (type === 'number') return '1';
  if (type === 'date') return '2024-01-01';
  if (type === 'month') return '2024-01';
  if (type === 'week') return '2024-W01';
  if (type === 'time') return '12:00';
  if (type === 'datetime-local') return '2024-01-01T12:00';
  return 'x';
}
