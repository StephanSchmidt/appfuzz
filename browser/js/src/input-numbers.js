// Input numeric/date conversions use private values and captured intrinsics.
// Gregorian arithmetic is independent of Date's representable time range:
// Date objects are fresh and obey JavaScript's separate TimeClip limit.
import { controlValue, setControlValue } from './control-values.js';
import { htmlName, controlType } from './controls.js';
import { inputNumber } from './input-domains.js';
import { runDOMCallback } from './dom-callbacks.js';
const NativeDate = Date, NativeTypeError = TypeError;
const dateTime = Function.call.bind(Date.prototype.getTime);
const exec = Function.call.bind(RegExp.prototype.exec), slice = Function.call.bind(String.prototype.slice);
const num = Number, str = String, bigint = BigInt, floor = Math.floor, abs = Math.abs;
const define = Object.defineProperty;
const DAY = 86400000n, EPOCH = 719162n;
const DATE = /^([0-9]+)-([0-9]{2})-([0-9]{2})/;
const MONTH = /^([0-9]+)-([0-9]{2})$/;
const WEEK = /^([0-9]+)-W([0-9]{2})$/;
const TIME = /^([0-9]{2}):([0-9]{2})(?::([0-9]{2})(?:\.([0-9]{1,3}))?)?$/;
const LOCAL = /^([0-9]+-[0-9]{2}-[0-9]{2})T([0-9:.]+)$/;
function numeric(type) { return type === 'number' || type === 'range' || dateType(type) || type === 'datetime-local'; }
function dateType(type) { return type === 'date' || type === 'month' || type === 'week' || type === 'time'; }
function check(node) { if (htmlName(node) !== 'input') throw new NativeTypeError('An HTMLInputElement is required'); }
function divide(a, b) { const q = a / b; return a % b < 0n ? q - 1n : q; }
function modulo(a, b) { const r = a % b; return r < 0n ? r + b : r; }
function beforeYear(year) { const previous = year - 1n; return previous * 365n + previous / 4n - previous / 100n + previous / 400n; }
function leap(year) { return year % 4n === 0n && (year % 100n !== 0n || year % 400n === 0n); }
function monthDays(year, month) { return month === 2 ? leap(year) ? 29 : 28 : month === 4 || month === 6 || month === 9 || month === 11 ? 30 : 31; }
function dayNumber(year, month, day) {
  let result = beforeYear(year) - EPOCH + bigint(day - 1);
  for (let i = 1; i < month; i++) result += bigint(monthDays(year, i));
  return result;
}
function dateDay(value) { const m = exec(DATE, value); return dayNumber(bigint(m[1]), num(m[2]), num(m[3])); }
function monday(year) { const fourth = beforeYear(year) - EPOCH + 3n; return fourth - modulo(fourth + 3n, 7n); }
function timeNumber(value) {
  const m = exec(TIME, value); let fraction = m[4] || '';
  while (fraction.length < 3) fraction += '0';
  return num(m[1]) * 3600000 + num(m[2]) * 60000 + num(m[3] || 0) * 1000 + num(fraction);
}
export function numericInputValue(type, value, asDate = false) {
  if (value === '') return NaN;
  if (type === 'number' || type === 'range') return inputNumber(value) ?? NaN;
  if (type === 'month') {
    const m = exec(MONTH, value), year = bigint(m[1]), month = num(m[2]);
    return num(asDate ? dayNumber(year, month, 1) * DAY : (year - 1970n) * 12n + bigint(month - 1));
  }
  if (type === 'date') return num(dateDay(value) * DAY);
  if (type === 'week') { const m = exec(WEEK, value); return num((monday(bigint(m[1])) + bigint(num(m[2]) - 1) * 7n) * DAY); }
  if (type === 'time') return timeNumber(value);
  if (type === 'datetime-local') { const m = exec(LOCAL, value); return num(dateDay(m[1]) * DAY + bigint(timeNumber(m[2]))); }
  return NaN;
}
function civil(day) {
  const absolute = day + EPOCH; if (absolute < 0n) return null;
  const era = absolute / 146097n, within = num(absolute % 146097n);
  let low = 0, high = 400;
  while (low + 1 < high) {
    const middle = floor((low + high) / 2), start = middle * 365 + floor(middle / 4) - floor(middle / 100) + floor(middle / 400);
    if (start <= within) low = middle; else high = middle;
  }
  const year = era * 400n + bigint(low + 1);
  let remaining = within - (low * 365 + floor(low / 4) - floor(low / 100) + floor(low / 400)), month = 1;
  while (remaining >= monthDays(year, month)) remaining -= monthDays(year, month++);
  return { year, month, day: remaining + 1 };
}
function pad(value, width) { let result = str(value); while (result.length < width) result = '0' + result; return result; }
function monthText(year, month) { return pad(year, 4) + '-' + pad(month, 2); }
function dateText(date) { return monthText(date.year, date.month) + '-' + pad(date.day, 2); }
function timeText(value, shortest = false) {
  const hours = floor(value / 3600000), minutes = floor(value / 60000) % 60, seconds = floor(value / 1000) % 60, milliseconds = value % 1000;
  let result = pad(hours, 2) + ':' + pad(minutes, 2);
  if (seconds || milliseconds) result += ':' + pad(seconds, 2);
  if (milliseconds) { let fraction = pad(milliseconds, 3); while (shortest && fraction[fraction.length - 1] === '0') fraction = slice(fraction, 0, -1); result += '.' + fraction; }
  return result;
}
function roundAway(value) { const magnitude = abs(value), base = floor(magnitude), rounded = magnitude - base >= 0.5 ? base + 1 : base; return value < 0 ? -rounded : rounded; }
function weekText(day) {
  const thursday = day + 3n - modulo(day + 3n, 7n), date = civil(thursday);
  if (!date) return '';
  const week = (day - monday(date.year)) / 7n + 1n;
  return pad(date.year, 4) + '-W' + pad(week, 2);
}
export function formatNumericInput(type, value) {
  if (value !== value) return '';
  if (type === 'number' || type === 'range') return str(value);
  if (type === 'month') {
    const months = bigint(roundAway(value)), year = 1970n + divide(months, 12n);
    return year > 0n ? monthText(year, num(modulo(months, 12n)) + 1) : '';
  }
  const milliseconds = bigint(type === 'datetime-local' ? roundAway(value) : floor(value));
  if (type === 'time') return timeText(num(modulo(milliseconds, DAY)));
  const day = divide(milliseconds, DAY);
  if (type === 'week') return weekText(day);
  const date = civil(day); if (!date) return '';
  if (type === 'date') return dateText(date);
  if (type === 'datetime-local') return dateText(date) + 'T' + timeText(num(modulo(milliseconds, DAY)), true);
  return '';
}
function formatDateInput(type, value) {
  if (value !== value) return '';
  if (type === 'month') { const date = civil(divide(bigint(value), DAY)); return date ? monthText(date.year, date.month) : ''; }
  return formatNumericInput(type, value);
}
export function installNumericProperties(L, DOMError) {
  define(L.HTMLInputElement.prototype, 'valueAsNumber', { configurable: true, enumerable: true,
    get() { check(this); const type = controlType(this); return numeric(type) ? numericInputValue(type, controlValue(this)) : NaN; },
    set(raw) {
      check(this); const value = runDOMCallback(() => +raw);
      if (value === Infinity || value === -Infinity) throw new NativeTypeError('A finite number is required');
      const type = controlType(this); if (!numeric(type)) throw new DOMError('This input has no numeric value', 'InvalidStateError');
      setControlValue(this, formatNumericInput(type, value));
    },
  });
  define(L.HTMLInputElement.prototype, 'valueAsDate', { configurable: true, enumerable: true,
    get() {
      check(this); const type = controlType(this); if (!dateType(type)) return null;
      const value = controlValue(this); return value === '' ? null : new NativeDate(numericInputValue(type, value, true));
    },
    set(raw) {
      check(this);
      if (raw != null && typeof raw !== 'object' && typeof raw !== 'function') throw new NativeTypeError('A Date object is required');
      const type = controlType(this); if (!dateType(type)) throw new DOMError('This input has no Date value', 'InvalidStateError');
      const value = raw == null ? NaN : dateTime(raw);
      setControlValue(this, formatDateInput(type, value));
    },
  });
}
