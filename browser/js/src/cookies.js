// Cookie records belong to the user agent. Never hand them to replaceable
// page collection methods, parsers, serializers or prototype accessors.
const native = globalThis.__native, parseURL = native.url;
const domainMatches = native.cookieDomainMatches, publicSuffix = native.cookiePublicSuffix, site = native.cookieSite;
const NativeMap = Map, string = String, number = Number, finite = Number.isFinite, NativeDate = Date, dateParse = Date.parse;
const create = Object.create, setPrototype = Object.setPrototypeOf, NativeTypeError = TypeError;
const get = Function.prototype.call.bind(Map.prototype.get), put = Function.prototype.call.bind(Map.prototype.set);
const remove = Function.prototype.call.bind(Map.prototype.delete), each = Function.prototype.call.bind(Map.prototype.forEach);
const split = Function.prototype.call.bind(String.prototype.split), slice = Function.prototype.call.bind(String.prototype.slice);
const trim = Function.prototype.call.bind(String.prototype.trim), lower = Function.prototype.call.bind(String.prototype.toLowerCase);
const index = Function.prototype.call.bind(String.prototype.indexOf), lastIndex = Function.prototype.call.bind(String.prototype.lastIndexOf);
const starts = Function.prototype.call.bind(String.prototype.startsWith), ends = Function.prototype.call.bind(String.prototype.endsWith);
const test = Function.prototype.call.bind(RegExp.prototype.test), sort = Function.prototype.call.bind(Array.prototype.sort);
const utcString = Function.prototype.call.bind(Date.prototype.toUTCString);
function address(text) { const parts = parseURL(text, null); if (!parts) throw new NativeTypeError('Invalid cookie URL'); return { protocol: parts[2], hostname: parts[6], pathname: parts[8] }; }
const secure = url => url.protocol === 'https:' || url.protocol === 'wss:';
const pathMatches = (path, scope) => path === scope || (starts(path, scope) && (ends(scope, '/') || path[scope.length] === '/'));
const defaultPath = url => slice(url.pathname, 0, lastIndex(url.pathname, '/')) || '/';
// Length prefixes make keys unambiguous without invoking page JSON hooks.
const cookieKey = (name, domain, path) => `${name.length}:${name}${domain.length}:${domain}${path}`;

export class CookieJar {
  constructor(now) { this.now = now; this.entries = new NativeMap(); this.sequence = 0; }

  request(text, url) {
    const pairs = split(string(text), ';');
    for (let n = 0; n < pairs.length; n++) {
      const pair = pairs[n], i = index(pair, '=');
      if (i > 0) this.seed(trim(slice(pair, 0, i)), trim(slice(pair, i + 1)), url);
    }
  }

  seed(name, input, url) {
    const c = input && typeof input === 'object' ? input : { value: input };
    let text = `${name}=${string(c.value)}; Path=${c.path || '/'}`;
    if (c.domain) text += '; Domain=' + c.domain;
    if (c.secure) text += '; Secure';
    if (c.httpOnly) text += '; HttpOnly';
    if (c.sameSite) text += '; SameSite=' + c.sameSite;
    if (c.expires != null) text += '; Expires=' + utcString(new NativeDate(c.expires));
    return this.set(text, url, true);
  }

  set(text, url, http = false) {
    text = string(text);
    if (test(/[\x00-\x08\x0a-\x1f\x7f]/, text)) return null;
    const parts = split(text, ';'), pair = parts[0], i = index(pair, '=');
    if (i < 1) return null;
    const name = trim(slice(pair, 0, i)), value = trim(slice(pair, i + 1));
    if (!name || test(/[\x00-\x1f\x7f]/, name) || test(/[\x00-\x1f\x7f]/, value)) return null;
    const flags = create(null);
    for (let n = 1; n < parts.length; n++) {
      const part = parts[n], at = index(part, '=');
      flags[lower(trim(at < 0 ? part : slice(part, 0, at)))] = at < 0 ? '' : trim(slice(part, at + 1));
    }
    const u = address(url);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    let domain = lower(u.hostname), hostOnly = true;
    if (flags.domain != null) {
      const raw = lower(flags.domain), wanted = raw[0] === '.' ? slice(raw, 1) : raw;
      if (!wanted || !domainMatches(domain, wanted)) return null;
      if (publicSuffix(wanted)) { if (wanted !== domain) return null; }
      else { domain = wanted; hostOnly = false; }
    }
    const path = flags.path != null && starts(flags.path, '/') ? flags.path : defaultPath(u);
    const httpOnly = 'httponly' in flags, isSecure = 'secure' in flags;
    if ((httpOnly && !http) || (isSecure && !secure(u))) return null;
    let sameSite = lower(string(flags.samesite || 'lax'));
    if (sameSite !== 'none' && sameSite !== 'lax' && sameSite !== 'strict') sameSite = 'lax';
    if (sameSite === 'none' && !isSecure) return null;
    if (starts(name, '__Secure-') && !isSecure) return null;
    if (starts(name, '__Host-') && (!isSecure || flags.domain != null || flags.path !== '/')) return null;
    const key = cookieKey(name, domain, path), old = get(this.entries, key);
    if ((old?.httpOnly && !http) || (old?.secure && !secure(u))) return null;
    let expires = Infinity;
    if (flags.expires != null) { const at = dateParse(flags.expires); if (finite(at)) expires = at; }
    if (flags['max-age'] != null && test(/^-?\d+$/, flags['max-age'])) {
      const age = number(flags['max-age']); expires = age <= 0 ? -Infinity : this.now() + age * 1000;
    }
    if (expires <= this.now()) remove(this.entries, key);
    else put(this.entries, key, { name, value, domain, path, hostOnly, httpOnly, secure: isSecure, sameSite, expires, order: old?.order ?? this.sequence++ });
    return { name, value, flags };
  }

  has(name) { let found = false; each(this.entries, c => { if (c.name === name && c.expires > this.now()) found = true; }); return found; }

  header(url, http = true, top = url) {
    const u = address(url), sameSite = site(url) === site(top), matches = [];
    setPrototype(matches, null);
    each(this.entries, (c, key) => {
      if (c.expires <= this.now()) { remove(this.entries, key); return; }
      if (c.hostOnly ? u.hostname !== c.domain : !domainMatches(u.hostname, c.domain)) return;
      if (!pathMatches(u.pathname, c.path) || (c.secure && !secure(u)) || (!http && c.httpOnly)) return;
      if (http && c.sameSite !== 'none' && !sameSite) return;
      matches[matches.length] = c;
    });
    sort(matches, (a, b) => b.path.length - a.path.length || a.order - b.order);
    let result = '';
    for (let i = 0; i < matches.length; i++) result += (i ? '; ' : '') + matches[i].name + '=' + matches[i].value;
    return result;
  }
}
