// A page's cookies: HTTP and script access share one jar, with the
// attributes a Cookie request header alone cannot carry.
import { parse } from 'tldts';

const domainInfo = (host) => parse(host, { allowPrivateDomains: true });
const secure = (url) => url.protocol === 'https:' || url.protocol === 'wss:';
const site = (url) => `${url.protocol.replace(/^ws/, 'http')}//${domainInfo(url.hostname).domain || url.hostname}`;
const domainMatches = (host, domain) => host === domain || (!domainInfo(host).isIp && host.endsWith('.' + domain));
const pathMatches = (path, scope) => path === scope || (path.startsWith(scope) && (scope.endsWith('/') || path[scope.length] === '/'));
const defaultPath = (url) => url.pathname.slice(0, url.pathname.lastIndexOf('/')) || '/';

export class CookieJar {
  constructor(now) {
    this.now = now;
    this.entries = new Map();
    this.sequence = 0;
  }

  // Initial Cookie headers have no attributes. Their pairs are already
  // applicable to the page; the model uses host-only, root-path cookies.
  request(text, url) {
    for (const pair of String(text).split(';')) {
      const i = pair.indexOf('=');
      if (i > 0) this.seed(pair.slice(0, i).trim(), pair.slice(i + 1).trim(), url);
    }
  }

  // The native guest also accepts the original {name: value|{value,
  // httpOnly}} input, with optional path/domain/secure/sameSite attributes.
  seed(name, input, url) {
    const c = input && typeof input === 'object' ? input : { value: input };
    let text = `${name}=${String(c.value)}; Path=${c.path || '/'}`;
    if (c.domain) text += '; Domain=' + c.domain;
    if (c.secure) text += '; Secure';
    if (c.httpOnly) text += '; HttpOnly';
    if (c.sameSite) text += '; SameSite=' + c.sameSite;
    if (c.expires != null) text += '; Expires=' + new Date(c.expires).toUTCString();
    return this.set(text, url, true);
  }

  set(text, url, http = false) {
    const parts = String(text).split(';');
    const pair = parts.shift();
    const i = pair.indexOf('=');
    if (i < 1) return null;
    const name = pair.slice(0, i).trim();
    const value = pair.slice(i + 1).trim();
    if (!name || /[\x00-\x20\x7f()<>@,;:\\"/\[\]?={}]/.test(name) || /[\x00-\x1f\x7f]/.test(value)) return null;
    const flags = {};
    for (const part of parts) {
      const at = part.indexOf('=');
      flags[(at < 0 ? part : part.slice(0, at)).trim().toLowerCase()] = at < 0 ? '' : part.slice(at + 1).trim();
    }
    const u = new URL(url);
    if (!['http:', 'https:'].includes(u.protocol)) return null;
    let domain = u.hostname.toLowerCase();
    let hostOnly = true;
    if (flags.domain != null) {
      const wanted = flags.domain.replace(/^\./, '').toLowerCase();
      if (!wanted || !domainMatches(domain, wanted)) return null;
      // A public suffix cannot be shared across its tenants, including
      // private suffixes such as github.io.
      if (domainInfo(wanted).publicSuffix === wanted) {
        if (wanted !== domain) return null;
      } else {
        domain = wanted;
        hostOnly = false;
      }
    }
    const path = flags.path?.startsWith('/') ? flags.path : defaultPath(u);
    const httpOnly = 'httponly' in flags;
    const isSecure = 'secure' in flags;
    if ((httpOnly && !http) || (isSecure && !secure(u))) return null;
    let sameSite = String(flags.samesite || 'lax').toLowerCase();
    if (!['none', 'lax', 'strict'].includes(sameSite)) sameSite = 'lax';
    if (sameSite === 'none' && !isSecure) return null;
    if (name.startsWith('__Secure-') && !isSecure) return null;
    if (name.startsWith('__Host-') && (!isSecure || flags.domain != null || flags.path !== '/')) return null;
    const key = JSON.stringify([name, domain, path]);
    const old = this.entries.get(key);
    if ((old?.httpOnly && !http) || (old?.secure && !secure(u))) return null;
    let expires = Infinity;
    if (flags.expires != null) {
      const at = Date.parse(flags.expires);
      if (Number.isFinite(at)) expires = at;
    }
    // Max-Age takes precedence irrespective of attribute order.
    if (flags['max-age'] != null && /^-?\d+$/.test(flags['max-age'])) {
      const age = Number(flags['max-age']);
      expires = age <= 0 ? -Infinity : this.now() + age * 1000;
    }
    if (expires <= this.now()) this.entries.delete(key);
    else this.entries.set(key, { name, value, domain, path, hostOnly, httpOnly, secure: isSecure, sameSite, expires, order: old?.order ?? this.sequence++ });
    return { name, value, flags };
  }

  has(name) {
    return [...this.entries.values()].some((c) => c.name === name && c.expires > this.now());
  }

  header(url, http = true, top = url) {
    const u = new URL(url);
    const sameSite = site(u) === site(new URL(top));
    const matches = [];
    for (const [key, c] of this.entries) {
      if (c.expires <= this.now()) { this.entries.delete(key); continue; }
      if (c.hostOnly ? u.hostname !== c.domain : !domainMatches(u.hostname, c.domain)) continue;
      if (!pathMatches(u.pathname, c.path) || (c.secure && !secure(u)) || (!http && c.httpOnly)) continue;
      if (http && c.sameSite !== 'none' && !sameSite) continue;
      matches.push(c);
    }
    matches.sort((a, b) => b.path.length - a.path.length || a.order - b.order);
    return matches.map((c) => `${c.name}=${c.value}`).join('; ');
  }
}
