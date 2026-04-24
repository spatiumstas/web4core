import {
    decodeBase64Url,
    isHttpUrl,
    SUPPORTED_SCHEMES,
    MAX_SUB_REDIRECTS,
    SUB_FETCH_TIMEOUT,
    SUB_FALLBACK_RETRIES,
    FETCH_INIT,
    PUBLIC_CORS_FALLBACKS
} from '../main.js';

function buildSchemesRegex(flags) {
    const escaped = SUPPORTED_SCHEMES.map(s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|');
    return new RegExp('(?:' + escaped + ')://', flags || 'i');
}

function looksLikeLinksList(text) {
    const t = (text || '').trim();
    if (!t) return false;
    const rx = buildSchemesRegex('i');
    return rx.test(t);
}

function looksLikeJsonContainer(text) {
    const t = String(text || '').trim();
    if (!t) return false;
    return (t.startsWith('{') && t.endsWith('}')) || (t.startsWith('[') && t.endsWith(']'));
}

function normalizeSubscriptionBody(raw) {
    const t = (raw || '').trim();
    if (!t) return '';
    const tryDecode = (s) => {
        const input = String(s || '').trim();
        if (!input) return '';
        const candidates = [];
        const push = (x) => {
            const v = String(x || '');
            if (!v) return;
            if (!candidates.includes(v)) candidates.push(v);
        };
        push(input);
        const m = input.match(/^[A-Za-z0-9+/=_-]+/);
        if (m) push(m[0]);
        const lastEq = input.lastIndexOf('=');
        if (lastEq !== -1 && lastEq < input.length - 1) {
            push(input.slice(0, lastEq + 1));
        }
        for (const cand of candidates) {
            const out = decodeBase64Url(cand);
            if (out) return out;
        }
        return '';
    };
    let body = t;
    const dec1 = tryDecode(t);
    if (dec1 && (looksLikeLinksList(dec1) || dec1.includes('\n') || looksLikeJsonContainer(dec1))) body = dec1;
    if (!looksLikeLinksList(body)) {
        const dec2 = tryDecode(body);
        if (dec2 && (looksLikeLinksList(dec2) || looksLikeJsonContainer(dec2))) body = dec2;
    }
    return body.replace(/\r\n/g, '\n');
}

function isLikelyHtml(s) {
    const t = (s || '').trim().slice(0, 2000).toLowerCase();
    if (!t) return false;
    return t.startsWith('<!doctype html') || t.includes('<html') || t.includes('<head') || t.includes('<body');
}

function parseMetaRefresh(html) {
    const s = (html || '');
    const m = s.match(/<meta[^>]+http-equiv=["']?refresh["']?[^>]*content=["']?\s*\d+\s*;\s*url=([^"'>\s]+)["']?[^>]*>/i);
    return m ? m[1] : '';
}

function extractLinksFromHtml(html) {
    const out = [];
    const addIf = (val) => {
        const v = (val || '').trim();
        if (v) out.push(v);
    };
    try {
        if (typeof DOMParser !== 'undefined') {
            const dp = new DOMParser();
            const doc = dp.parseFromString(html, 'text/html');
            const anchors = doc.querySelectorAll('a[href]');
            anchors.forEach(a => addIf(a.getAttribute('href')));
            const text = doc.body ? doc.body.textContent || '' : '';
            const re = new RegExp(buildSchemesRegex().source + "[^\\s<>\"']+", 'ig');
            let m;
            while ((m = re.exec(text)) !== null) addIf(m[0]);
        } else {
            const reHref = /href=["']([^"']+)["']/ig;
            let m1;
            while ((m1 = reHref.exec(html)) !== null) addIf(m1[1]);
            const re = new RegExp(buildSchemesRegex().source + "[^\\s<>\"']+", 'ig');
            let m2;
            while ((m2 = re.exec(html)) !== null) addIf(m2[0]);
        }
    } catch {
    }
    return out;
}

function filterSubscriptionLinks(items) {
    const out = [];
    const seen = new Set();
    const re = buildSchemesRegex('i');
    for (const item of (Array.isArray(items) ? items : [])) {
        const link = String(item || '').trim();
        if (!link || seen.has(link)) continue;
        if (!re.test(link)) continue;
        seen.add(link);
        out.push(link);
    }
    return out;
}

function extractLinksFromText(raw) {
    const out = [];
    const seen = new Set();
    const text = String(raw || '').replace(/\\\//g, '/');
    const re = new RegExp(buildSchemesRegex().source + "[^\\s<>\"'`,\\\\]+", 'ig');
    let m;
    while ((m = re.exec(text)) !== null) {
        const link = String(m[0] || '').trim();
        if (!link || seen.has(link)) continue;
        seen.add(link);
        out.push(link);
    }
    return out;
}

function extractLinksFromEmbeddedPayload(html) {
    const candidates = [];
    const addCandidate = (val) => {
        const s = String(val || '').trim();
        if (!s || s.length < 64 || s.length > 2_000_000) return;
        if (/[^A-Za-z0-9+/=_-]/.test(s)) return;
        if (!candidates.includes(s)) candidates.push(s);
    };

    const addLinksFrom = (source, out, seen) => {
        const links = extractLinksFromText(source);
        for (const link of links) {
            if (seen.has(link)) continue;
            seen.add(link);
            out.push(link);
        }
    };

    const htmlText = String(html || '');
    let m;
    const reDataAttr = /data-[\w:-]+=["']([^"']{64,})["']/ig;
    while ((m = reDataAttr.exec(htmlText)) !== null) addCandidate(m[1]);

    const reAtob = /atob\((['"])([A-Za-z0-9+/=_-]{64,})\1\)/ig;
    while ((m = reAtob.exec(htmlText)) !== null) addCandidate(m[2]);

    const reQuotedB64 = /['"]([A-Za-z0-9+/=_-]{160,})['"]/g;
    while ((m = reQuotedB64.exec(htmlText)) !== null) addCandidate(m[1]);

    const out = [];
    const seen = new Set();
    for (const candidate of candidates) {
        const decoded = decodeBase64Url(candidate) || '';
        if (!decoded) continue;
        addLinksFrom(decoded, out, seen);
        const nested = normalizeSubscriptionBody(decoded);
        if (nested && nested !== decoded) addLinksFrom(nested, out, seen);
    }
    return out;
}

function httpReason(status) {
    const map = {
        400: 'Bad Request',
        403: 'Forbidden',
        404: 'Not Found',
        408: 'Request Timeout',
        429: 'Too Many Requests',
        500: 'Internal Server Error',
        502: 'Bad Gateway',
        503: 'Service Unavailable',
        504: 'Gateway Timeout'
    };
    return map[status] || '';
}

async function fetchSubscription(url) {
    if (typeof fetch !== 'function') throw new Error('Fetch API not available');

    const allowedSchemes = new Set(SUPPORTED_SCHEMES.filter(s => s !== 'http' && s !== 'https'));
    const splitLines = (text) => (text || '').split(/\n/).map(s => s.trim()).filter(Boolean);
    const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));
    const isBrowser = (typeof window !== 'undefined') && (typeof window.document !== 'undefined');

    function hasRealSubscriptionLinks(text) {
        const lines = splitLines(text);
        if (!lines.length) return false;
        return lines.some(line => {
            const scheme = (line.split(':', 1)[0] || '').toLowerCase();
            return allowedSchemes.has(scheme);
        });
    }

    async function tryFetch(u) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), SUB_FETCH_TIMEOUT);
        try {
            const headers = new Headers((FETCH_INIT && FETCH_INIT.headers) ? FETCH_INIT.headers : {});
            if (!headers.has('Accept')) headers.set('Accept', 'text/plain, */*');
            if (!isBrowser) {
                if (/github\.com|raw\.githubusercontent\.com/i.test(u)) {
                    headers.set('Referer', 'https://github.com/');
                }
            }

            const resp = await fetch(u, Object.assign({}, FETCH_INIT, { headers, signal: controller.signal }));
            if (!resp.ok) {
                const reason = resp.statusText || httpReason(resp.status) || '';
                const label = 'HTTP ' + resp.status + (reason ? (' ' + reason) : '');
                return {error: new Error(label)};
            }
            const text = await resp.text();
            return {text};
        } catch (e) {
            return {error: e};
        } finally {
            clearTimeout(timeoutId);
        }
    }

    function classifyError(err) {
        const msg = (err && err.message) ? err.message : '';
        const http = msg.match(/^HTTP\s+(\d+)(?:\s+(.+))?/);
        if (http) {
            const code = parseInt(http[1], 10);
            const reason = (http[2] || '').trim();
            if (code === 403) return '403 Forbidden (upstream blocked subscription fetch; retry usually helps)';
            if (code === 429) return '429 Too Many Requests (rate-limited; retry later)';
            return String(code) + (reason ? (' ' + reason) : '');
        }
        if (msg.includes('aborted') || msg.includes('abort') || msg.includes('timeout')) {
            return 'Request timeout (15s)';
        }
        if (msg.includes('NetworkError') || msg.includes('Failed to fetch') || msg.includes('Network request failed')) {
            return 'Network error, check connection';
        }
        if (msg.includes('Subscription returned no valid links')) {
            return 'Subscription returned no valid links';
        }
        return 'CORS error, using fallback proxy';
    }

    async function fetchWithFallback(u, depth) {
        if (depth > MAX_SUB_REDIRECTS) throw new Error('Too many redirects');

        const handleResponse = async (text) => {
            if (!text || typeof text !== 'string') return null;
            let probe = text;

            const resolveHtmlProbe = async () => {
                if (!isLikelyHtml(probe)) return null;
                const redir = parseMetaRefresh(probe);
                if (redir) return await fetchWithFallback(redir, depth + 1);
                const extracted = filterSubscriptionLinks(extractLinksFromHtml(probe));
                if (extracted.length) return extracted.join('\n');
                const embedded = extractLinksFromEmbeddedPayload(probe);
                if (embedded.length) return embedded.join('\n');
                return null;
            };

            const htmlPass1 = await resolveHtmlProbe();
            if (htmlPass1) return htmlPass1;

            const dec = normalizeSubscriptionBody(probe);
            if (dec) probe = dec;

            const htmlPass2 = await resolveHtmlProbe();
            if (htmlPass2) return htmlPass2;

            if (hasRealSubscriptionLinks(probe)) return probe;

            const extractedGeneric = extractLinksFromText(probe);
            if (extractedGeneric.length) return extractedGeneric.join('\n');

            const maybeUrl = splitLines(probe);
            if (maybeUrl.length === 1 && isHttpUrl(maybeUrl[0])) return maybeUrl[0];

            return null;
        };

        const consumeFetchResult = async (result) => {
            if (result.error || typeof result.text !== 'string') return null;
            return await handleResponse(result.text);
        };

        const direct = isHttpUrl(u) ? await tryFetch(u) : {error: new Error('not-http')};

        const directResolved = await consumeFetchResult(direct);
        if (directResolved) return directResolved;
        if (!direct.error) {
            direct.error = new Error('Subscription returned no valid links');
        }

        if (!isBrowser) {
            throw new Error(classifyError(direct.error || new Error('Fetch failed')));
        }

        if (direct.error) {
            if (/^HTTP\s+(403|429|5\d\d)/.test(String(direct.error.message || ''))) {
                await sleep(350);
                const retry = await tryFetch(u);
                const retryResolved = await consumeFetchResult(retry);
                if (retryResolved) return retryResolved;
            }

            for (const makeUrl of PUBLIC_CORS_FALLBACKS) {
                const maxRetries = Math.max(0, Number(SUB_FALLBACK_RETRIES || 0));
                for (let retry = 0; retry <= maxRetries; retry++) {
                    const result = await tryFetch(makeUrl(u));
                    const resolved = await consumeFetchResult(result);
                    if (resolved) return resolved;
                    if (result.error && retry < maxRetries) {
                        await sleep(500);
                    }
                }
            }
        }

        throw new Error(classifyError(direct.error));
    }

    let body = await fetchWithFallback(url, 0);
    if (!body) throw new Error('Empty response');
    {
        const cand = body.split(/\n/).map(s => s.trim()).filter(Boolean);
        if (cand.length === 1 && isHttpUrl(cand[0]) && !looksLikeLinksList(cand[0])) {
            body = await fetchWithFallback(cand[0], 1);
        }
    }
    if (/\bproxies\s*:/i.test(body) && !looksLikeLinksList(body)) throw new Error('Clash YAML subscription is not supported here');
    const lines = splitLines(body);
    const filtered = lines.filter(line => allowedSchemes.has((line.split(':', 1)[0] || '').toLowerCase()));
    return filtered.join('\n');
}

export {
    fetchSubscription
};


