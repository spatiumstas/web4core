import {
    decodeBase64Url,
    isHttpUrl,
    parseUrl,
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

function normalizeSubscriptionBody(raw) {
    const t = (raw || '').trim();
    if (!t) return '';
    const tryDecode = (s) => {
        try {
            return decodeBase64Url(s);
        } catch {
            return '';
        }
    };
    let body = t;
    const dec1 = tryDecode(t);
    if (dec1 && (looksLikeLinksList(dec1) || dec1.includes('\n'))) body = dec1;
    if (!looksLikeLinksList(body)) {
        const dec2 = tryDecode(body);
        if (dec2 && looksLikeLinksList(dec2)) body = dec2;
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
        const timeout = setTimeout(() => controller.abort(), SUB_FETCH_TIMEOUT);
        try {
            const headers = new Headers((FETCH_INIT && FETCH_INIT.headers) ? FETCH_INIT.headers : {});
            if (!headers.has('Accept')) headers.set('Accept', 'text/plain, */*');
            if (!isBrowser) {
                headers.set('User-Agent', 'web4core (subscription fetch)');
                if (/github\.com|raw\.githubusercontent\.com/i.test(u)) {
                    headers.set('Referer', 'https://github.com/');
                }
            }

            const resp = await fetch(u, Object.assign({}, FETCH_INIT, { headers, signal: controller.signal }));
            clearTimeout(timeout);
            if (!resp.ok) {
                const reason = resp.statusText || httpReason(resp.status) || '';
                const label = 'HTTP ' + resp.status + (reason ? (' ' + reason) : '');
                return {error: new Error(label)};
            }
            const text = await resp.text();
            return {text};
        } catch (e) {
            clearTimeout(timeout);
            return {error: e};
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
        return 'CORS error, using fallback proxy';
    }

    async function fetchWithFallback(u, depth) {
        if (depth > MAX_SUB_REDIRECTS) throw new Error('Too many redirects');

        const handleResponse = async (text) => {
            if (!text || typeof text !== 'string') return null;
            let probe = text;

            if (isLikelyHtml(probe)) {
                const redir = parseMetaRefresh(probe);
                if (redir) return await fetchWithFallback(redir, depth + 1);
                const extracted = extractLinksFromHtml(probe);
                if (extracted && extracted.length) return extracted.join('\n');
            }

            const dec = normalizeSubscriptionBody(probe);
            if (dec) probe = dec;

            if (isLikelyHtml(probe)) {
                const redir2 = parseMetaRefresh(probe);
                if (redir2) return await fetchWithFallback(redir2, depth + 1);
                const extracted2 = extractLinksFromHtml(probe);
                if (extracted2 && extracted2.length) return extracted2.join('\n');
            }

            if (hasRealSubscriptionLinks(probe)) return probe;

            return probe;
        };

        const attempts = [];
        const direct = isHttpUrl(u) ? await tryFetch(u) : {error: new Error('not-http')};
        attempts.push(direct);

        if (!direct.error && typeof direct.text === 'string') {
            const res = await handleResponse(direct.text);
            if (res) return res;
            direct.error = new Error('Subscription returned no valid links');
        }

        if (!isBrowser) {
            throw new Error(classifyError(direct.error || new Error('Fetch failed')));
        }

        if (direct.error) {
            if (/^HTTP\s+(403|429|5\d\d)/.test(String(direct.error.message || ''))) {
                await new Promise(resolve => setTimeout(resolve, 350));
                const retry = await tryFetch(u);
                attempts.push(retry);
                if (!retry.error) {
                    const res = await handleResponse(retry.text);
                    if (res) return res;
                }
            }

            for (const makeUrl of PUBLIC_CORS_FALLBACKS) {
                const maxRetries = 1;
                for (let retry = 0; retry <= maxRetries; retry++) {
                    const result = await tryFetch(makeUrl(u));
                    attempts.push(result);
                    if (!result.error) {
                        const res = await handleResponse(result.text);
                        if (res) return res;
                    }
                    if (result.error && retry < maxRetries) {
                        await new Promise(resolve => setTimeout(resolve, 500));
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


