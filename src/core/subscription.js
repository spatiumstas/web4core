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
            const resp = await fetch(u, Object.assign({}, FETCH_INIT, {signal: controller.signal}));
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
        if (/^HTTP\s+\d+/.test(msg)) {
            return msg.replace(/^HTTP\s+/, '').trim();
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

        const attempts = [];
        const direct = isHttpUrl(u) ? await tryFetch(u) : {error: new Error('not-http')};

        if (!direct.error && typeof direct.text === 'string') {
            let probe = direct.text || '';
            const dec = normalizeSubscriptionBody(probe);
            if (dec) probe = dec;
            const lines = splitLines(probe);
            const isSingleHttpPointer = lines.length === 1 && isHttpUrl(lines[0]) && !looksLikeLinksList(lines[0]);
            if (!isSingleHttpPointer && !hasRealSubscriptionLinks(probe)) {
                direct.error = new Error('Subscription returned no valid links');
            }
        }

        attempts.push(direct);
        if (direct.error) {
            for (const makeUrl of PUBLIC_CORS_FALLBACKS) {
                let fallbackSuccess = false;
                for (let retry = 0; retry < SUB_FALLBACK_RETRIES; retry++) {
                    const result = await tryFetch(makeUrl(u));
                    attempts.push(result);
                    if (!result.error) {
                        fallbackSuccess = true;
                        break;
                    }
                    if (retry < SUB_FALLBACK_RETRIES - 1) {
                        await new Promise(resolve => setTimeout(resolve, 500));
                    }
                }
                if (fallbackSuccess) break;
            }
        }

        let lastErr = null;
        for (const a of attempts) {
            if (a && !a.error && a.text) {
                const text = a.text;
                if (isLikelyHtml(text)) {
                    const redir = parseMetaRefresh(text);
                    if (redir) return fetchWithFallback(redir, depth + 1);
                    const extracted = extractLinksFromHtml(text);
                    if (extracted && extracted.length) return extracted.join('\n');
                }
                let body = normalizeSubscriptionBody(text);
                if (isLikelyHtml(body)) {
                    const redir2 = parseMetaRefresh(body);
                    if (redir2) return fetchWithFallback(redir2, depth + 1);
                    const extracted2 = extractLinksFromHtml(body);
                    if (extracted2 && extracted2.length) return extracted2.join('\n');
                }
                if (body) return body;
                lastErr = new Error('Empty response');
            } else if (a && a.error) {
                lastErr = a.error;
            }
        }
        throw new Error(classifyError(lastErr));
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

try {
    if (typeof globalThis !== 'undefined') {
        globalThis.web4core = Object.assign({}, globalThis.web4core || {}, {
            fetchSubscription
        });
    }
} catch {
}


