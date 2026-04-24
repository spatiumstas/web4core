function decodeBase64Url(input) {
    try {
        const s = input.replace(/-/g, '+').replace(/_/g, '/');
        const pad = s.length % 4 === 2 ? '==' : s.length % 4 === 3 ? '=' : '';
        return atob(s + pad);
    } catch {
        return '';
    }
}

function safeDecodeURIComponent(input) {
    const s = (input ?? '').toString();
    if (!s) return '';
    try {
        return decodeURIComponent(s);
    } catch {
        return s;
    }
}

function tryJSON(s) {
    try {
        return JSON.parse(s);
    } catch {
        return null;
    }
}

function takeBase64Prefix(s) {
    const t = String(s || '').trim();
    if (!t) return '';
    const m = t.match(/^[A-Za-z0-9+/=_-]+/);
    return m ? m[0] : t;
}

function isHttpUrl(s) {
    try {
        const u = parseUrl((s || '').trim());
        return u.protocol === 'http:' || u.protocol === 'https:';
    } catch {
        return false;
    }
}

function parseUrl(urlStr) {
    const raw = (urlStr || '').trim();
    if (!raw) throw new Error('Invalid URL');
    if (typeof globalThis !== 'undefined' && typeof globalThis.parseUri === 'function') {
        const parsed = globalThis.parseUri(raw, 'default');
        const qp = parsed.queryParams || new URLSearchParams(parsed.query ? ('?' + parsed.query) : '');
        const scheme = (parsed.protocol || raw.split(':', 1)[0] || '').toLowerCase();
        return {
            href: parsed.href || raw,
            protocol: parsed.protocol ? (parsed.protocol + ':') : (scheme ? (scheme + ':') : ''),
            hostname: parsed.hostname || '',
            port: parsed.port || '',
            username: parsed.username || '',
            password: parsed.password || '',
            hash: parsed.fragment ? ('#' + parsed.fragment) : '',
            searchParams: qp
        };
    }
    if (typeof URL === 'function') {
        const u = new URL(raw);
        return {
            href: u.href,
            protocol: u.protocol,
            hostname: u.hostname,
            port: u.port,
            username: u.username,
            password: u.password,
            hash: u.hash,
            searchParams: u.searchParams
        };
    }
    throw new Error('URL parser not available');
}

const SUPPORTED_SCHEMES = [
    'vmess',
    'vless',
    'trojan',
    'anytls',
    'ss',
    'socks',
    'socks4',
    'socks4a',
    'socks5',
    'socks5h',
    'http',
    'https',
    'hy2',
    'hysteria2',
    'tuic',
    'tt',
    'mieru',
    'mierus',
    'sdns',
    'masque'
];
const MAX_SUB_REDIRECTS = 2;
const SUB_FETCH_TIMEOUT = 15000;
const PROXY_FETCH_INTERVAL = 300;
const SUB_REFRESH_INTERVAL = 43200;
const SUB_FALLBACK_RETRIES = 2;
const URLTEST_LOGO_GOOGLE = '<svg viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="10" fill="#fff"/><path d="M16.98 10.2c0-.43-.04-.75-.13-1.09H10v2.14h4.02c-.08.53-.5 1.33-1.44 1.86l-.01.07 2.09 1.58.14.01c1.26-1.13 2.18-2.79 2.18-4.57Z" fill="#4285F4"/><path d="M10 17.2c1.97 0 3.63-.64 4.84-1.74l-2.31-1.76c-.62.42-1.46.71-2.53.71-1.93 0-3.57-1.25-4.15-2.98l-.07.01-2.17 1.64-.02.07A7.31 7.31 0 0 0 10 17.2Z" fill="#34A853"/><path d="M5.85 11.43A4.3 4.3 0 0 1 5.61 10c0-.5.09-.99.23-1.43l-.01-.1-2.2-1.67-.07.03A7.15 7.15 0 0 0 2.8 10c0 1.14.28 2.22.76 3.17l2.29-1.74Z" fill="#FBBC05"/><path d="M10 5.59c1.34 0 2.25.57 2.77 1.05l2.02-1.93C13.62 3.65 11.97 2.8 10 2.8a7.31 7.31 0 0 0-6.44 3.85l2.28 1.72C6.43 6.84 8.07 5.59 10 5.59Z" fill="#EA4335"/></svg>';
const URLTEST_LOGO_CLOUDFLARE = '<svg viewBox="0 0 20 20" aria-hidden="true"><rect width="20" height="20" rx="10" fill="#fff" fill-opacity="0"/><path d="M14.18 11.17a2.22 2.22 0 0 0-2.18-2.61 3.02 3.02 0 0 0-5.76-.5 1.84 1.84 0 0 0-1.83 1.84c0 .14.02.27.05.4A1.78 1.78 0 0 0 5.3 13.8h8.58a1.32 1.32 0 0 0 .3-2.63Z" fill="#F38020"/><path d="M14.96 11.48a1.43 1.43 0 0 0-1.4-1.69 1.95 1.95 0 0 0-1.82 1.24 1.12 1.12 0 0 0-.72 2h3.78a.79.79 0 0 0 .16-1.55Z" fill="#FAAE40"/></svg>';
const URLTEST_LOGO_APPLE = '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M13.53 10.53c.02 2 1.76 2.67 1.78 2.68-.01.04-.27.92-.89 1.82-.54.78-1.1 1.56-1.98 1.58-.87.02-1.16-.51-2.16-.51-1 0-1.33.49-2.09.53-.84.03-1.48-.84-2.03-1.61-1.13-1.58-2-4.48-.84-6.48.57-.99 1.6-1.62 2.72-1.64.85-.02 1.65.57 2.16.57.5 0 1.45-.7 2.45-.6.42.02 1.58.17 2.33 1.25-.06.04-1.39.8-1.38 2.41Zm-1.84-4.3c.45-.54.76-1.28.68-2.03-.66.03-1.46.43-1.94.97-.43.48-.8 1.23-.7 1.95.74.06 1.5-.38 1.96-.89Z" fill="#D0D3D8"/></svg>';
const URLTEST_LOGO_MICROSOFT = '<svg viewBox="0 0 20 20" aria-hidden="true"><rect x="2.5" y="2.5" width="7" height="7" fill="#F25022"/><rect x="10.5" y="2.5" width="7" height="7" fill="#7FBA00"/><rect x="2.5" y="10.5" width="7" height="7" fill="#00A4EF"/><rect x="10.5" y="10.5" width="7" height="7" fill="#FFB900"/></svg>';
const URLTEST_LOGO_UBUNTU = '<svg viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="10" fill="#E95420"/><circle cx="10" cy="10" r="2.1" fill="#fff"/><circle cx="5.1" cy="10" r="1.45" fill="#fff"/><circle cx="12.45" cy="5.76" r="1.45" fill="#fff"/><circle cx="12.45" cy="14.24" r="1.45" fill="#fff"/><path d="M6.5 10h2.1" stroke="#fff" stroke-width="1.2" stroke-linecap="round"/><path d="M11.08 6.7l-1.05 1.82" stroke="#fff" stroke-width="1.2" stroke-linecap="round"/><path d="m11.08 13.3-1.05-1.82" stroke="#fff" stroke-width="1.2" stroke-linecap="round"/></svg>';
const URLTEST_LOGO_FEDORA = '<svg viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="10" fill="#294172"/><path d="M11.2 4.5c1.6 0 2.9 1.2 2.9 2.8 0 1.25-.8 2.3-1.95 2.67v2.75c0 1.57-1.31 2.8-2.94 2.8H7.85v-2.12h1.27c.49 0 .86-.37.86-.84v-3.9c0-1.54 1.26-2.8 2.83-2.8h1.33V4.5H11.2Zm-.3 3.54c-.48 0-.88.4-.88.88v.62h.88c.49 0 .89-.4.89-.88 0-.35-.21-.62-.52-.75a.86.86 0 0 0-.37-.07Z" fill="#fff"/></svg>';
const URLTEST_CHOICES = [
    { id: 'google', label: 'Google', url: 'http://google.com/generate_204', logo: URLTEST_LOGO_GOOGLE, expectedStatus: 204 },
    { id: 'cloudflare', label: 'Cloudflare', url: 'http://cp.cloudflare.com/generate_204', logo: URLTEST_LOGO_CLOUDFLARE, expectedStatus: 204 },
    { id: 'apple', label: 'Apple', url: 'http://captive.apple.com/hotspot-detect.html', logo: URLTEST_LOGO_APPLE, expectedStatus: 200 },
    { id: 'microsoft', label: 'Microsoft', url: 'http://msftconnecttest.com/connecttest.txt', logo: URLTEST_LOGO_MICROSOFT, expectedStatus: 200 },
    { id: 'ubuntu', label: 'Ubuntu', url: 'http://connectivity-check.ubuntu.com/', logo: URLTEST_LOGO_UBUNTU, expectedStatus: 200 },
    { id: 'fedora', label: 'Fedora', url: 'http://fedoraproject.org/static/hotspot.txt', logo: URLTEST_LOGO_FEDORA, expectedStatus: 200 }
];
const URLTEST = URLTEST_CHOICES[0].url;
const URLTEST_INTERVAL = '3m';
const FETCH_INIT = {
    method: 'GET',
    cache: 'no-store',
    credentials: 'omit',
    headers: { 'Accept': 'text/plain, */*' },
    redirect: 'follow'
};
const PUBLIC_CORS_FALLBACKS = [
    (x) => 'https://sub.web2core.workers.dev/?url=' + encodeURIComponent(x)
];

const CORE_PROTOCOL_SUPPORT = {
    singbox: {
        base: ['vmess', 'vless', 'trojan', 'ss', 'socks', 'http', 'hy2', 'tuic', 'anytls', 'wireguard'],
        extendedOnly: ['mieru', 'sdns'],
    },
    xray: {
        base: ['vmess', 'vless', 'trojan', 'ss', 'socks', 'http', 'hy2'],
    },
    mihomo: {
        base: ['vmess', 'vless', 'trojan', 'ss', 'socks', 'http', 'hy2', 'tuic', 'wireguard', 'masque', 'mieru', 'trusttunnel'],
    }
};

function getAllowedCoreProtocols(core, options) {
    const c = String(core || '').toLowerCase();
    const cfg = CORE_PROTOCOL_SUPPORT[c];
    if (!cfg) return [];
    const useExtended = !!(options && options.useExtended);
    if (c === 'singbox' && useExtended && Array.isArray(cfg.extendedOnly)) {
        return Array.from(new Set([...(cfg.base || []), ...cfg.extendedOnly]));
    }
    return Array.from(new Set([...(cfg.base || [])]));
}

function splitCSV(str) {
    return (str || '').split(',').map(s => safeDecodeURIComponent(s.trim())).filter(Boolean);
}

function getQuery(u) {
    return u.searchParams;
}

function getFirstTrimmedQueryValue(q, keys) {
    for (const key of keys) {
        const value = (q.get(key) || '').trim();
        if (value) return value;
    }
    return '';
}

function parseTlsQueryExtras(q) {
    return {
        certificatePublicKeySha256: getFirstTrimmedQueryValue(q, [
            'certificate_public_key_sha256',
            'certificate-public-key-sha256'
        ]),
        ech: {
            config: getFirstTrimmedQueryValue(q, ['echConfig', 'ech-config', 'ech_config']),
            configPath: getFirstTrimmedQueryValue(q, ['echConfigPath', 'ech-config-path', 'ech_config_path']),
            configList: getFirstTrimmedQueryValue(q, ['echConfigList', 'ech-config-list', 'ech_config_list']),
            queryServerName: getFirstTrimmedQueryValue(q, ['echQueryServerName', 'ech-query-server-name', 'ech_query_server_name']),
            forceQuery: getFirstTrimmedQueryValue(q, ['echForceQuery', 'ech-force-query', 'ech_force_query'])
        }
    };
}

function asInt(n, def = 0) {
    const x = parseInt(n, 10);
    return Number.isFinite(x) ? x : def;
}

function sanitizeTag(s) {
    const cleaned = (s || '').replace(/[\u0000-\u001f]/g, '').trim();
    return cleaned || 'proxy';
}

function generateSecretHex32() {
    try {
        const buf = new Uint8Array(16);
        (self.crypto || window.crypto).getRandomValues(buf);
        return Array.from(buf, b => b.toString(16).padStart(2, '0')).join('');
    } catch {
        const bytes = [];
        for (let i = 0; i < 16; i++) bytes.push(Math.floor(Math.random() * 256));
        return bytes.map(b => b.toString(16).padStart(2, '0')).join('');
    }
}

function computeTag(bean, used) {
    const base = sanitizeTag((bean.name || '').trim()) || sanitizeTag(`${bean.proto}-${bean.host}-${bean.port}`);
    let tag = base;
    let i = 1;
    while (used.has(tag)) {
        tag = `${base}-${++i}`;
    }
    used.add(tag);
    return tag;
}

function isValidUuid(str) {
    const s = (str || '').trim();
    return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(s);
}

function findUuidToken(str) {
    const s = (str || '').trim();
    if (!s) return '';
    const tokens = s.split(/[:@]/).map(x => x.trim()).filter(Boolean);
    for (const t of tokens) {
        if (isValidUuid(t)) return t;
    }
    if (isValidUuid(s)) return s;
    return '';
}

function parseAddrHostPort(addr, defaultPort) {
    let host = '';
    let port = defaultPort;
    const a = (addr || '').trim();
    if (!a) return { host, port };
    if (a.startsWith('[')) {
        const ix = a.indexOf(']');
        if (ix !== -1) {
            host = a.slice(0, ix + 1);
            const rest = a.slice(ix + 1);
            if (rest.startsWith(':')) port = asInt(rest.slice(1), defaultPort);
        } else {
            host = a;
        }
    } else {
        const lastColon = a.lastIndexOf(':');
        if (lastColon > 0) {
            host = a.slice(0, lastColon);
            port = asInt(a.slice(lastColon + 1), defaultPort);
        } else {
            host = a;
        }
    }
    return { host, port };
}

function readTlsVarIntBinary(input, offset) {
    const source = String(input || '');
    if (!Number.isInteger(offset) || offset < 0 || offset >= source.length) {
        throw new Error('tt: invalid varint offset');
    }
    const first = source.charCodeAt(offset);
    const prefix = first >> 6;
    const size = 1 << prefix;
    if (offset + size > source.length) throw new Error('tt: truncated varint');

    let value = BigInt(first & 0x3f);
    for (let i = 1; i < size; i++) {
        value = (value << 8n) | BigInt(source.charCodeAt(offset + i));
    }
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('tt: varint too large');
    return { value: Number(value), nextOffset: offset + size };
}

function decodeAuthorityAndExtract(authority, defaultPort) {
    const dec = decodeBase64Url(authority || '');
    if (!dec || !dec.includes('@')) return null;
    const i = dec.lastIndexOf('@');
    const cred = dec.slice(0, i);
    const addr = dec.slice(i + 1);
    const uuid = findUuidToken(cred);
    const { host, port } = parseAddrHostPort(addr, defaultPort);
    return { uuid, host, port };
}

function decodeSSFullAuthority(raw, defaultPort) {
    const decAll = decodeBase64Url(raw || '');
    if (!decAll || !decAll.includes('@')) return null;
    const at = decAll.lastIndexOf('@');
    const cred = decAll.slice(0, at);
    const addr = decAll.slice(at + 1);
    let method = '', password = '';
    const i = cred.indexOf(':');
    if (i !== -1) {
        method = cred.slice(0, i);
        password = cred.slice(i + 1);
    }
    const ap = parseAddrHostPort(addr, defaultPort);
    return { method, password, host: ap.host, port: ap.port };
}

function validateBean(bean) {
    if (!bean || typeof bean !== 'object') throw new Error('Incorrect link');
    const p = bean.proto;
    const requireHost = () => {
        if (!bean.host) throw new Error(p + ': missing host');
    };
    const requirePort = () => {
        if (!Number.isFinite(bean.port) || bean.port <= 0) throw new Error(p + ': invalid port');
    };
    const checkReserved = (val, label) => {
        if (val === undefined) return;
        if (typeof val === 'string') {
            if (val.trim()) return;
        } else if (Array.isArray(val)) {
            const ok = val.length === 3 && val.every(x => Number.isInteger(x) && x >= 0 && x <= 255);
            if (ok) return;
        }
        throw new Error(label + ': reserved must be 3 bytes or a non-empty base64 string');
    };
    const parsePortRangeItem = (item) => {
        const m = String(item || '').trim().match(/^(\d+)(?:\s*-\s*(\d+))?$/);
        if (!m) return null;
        const a = parseInt(m[1], 10);
        const b = m[2] ? parseInt(m[2], 10) : a;
        if (!Number.isFinite(a) || !Number.isFinite(b)) return null;
        if (a < 1 || a > 65535 || b < 1 || b > 65535 || a > b) return null;
        return { start: a, end: b };
    };
    const hasValidPortRange = (raw) => {
        const text = String(raw || '').trim();
        if (!text) return false;
        const items = text.split(',').map(x => x.trim()).filter(Boolean);
        if (!items.length) return false;
        return items.every(x => !!parsePortRangeItem(x));
    };
    switch (p) {
        case 'mieru':
            requireHost();
            if (!Number.isFinite(bean.port) || bean.port <= 0) {
                if (!hasValidPortRange(bean.mieru?.server_ports)) {
                    throw new Error('mieru: invalid port or port range');
                }
            }
            if (!bean.mieru?.username || !bean.mieru?.password) throw new Error('mieru: missing username/password');
            break;
        case 'trusttunnel':
            requireHost();
            requirePort();
            if (!bean.trusttunnel?.username || !bean.trusttunnel?.password) throw new Error('trusttunnel: missing username/password');
            break;
        case 'vless':
            requireHost();
            requirePort();
            if (!bean.auth?.uuid) throw new Error('vless missing UUID');
            break;
        case 'vmess':
            requireHost();
            requirePort();
            if (!bean.auth?.uuid) throw new Error('vmess missing UUID');
            break;
        case 'trojan':
            requireHost();
            requirePort();
            if (!bean.auth?.password) throw new Error('trojan: missing password');
            break;
        case 'anytls':
            requireHost();
            requirePort();
            if (!bean.auth?.password) throw new Error('anytls: missing password');
            break;
        case 'ss':
            requireHost();
            requirePort();
            if (!bean.ss?.method || !bean.ss?.password) throw new Error('shadowsocks: missing method/password');
            break;
        case 'socks':
        case 'http':
            requireHost();
            requirePort();
            break;
        case 'hy2':
            requireHost();
            requirePort();
            if (!bean.auth?.password) throw new Error('hysteria2: missing password');
            break;
        case 'tuic':
            requireHost();
            requirePort();
            {
                const hasToken = !!(bean.tuic && bean.tuic.token);
                if (!hasToken) {
                    if (!bean.auth?.uuid || !isValidUuid(bean.auth.uuid)) throw new Error('tuic: invalid UUID');
                    if (!bean.auth?.password) throw new Error('tuic: missing password');
                }
            }
            break;
        case 'sdns':
            if (!bean.sdns?.stamp) throw new Error('sdns: missing stamp');
            break;
        case 'wireguard': {
            requireHost();
            requirePort();
            const wg = bean.wireguard || {};
            if (!wg.privateKey) throw new Error('wireguard: missing PrivateKey');
            if (!wg.ip && !wg.ipv6) throw new Error('wireguard: missing Address');
            const peers = Array.isArray(wg.peers) ? wg.peers : [];
            const hasPeers = peers.length > 0;
            if (hasPeers) {
                for (let i = 0; i < peers.length; i++) {
                    const peer = peers[i] || {};
                    if (!peer.server) throw new Error(`wireguard: peers[${i}]: missing server`);
                    if (!Number.isFinite(peer.port) || peer.port <= 0) throw new Error(`wireguard: peers[${i}]: invalid port`);
                    if (!peer.publicKey) throw new Error(`wireguard: peers[${i}]: missing PublicKey`);
                    if (!Array.isArray(peer.allowedIPs) || peer.allowedIPs.length === 0) throw new Error(`wireguard: peers[${i}]: missing AllowedIPs`);
                    checkReserved(peer.reserved, `wireguard: peers[${i}]`);
                }
            } else {
                if (!wg.publicKey) throw new Error('wireguard: missing PublicKey');
                if (!Array.isArray(wg.allowedIPs) || wg.allowedIPs.length === 0) throw new Error('wireguard: missing AllowedIPs');
                checkReserved(wg.reserved, 'wireguard');
            }
            break;
        }
        case 'masque': {
            requireHost();
            requirePort();
            const mq = bean.masque || {};
            if (!mq.privateKey) throw new Error('masque: missing private-key');
            if (!mq.publicKey) throw new Error('masque: missing public-key');
            if (!mq.ip && !mq.ipv6) throw new Error('masque: missing ip/ipv6');
            break;
        }
        default:
            throw new Error('Unknown protocol: ' + p);
    }
    if (bean.stream && bean.stream.reality && typeof bean.stream.reality.sid === 'string') {
        const sidTrimmed = bean.stream.reality.sid.trim();
        if (sidTrimmed && sidTrimmed.length > 16) {
            throw new Error('REALITY shortId is too long (max 16 hex characters)');
        }
    }
}

function normalizeStream(stream, serverAddress) {
    if (!stream) return stream;
    if (stream.security === 'none' || stream.security === '0' || stream.security === 'false') {
        stream.security = '';
    } else if (stream.security === '1' || stream.security === 'true') {
        stream.security = 'tls';
    }
    if (stream.security === 'tls' && stream.host && !stream.sni) {
        const isIp = /^(\d{1,3}\.){3}\d{1,3}$|^\[?[0-9a-fA-F:]+\]?$/.test(serverAddress || '');
        if (isIp) {
            stream.sni = stream.host;
        }
    }
    return stream;
}

function parseTunSpec(tunSpec) {
    return (tunSpec || '')
        .split(',')
        .map(s => s.trim())
        .filter(Boolean)
        .map(raw => {
            const [namePart, modePart] = raw.split(':');
            const name = (namePart || '').trim();
            const m = (modePart || '').trim().toLowerCase();
            const mode = (m === 'auto' || m === 'select') ? m : 'select';
            return { name, mode };
        })
        .filter(x => x.name);
}

function getUrlTestChoice(input) {
    const candidate = String(input || '').trim();
    if (!candidate) return URLTEST_CHOICES[0];
    const found = URLTEST_CHOICES.find((choice) => choice && choice.url === candidate);
    if (found) return found;
    if (isHttpUrl(candidate)) {
        return {
            id: 'custom',
            label: candidate.replace(/^https?:\/\//i, ''),
            url: candidate,
            logo: '',
            expectedStatus: candidate.includes('generate_204') ? 204 : 200,
        };
    }
    return URLTEST_CHOICES[0];
}

function resolveUrlTest(input) {
    return getUrlTestChoice(input).url;
}

function resolveUrlTestExpectedStatus(input) {
    return getUrlTestChoice(input).expectedStatus || 204;
}

function parseLink(input) {
    const trimmed = input.trim();
    const scheme = trimmed.split(':', 1)[0].toLowerCase();
    if (scheme === 'tt') return parseTrustTunnel(trimmed);
    if (scheme === 'mieru' || scheme === 'mierus') return parseMieru(trimmed);
    if (scheme === 'vmess') return parseVMess(trimmed);
    if (scheme === 'vless') return parseVLESS(trimmed);
    if (scheme === 'trojan') return parseTrojan(trimmed);
    if (scheme === 'anytls') return parseAnyTLS(trimmed);
    if (scheme === 'ss') return parseSS(trimmed);
    if (scheme.startsWith('socks')) return parseSocksHttp(trimmed);
    if (scheme === 'http' || scheme === 'https') return parseSocksHttp(trimmed);
    if (scheme === 'hy2' || scheme === 'hysteria2') return parseHysteria2(trimmed);
    if (scheme === 'tuic') return parseTUIC(trimmed);
    if (scheme === 'sdns') return parseSDNS(trimmed);
    if (scheme === 'masque') return parseMasque(trimmed);
    throw new Error('Unknown link: ' + scheme);
}

function parseMasque(urlStr) {
    const u = parseUrl(urlStr);
    if (u.protocol !== 'masque:') throw new Error('A masque:// link is required');
    const q = getQuery(u);
    const name = safeDecodeURIComponent(u.hash.replace('#', ''));
    const getBool = (key) => {
        const raw = (q.get(key) || '').toString().toLowerCase();
        return raw === '1' || raw === 'true' || raw === 'yes';
    };
    const dnsRaw = q.get('dns') || '';
    const dns = dnsRaw ? dnsRaw.split(',').map(s => s.trim()).filter(Boolean) : [];
    return {
        proto: 'masque',
        host: u.hostname,
        port: asInt(u.port, 443),
        name,
        masque: {
            privateKey: (q.get('private-key') || '').trim(),
            publicKey: (q.get('public-key') || '').trim(),
            ip: (q.get('ip') || '').trim(),
            ipv6: (q.get('ipv6') || '').trim(),
            uri: (q.get('uri') || '').trim(),
            sni: (q.get('sni') || '').trim(),
            network: (q.get('network') || '').trim().toLowerCase(),
            mtu: asInt(q.get('mtu'), 0),
            udp: getBool('udp'),
            congestionController: (q.get('congestion-controller') || '').trim(),
            bbrProfile: (q.get('bbr-profile') || q.get('bbr_profile') || '').trim(),
            cwnd: asInt(q.get('cwnd'), 0),
            remoteDnsResolve: getBool('remote-dns-resolve'),
            dns
        }
    };
}
function parseSocksHttp(urlStr) {
    const u = parseUrl(urlStr);
    const query = getQuery(u);
    const isHttps = u.protocol === 'https:';
    const isHttp = u.protocol === 'http:';
    const isSocks4 = u.protocol.startsWith('socks4');
    let effectiveSecurity = (query.get('security') || '').toLowerCase();
    if (!effectiveSecurity) {
        if (isHttps) effectiveSecurity = 'tls';
        else if (isHttp) effectiveSecurity = '';
        else effectiveSecurity = '';
    }
    const bean = {
        proto: (isHttp || isHttps) ? 'http' : 'socks',
        host: u.hostname,
        port: asInt(u.port, isHttps ? 443 : isHttp ? 80 : 1080),
        name: safeDecodeURIComponent(u.hash.replace('#', '')),
        socks: {
            type: isHttp || isHttps ? 'http' : (isSocks4 ? 'socks4' : 'socks5'),
            username: safeDecodeURIComponent(u.username || ''),
            password: safeDecodeURIComponent(u.password || '')
        },
        stream: {
            network: 'tcp',
            security: effectiveSecurity.replace('reality', 'tls').replace('none', ''),
            sni: query.get('sni') || '',
            alpn: [],
            allowInsecure: false,
            fp: '',
            headerType: '',
            host: '',
            path: '',
            packet_encoding: ''
        }
    };
    if (!bean.socks.password && bean.socks.username) {
        const n = decodeBase64Url(bean.socks.username);
        if (n.includes(':')) {
            const [user, pass] = n.split(':');
            bean.socks.username = user;
            bean.socks.password = pass;
        }
    }
    return bean;
}

function parseTrojan(urlStr) {
    const u = parseUrl(urlStr);
    const q = getQuery(u);
    const bean = {
        proto: 'trojan',
        host: u.hostname,
        port: asInt(u.port, 443),
        name: safeDecodeURIComponent(u.hash.replace('#', '')),
        auth: { password: safeDecodeURIComponent(u.username || '') },
        stream: buildStreamFromQuery(q, true),
        udp: q.get('udp') === '1' || q.get('udp') === 'true',
        udpOverTcp: q.get('udp-over-tcp') === '1' || q.get('udp-over-tcp') === 'true',
        ipVersion: q.get('ip-version') || ''
    };
    bean.stream = normalizeStream(bean.stream, bean.host);
    return bean;
}

function parseAnyTLS(urlStr) {
    const u = parseUrl(urlStr);
    if (u.protocol !== 'anytls:') throw new Error('A anytls:// link is required');
    const q = getQuery(u);
    const pwd = safeDecodeURIComponent(u.username || '').trim() || (q.get('password') || '').trim();
    const bean = {
        proto: 'anytls',
        host: u.hostname,
        port: asInt(u.port, 443),
        name: safeDecodeURIComponent(u.hash.replace('#', '')),
        auth: { password: pwd },
        stream: buildStreamFromQuery(q, false),
        udp: q.get('udp') === '1' || q.get('udp') === 'true',
        udpOverTcp: q.get('udp-over-tcp') === '1' || q.get('udp-over-tcp') === 'true',
        ipVersion: q.get('ip-version') || ''
    };
    if (!bean.stream || typeof bean.stream !== 'object') bean.stream = {};
    bean.stream.network = 'tcp';
    bean.stream.headerType = '';
    bean.stream.host = '';
    bean.stream.path = '';
    bean.stream.authority = '';
    bean.stream.security = 'tls';
    bean.stream = normalizeStream(bean.stream, bean.host);
    return bean;
}

function parseVLESS(urlStr) {
    const u = parseUrl(urlStr);
    if (u.protocol !== 'vless:') throw new Error('A vless:// link is required');
    const q = getQuery(u);
    const rawAfterScheme = urlStr.slice('vless://'.length);
    const rawAuthority = rawAfterScheme.split(/[?#]/)[0];
    let host = u.hostname;
    let port = asInt(u.port, 443);
    const rawUser = safeDecodeURIComponent(u.username || '').trim();
    let uuid = rawUser;
    if (!isValidUuid(uuid) && rawUser) {
        const dec = decodeBase64Url(rawUser);
        if (dec) {
            const at = dec.lastIndexOf('@');
            if (at !== -1) {
                const cred = dec.slice(0, at);
                const addr = dec.slice(at + 1);
                const token = findUuidToken(cred);
                if (token) uuid = token;
                const ap = parseAddrHostPort(addr, port);
                if (ap.host) host = ap.host;
                if (ap.port) port = ap.port;
            } else {
                const token2 = findUuidToken(dec);
                if (token2) uuid = token2;
            }
        }
    }
    if (!uuid) {
        const pwd = safeDecodeURIComponent(u.password || '').trim();
        if (isValidUuid(pwd)) uuid = pwd;
    }
    if (!uuid) {
        const qp = (q.get('id') || q.get('uuid') || q.get('u') || '').trim();
        if (isValidUuid(qp)) uuid = qp;
    }
    if (!uuid && rawAuthority && !rawAuthority.includes('@')) {
        const r = decodeAuthorityAndExtract(rawAuthority, port);
        if (r) {
            if (r.uuid) uuid = r.uuid;
            if (r.host) host = r.host;
            if (r.port) port = r.port;
        }
    }
    if (!uuid) {
        const r2 = decodeAuthorityAndExtract(host, port);
        if (r2) {
            if (r2.uuid) uuid = r2.uuid;
            if (r2.host) host = r2.host;
            if (r2.port) port = r2.port;
        }
    }

    const bean = {
        proto: 'vless',
        host,
        port,
        name: safeDecodeURIComponent(u.hash.replace('#', '')),
        auth: {
            uuid,
            flow: (q.get('flow') || '').replace(/-udp443$/, '').replace(/^none$/, ''),
            encryption: (q.get('encryption') || '').trim() || 'none'
        },
        stream: buildStreamFromQuery(q, false),
        udp: q.get('udp') === '1' || q.get('udp') === 'true',
        udpOverTcp: q.get('udp-over-tcp') === '1' || q.get('udp-over-tcp') === 'true',
        ipVersion: q.get('ip-version') || ''
    };
    bean.stream = normalizeStream(bean.stream, bean.host);
    return bean;
}

function parseVMess(urlStr) {
    const payloadRaw = urlStr.slice('vmess://'.length);
    let payload = (payloadRaw || '').split('#')[0].split('?')[0];
    const tryDecode = (s) => {
        const decoded = decodeBase64Url(s || '');
        const obj = decoded ? tryJSON(decoded) : null;
        return obj;
    };
    const candidates = [];
    const push = (x) => {
        const v = String(x || '');
        if (!v) return;
        if (!candidates.includes(v)) candidates.push(v);
    };
    push(payload);
    push(takeBase64Prefix(payload));

    let obj = null;
    for (let i = 0; i < candidates.length && !obj; i++) {
        const cand = candidates[i];
        obj = tryDecode(cand);
        if (obj) break;

        const lastEq = cand.lastIndexOf('=');
        if (lastEq !== -1 && lastEq < cand.length - 1) {
            push(cand.slice(0, lastEq + 1));
        }
        for (let cut = cand.lastIndexOf('/'); cut > 0; cut = cand.lastIndexOf('/', cut - 1)) {
            push(cand.slice(0, cut));
        }
    }
    if (obj) {
        const net = (obj.net || '').toLowerCase();
        const type = (net || 'tcp');
        const stream = {
            network: type,
            security: (obj.tls || '').replace('reality', 'tls') || (obj.security || ''),
            sni: obj.sni || '',
            host: obj.host || '',
            path: obj.path || '',
            headerType: obj.type || '',
            alpn: splitCSV(obj.alpn || ''),
            allowInsecure: false,
            fp: obj.fp || '',
            packet_encoding: obj.pac_enc || '',
            reality: { pbk: obj.pbk || '', sid: obj.sid || '', spx: obj.spx || '' }
        };
        const bean = {
            proto: 'vmess',
            host: obj.add || 'localhost',
            port: asInt(obj.port, 443),
            name: obj.ps || '',
            auth: { uuid: obj.id, security: obj.scy || 'auto' },
            stream,
            udp: obj.udp === true || obj.udp === 1,
            udpOverTcp: obj['udp-over-tcp'] === true,
            ipVersion: obj['ip-version'] || ''
        };
        bean.stream = normalizeStream(bean.stream, bean.host);
        return bean;
    }
    const u = parseUrl(urlStr);
    const q = getQuery(u);
    const bean = {
        proto: 'vmess',
        host: u.hostname,
        port: asInt(u.port, 443),
        name: safeDecodeURIComponent(u.hash.replace('#', '')),
        auth: { uuid: safeDecodeURIComponent(u.username || ''), security: q.get('encryption') || 'auto' },
        stream: buildStreamFromQuery(q, false),
        udp: q.get('udp') === '1' || q.get('udp') === 'true',
        udpOverTcp: q.get('udp-over-tcp') === '1' || q.get('udp-over-tcp') === 'true',
        ipVersion: q.get('ip-version') || ''
    };
    bean.stream = normalizeStream(bean.stream, bean.host);
    return bean;
}

function parseSS(urlStr) {
    const u = parseUrl(urlStr);
    const name = safeDecodeURIComponent(u.hash.replace('#', ''));
    let method = u.username, password = u.password;
    let host = u.hostname;
    let port = asInt(u.port, 0);
    if (!password && u.username) {
        const dec = decodeBase64Url(u.username);
        if (dec.includes(':')) {
            const i = dec.indexOf(':'), b = dec.slice(i + 1);
            method = dec.slice(0, i);
            password = b;
        }
    }
    if ((!host || !port) || (!method && !password)) {
        const after = urlStr.slice('ss://'.length);
        const raw = after.split(/[?#]/)[0];
        const full = decodeSSFullAuthority(raw, port || 0);
        if (full) {
            host = full.host;
            port = full.port;
            if (!method) method = full.method;
            if (!password) password = full.password;
        }
    }
    const q = getQuery(u);
    const parseUotVersion = () => {
        const raw = (q.get('udp-over-tcp-version') || q.get('uotVersion') || q.get('uot') || '').toString().trim().toLowerCase();
        if (!raw) return 0;
        if (raw === 'true' || raw === 'yes' || raw === 'on') return 2;
        if (raw === '1') return 2;
        const n = parseInt(raw, 10);
        return Number.isFinite(n) && n > 0 ? n : 0;
    };
    const uotVersion = parseUotVersion();
    let plugin = q.get('plugin') || '';
    const pluginOpts = {};

    if (plugin && plugin.includes(';')) {
        const parts = plugin.split(';');
        plugin = parts[0].trim();
        for (let i = 1; i < parts.length; i++) {
            const raw = parts[i] || '';
            if (!raw.trim()) continue;
            const eq = raw.indexOf('=');
            if (eq === -1) {
                const key = raw.trim();
                if (key) pluginOpts[key] = true;
            } else {
                const key = raw.slice(0, eq).trim();
                const val = raw.slice(eq + 1).trim();
                if (key && val) pluginOpts[key] = val;
            }
        }
    } else if (plugin) {
        const mode = q.get('obfs') || q.get('mode') || '';
        const obfsHost = q.get('obfs-host') || q.get('host') || '';
        const obfsPath = q.get('obfs-path') || q.get('path') || '';
        const tls = q.get('tls') === 'true' || q.get('tls') === '1';
        if (mode) pluginOpts.mode = mode;
        if (obfsHost) pluginOpts.host = obfsHost;
        if (obfsPath) pluginOpts.path = obfsPath;
        if (tls) pluginOpts.tls = true;
        if (plugin === 'shadow-tls' || plugin.includes('shadow-tls')) {
            const stPassword = q.get('password') || q.get('shadow-tls-password') || '';
            const version = q.get('version') || q.get('shadow-tls-version') || '3';
            if (stPassword) pluginOpts.password = stPassword;
            if (version) pluginOpts.version = parseInt(version, 10);
        }
    }
    const smux = {};
    const smuxEnabled = q.get('smux') === '1' || q.get('smux') === 'true';
    if (smuxEnabled) {
        smux.enabled = true;
        smux.protocol = q.get('smux-protocol') || 'smux';
        const maxStreams = q.get('smux-max-streams');
        if (maxStreams) smux['max-streams'] = parseInt(maxStreams, 10);
    }
    return {
        proto: 'ss',
        host,
        port,
        name,
        ss: {
            method,
            password,
            uot: uotVersion,
            plugin,
            pluginOpts: Object.keys(pluginOpts).length ? pluginOpts : '',
            smux: smuxEnabled ? smux : null
        },
        stream: { network: 'tcp', security: '' },
        udp: q.get('udp') === '1' || q.get('udp') === 'true',
        udpOverTcp: q.get('udp-over-tcp') === '1' || q.get('udp-over-tcp') === 'true'
    };
}

function parseHysteria2(urlStr) {
    const u = parseUrl(urlStr);
    const q = getQuery(u);
    const pwd = u.password ? (safeDecodeURIComponent(u.username || '') + ':' + safeDecodeURIComponent(u.password)) : safeDecodeURIComponent(u.username || '');
    const tlsExtras = parseTlsQueryExtras(q);
    const qParams = tryJSON(q.get('quicParams') || q.get('quic_params') || '') || {};
    const fmTcp = tryJSON(q.get('finalmask_tcp') || q.get('finalmask-tcp') || '') || [];
    const fmUdp = tryJSON(q.get('finalmask_udp') || q.get('finalmask-udp') || '') || [];
    const hy2Finalmask = {};
    if (Array.isArray(fmTcp) && fmTcp.length) hy2Finalmask.tcp = fmTcp;
    if (Array.isArray(fmUdp) && fmUdp.length) hy2Finalmask.udp = fmUdp;
    const hy2QuicParams = (qParams && typeof qParams === 'object') ? { ...qParams } : {};
    const congestion = (q.get('congestion') || '').trim().toLowerCase();
    const brutalUp = (q.get('brutal_up') || q.get('brutalUp') || q.get('up') || '').trim();
    const brutalDown = (q.get('brutal_down') || q.get('brutalDown') || q.get('down') || '').trim();
    const hopPort = (q.get('mport') || '').trim();
    const hopIntervalRaw = (q.get('hop_interval') || '').trim();
    let hopIntervalValue = null;
    if (hopIntervalRaw) {
        const m = hopIntervalRaw.match(/^(\d+)\s*-\s*(\d+)$/);
        if (m && m[1] && m[2]) {
            hopIntervalValue = `${m[1]}-${m[2]}`;
        } else if (/^\d+$/.test(hopIntervalRaw)) {
            hopIntervalValue = asInt(hopIntervalRaw, 0);
        }
    }
    if (congestion && !hy2QuicParams.congestion) hy2QuicParams.congestion = congestion;
    if (brutalUp && !hy2QuicParams.brutalUp) hy2QuicParams.brutalUp = brutalUp;
    if (brutalDown && !hy2QuicParams.brutalDown) hy2QuicParams.brutalDown = brutalDown;
    if (hopPort || hopIntervalValue !== null) {
        if (!hy2QuicParams.udpHop || typeof hy2QuicParams.udpHop !== 'object') hy2QuicParams.udpHop = {};
        if (hopPort && !hy2QuicParams.udpHop.ports) hy2QuicParams.udpHop.ports = hopPort;
        if (hopIntervalValue !== null && hy2QuicParams.udpHop.interval === undefined) {
            hy2QuicParams.udpHop.interval = hopIntervalValue;
        }
    }
    if (Object.keys(hy2QuicParams).length) hy2Finalmask.quicParams = hy2QuicParams;
    return {
        proto: 'hy2',
        host: u.hostname,
        port: asInt(u.port, 443),
        name: safeDecodeURIComponent(u.hash.replace('#', '')),
        auth: { password: pwd },
        hysteria2: {
            obfsPassword: q.get('obfs-password') || '',
            hopPort: q.get('mport') || '',
            hopInterval: (q.get('hop_interval') || ''),
            bbrProfile: q.get('bbr-profile') || q.get('bbr_profile') || '',
            alpn: q.get('alpn') || 'h3',
            sni: q.get('sni') || '',
            allowInsecure: ['1', 'true', 'yes'].includes(((q.get('allowInsecure') || q.get('insecure') || '')).toLowerCase()),
            pinnedPeerCertSha256: (q.get('pinnedPeerCertSha256') || q.get('pinned-peer-cert-sha256') || q.get('pinSHA256') || q.get('pin-sha256') || '').trim(),
            verifyPeerCertByName: (q.get('verifyPeerCertByName') || q.get('verify-peer-cert-by-name') || '').trim(),
            certificatePublicKeySha256: tlsExtras.certificatePublicKeySha256,
            ech: tlsExtras.ech,
            congestion: q.get('congestion') || '',
            brutalUp,
            brutalDown,
            finalmask: Object.keys(hy2Finalmask).length ? hy2Finalmask : null
        }
    };
}

function parseTUIC(urlStr) {
    const u = parseUrl(urlStr);
    const q = getQuery(u);
    const tlsExtras = parseTlsQueryExtras(q);
    return {
        proto: 'tuic',
        host: u.hostname,
        port: asInt(u.port, 443),
        name: safeDecodeURIComponent(u.hash.replace('#', '')),
        auth: {
            uuid: safeDecodeURIComponent(u.username || ''),
            password: safeDecodeURIComponent(u.password || '')
        },
        tuic: {
            congestion_control: q.get('congestion_control') || 'bbr',
            bbr_profile: q.get('bbr-profile') || q.get('bbr_profile') || '',
            udp_relay_mode: q.get('udp_relay_mode') || 'native',
            zero_rtt_handshake: q.get('zero_rtt') === '1',
            udp_over_stream: q.get('udp_over_stream') === '1',
            heartbeat: q.get('heartbeat') || '',
            alpn: q.get('alpn') || '',
            sni: q.get('sni') || '',
            allowInsecure: ['1', 'true', 'yes'].includes(((q.get('allow_insecure') || q.get('allowInsecure') || q.get('insecure') || '')).toLowerCase()),
            disableSni: ['1', 'true', 'yes'].includes(((q.get('disable_sni') || q.get('disableSni') || '')).toLowerCase()),
            token: q.get('token') || '',
            requestTimeout: q.get('request_timeout') || q.get('request-timeout') || '',
            reduceRtt: ['1', 'true'].includes((q.get('reduce_rtt') || q.get('reduce-rtt') || '').toLowerCase()),
            certificatePublicKeySha256: tlsExtras.certificatePublicKeySha256,
            ech: tlsExtras.ech
        }
    };
}

function parseMieru(urlStr) {
    const u = parseUrl(urlStr);
    if (u.protocol !== 'mieru:' && u.protocol !== 'mierus:') throw new Error('A mieru:// or mierus:// link is required');
    const q = getQuery(u);
    const isLikelyStandardShare = (() => {
        const raw = String(urlStr || '').trim();
        const isMieruScheme = raw.toLowerCase().startsWith('mieru://');
        const isMierusScheme = raw.toLowerCase().startsWith('mierus://');
        if (!isMieruScheme && !isMierusScheme) return false;
        if ((u.username || '').trim() || (u.password || '').trim()) return false;
        const queryText = (q && typeof q.toString === 'function') ? q.toString() : '';
        if (queryText.trim()) return false;
        const offset = isMierusScheme ? 'mierus://'.length : 'mieru://'.length;
        const payload = raw.slice(offset).split('#', 1)[0].trim();
        return /^[A-Za-z0-9+/=_-]+$/.test(payload) && payload.length > 20;
    })();
    if (isLikelyStandardShare) {
        throw new Error('mieru: standard base64 share link is not supported yet');
    }
    const extractRangeFromAuthority = (raw) => {
        const src = String(raw || '').trim();
        if (!src) return '';
        const noHash = src.split('#', 1)[0] || '';
        const noQuery = noHash.split('?', 1)[0] || '';
        const schemePos = noQuery.indexOf('://');
        const authority = schemePos >= 0 ? noQuery.slice(schemePos + 3) : noQuery;
        const hostPort = authority.includes('@') ? authority.slice(authority.lastIndexOf('@') + 1) : authority;
        const m = hostPort.match(/:(\d+\s*-\s*\d+)$/);
        if (!m) return '';
        return m[1].replace(/\s+/g, '');
    };
    const getAllQueryValues = (key) => {
        if (q && typeof q.getAll === 'function') {
            const values = q.getAll(key);
            if (Array.isArray(values)) return values.map(v => String(v || '').trim()).filter(Boolean);
        }
        const raw = String(urlStr || '');
        const queryPart = raw.includes('?') ? raw.slice(raw.indexOf('?') + 1).split('#', 1)[0] : '';
        if (!queryPart) return [];
        try {
            const sp = new URLSearchParams(queryPart);
            return sp.getAll(key).map(v => String(v || '').trim()).filter(Boolean);
        } catch {
            return [];
        }
    };
    const username = safeDecodeURIComponent(u.username || '');
    const password = safeDecodeURIComponent(u.password || '');
    const name = safeDecodeURIComponent(u.hash.replace('#', ''));
    const repeatedPorts = getAllQueryValues('port');
    let serverPorts = q.get('server_ports') || q.get('ports') || q.get('portRange') || q.get('port_range') || '';
    if (!serverPorts && repeatedPorts.length) serverPorts = repeatedPorts.join(',');
    if (!serverPorts) serverPorts = extractRangeFromAuthority(urlStr);
    const protocolItems = getAllQueryValues('protocol').map(x => x.toUpperCase());
    const transport = (q.get('transport') || q.get('protocol') || protocolItems[0] || 'TCP').toUpperCase();
    const multiplexing = (q.get('multiplexing') || '').toUpperCase();
    const handshakeMode = (q.get('handshake_mode') || q.get('handshake-mode') || '').toUpperCase();
    const trafficPattern = (q.get('traffic_pattern') || q.get('traffic-pattern') || '').trim();
    let fallbackPort = 0;
    if (serverPorts) {
        const m = String(serverPorts).match(/^(\d+)/);
        if (m) fallbackPort = asInt(m[1], fallbackPort);
    }
    return {
        proto: 'mieru',
        host: u.hostname,
        port: asInt(u.port, fallbackPort),
        name,
        mieru: {
            username,
            password,
            server_ports: serverPorts,
            transport,
            multiplexing,
            handshake_mode: handshakeMode,
            traffic_pattern: trafficPattern
        }
    };
}

function parseTrustTunnel(urlStr) {
    const raw = String(urlStr || '').trim();
    if (!raw.toLowerCase().startsWith('tt://?')) throw new Error('A tt://? link is required');

    const hashIndex = raw.indexOf('#');
    const payloadPlus = raw.slice('tt://?'.length, hashIndex === -1 ? undefined : hashIndex).trim();
    const ampIndex = payloadPlus.indexOf('&');
    const payload = (ampIndex === -1 ? payloadPlus : payloadPlus.slice(0, ampIndex)).trim();
    const extraQuery = ampIndex === -1 ? '' : payloadPlus.slice(ampIndex + 1);
    const extraParams = new URLSearchParams(extraQuery);
    if (!payload) throw new Error('tt: missing payload');

    const decoded = decodeBase64Url(payload);
    if (!decoded) throw new Error('tt: invalid base64 payload');

    const fields = new Map();
    const addresses = [];
    for (let i = 0; i < decoded.length;) {
        const tagInfo = readTlsVarIntBinary(decoded, i);
        const lenInfo = readTlsVarIntBinary(decoded, tagInfo.nextOffset);
        const valueStart = lenInfo.nextOffset;
        const valueEnd = valueStart + lenInfo.value;
        if (valueEnd > decoded.length) throw new Error('tt: truncated field value');
        const value = decoded.slice(valueStart, valueEnd);
        if (tagInfo.value === 0x02) addresses.push(value);
        else fields.set(tagInfo.value, value);
        i = valueEnd;
    }

    const versionRaw = fields.get(0x00);
    if (versionRaw && versionRaw.length) {
        const version = versionRaw.charCodeAt(0);
        if (version !== 0) throw new Error('tt: unsupported version ' + version);
    }

    const endpoint = addresses.find(Boolean) || '';
    const parsed = parseAddrHostPort(endpoint, 443);
    const hostname = fields.get(0x01) || '';
    const customSni = fields.get(0x03) || '';
    const skipVerification = (fields.get(0x07) || '').charCodeAt(0) === 0x01;
    const upstreamProtocol = (fields.get(0x09) || '').charCodeAt(0);
    const sni = customSni || hostname || parsed.host || '';
    const name = hashIndex === -1 ? '' : safeDecodeURIComponent(raw.slice(hashIndex + 1));

    if (!hostname) throw new Error('tt: missing hostname');
    if (!endpoint) throw new Error('tt: missing address');
    if (!fields.get(0x05)) throw new Error('tt: missing username');
    if (!fields.get(0x06)) throw new Error('tt: missing password');

    const bean = {
        proto: 'trusttunnel',
        host: parsed.host,
        port: parsed.port,
        name,
        trusttunnel: {
            username: fields.get(0x05) || '',
            password: fields.get(0x06) || '',
            healthCheck: false,
            quic: false,
            congestionController: '',
            cwnd: 0,
            maxConnections: 0,
            minStreams: 0,
            maxStreams: 0,
            fingerprint: '',
            certificate: '',
            privateKey: ''
        },
        stream: {
            network: 'tcp',
            security: 'tls',
            sni,
            alpn: [],
            allowInsecure: skipVerification,
            ech: {
                config: '',
                queryServerName: '',
            },
            fp: '',
        },
        udp: false,
        udpOverTcp: false,
        ipVersion: ''
    };
    if (upstreamProtocol === 0x01) bean.stream.alpn = ['h2'];
    if (upstreamProtocol === 0x02) {
        bean.stream.alpn = ['h3'];
        bean.trusttunnel.quic = true;
    }
    const tt = bean.trusttunnel;
    const qQuic = (extraParams.get('quic') || '').toLowerCase();
    if (['1', 'true', 'yes'].includes(qQuic)) tt.quic = true;
    const qHealth = (extraParams.get('health-check') || extraParams.get('health_check') || '').toLowerCase();
    if (['1', 'true', 'yes'].includes(qHealth)) tt.healthCheck = true;
    const qCc = (extraParams.get('congestion-controller') || extraParams.get('congestion_controller') || '').trim();
    if (qCc) tt.congestionController = qCc;
    const qBbrProfile = (extraParams.get('bbr-profile') || extraParams.get('bbr_profile') || '').trim();
    if (qBbrProfile) tt.bbrProfile = qBbrProfile;
    const qCwnd = asInt(extraParams.get('cwnd'), 0);
    if (qCwnd > 0) tt.cwnd = qCwnd;
    const qMaxConn = asInt(extraParams.get('max-connections') || extraParams.get('max_connections'), 0);
    if (qMaxConn > 0) tt.maxConnections = qMaxConn;
    const qMinStreams = asInt(extraParams.get('min-streams') || extraParams.get('min_streams'), 0);
    if (qMinStreams >= 0) tt.minStreams = qMinStreams;
    const qMaxStreams = asInt(extraParams.get('max-streams') || extraParams.get('max_streams'), 0);
    if (qMaxStreams >= 0) tt.maxStreams = qMaxStreams;

    bean.stream = normalizeStream(bean.stream, bean.host);
    return bean;
}

function parseMieruProfilesJson(jsonObj) {
    if (!jsonObj || typeof jsonObj !== 'object') return [];
    const profiles = Array.isArray(jsonObj.profiles)
        ? jsonObj.profiles
        : ((jsonObj.profileName || jsonObj.user || jsonObj.servers) ? [jsonObj] : []);
    if (!profiles.length) return [];
    const beans = [];
    for (const p of profiles) {
        const username = p?.user?.name || '';
        const password = p?.user?.password || '';
        const profileName = (p?.profileName || '').trim();
        const servers = Array.isArray(p?.servers) ? p.servers : [];
        const multiplexing = (() => {
            const mx = p?.multiplexing;
            if (typeof mx === 'string') return mx.toUpperCase();
            if (mx && typeof mx === 'object') {
                const level = (mx.level || mx.Level || '').toString().trim();
                return level ? level.toUpperCase() : '';
            }
            return '';
        })();
        const handshakeMode = (p?.handshakeMode || p?.handshake_mode || '').toString().toUpperCase();
        const trafficPattern = (() => {
            const tp = p?.trafficPattern ?? p?.traffic_pattern;
            if (typeof tp === 'string') return tp.trim();
            return '';
        })();
        for (const s of servers) {
            const host = s?.ipAddress || s?.host || s?.hostname || '';
            const bindings = Array.isArray(s?.portBindings) ? s.portBindings : [];
            if (!host || !bindings.length) continue;
            for (const b of bindings) {
                const protocol = (b?.protocol || 'TCP').toString().toUpperCase();
                const portRange = (b?.portRange || '').toString();
                const singlePort = asInt(b?.port, 0);
                let serverPort = singlePort > 0 ? singlePort : 0;
                if (portRange) {
                    const m = portRange.match(/^(\d+)(?:\s*-\s*(\d+))?$/);
                    if (m) {
                        serverPort = asInt(m[1], serverPort);
                    }
                }
                const bean = {
                    proto: 'mieru',
                    host,
                    port: serverPort,
                    name: profileName || `mieru-${host}:${serverPort}`,
                    mieru: {
                        username,
                        password,
                        server_ports: portRange,
                        transport: protocol,
                        multiplexing,
                        handshake_mode: handshakeMode,
                        traffic_pattern: trafficPattern
                    }
                };
                beans.push(bean);
            }
        }
    }
    return beans;
}

function parseSDNS(urlStr) {
    const u = parseUrl(urlStr);
    if (u.protocol !== 'sdns:') throw new Error('A sdns:// link is required');
    const stamp = urlStr;
    const name = safeDecodeURIComponent(u.hash.replace('#', ''));
    return {
        proto: 'sdns',
        host: u.hostname,
        port: asInt(u.port, 443),
        name: name || 'sdns-server',
        sdns: {
            stamp: stamp
        }
    };
}

function buildBeansFromInput(raw) {
    const text = (raw || '').trim();
    if (!text) return [];

    if ((text.startsWith('{') || text.startsWith('['))) {
        const obj = tryJSON(text);
        if (obj) {
            const fromProfiles = parseMieruProfilesJson(obj);
            if (fromProfiles.length) return fromProfiles;
            return [];
        }
    }
    const lines = text.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
    return lines.map(parseLink);
}

function buildStreamFromQuery(q, isTrojan) {
    const parseIntOrRange = (raw) => {
        const t = String(raw || '').trim();
        if (!t) return '';
        if (/^\d+\s*-\s*\d+$/.test(t)) return t.replace(/\s+/g, '');
        const n = asInt(t, 0);
        return n > 0 ? n : '';
    };
    let type = (q.get('type') || 'tcp').toLowerCase();
    const mode = (q.get('mode') || '').toLowerCase();
    if (mode === 'gun') type = 'grpc';
    if (type === 'h2') type = 'http';
    if (type === 'w' || type === 'websocket') type = 'ws';
    if (type !== 'xhttp' && (q.get('xhttp') === '1' || q.get('xhttp') === 'true')) type = 'xhttp';
    const security = (q.get('security') || (isTrojan ? 'tls' : '')).toLowerCase().replace('reality', 'tls').replace('none', '');
    const sni = q.get('sni') || q.get('peer') || '';
    const authority = q.get('authority') || '';
    const grpcUserAgent = q.get('grpc-user-agent') || '';
    const grpcPingInterval = asInt(q.get('ping-interval') || q.get('ping_interval'), 0);
    const grpcMaxConnections = asInt(q.get('grpc-max-connections') || q.get('grpc_max_connections'), 0);
    const grpcMinStreams = asInt(q.get('grpc-min-streams') || q.get('grpc_min_streams'), 0);
    const grpcMaxStreams = asInt(q.get('grpc-max-streams') || q.get('grpc_max_streams'), 0);
    const alpn = splitCSV(q.get('alpn') || '');
    const aiRaw = (q.get('allowInsecure') || q.get('insecure') || '').toLowerCase();
    const allowInsecure = ['1', 'true', 'yes'].includes(aiRaw);
    const pinnedPeerCertSha256 = (q.get('pinnedPeerCertSha256') || q.get('pinned-peer-cert-sha256') || q.get('pinSHA256') || q.get('pin-sha256') || '').trim();
    const verifyPeerCertByName = (q.get('verifyPeerCertByName') || q.get('verify-peer-cert-by-name') || '').trim();
    const {certificatePublicKeySha256, ech} = parseTlsQueryExtras(q);
    const fp = q.get('fp') || '';
    const reality = {
        pbk: q.get('pbk') || '',
        sid: (q.get('sid') || '').split(',')[0] || '',
        spx: q.get('spx') || '',
        pqv: q.get('pqv') || ''
    };
    const stream = {
        network: type,
        security,
        sni,
        authority,
        grpcUserAgent,
        grpcPingInterval,
        grpcMaxConnections,
        grpcMinStreams,
        grpcMaxStreams,
        alpn,
        allowInsecure,
        pinnedPeerCertSha256,
        verifyPeerCertByName,
        certificatePublicKeySha256,
        ech,
        fp,
        reality,
        headerType: '',
        host: '',
        path: '',
        packet_encoding: '',
        xhttpMode: '',
        xhttpXmux: {},
        xhttpDownload: {}
    };
    if (type === 'ws') {
        stream.path = q.get('path') || '';
        stream.host = q.get('host') || '';
        const ed = asInt((q.get('ed') || '').toString(), 0);
        if (ed > 0) {
            stream.wsEarlyData = { max_early_data: ed, early_data_header_name: 'Sec-WebSocket-Protocol' };
        }
    } else if (type === 'http') {
        stream.path = q.get('path') || '';
        stream.host = (q.get('host') || '').replace(/\|/g, ',');
    } else if (type === 'xhttp') {
        stream.path = q.get('path') || '';
        stream.host = q.get('host') || '';
        stream.xhttpMode = q.get('xmode') || q.get('mode') || '';
        stream.xhttpXmux = {
            max_concurrency: q.get('xmux_max_concurrency') || q.get('reuse_max_concurrency') || '',
            max_connections: q.get('xmux_max_connections') || q.get('reuse_max_connections') || '',
            c_max_reuse_times: q.get('xmux_c_max_reuse_times') || q.get('reuse_c_max_reuse_times') || '',
            h_max_request_times: q.get('xmux_h_max_request_times') || q.get('reuse_h_max_request_times') || '',
            h_max_reusable_secs: q.get('xmux_h_max_reusable_secs') || q.get('reuse_h_max_reusable_secs') || '',
            h_keep_alive_period: asInt(q.get('xmux_h_keep_alive_period'), 0)
        };
        stream.xhttpScMaxEachPostBytes = parseIntOrRange(q.get('sc-max-each-post-bytes') || q.get('sc_max_each_post_bytes'));
        stream.xhttpScMaxBufferedPosts = asInt(q.get('sc-max-buffered-posts') || q.get('sc_max_buffered_posts'), 0);
        stream.xhttpScMinPostsIntervalMs = parseIntOrRange(q.get('sc-min-posts-interval-ms') || q.get('sc_min_posts_interval_ms'));
        stream.xhttpDownload = {
            mode: q.get('download_mode') || '',
            host: q.get('download_host') || '',
            path: q.get('download_path') || '',
            x_padding_bytes: q.get('download_x_padding_bytes') || '',
            sc_max_each_post_bytes: q.get('download_sc_max_each_post_bytes') || '',
            sc_min_posts_interval_ms: q.get('download_sc_min_posts_interval_ms') || '',
            sc_stream_up_server_secs: q.get('download_sc_stream_up_server_secs') || '',
            no_sse_header: q.get('download_no_sse_header') || '',
            server: q.get('download_server') || '',
            server_port: asInt(q.get('download_server_port'), 0),
            detour: q.get('download_detour') || '',
            xmux: {
                max_concurrency: q.get('download_xmux_max_concurrency') || q.get('download_reuse_max_concurrency') || '',
                max_connections: q.get('download_xmux_max_connections') || q.get('download_reuse_max_connections') || '',
                c_max_reuse_times: q.get('download_xmux_c_max_reuse_times') || q.get('download_reuse_c_max_reuse_times') || '',
                h_max_request_times: q.get('download_xmux_h_max_request_times') || q.get('download_reuse_h_max_request_times') || '',
                h_max_reusable_secs: q.get('download_xmux_h_max_reusable_secs') || q.get('download_reuse_h_max_reusable_secs') || ''
            }
        };
        const xhttpQParams = tryJSON(q.get('quicParams') || q.get('quic_params') || '') || {};
        const xhttpFinalmask = {};
        const xhttpTcp = tryJSON(q.get('finalmask_tcp') || q.get('finalmask-tcp') || '') || [];
        const xhttpUdp = tryJSON(q.get('finalmask_udp') || q.get('finalmask-udp') || '') || [];
        if (Array.isArray(xhttpTcp) && xhttpTcp.length) xhttpFinalmask.tcp = xhttpTcp;
        if (Array.isArray(xhttpUdp) && xhttpUdp.length) xhttpFinalmask.udp = xhttpUdp;
        const xhttpQuicParams = (xhttpQParams && typeof xhttpQParams === 'object') ? { ...xhttpQParams } : {};
        const xhttpCongestion = (q.get('congestion') || '').trim().toLowerCase();
        const xhttpBrutalUp = (q.get('brutal_up') || q.get('brutalUp') || q.get('up') || '').trim();
        const xhttpBrutalDown = (q.get('brutal_down') || q.get('brutalDown') || q.get('down') || '').trim();
        if (xhttpCongestion && !xhttpQuicParams.congestion) xhttpQuicParams.congestion = xhttpCongestion;
        if (xhttpBrutalUp && !xhttpQuicParams.brutalUp) xhttpQuicParams.brutalUp = xhttpBrutalUp;
        if (xhttpBrutalDown && !xhttpQuicParams.brutalDown) xhttpQuicParams.brutalDown = xhttpBrutalDown;
        if (Object.keys(xhttpQuicParams).length) xhttpFinalmask.quicParams = xhttpQuicParams;
        if (Object.keys(xhttpFinalmask).length) stream.finalmask = xhttpFinalmask;
    } else if (type === 'httpupgrade') {
        stream.path = q.get('path') || '';
        stream.host = q.get('host') || '';
    } else if (type === 'grpc') {
        stream.path = q.get('serviceName') || '';
        if (!stream.authority) stream.authority = q.get('authority') || '';
    } else if (type === 'tcp') {
        if ((q.get('headerType') || '') === 'http') {
            stream.headerType = 'http';
            stream.path = q.get('path') || '';
            stream.host = q.get('host') || '';
        }
    }
    return stream;
}

export {
    decodeBase64Url,
    tryJSON,
    isHttpUrl,
    parseUrl,
    splitCSV,
    getQuery,
    asInt,
    sanitizeTag,
    generateSecretHex32,
    SUPPORTED_SCHEMES,
    MAX_SUB_REDIRECTS,
    SUB_FETCH_TIMEOUT,
    PROXY_FETCH_INTERVAL,
    SUB_REFRESH_INTERVAL,
    SUB_FALLBACK_RETRIES,
    URLTEST,
    URLTEST_CHOICES,
    URLTEST_INTERVAL,
    FETCH_INIT,
    PUBLIC_CORS_FALLBACKS,
    computeTag,
    CORE_PROTOCOL_SUPPORT,
    getAllowedCoreProtocols,
    getUrlTestChoice,
    validateBean,
    buildBeansFromInput,
    parseTunSpec,
    parseAddrHostPort,
    resolveUrlTest,
    resolveUrlTestExpectedStatus
};
