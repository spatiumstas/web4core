if (typeof document !== 'undefined') {
    document.addEventListener('keydown', function (e) {
        if ((e.ctrlKey || e.metaKey) && e.code === 'KeyS') {
            e.preventDefault();
            document.querySelector('input[type="submit"]').click();
        }
    });
}

function decodeBase64Url(input) {
    try {
        const s = input.replace(/-/g, '+').replace(/_/g, '/');
        const pad = s.length % 4 === 2 ? '==' : s.length % 4 === 3 ? '=' : '';
        return atob(s + pad);
    } catch {
        return '';
    }
}

function tryJSON(s) {
    try {
        return JSON.parse(s);
    } catch {
        return null;
    }
}

function isHttpUrl(s) {
    try {
        const u = new URL((s || '').trim());
        return u.protocol === 'http:' || u.protocol === 'https:';
    } catch {
        return false;
    }
}

const SUPPORTED_SCHEMES = ['vmess', 'vless', 'trojan', 'ss', 'socks', 'http', 'https', 'hy2', 'hysteria2', 'tuic', 'mieru', 'sdns'];
const SUPPORTED_SCHEMES_URL_REGEX = new RegExp(buildSchemesRegex().source + "[^\\s<>\"']+", 'ig');
const MAX_SUB_REDIRECTS = 2;
const SUB_FETCH_TIMEOUT = 15000;
const SUB_FALLBACK_RETRIES = 2;
const FETCH_INIT = {
    method: 'GET',
    cache: 'no-store',
    credentials: 'omit',
    headers: {'Accept': 'text/plain, */*'},
    redirect: 'follow'
};
const PUBLIC_CORS_FALLBACKS = [
    (x) => 'https://api.allorigins.win/raw?url=' + encodeURIComponent(x)
];
const URLTEST_URL = 'https://www.gstatic.com/generate_204';
const URLTEST_INTERVAL = '3m';

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

function splitCSV(str) {
    return (str || '').split(',').map(s => decodeURIComponent(s.trim())).filter(Boolean);
}

function getQuery(u) {
    return u.searchParams;
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
    if (!a) return {host, port};
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
    return {host, port};
}

function decodeAuthorityAndExtract(authority, defaultPort) {
    const dec = decodeBase64Url(authority || '');
    if (!dec || !dec.includes('@')) return null;
    const i = dec.lastIndexOf('@');
    const cred = dec.slice(0, i);
    const addr = dec.slice(i + 1);
    const uuid = findUuidToken(cred);
    const {host, port} = parseAddrHostPort(addr, defaultPort);
    return {uuid, host, port};
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
    return {method, password, host: ap.host, port: ap.port};
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
    switch (p) {
        case 'mieru':
            requireHost();
            requirePort();
            if (!bean.mieru?.username || !bean.mieru?.password) throw new Error('mieru: missing username/password');
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
            if (!isValidUuid(bean.auth.uuid)) throw new Error('vmess invalid UUID');
            break;
        case 'trojan':
            requireHost();
            requirePort();
            if (!bean.auth?.password) throw new Error('trojan: missing password');
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
        default:
            throw new Error('Unknown protocol: ' + p);
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
            return {name, mode};
        })
        .filter(x => x.name);
}

function parseLink(input) {
    const trimmed = input.trim();
    const scheme = trimmed.split(':', 1)[0].toLowerCase();
    if (scheme === 'mieru') return parseMieru(trimmed);
    if (scheme === 'vmess') return parseVMess(trimmed);
    if (scheme === 'vless') return parseVLESS(trimmed);
    if (scheme === 'trojan') return parseTrojan(trimmed);
    if (scheme === 'ss') return parseSS(trimmed);
    if (scheme.startsWith('socks')) return parseSocksHttp(trimmed);
    if (scheme === 'http' || scheme === 'https') return parseSocksHttp(trimmed);
    if (scheme === 'hy2' || scheme === 'hysteria2') return parseHysteria2(trimmed);
    if (scheme === 'tuic') return parseTUIC(trimmed);
    if (scheme === 'sdns') return parseSDNS(trimmed);
    throw new Error('Unknown link: ' + scheme);
}

function parseSocksHttp(urlStr) {
    const u = new URL(urlStr);
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
        name: decodeURIComponent(u.hash.replace('#', '')),
        socks: {
            type: isHttp || isHttps ? 'http' : (isSocks4 ? 'socks4' : 'socks5'),
            username: decodeURIComponent(u.username || ''),
            password: decodeURIComponent(u.password || '')
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
    const u = new URL(urlStr);
    const q = getQuery(u);
    const bean = {
        proto: 'trojan',
        host: u.hostname,
        port: asInt(u.port, 443),
        name: decodeURIComponent(u.hash.replace('#', '')),
        auth: {password: decodeURIComponent(u.username || '')},
        stream: buildStreamFromQuery(q, true),
        udp: q.get('udp') === '1' || q.get('udp') === 'true',
        udpOverTcp: q.get('udp-over-tcp') === '1' || q.get('udp-over-tcp') === 'true',
        ipVersion: q.get('ip-version') || ''
    };
    bean.stream = normalizeStream(bean.stream, bean.host);
    return bean;
}

function parseVLESS(urlStr) {
    const u = new URL(urlStr);
    if (u.protocol !== 'vless:') throw new Error('A vless:// link is required');
    const q = getQuery(u);
    const rawAfterScheme = urlStr.slice('vless://'.length);
    const rawAuthority = rawAfterScheme.split(/[?#]/)[0];
    let host = u.hostname;
    let port = asInt(u.port, 443);
    const rawUser = decodeURIComponent(u.username || '').trim();
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
        const pwd = decodeURIComponent(u.password || '').trim();
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
        name: decodeURIComponent(u.hash.replace('#', '')),
        auth: {
            uuid,
            flow: (q.get('flow') || '').replace(/-udp443$/, '').replace(/^none$/, '')
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
    const payload = urlStr.slice('vmess://'.length);
    const decoded = atob(payload || '');
    const obj = tryJSON(decoded);
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
            reality: {pbk: obj.pbk || '', sid: obj.sid || '', spx: obj.spx || ''}
        };
        const bean = {
            proto: 'vmess',
            host: obj.add || 'localhost',
            port: asInt(obj.port, 443),
            name: obj.ps || '',
            auth: {uuid: obj.id, security: obj.scy || 'auto'},
            stream,
            udp: obj.udp === true || obj.udp === 1,
            udpOverTcp: obj['udp-over-tcp'] === true,
            ipVersion: obj['ip-version'] || ''
        };
        bean.stream = normalizeStream(bean.stream, bean.host);
        return bean;
    }
    const u = new URL(urlStr);
    const q = getQuery(u);
    const bean = {
        proto: 'vmess',
        host: u.hostname,
        port: asInt(u.port, 443),
        name: decodeURIComponent(u.hash.replace('#', '')),
        auth: {uuid: decodeURIComponent(u.username || ''), security: q.get('encryption') || 'auto'},
        stream: buildStreamFromQuery(q, false),
        udp: q.get('udp') === '1' || q.get('udp') === 'true',
        udpOverTcp: q.get('udp-over-tcp') === '1' || q.get('udp-over-tcp') === 'true',
        ipVersion: q.get('ip-version') || ''
    };
    bean.stream = normalizeStream(bean.stream, bean.host);
    return bean;
}

function parseSS(urlStr) {
    const u = new URL(urlStr);
    const name = decodeURIComponent(u.hash.replace('#', ''));
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
    let plugin = q.get('plugin') || '';
    const pluginOpts = {};

    if (plugin && plugin.includes(';')) {
        const parts = plugin.split(';');
        plugin = parts[0].trim();
        for (let i = 1; i < parts.length; i++) {
            const kv = parts[i].split('=');
            if (kv.length === 2) {
                const key = kv[0].trim();
                const val = kv[1].trim();
                pluginOpts[key] = val;
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
            uot: q.get('uot') === '1' ? 1 : 0,
            plugin,
            pluginOpts: Object.keys(pluginOpts).length ? pluginOpts : '',
            smux: smuxEnabled ? smux : null
        },
        stream: {network: 'tcp', security: ''},
        udp: q.get('udp') === '1' || q.get('udp') === 'true',
        udpOverTcp: q.get('udp-over-tcp') === '1' || q.get('udp-over-tcp') === 'true'
    };
}

function parseHysteria2(urlStr) {
    const u = new URL(urlStr);
    const q = getQuery(u);
    const pwd = u.password ? (decodeURIComponent(u.username || '') + ':' + decodeURIComponent(u.password)) : decodeURIComponent(u.username || '');
    return {
        proto: 'hy2',
        host: u.hostname,
        port: asInt(u.port, 443),
        name: decodeURIComponent(u.hash.replace('#', '')),
        auth: {password: pwd},
        hysteria2: {
            obfsPassword: q.get('obfs-password') || '',
            hopPort: q.get('mport') || '',
            hopInterval: (q.get('hop_interval') || ''),
            alpn: q.get('alpn') || 'h3',
            sni: q.get('sni') || '',
            allowInsecure: ['1', 'true'].includes((q.get('insecure') || '').toLowerCase())
        }
    };
}

function parseTUIC(urlStr) {
    const u = new URL(urlStr);
    const q = getQuery(u);
    return {
        proto: 'tuic',
        host: u.hostname,
        port: asInt(u.port, 443),
        name: decodeURIComponent(u.hash.replace('#', '')),
        auth: {
            uuid: decodeURIComponent(u.username || ''),
            password: decodeURIComponent(u.password || '')
        },
        tuic: {
            congestion_control: q.get('congestion_control') || 'bbr',
            udp_relay_mode: q.get('udp_relay_mode') || 'native',
            zero_rtt_handshake: q.get('zero_rtt') === '1',
            udp_over_stream: q.get('udp_over_stream') === '1',
            heartbeat: q.get('heartbeat') || '',
            alpn: q.get('alpn') || '',
            sni: q.get('sni') || '',
            allowInsecure: q.get('allow_insecure') === '1',
            disableSni: q.get('disable_sni') === '1',
            token: q.get('token') || '',
            requestTimeout: q.get('request_timeout') || q.get('request-timeout') || '',
            reduceRtt: ['1', 'true'].includes((q.get('reduce_rtt') || q.get('reduce-rtt') || '').toLowerCase())
        }
    };
}

function parseMieru(urlStr) {
    const u = new URL(urlStr);
    if (u.protocol !== 'mieru:') throw new Error('A mieru:// link is required');
    const q = getQuery(u);
    const username = decodeURIComponent(u.username || '');
    const password = decodeURIComponent(u.password || '');
    const name = decodeURIComponent(u.hash.replace('#', ''));
    const serverPorts = q.get('server_ports') || q.get('ports') || '';
    const transport = (q.get('transport') || 'TCP').toUpperCase();
    const multiplexing = (q.get('multiplexing') || '').toUpperCase();
    return {
        proto: 'mieru',
        host: u.hostname,
        port: asInt(u.port, 27017),
        name,
        mieru: {
            username,
            password,
            server_ports: serverPorts,
            transport,
            multiplexing
        }
    };
}

function parseMieruProfilesJson(jsonObj) {
    if (!jsonObj || typeof jsonObj !== 'object') return [];
    const profiles = Array.isArray(jsonObj.profiles) ? jsonObj.profiles : [];
    if (!profiles.length) return [];
    const beans = [];
    for (const p of profiles) {
        const username = p?.user?.name || '';
        const password = p?.user?.password || '';
        const profileName = (p?.profileName || '').trim();
        const servers = Array.isArray(p?.servers) ? p.servers : [];
        const multiplexing = (p?.multiplexing || '').toString().toUpperCase();
        for (const s of servers) {
            const host = s?.ipAddress || s?.host || s?.hostname || '';
            const bindings = Array.isArray(s?.portBindings) ? s.portBindings : [];
            if (!host || !bindings.length) continue;
            for (const b of bindings) {
                const protocol = (b?.protocol || 'TCP').toString().toUpperCase();
                const portRange = (b?.portRange || '').toString();
                let serverPort = 27017;
                if (portRange) {
                    const m = portRange.match(/^(\d+)(?:-(\d+))?$/);
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
                        multiplexing
                    }
                };
                beans.push(bean);
            }
        }
    }
    return beans;
}

function parseSDNS(urlStr) {
    const u = new URL(urlStr);
    if (u.protocol !== 'sdns:') throw new Error('A sdns:// link is required');
    const stamp = urlStr;
    const name = decodeURIComponent(u.hash.replace('#', ''));
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
            if (obj.profiles) {
                const fromProfiles = parseMieruProfilesJson(obj);
                if (fromProfiles.length) return fromProfiles;
            }
            return [];
        }
    }
    const lines = text.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
    return lines.map(parseLink);
}

function buildStreamFromQuery(q, isTrojan) {
    let type = (q.get('type') || 'tcp').toLowerCase();
    if (type === 'h2') type = 'http';
    if (type === 'w' || type === 'websocket') type = 'ws';
    if (type !== 'xhttp' && (q.get('xhttp') === '1' || q.get('xhttp') === 'true')) type = 'xhttp';
    const security = (q.get('security') || (isTrojan ? 'tls' : '')).toLowerCase().replace('reality', 'tls').replace('none', '');
    const sni = q.get('sni') || q.get('peer') || '';
    const alpn = splitCSV(q.get('alpn') || '');
    const aiRaw = (q.get('allowInsecure') || q.get('insecure') || '').toLowerCase();
    const allowInsecure = ['1', 'true', 'yes'].includes(aiRaw);
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
        alpn,
        allowInsecure,
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
            stream.wsEarlyData = {max_early_data: ed, early_data_header_name: 'Sec-WebSocket-Protocol'};
        }
    } else if (type === 'http') {
        stream.path = q.get('path') || '';
        stream.host = (q.get('host') || '').replace(/\|/g, ',');
    } else if (type === 'xhttp') {
        stream.path = q.get('path') || '';
        stream.host = q.get('host') || '';
        stream.xhttpMode = q.get('xmode') || q.get('mode') || '';
        stream.xhttpXmux = {
            max_concurrency: q.get('xmux_max_concurrency') || '',
            max_connections: q.get('xmux_max_connections') || '',
            c_max_reuse_times: q.get('xmux_c_max_reuse_times') || '',
            h_max_request_times: q.get('xmux_h_max_request_times') || '',
            h_max_reusable_secs: q.get('xmux_h_max_reusable_secs') || '',
            h_keep_alive_period: asInt(q.get('xmux_h_keep_alive_period'), 0)
        };
        stream.xhttpDownload = {
            mode: q.get('download_mode') || '',
            host: q.get('download_host') || '',
            path: q.get('download_path') || '',
            x_padding_bytes: q.get('download_x_padding_bytes') || '',
            sc_max_each_post_bytes: q.get('download_sc_max_each_post_bytes') || '',
            sc_min_posts_interval_ms: q.get('download_sc_min_posts_interval_ms') || '',
            sc_stream_up_server_secs: q.get('download_sc_stream_up_server_secs') || '',
            server: q.get('download_server') || '',
            server_port: asInt(q.get('download_server_port'), 0),
            detour: q.get('download_detour') || ''
        };
    } else if (type === 'httpupgrade') {
        stream.path = q.get('path') || '';
        stream.host = q.get('host') || '';
    } else if (type === 'grpc') {
        stream.path = q.get('serviceName') || '';
    } else if (type === 'tcp') {
        if ((q.get('headerType') || '') === 'http') {
            stream.headerType = 'http';
            stream.path = q.get('path') || '';
            stream.host = q.get('host') || '';
        }
    }
    return stream;
}

function buildSingBoxOutbound(bean) {
    const commonTLS = () => {
        const s = bean.stream || {};
        const isReality = !!(s.reality && s.reality.pbk);
        const hasTlsHints = !!(s.sni || (s.alpn && s.alpn.length) || s.fp);
        const needTls = s.security === 'tls' || isReality || (['vless', 'vmess'].includes(bean.proto) && hasTlsHints);
        if (!needTls) return undefined;
        const tls = {enabled: true};
        if (s.allowInsecure) tls.insecure = true;
        if (s.sni) tls.server_name = s.sni;
        if (s.alpn && s.alpn.length) tls.alpn = s.alpn;
        if (isReality) {
            tls.reality = {enabled: true, public_key: s.reality.pbk, short_id: s.reality.sid || ''};
            if (!s.fp) tls.utls = {enabled: true, fingerprint: 'random'};
        }
        if (s.fp) tls.utls = {enabled: true, fingerprint: s.fp};
        return tls;
    };

    function applyTransport(outbound, stream) {
        if (stream.network !== 'tcp') {
            const t = {type: stream.network};
            if (stream.network === 'ws') {
                const hostHeader = stream.host || stream.sni || '';
                if (hostHeader) t.headers = {Host: hostHeader};
                const pathWithoutEd = (stream.path || '').split('?ed=')[0];
                if (pathWithoutEd) t.path = pathWithoutEd;
                const ed = stream.wsEarlyData?.max_early_data || 0;
                const edName = stream.wsEarlyData?.early_data_header_name || '';
                if (ed > 0) {
                    t.max_early_data = ed;
                    t.early_data_header_name = edName || 'Sec-WebSocket-Protocol';
                }
            } else if (stream.network === 'http') {
                if (stream.path) t.path = stream.path;
                if (stream.host) t.host = splitCSV(stream.host).map(s => s);
            } else if (stream.network === 'h2') {
                t.type = 'http';
                if (stream.path) t.path = stream.path;
                if (stream.host) t.host = splitCSV(stream.host).map(s => s);
            } else if (stream.network === 'xhttp') {
                if (!bean._useExtended) return;
                if (stream.path) t.path = stream.path;
                if (stream.host) t.host = stream.host;
                if (stream.xhttpMode) t.mode = stream.xhttpMode;

                const xmux = stream.xhttpXmux || {};
                const hasXmux = Object.values(xmux).some(v => v !== '' && v !== 0);
                if (hasXmux) {
                    t.xmux = {};
                    if (xmux.max_concurrency) t.xmux.max_concurrency = xmux.max_concurrency;
                    if (xmux.max_connections) t.xmux.max_connections = xmux.max_connections;
                    if (xmux.c_max_reuse_times) t.xmux.c_max_reuse_times = xmux.c_max_reuse_times;
                    if (xmux.h_max_request_times) t.xmux.h_max_request_times = xmux.h_max_request_times;
                    if (xmux.h_max_reusable_secs) t.xmux.h_max_reusable_secs = xmux.h_max_reusable_secs;
                    if (xmux.h_keep_alive_period) t.xmux.h_keep_alive_period = xmux.h_keep_alive_period;
                }

                const download = stream.xhttpDownload || {};
                const hasDownload = Object.values(download).some(v => v !== '' && v !== 0);
                if (hasDownload) {
                    t.download = {};
                    if (download.mode) t.download.mode = download.mode;
                    if (download.host) t.download.host = download.host;
                    if (download.path) t.download.path = download.path;
                    if (download.x_padding_bytes) t.download.x_padding_bytes = download.x_padding_bytes;
                    if (download.sc_max_each_post_bytes) t.download.sc_max_each_post_bytes = download.sc_max_each_post_bytes;
                    if (download.sc_min_posts_interval_ms) t.download.sc_min_posts_interval_ms = download.sc_min_posts_interval_ms;
                    if (download.sc_stream_up_server_secs) t.download.sc_stream_up_server_secs = download.sc_stream_up_server_secs;
                    if (download.server) t.download.server = download.server;
                    if (download.server_port) t.download.server_port = download.server_port;
                    if (download.detour) t.download.detour = download.detour;

                    if (hasXmux) {
                        t.download.xmux = t.xmux;
                    }
                }
            } else if (stream.network === 'grpc') {
                if (stream.path) t.service_name = stream.path;
            } else if (stream.network === 'httpupgrade') {
                if (stream.path) t.path = stream.path;
                if (stream.host) t.host = stream.host;
            }
            outbound.transport = t;
        } else if (stream.headerType === 'http') {
            outbound.transport = {
                type: 'http',
                method: 'GET',
                path: stream.path || '',
                headers: {Host: splitCSV(stream.host)}
            };
        }
        if (outbound.type === 'vmess' || outbound.type === 'vless') {
            if (bean.stream.packet_encoding) outbound.packet_encoding = bean.stream.packet_encoding;
        }
    }

    let outbound = null;
    if (bean.proto === 'vmess') outbound = {
        type: 'vmess',
        server: bean.host,
        server_port: bean.port,
        uuid: bean.auth.uuid,
        security: bean.auth.security || 'auto'
    }; else if (bean.proto === 'vless') {
        outbound = {type: 'vless', server: bean.host, server_port: bean.port, uuid: bean.auth.uuid};
        if (bean.auth.flow) outbound.flow = bean.auth.flow;
    } else if (bean.proto === 'trojan') outbound = {
        type: 'trojan',
        server: bean.host,
        server_port: bean.port,
        password: bean.auth.password
    }; else if (bean.proto === 'ss') outbound = {
        type: 'shadowsocks',
        server: bean.host,
        server_port: bean.port,
        method: bean.ss.method,
        password: bean.ss.password
    }; else if (bean.proto === 'socks' || bean.proto === 'http') {
        outbound = {type: bean.proto, server: bean.host, server_port: bean.port};
        if (bean.socks?.type === 'socks4') outbound.version = '4';
        if (bean.socks?.username && bean.socks?.password) {
            outbound.username = bean.socks.username;
            outbound.password = bean.socks.password;
        }
    } else if (bean.proto === 'hy2') {
        const tls = commonTLS() || {enabled: true, alpn: 'h3'};
        outbound = {type: 'hysteria2', server: bean.host, server_port: bean.port || 443, tls};
        outbound.password = bean.auth.password;
        if (bean.hysteria2?.obfsPassword) {
            outbound.obfs = {type: 'salamander', password: bean.hysteria2.obfsPassword};
        }
        if (bean.hysteria2?.hopPort) outbound.hop_ports = bean.hysteria2.hopPort;
        if (bean.hysteria2?.hopInterval) {
            const hi = String(bean.hysteria2.hopInterval).trim();
            const hasUnit = /(?:ms|s|m|h|d)$/i.test(hi);
            outbound.hop_interval = hasUnit ? hi : (/^\d+$/.test(hi) ? hi + 's' : hi);
        } else {
            outbound.hop_interval = '10s';
        }
    } else if (bean.proto === 'tuic') {
        const tls = commonTLS() || {enabled: true};
        outbound = {type: 'tuic', server: bean.host, server_port: bean.port || 443, tls};
        if (bean.auth.uuid) outbound.uuid = bean.auth.uuid;
        if (bean.auth.password) outbound.password = bean.auth.password;
        if (bean.tuic.congestion_control) outbound.congestion_control = bean.tuic.congestion_control;
        if (bean.tuic.udp_over_stream) outbound.udp_over_stream = true;
        else if (bean.tuic.udp_relay_mode) outbound.udp_relay_mode = bean.tuic.udp_relay_mode;
        if (bean.tuic.zero_rtt_handshake) outbound.zero_rtt_handshake = true;
        if (bean.tuic.heartbeat) outbound.heartbeat = bean.tuic.heartbeat;
    } else if (bean.proto === 'mieru') {
        outbound = {
            type: 'mieru',
            server: bean.host,
            server_port: bean.port
        };
        if (bean.mieru?.server_ports) outbound.server_ports = bean.mieru.server_ports;
        if (bean.mieru?.transport) outbound.transport = bean.mieru.transport;
        if (bean.mieru?.username) outbound.username = bean.mieru.username;
        if (bean.mieru?.password) outbound.password = bean.mieru.password;
        if (bean.mieru?.multiplexing) outbound.multiplexing = bean.mieru.multiplexing;
    } else throw new Error('Not supported by sing-box: ' + bean.proto);
    const tls = commonTLS();
    if (tls) outbound.tls = tls;
    if (bean.stream) {
        if ((outbound.type === 'vless' || outbound.type === 'vmess') && !bean.stream.packet_encoding) {
            if (outbound.type === 'vless') {
                if (bean._useExtended) bean.stream.packet_encoding = 'xudp';
            }
        }
        applyTransport(outbound, bean.stream);
    }
    return outbound;
}

function buildSingBoxInbounds(opts) {
    const inbounds = [];
    if (opts.addTun) {
        const specs = parseTunSpec(opts.tunName || '');
        const ifaces = specs.length ? specs.map(x => x.name) : ['singtun0'];
        for (let i = 0; i < ifaces.length; i++) {
            const name = ifaces[i];
            const tag = ifaces.length > 1 ? `tun-in-${name}` : 'tun-in';
            const octet = ifaces.length > 1 ? (i === 0 ? 1 : i * 10) : 1;
            const cidr = ifaces.length > 1 ? `${`172.19.0.${octet}`}/30` : '172.19.0.1/32';
            const tun = {
                type: 'tun',
                tag,
                interface_name: name,
                address: [cidr],
                stack: 'gvisor',
                auto_route: false,
                strict_route: false
            };
            inbounds.push(tun);
        }
    }
    if (opts.addSocks) {
        const specs = parseTunSpec(opts.tunName || '');
        if (opts.addTun && opts.perTunMixed && specs.length > 1) {
            const ifaces = specs.map(x => x.name);
            for (let i = 0; i < ifaces.length; i++) {
                const name = ifaces[i];
                inbounds.push({
                    tag: `mixed-in-${name}`,
                    type: 'mixed',
                    listen: '127.0.0.1',
                    listen_port: 2080 + i,
                });
            }
        } else {
            inbounds.push({
                tag: 'mixed-in',
                type: 'mixed',
                listen: '127.0.0.1',
                listen_port: 2080,
            });
        }
    }
    return inbounds;
}

function buildDNSServers(dnsBeans) {
    const servers = [];
    for (const bean of dnsBeans) {
        if (bean.proto === 'sdns') {
            servers.push({
                type: 'sdns',
                stamp: bean.sdns.stamp,
                tag: bean.name || 'sdns-server'
            });
        }
    }
    return servers;
}

function buildSingBoxConfig(outboundsWithTags, opts) {
    const tags = outboundsWithTags.map(ob => ob.tag);
    const inbounds = buildSingBoxInbounds(opts);
    const managementOutbounds = [];
    const routeRules = [];
    const hasMany = tags.length > 1;
    const tunSpecs = parseTunSpec(opts?.tunName || '');
    const inboundTagFor = (name) => (tunSpecs.length > 1 ? `tun-in-${name}` : 'tun-in');
    const mixedInboundTagFor = (name) => (tunSpecs.length > 1 ? `mixed-in-${name}` : 'mixed-in');
    let createdGlobalAuto = false;
    let createdGlobalSelector = false;

    if (hasMany) {
        const hasPerTunAuto = tunSpecs.some(t => t.mode === 'auto');
        const hasTun = tunSpecs.length > 0;
        if (!hasPerTunAuto && !hasTun) {
            managementOutbounds.push({
                type: 'urltest',
                tag: 'auto',
                outbounds: tags,
                url: URLTEST_URL,
                interval: URLTEST_INTERVAL,
                tolerance: 50,
                idle_timeout: '30m',
                interrupt_exist_connections: false
            });
            createdGlobalAuto = true;
            managementOutbounds.push({
                type: 'selector',
                tag: 'select',
                outbounds: ['auto', ...tags],
                default: 'auto',
                interrupt_exist_connections: false
            });
            createdGlobalSelector = true;
        } else if (!hasTun) {
            managementOutbounds.push({
                type: 'selector',
                tag: 'select',
                outbounds: tags,
                default: tags[0] || 'direct',
                interrupt_exist_connections: false
            });
            createdGlobalSelector = true;
        }
    } else {
        const onlyTag = tags[0] || 'direct';
        const hasTun = tunSpecs.length > 0;
        if (!hasTun) {
            managementOutbounds.push({
                type: 'selector',
                tag: 'select',
                outbounds: [onlyTag],
                default: onlyTag,
                interrupt_exist_connections: false
            });
            createdGlobalSelector = true;
        }
    }

    if (tunSpecs.length > 0) {
        const hasPerTunAuto = tunSpecs.some(t => t.mode === 'auto');
        const globalAutoAvailable = createdGlobalAuto === true;
        const autoNames = tunSpecs.filter(t => t.mode === 'auto').map(t => t.name);
        const selectNames = tunSpecs.filter(t => t.mode === 'select').map(t => t.name);

        for (const name of autoNames) {
            if (hasMany) {
                managementOutbounds.push({
                    type: 'urltest',
                    tag: `auto-${name}`,
                    outbounds: tags,
                    url: URLTEST_URL,
                    interval: URLTEST_INTERVAL,
                    tolerance: 50,
                    idle_timeout: '30m',
                    interrupt_exist_connections: false
                });
                routeRules.push({inbound: inboundTagFor(name), outbound: `auto-${name}`});
            } else {
                const onlyTag = tags[0] || 'direct';
                routeRules.push({inbound: inboundTagFor(name), outbound: onlyTag});
            }
        }
        for (const name of selectNames) {
            if (hasMany) {
                const outs = globalAutoAvailable ? ['auto', ...tags] : [...tags];
                const def = globalAutoAvailable ? 'auto' : (tags[0] || 'direct');
                managementOutbounds.push({
                    type: 'selector',
                    tag: `select-${name}`,
                    outbounds: outs,
                    default: def,
                    interrupt_exist_connections: false
                });
                routeRules.push({inbound: inboundTagFor(name), outbound: `select-${name}`});
            } else {
                const onlyTag = tags[0] || 'direct';
                routeRules.push({inbound: inboundTagFor(name), outbound: onlyTag});
            }
        }

        if (opts.addSocks && opts.perTunMixed) {
            for (const name of autoNames) {
                const onlyTag = tags[0] || 'direct';
                routeRules.push({inbound: mixedInboundTagFor(name), outbound: hasMany ? `auto-${name}` : onlyTag});
            }
            for (const name of selectNames) {
                const onlyTag = tags[0] || 'direct';
                routeRules.push({inbound: mixedInboundTagFor(name), outbound: hasMany ? `select-${name}` : onlyTag});
            }
        }
    }

    routeRules.push({ip_version: 6, outbound: 'block'});
    const outbounds = [
        ...managementOutbounds,
        ...outboundsWithTags,
        {tag: 'direct', type: 'direct'},
        {tag: 'block', type: 'block'}
    ];
    const config = {
        log: {level: 'info'},
        inbounds,
        outbounds,
        route: {rules: routeRules, final: (createdGlobalSelector ? 'select' : 'direct')},
        experimental: {
            cache_file: {enabled: true},
            clash_api: {
                external_controller: '[::]:9090',
                external_ui: 'ui',
                external_ui_download_detour: 'direct',
                access_control_allow_private_network: true,
                secret: opts?.genClashSecret ? generateSecretHex32() : ''
            },
        }
    };

    const dnsServers = (opts?.useExtended ? buildDNSServers(opts?.dnsBeans || []) : []);
    if (dnsServers.length > 0) {
        config.dns = {servers: dnsServers};
        config.route.default_domain_resolver = dnsServers[0]?.tag || '';
    }

    if (opts?.useExtended) {
        config.experimental.unified_delay = {enabled: true};
    }

    return config;
}

function buildXrayOutbound(bean) {
    const s = bean.stream || {};
    const network = s.network || 'tcp';
    const streamSettings = {network: (network === 'http' || network === 'h2') ? 'xhttp' : network};
    const hasReality = !!(s.reality && s.reality.pbk);
    const sec = hasReality ? 'reality' : (s.security === 'tls' ? 'tls' : '');
    if (sec === 'tls') {
        streamSettings.security = 'tls';
        streamSettings.tlsSettings = {};
        if (s.sni) streamSettings.tlsSettings.serverName = s.sni;
        if (s.alpn && s.alpn.length) streamSettings.tlsSettings.alpn = s.alpn;
        if (s.fp) streamSettings.tlsSettings.fingerprint = s.fp;
        if (s.allowInsecure) streamSettings.tlsSettings.allowInsecure = true;
    } else if (sec === 'reality') {
        streamSettings.security = 'reality';
        streamSettings.realitySettings = {show: false, publicKey: s.reality.pbk};
        if (s.reality.sid) streamSettings.realitySettings.shortId = s.reality.sid;
        if (s.sni) streamSettings.realitySettings.serverName = s.sni;
        if (s.fp) streamSettings.realitySettings.fingerprint = s.fp;
    }
    if (streamSettings.network === 'ws') {
        streamSettings.network = 'xhttp';
        streamSettings.xhttpSettings = {};
        if (s.host) streamSettings.xhttpSettings.host = s.host;
        if (s.path) streamSettings.xhttpSettings.path = s.path;
        streamSettings.xhttpSettings.mode = 'auto';
    } else if (streamSettings.network === 'xhttp') {
        streamSettings.xhttpSettings = {};
        if (s.host) streamSettings.xhttpSettings.host = s.host;
        if (s.path) streamSettings.xhttpSettings.path = s.path;
        if (s.xhttpMode) streamSettings.xhttpSettings.mode = s.xhttpMode; else streamSettings.xhttpSettings.mode = 'stream-up';
    } else if (streamSettings.network === 'grpc') {
        streamSettings.network = 'xhttp';
        streamSettings.xhttpSettings = {};
        if (s.path) streamSettings.xhttpSettings.path = s.path;
        if (s.host) streamSettings.xhttpSettings.host = s.host;
        streamSettings.xhttpSettings.mode = 'stream-up';
    } else if (streamSettings.network === 'tcp' && s.headerType === 'http') {
        streamSettings.tcpSettings = {header: {type: 'http', request: {headers: {Host: s.host}}}};
        if (s.path) streamSettings.tcpSettings.header.request.path = [s.path];
    }
    if (streamSettings.network === 'xhttp' && streamSettings.tlsSettings && Array.isArray(streamSettings.tlsSettings.alpn)) {
        streamSettings.tlsSettings.alpn = streamSettings.tlsSettings.alpn.filter(v => (v || '').toLowerCase() !== 'http/1.1');
        if (streamSettings.tlsSettings.alpn.length === 0) delete streamSettings.tlsSettings.alpn;
    }
    let outbound = null;
    if (bean.proto === 'vmess') {
        outbound = {
            protocol: 'vmess',
            tag: (bean.name || 'vmess'),
            settings: {
                vnext: [{
                    address: bean.host,
                    port: bean.port,
                    users: [{
                        id: bean.auth.uuid,
                        security: bean.auth.security || 'auto'
                    }]
                }]
            }
        };
    } else if (bean.proto === 'vless') {
        const user = {id: bean.auth.uuid, encryption: 'none'};
        if (bean.auth.flow) user.flow = bean.auth.flow;
        outbound = {
            protocol: 'vless',
            tag: (bean.name || 'vless'),
            settings: {vnext: [{address: bean.host, port: bean.port, users: [user]}]}
        };
    } else if (bean.proto === 'trojan') outbound = {
        protocol: 'trojan',
        tag: (bean.name || 'trojan'),
        settings: {servers: [{address: bean.host, port: bean.port, password: bean.auth.password}]}
    }; else if (bean.proto === 'ss') outbound = {
        protocol: 'shadowsocks',
        tag: (bean.name || 'ss'),
        settings: {servers: [{address: bean.host, port: bean.port, method: bean.ss.method, password: bean.ss.password}]}
    }; else if (bean.proto === 'socks' || bean.proto === 'http') {
        const s = {address: bean.host, port: bean.port};
        if (bean.socks?.username && bean.socks?.password) {
            s.users = [{user: bean.socks.username, pass: bean.socks.password}];
        }
        outbound = {protocol: bean.proto, tag: (bean.name || bean.proto), settings: {servers: [s]}};
    } else if (bean.proto === 'hy2' || bean.proto === 'tuic') {
        throw new Error(bean.proto + ' not supported in Xray');
    } else {
        throw new Error('Unknown protocol: ' + bean.proto);
    }
    outbound.streamSettings = streamSettings;
    return outbound;
}

function buildXrayConfig(outbounds, opts) {
    if (!Array.isArray(outbounds)) outbounds = [outbounds];
    if (outbounds.length === 1) {
        return {
            log: {loglevel: 'warning'},
            inbounds: [{tag: 'socks-in', port: 1080, listen: '127.0.0.1', protocol: 'socks', settings: {udp: true}}],
            outbounds: [outbounds[0], {tag: 'direct', protocol: 'freedom'}, {tag: 'block', protocol: 'blackhole'}]
        };
    }
    const basePort = 1080;
    const enableBalancer = !!(opts && opts.enableBalancer);
    const inbounds = enableBalancer
        ? [{tag: 'socks-in', port: basePort, listen: '127.0.0.1', protocol: 'socks', settings: {udp: true}}]
        : outbounds.map((ob, idx) => ({
            tag: `socks-in-${idx + 1}`,
            port: basePort + idx,
            listen: '127.0.0.1',
            protocol: 'socks',
            settings: {udp: true}
        }));
    const rules = enableBalancer
        ? [{inboundTag: ['socks-in'], balancerTag: 'auto'}]
        : outbounds.map((ob, idx) => ({
            inboundTag: [`socks-in-${idx + 1}`],
            outboundTag: ob.tag || 'proxy'
        }));
    const routing = enableBalancer
        ? {
            rules,
            balancers: [{
                tag: 'auto',
                selector: outbounds.map(ob => ob.tag).filter(Boolean),
                strategy: {type: 'leastPing'}
            }]
        }
        : {rules};
    const config = {
        log: {loglevel: 'warning'},
        inbounds,
        outbounds: [...outbounds, {tag: 'direct', protocol: 'freedom'}, {tag: 'block', protocol: 'blackhole'}],
        routing
    };
    if (enableBalancer) {
        const selector = outbounds.map(ob => ob.tag).filter(Boolean);
        config.observatory = {
            subjectSelector: selector,
            probeURL: URLTEST_URL,
            probeInterval: URLTEST_INTERVAL,
            enableConcurrency: selector.length > 8
        };
    }
    return config;
}

function toYamlScalar(value, key) {
    if (value === null || value === undefined) return '';
    if (typeof value === 'boolean') return value ? 'true' : 'false';
    if (typeof value === 'number') return String(value);
    const s = String(value);
    if (key === 'grpc-service-name') {
        return '"' + s.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
    }
    if (/^[A-Za-z0-9_.:@#\-]+$/.test(s)) return s;
    return '"' + s.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
}

function toYAML(obj, indent = 0) {
    const space = '  '.repeat(indent);
    if (Array.isArray(obj)) {
        return obj.map(item => {
            if (item && typeof item === 'object') {
                const body = toYAML(item, indent + 1);
                const lines = body.split('\n');
                const indentPrefix = '  '.repeat(indent + 1);
                const firstLine = (lines[0] || '').replace(new RegExp('^' + indentPrefix), '');
                const rest = lines.slice(1).join('\n');
                return space + '- ' + firstLine + (rest ? '\n' + rest : '');
            }
            return space + '- ' + toYamlScalar(item, null);
        }).join('\n');
    }
    if (obj && typeof obj === 'object') {
        const lines = [];
        for (const [k, v] of Object.entries(obj)) {
            if (v === undefined) continue;
            if (v && typeof v === 'object') {
                const child = toYAML(v, indent + 1);
                if (child) {
                    lines.push(space + k + ':');
                    lines.push(child);
                } else {
                    lines.push(space + k + ': {}');
                }
            } else {
                lines.push(space + k + ': ' + toYamlScalar(v, k));
            }
        }
        return lines.join('\n');
    }
    return space + toYamlScalar(obj, null);
}

function buildMihomoProxy(bean) {
    const s = bean.stream || {};
    const base = {name: bean.name || computeTag(bean, new Set()), type: '', server: bean.host, port: bean.port};
    const applyCommon = (obj) => {
        if (bean.udp === true) obj.udp = true;
        if (bean.udpOverTcp === true) obj['udp-over-tcp'] = true;
        if (bean.ipVersion) obj['ip-version'] = bean.ipVersion;
    };
    const applyTls = (obj) => {
        if (s.security === 'tls') {
            obj.tls = true;
            if (s.sni) {
                obj.servername = s.sni;
                if (bean.proto === 'http' || bean.proto === 'tuic' || bean.proto === 'hy2' || bean.proto === 'trojan') {
                    obj.sni = s.sni;
                }
            }
            if (s.alpn && s.alpn.length) obj.alpn = s.alpn;
            if (s.allowInsecure) obj['skip-cert-verify'] = true;
            if (s.fp) obj['client-fingerprint'] = s.fp;
            if (s.reality && s.reality.pbk) {
                const ro = {'public-key': s.reality.pbk};
                if (s.reality.sid) ro['short-id'] = s.reality.sid;
                if (s.reality.spx) ro['spider-x'] = s.reality.spx;
                if (s.reality.pqv) ro.pqv = s.reality.pqv;
                obj['reality-opts'] = ro;
            }
        }
    };
    const applyNetwork = (obj) => {
        if (s.network === 'ws') {
            obj.network = 'ws';
            obj['ws-opts'] = {};
            if (s.path) obj['ws-opts'].path = s.path;
            if (s.host) obj['ws-opts'].headers = {Host: s.host};
            if (s.wsEarlyData && s.wsEarlyData.max_early_data) {
                obj['ws-opts']['max-early-data'] = s.wsEarlyData.max_early_data;
                if (s.wsEarlyData.early_data_header_name) obj['ws-opts']['early-data-header-name'] = s.wsEarlyData.early_data_header_name;
            }
        } else if (s.network === 'http') {
            obj.network = 'http';
            obj['http-opts'] = {};
            if (s.path) obj['http-opts'].path = [s.path];
            if (s.host) obj['http-opts'].host = s.host.split(',').map(x => x.trim()).filter(Boolean);
        } else if (s.network === 'h2') {
            obj.network = 'h2';
            obj['h2-opts'] = {};
            if (s.path) obj['h2-opts'].path = s.path;
            if (s.host) obj['h2-opts'].host = s.host.split(',').map(x => x.trim()).filter(Boolean);
        } else if (s.network === 'grpc') {
            obj.network = 'grpc';
            obj['grpc-opts'] = {};
            if (s.path) obj['grpc-opts']['grpc-service-name'] = s.path;
        } else if (s.network === 'tcp' && s.headerType === 'http') {
            obj.network = 'tcp';
            obj['http-opts'] = {headers: {Host: s.host}, path: [s.path].filter(Boolean)};
        } else {
            obj.network = 'tcp';
        }
    };
    if (bean.proto === 'vmess') {
        const p = {...base, type: 'vmess', uuid: bean.auth.uuid, cipher: bean.auth.security || 'auto', alterId: 0};
        applyTls(p);
        applyNetwork(p);
        applyCommon(p);
        return p;
    }
    if (bean.proto === 'vless') {
        const p = {...base, type: 'vless', uuid: bean.auth.uuid, encryption: 'none'};
        if (bean.auth.flow) p.flow = bean.auth.flow;
        applyTls(p);
        applyNetwork(p);
        applyCommon(p);
        return p;
    }
    if (bean.proto === 'trojan') {
        const p = {...base, type: 'trojan', password: bean.auth.password};
        applyTls(p);
        applyNetwork(p);
        applyCommon(p);
        return p;
    }
    if (bean.proto === 'ss') {
        const p = {...base, type: 'ss', cipher: bean.ss.method, password: bean.ss.password};
        if (bean.ss.plugin) {
            p.plugin = bean.ss.plugin;
            if (bean.ss.pluginOpts && typeof bean.ss.pluginOpts === 'object') {
                p['plugin-opts'] = bean.ss.pluginOpts;
            }
        }
        if (bean.ss.smux && bean.ss.smux.enabled) {
            p.smux = bean.ss.smux;
        }
        applyCommon(p);
        return p;
    }
    if (bean.proto === 'http') {
        const p = {...base, type: 'http'};
        if (bean.socks?.username) p.username = bean.socks.username;
        if (bean.socks?.password) p.password = bean.socks.password;
        applyTls(p);
        applyCommon(p);
        return p;
    }
    if (bean.proto === 'socks') {
        if (bean.socks?.type === 'socks4') {
            throw new Error('Mihomo does not support: socks4');
        }
        const p = {...base, type: 'socks5'};
        if (bean.socks?.username) p.username = bean.socks.username;
        if (bean.socks?.password) p.password = bean.socks.password;
        applyCommon(p);
        return p;
    }
    if (bean.proto === 'hy2') {
        const p = {...base, type: 'hysteria2', password: bean.auth.password};
        if (bean.hysteria2?.alpn) p.alpn = bean.hysteria2.alpn.split(',').filter(Boolean);
        if (bean.hysteria2?.sni) p.sni = bean.hysteria2.sni;
        if (bean.hysteria2?.allowInsecure) p['skip-cert-verify'] = true;
        if (bean.hysteria2?.obfsPassword) {
            p.obfs = 'salamander';
            p['obfs-password'] = bean.hysteria2.obfsPassword;
        }
        if (bean.hysteria2?.hopInterval) {
            const hi = String(bean.hysteria2.hopInterval).trim();
            const m = hi.match(/^(\d+)/);
            if (m && m[1]) {
                p['hop-interval'] = parseInt(m[1], 10);
            }
        }
        applyCommon(p);
        return p;
    }
    if (bean.proto === 'tuic') {
        const p = {...base, type: 'tuic'};
        if (bean.tuic?.token) {
            p.token = bean.tuic.token;
        } else {
            if (bean.auth?.uuid) p.uuid = bean.auth.uuid;
            if (bean.auth?.password) p.password = bean.auth.password;
        }
        if (bean.tuic?.alpn) p.alpn = bean.tuic.alpn.split(',').filter(Boolean);
        if (bean.tuic?.sni) p.sni = bean.tuic.sni;
        if (bean.tuic?.allowInsecure) p['skip-cert-verify'] = true;
        if (bean.tuic?.congestion_control) p['congestion-controller'] = bean.tuic.congestion_control;
        if (bean.tuic?.udp_relay_mode) p['udp-relay-mode'] = bean.tuic.udp_relay_mode;
        if (bean.tuic?.disableSni) p['disable-sni'] = true;
        if (bean.tuic?.heartbeat) {
            const hb = String(bean.tuic.heartbeat).trim();
            p['heartbeat-interval'] = /^\d+$/.test(hb) ? parseInt(hb, 10) : hb;
        }
        if (bean.tuic?.requestTimeout) {
            const rt = String(bean.tuic.requestTimeout).trim();
            p['request-timeout'] = /^\d+$/.test(rt) ? parseInt(rt, 10) : rt;
        }
        if (bean.tuic?.reduceRtt) p['reduce-rtt'] = true;
        applyCommon(p);
        return p;
    }
    throw new Error('Not supported by Mihomo: ' + bean.proto);
}

function deduplicateProxies(beans) {
    const seen = new Set();
    return beans.filter(b => {
        const auth = b.auth?.uuid || b.auth?.password || b.ss?.password || b.socks?.username || '';
        const network = b.stream?.network || 'tcp';
        const security = b.stream?.security || '';
        const flow = b.auth?.flow || '';
        const pqv = b.stream?.reality?.pqv || '';
        const pqvKey = pqv ? pqv.substring(0, 50) : '';
        const key = `${b.proto}|${b.host}|${b.port}|${auth}|${network}|${security}|${flow}|${pqvKey}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    });
}

function buildMihomoConfig(beans) {
    const dedupedBeans = deduplicateProxies(beans);
    const proxies = dedupedBeans.map(b => buildMihomoProxy(b));
    const used = new Set();
    for (const p of proxies) {
        let base = (p.name || 'proxy').toString();
        if (!base.trim()) base = 'proxy';
        let name = base;
        let i = 2;
        while (used.has(name)) {
            name = `${base}-${i++}`;
        }
        p.name = name;
        used.add(name);
    }
    const names = proxies.map(p => p.name);
    const groups = [];
    if (names.length > 1) {
        groups.push({
            name: 'auto',
            type: 'url-test',
            proxies: names,
            url: 'https://www.gstatic.com/generate_204',
            interval: 45
        });
    }
    groups.push({name: 'select', type: 'select', proxies: names.length > 1 ? ['auto', ...names] : names});
    const config = {
        'mixed-port': 7890,
        'allow-lan': false,
        mode: 'rule',
        'log-level': 'info',
        proxies,
        'proxy-groups': groups,
        rules: ['MATCH,select']
    };
    return config;
}

function overlayMihomoYaml(baseYamlText, proxies, groups, providers, rules) {
    const text = (baseYamlText || '').replace(/\r\n/g, '\n');
    const lines = text.split('\n');
    const findSection = (key) => {
        const start = lines.findIndex(l => new RegExp('^' + key + '\\s*:\\s*$', 'i').test(l));
        if (start === -1) return {start: -1, end: -1};
        let end = start + 1;
        while (end < lines.length) {
            const ln = lines[end];
            if (/^[^\s#][^:]*:\s*/.test(ln)) break;
            end++;
        }
        return {start, end};
    };
    const replaceSection = (key, sectionYaml) => {
        const {start, end} = findSection(key);
        const inject = (key + ':\n' + toYAML(sectionYaml, 1));
        if (start === -1) {
            lines.push('', inject);
        } else {
            lines.splice(start, end - start, ...inject.split('\n'));
        }
    };
    replaceSection('proxies', proxies);
    replaceSection('proxy-groups', groups);
    if (providers) replaceSection('proxy-providers', providers);
    if (rules) replaceSection('rules', rules);
    return lines.join('\n');
}

const MIHOMO_DEFAULT_TEMPLATE = [
    'mixed-port: 7890',
    'allow-lan: false',
    'tcp-concurrent: true',
    'mode: rule',
    'log-level: info',
    'ipv6: false',
    'unified-delay: true',
    'profile:',
    '  store-selected: true',
    '  store-fake-ip: true',
    'dns:',
    '  enable: true',
    '  prefer-h3: true',
    '  use-system-hosts: true',
    '  enhanced-mode: redir-host',
    '  nameserver:',
    '    - https://cloudflare-dns.com/dns-query',
    '',
    'proxies:',
    'proxy-groups:',
    'rules:',
    '  - "MATCH,select"'
].join('\n');

try {
    if (typeof globalThis !== 'undefined') globalThis.MIHOMO_DEFAULT_TEMPLATE = MIHOMO_DEFAULT_TEMPLATE;
} catch {
}

async function fetchSubscription(url) {
    if (typeof fetch !== 'function') throw new Error('Fetch API not available');

    async function tryFetch(u) {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), SUB_FETCH_TIMEOUT);
        try {
            const resp = await fetch(u, {
                method: 'GET',
                cache: 'no-store',
                credentials: 'omit',
                headers: {
                    'Accept': 'text/plain, */*'
                },
                redirect: 'follow',
                signal: controller.signal
            });
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

        const direct = isHttpUrl(u) ? await tryFetch(u) : {error: new Error('not-http')};
        const attempts = [];
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
    const lines = body.split(/\n/).map(s => s.trim()).filter(Boolean);
    const allowed = new Set(SUPPORTED_SCHEMES);
    const filtered = lines.filter(line => allowed.has((line.split(':', 1)[0] || '').toLowerCase()));
    return filtered.join('\n');
}

function buildLinkFromBean(bean) {
    const namePart = bean.name ? ('#' + encodeURIComponent(bean.name)) : '';
    const s = bean.stream || {};
    const qp = new URLSearchParams();
    const addParam = (k, v) => {
        if (v === undefined || v === null) return;
        const sv = Array.isArray(v) ? v.join(',') : String(v);
        if (sv !== '') qp.set(k, sv);
    };
    const addTlsAndReality = () => {
        const hasReality = !!(s.reality && s.reality.pbk);
        const hasTls = (s.security === 'tls') || hasReality;
        if (hasTls) qp.set('security', hasReality ? 'reality' : 'tls');
        addParam('sni', s.sni);
        if (Array.isArray(s.alpn) && s.alpn.length) addParam('alpn', s.alpn);
        addParam('fp', s.fp);
        if (hasReality) {
            addParam('pbk', s.reality.pbk);
            addParam('sid', s.reality.sid);
            addParam('spx', s.reality.spx);
            addParam('pqv', s.reality.pqv);
        }
    };
    const addCommonFlags = () => {
        if (bean.udp === true) qp.set('udp', '1');
        if (bean.udpOverTcp === true) qp.set('udp-over-tcp', '1');
        if (bean.ipVersion) qp.set('ip-version', bean.ipVersion);
    };
    const addTransport = () => {
        const net = (s.network || 'tcp').toLowerCase();
        if (net && net !== 'tcp') qp.set('type', net === 'h2' ? 'http' : net);
        if (net === 'ws') {
            addParam('path', s.path);
            addParam('host', s.host);
            if (s.wsEarlyData && s.wsEarlyData.max_early_data) addParam('ed', String(s.wsEarlyData.max_early_data));
        } else if (net === 'http' || net === 'h2') {
            addParam('path', s.path);
            addParam('host', s.host);
        } else if (net === 'grpc') {
            addParam('serviceName', s.path);
        } else if (net === 'httpupgrade') {
            addParam('path', s.path);
            addParam('host', s.host);
        } else if (net === 'xhttp') {
            addParam('path', s.path);
            addParam('host', s.host);
            addParam('xmode', s.xhttpMode);
        }
        if (s.headerType === 'http') {
            qp.set('headerType', 'http');
            addParam('path', s.path);
            addParam('host', s.host);
        }
    };
    switch (bean.proto) {
        case 'vless': {
            addTlsAndReality();
            addTransport();
            if (bean.auth?.flow) qp.set('flow', bean.auth.flow);
            qp.set('encryption', 'none');
            {
                const net0 = (s.network || 'tcp').toLowerCase();
                const net = (net0 === 'h2') ? 'http' : net0;
                qp.set('type', net);
            }
            addCommonFlags();
            const user = encodeURIComponent(bean.auth?.uuid || '');
            return `vless://${user}@${bean.host}:${bean.port}?${qp.toString()}${namePart}`;
        }
        case 'vmess': {
            const obj = {
                add: bean.host,
                port: bean.port,
                id: bean.auth?.uuid || '',
                ps: bean.name || '',
                scy: bean.auth?.security || 'auto',
                net: (s.network || 'tcp'),
                alpn: Array.isArray(s.alpn) && s.alpn.length ? s.alpn.join(',') : '',
                host: s.host || '',
                path: s.path || '',
                type: s.headerType || '',
                fp: s.fp || '',
                pac_enc: s.packet_encoding || ''
            };
            if (s.reality && s.reality.pbk) {
                obj.tls = 'reality';
                obj.pbk = s.reality.pbk;
                if (s.reality.sid) obj.sid = s.reality.sid;
                if (s.reality.spx) obj.spx = s.reality.spx;
            } else {
                obj.tls = (s.security === 'tls') ? 'tls' : '';
            }
            if (s.sni) obj.sni = s.sni;
            const b64 = btoa(JSON.stringify(obj));
            return `vmess://${b64}`;
        }
        case 'trojan': {
            addTlsAndReality();
            addTransport();
            {
                const net0 = (s.network || 'tcp').toLowerCase();
                const net = (net0 === 'h2') ? 'http' : net0;
                qp.set('type', net);
            }
            addCommonFlags();
            const user = encodeURIComponent(bean.auth?.password || '');
            return `trojan://${user}@${bean.host}:${bean.port}?${qp.toString()}${namePart}`;
        }
        case 'http': {
            addTlsAndReality();
            addCommonFlags();
            const scheme = (s.security === 'tls') ? 'https' : 'http';
            const user = encodeURIComponent(bean.socks?.username || '');
            const pass = encodeURIComponent(bean.socks?.password || '');
            const auth = (user || pass) ? `${user}:${pass}@` : '';
            return `${scheme}://${auth}${bean.host}:${bean.port}${qp.toString() ? ('?' + qp.toString()) : ''}${namePart}`;
        }
        case 'socks': {
            addTlsAndReality();
            addTransport();
            addCommonFlags();
            const ver = (bean.socks?.type === 'socks4') ? 'socks4' : 'socks5';
            const user = encodeURIComponent(bean.socks?.username || '');
            const pass = encodeURIComponent(bean.socks?.password || '');
            const auth = (user || pass) ? `${user}:${pass}@` : '';
            return `${ver}://${auth}${bean.host}:${bean.port}${qp.toString() ? ('?' + qp.toString()) : ''}${namePart}`;
        }
        default:
            throw new Error('Unknown protocol: ' + bean.proto);
    }
}

function beansToLinks(beans) {
    const links = [];
    for (const b of beans) {
        validateBean(b);
        links.push(buildLinkFromBean(b));
    }
    return links.join('\n');
}

function parseSingBoxConfigToBeans(conf) {
    const beans = [];
    const obs = Array.isArray(conf?.outbounds) ? conf.outbounds : [];
    for (const ob of obs) {
        const t = (ob?.type || '').toLowerCase();
        const supported = ['vmess', 'vless', 'trojan', 'shadowsocks', 'socks', 'http', 'hysteria2', 'tuic', 'mieru'];
        if (!supported.includes(t)) continue;
        const s = {network: 'tcp', security: '', sni: '', alpn: [], allowInsecure: false, fp: '', reality: {}};
        if (ob?.tls && (ob.tls.enabled || ob.tls.reality)) {
            s.security = 'tls';
            if (ob.tls.server_name) s.sni = ob.tls.server_name;
            if (Array.isArray(ob.tls.alpn)) s.alpn = ob.tls.alpn;
            if (ob.tls.utls && ob.tls.utls.fingerprint) s.fp = ob.tls.utls.fingerprint;
            if (ob.tls.reality && (ob.tls.reality.public_key || ob.tls.reality.short_id)) {
                s.reality = {pbk: ob.tls.reality.public_key || '', sid: ob.tls.reality.short_id || ''};
                if (ob.tls.reality.spider_x) s.reality.spx = ob.tls.reality.spider_x;
            }
        }
        if (ob?.transport && ob.transport.type) {
            const tt = ob.transport.type;
            if (tt === 'http') {
                if (t === 'vmess' || t === 'vless') {
                    s.network = 'http';
                    if (ob.transport.path) s.path = ob.transport.path;
                    if (ob.transport.host) s.host = Array.isArray(ob.transport.host) ? ob.transport.host.join(',') : ob.transport.host;
                } else {
                    s.network = 'http';
                }
            } else if (tt === 'ws') {
                s.network = 'ws';
                if (ob.transport.path) s.path = ob.transport.path;
                if (ob.transport.headers && ob.transport.headers.Host) s.host = ob.transport.headers.Host;
                if (typeof ob.transport.max_early_data === 'number' && ob.transport.max_early_data > 0) {
                    s.wsEarlyData = {
                        max_early_data: ob.transport.max_early_data,
                        early_data_header_name: ob.transport.early_data_header_name || 'Sec-WebSocket-Protocol'
                    };
                }
            } else if (tt === 'grpc') {
                s.network = 'grpc';
                if (ob.transport.service_name) s.path = ob.transport.service_name;
            } else if (tt === 'httpupgrade') {
                s.network = 'httpupgrade';
                if (ob.transport.path) s.path = ob.transport.path;
                if (ob.transport.host) s.host = ob.transport.host;
            } else if (tt === 'xhttp') {
                s.network = 'xhttp';
                if (ob.transport.path) s.path = ob.transport.path;
                if (ob.transport.host) s.host = ob.transport.host;
                if (ob.transport.mode) s.xhttpMode = ob.transport.mode;
            }
        } else if (ob?.transport === undefined && ob?.type && (ob.type === 'vless' || ob.type === 'vmess') && ob?.packet_encoding) {
            s.packet_encoding = ob.packet_encoding;
        }
        if (t === 'vmess') {
            beans.push({
                proto: 'vmess',
                host: ob.server,
                port: ob.server_port,
                name: ob.tag || 'vmess',
                auth: {uuid: ob.uuid, security: ob.security || 'auto'},
                stream: s
            });
        } else if (t === 'vless') {
            const bean = {
                proto: 'vless',
                host: ob.server,
                port: ob.server_port,
                name: ob.tag || 'vless',
                auth: {uuid: ob.uuid},
                stream: s
            };
            if (ob.flow) bean.auth.flow = ob.flow;
            if (ob.packet_encoding) s.packet_encoding = ob.packet_encoding;
            beans.push(bean);
        } else if (t === 'trojan') {
            beans.push({
                proto: 'trojan',
                host: ob.server,
                port: ob.server_port,
                name: ob.tag || 'trojan',
                auth: {password: ob.password},
                stream: s
            });
        } else if (t === 'shadowsocks') {
            beans.push({
                proto: 'ss',
                host: ob.server,
                port: ob.server_port,
                name: ob.tag || 'ss',
                ss: {method: ob.method, password: ob.password},
                stream: {network: 'tcp', security: ''}
            });
        } else if (t === 'socks' || t === 'http') {
            const sock = {};
            if (ob.username) sock.username = ob.username;
            if (ob.password) sock.password = ob.password;
            if (ob.version === '4') sock.type = 'socks4';
            beans.push({proto: t, host: ob.server, port: ob.server_port, name: ob.tag || t, socks: sock, stream: s});
        } else if (t === 'hysteria2') {
            const hy = {alpn: Array.isArray(s.alpn) ? s.alpn.join(',') : '', sni: s.sni || '', allowInsecure: false};
            if (ob.obfs && ob.obfs.type === 'salamander' && ob.obfs.password) hy.obfsPassword = ob.obfs.password;
            if (ob.hop_ports) hy.hopPort = ob.hop_ports;
            if (ob.hop_interval) hy.hopInterval = ob.hop_interval;
            beans.push({
                proto: 'hy2',
                host: ob.server,
                port: ob.server_port,
                name: ob.tag || 'hy2',
                auth: {password: ob.password},
                hysteria2: hy,
                stream: s
            });
        } else if (t === 'tuic') {
            const tu = {};
            if (ob.congestion_control) tu.congestion_control = ob.congestion_control;
            if (ob.udp_over_stream) tu.udp_over_stream = true; else if (ob.udp_relay_mode) tu.udp_relay_mode = ob.udp_relay_mode;
            if (ob.zero_rtt_handshake) tu.zero_rtt_handshake = true;
            if (ob.heartbeat) tu.heartbeat = ob.heartbeat;
            const auth = {uuid: ob.uuid || '', password: ob.password || ''};
            if (ob.token) tu.token = ob.token;
            beans.push({
                proto: 'tuic',
                host: ob.server,
                port: ob.server_port,
                name: ob.tag || 'tuic',
                auth,
                tuic: tu,
                stream: s
            });
        } else if (t === 'mieru') {
            const m = {};
            if (ob.server_ports) m.server_ports = ob.server_ports;
            if (ob.transport) m.transport = ob.transport;
            if (ob.username) m.username = ob.username;
            if (ob.password) m.password = ob.password;
            if (ob.multiplexing) m.multiplexing = ob.multiplexing;
            beans.push({proto: 'mieru', host: ob.server, port: ob.server_port, name: ob.tag || 'mieru', mieru: m});
        }
    }
    return beans;
}

function parseXrayConfigToBeans(conf) {
    const beans = [];
    const obs = Array.isArray(conf?.outbounds) ? conf.outbounds : [];
    for (const ob of obs) {
        const p = (ob?.protocol || '').toLowerCase();
        const supported = ['vmess', 'vless', 'trojan', 'shadowsocks', 'socks', 'http'];
        if (!supported.includes(p)) continue;
        const s = {
            network: 'tcp',
            security: '',
            sni: '',
            alpn: [],
            allowInsecure: false,
            fp: '',
            reality: {},
            headerType: '',
            host: '',
            path: ''
        };
        const ss = ob.streamSettings || {};
        const net = (ss.network || 'tcp').toLowerCase();
        if (net === 'xhttp') s.network = 'xhttp'; else s.network = net;
        if (ss.tlsSettings) {
            s.security = 'tls';
            if (ss.tlsSettings.serverName) s.sni = ss.tlsSettings.serverName;
            if (Array.isArray(ss.tlsSettings.alpn)) s.alpn = ss.tlsSettings.alpn;
            if (ss.tlsSettings.fingerprint) s.fp = ss.tlsSettings.fingerprint;
            if (ss.tlsSettings.allowInsecure) s.allowInsecure = true;
        }
        if (ss.security === 'reality' || ss.realitySettings) {
            s.security = 'tls';
            const r = ss.realitySettings || {};
            s.reality = {pbk: r.publicKey || '', sid: r.shortId || ''};
            if (r.fingerprint) s.fp = r.fingerprint;
            if (r.serverName) s.sni = r.serverName;
        }
        if (s.network === 'xhttp') {
            const xh = ss.xhttpSettings || {};
            if (xh.host) s.host = xh.host;
            if (xh.path) s.path = xh.path;
            if (xh.mode) s.xhttpMode = xh.mode;
        } else if (s.network === 'tcp' && ss.tcpSettings && ss.tcpSettings.header && ss.tcpSettings.header.type === 'http') {
            s.headerType = 'http';
            const req = ss.tcpSettings.header.request || {};
            if (Array.isArray(req.path) && req.path.length) s.path = req.path[0];
            if (req.headers && req.headers.Host) s.host = req.headers.Host;
        }
        if (p === 'vmess') {
            const vn = ob.settings?.vnext?.[0];
            const user = vn?.users?.[0] || {};
            beans.push({
                proto: 'vmess',
                host: vn?.address || '',
                port: vn?.port || 0,
                name: ob.tag || 'vmess',
                auth: {uuid: user.id || '', security: user.security || 'auto'},
                stream: s
            });
        } else if (p === 'vless') {
            const vn = ob.settings?.vnext?.[0];
            const user = vn?.users?.[0] || {};
            const bean = {
                proto: 'vless',
                host: vn?.address || '',
                port: vn?.port || 0,
                name: ob.tag || 'vless',
                auth: {uuid: user.id || ''},
                stream: s
            };
            if (user.flow) bean.auth.flow = user.flow;
            beans.push(bean);
        } else if (p === 'trojan') {
            const sv = ob.settings?.servers?.[0];
            beans.push({
                proto: 'trojan',
                host: sv?.address || '',
                port: sv?.port || 0,
                name: ob.tag || 'trojan',
                auth: {password: sv?.password || ''},
                stream: s
            });
        } else if (p === 'shadowsocks') {
            const sv = ob.settings?.servers?.[0];
            beans.push({
                proto: 'ss',
                host: sv?.address || '',
                port: sv?.port || 0,
                name: ob.tag || 'ss',
                ss: {method: sv?.method || '', password: sv?.password || ''},
                stream: {network: 'tcp', security: ''}
            });
        } else if (p === 'socks' || p === 'http') {
            const sv = ob.settings?.servers?.[0];
            const sock = {};
            if (sv?.users && sv.users[0]) {
                sock.username = sv.users[0].user || '';
                sock.password = sv.users[0].pass || '';
            }
            beans.push({
                proto: p,
                host: sv?.address || '',
                port: sv?.port || 0,
                name: ob.tag || p,
                socks: sock,
                stream: s
            });
        }
    }
    return beans;
}

function detectConfigAndConvertToLinks(raw) {
    const text = (raw || '').trim();
    if (!text) throw new Error('Empty input');
    let obj = null;
    try {
        obj = JSON.parse(text);
    } catch {
        obj = null;
    }
    if (!obj) throw new Error('Unsupported or invalid JSON config');
    let beans = [];
    if (Array.isArray(obj?.outbounds) && obj.outbounds.length) {
        if (obj.outbounds[0] && (obj.outbounds[0].type || obj.outbounds[0].server)) {
            beans = parseSingBoxConfigToBeans(obj);
        } else if (obj.outbounds[0] && (obj.outbounds[0].protocol || obj.outbounds[0].settings)) {
            beans = parseXrayConfigToBeans(obj);
        }
    }
    if (!beans.length) throw new Error('No supported outbounds found in config');
    return beansToLinks(beans);
}

try {
    if (typeof globalThis !== 'undefined') {
        globalThis.web4core = Object.assign({}, globalThis.web4core || {}, {
            buildBeansFromInput,
            validateBean,
            computeTag,
            buildSingBoxOutbound,
            buildSingBoxConfig,
            buildXrayOutbound,
            buildXrayConfig,
            buildMihomoConfig,
            buildMihomoYaml: function (proxies, groups, providers, rules) {
                return overlayMihomoYaml(MIHOMO_DEFAULT_TEMPLATE, proxies, groups, providers, rules);
            },
            reverseConvert: detectConfigAndConvertToLinks,
            fetchSubscription
        });
    }
} catch {
}