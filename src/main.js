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
    'mieru',
    'sdns'
];
const MAX_SUB_REDIRECTS = 2;
const SUB_FETCH_TIMEOUT = 15000;
const SUB_FETCH_INTERVAL = 600;
const SUB_FALLBACK_RETRIES = 2;
const URLTEST = 'https://www.gstatic.com/generate_204';
const URLTEST_INTERVAL = '3m';
const FETCH_INIT = {
    method: 'GET',
    cache: 'no-store',
    credentials: 'omit',
    headers: { 'Accept': 'text/plain, */*' },
    redirect: 'follow'
};
const PUBLIC_CORS_FALLBACKS = [
    (x) => 'https://sub.web2core.workers.dev/?url=' + encodeURIComponent(x),
    (x) => 'https://api.allorigins.win/raw?url=' + encodeURIComponent(x)
];

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
    const u = parseUrl(urlStr);
    const q = getQuery(u);
    const bean = {
        proto: 'trojan',
        host: u.hostname,
        port: asInt(u.port, 443),
        name: decodeURIComponent(u.hash.replace('#', '')),
        auth: { password: decodeURIComponent(u.username || '') },
        stream: buildStreamFromQuery(q, true),
        udp: q.get('udp') === '1' || q.get('udp') === 'true',
        udpOverTcp: q.get('udp-over-tcp') === '1' || q.get('udp-over-tcp') === 'true',
        ipVersion: q.get('ip-version') || ''
    };
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
    const payloadRaw = urlStr.slice('vmess://'.length);
    const payload = (payloadRaw || '').split('#')[0].split('?')[0];
    const decoded = decodeBase64Url(payload || '');
    const obj = decoded ? tryJSON(decoded) : null;
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
        name: decodeURIComponent(u.hash.replace('#', '')),
        auth: { uuid: decodeURIComponent(u.username || ''), security: q.get('encryption') || 'auto' },
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
        stream: { network: 'tcp', security: '' },
        udp: q.get('udp') === '1' || q.get('udp') === 'true',
        udpOverTcp: q.get('udp-over-tcp') === '1' || q.get('udp-over-tcp') === 'true'
    };
}

function parseHysteria2(urlStr) {
    const u = parseUrl(urlStr);
    const q = getQuery(u);
    const pwd = u.password ? (decodeURIComponent(u.username || '') + ':' + decodeURIComponent(u.password)) : decodeURIComponent(u.username || '');
    return {
        proto: 'hy2',
        host: u.hostname,
        port: asInt(u.port, 443),
        name: decodeURIComponent(u.hash.replace('#', '')),
        auth: { password: pwd },
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
    const u = parseUrl(urlStr);
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
    const u = parseUrl(urlStr);
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
    const u = parseUrl(urlStr);
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
    const mode = (q.get('mode') || '').toLowerCase();
    if (mode === 'gun') type = 'grpc';
    if (type === 'h2') type = 'http';
    if (type === 'w' || type === 'websocket') type = 'ws';
    if (type !== 'xhttp' && (q.get('xhttp') === '1' || q.get('xhttp') === 'true')) type = 'xhttp';
    const security = (q.get('security') || (isTrojan ? 'tls' : '')).toLowerCase().replace('reality', 'tls').replace('none', '');
    const sni = q.get('sni') || q.get('peer') || '';
    const authority = q.get('authority') || '';
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
        authority,
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

try {
    if (typeof globalThis !== 'undefined') {
        globalThis.web4core = Object.assign({}, globalThis.web4core || {}, {
            buildBeansFromInput,
            validateBean,
            computeTag
        });
    }
} catch {
}