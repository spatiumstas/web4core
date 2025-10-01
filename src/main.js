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
    const bytes = [];
    for (let i = 0; i < 16; i++) {
        bytes.push(Math.floor(Math.random() * 256));
    }
    return bytes.map(b => b.toString(16).padStart(2, '0')).join('');
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

function generateIfaceName() {
    const numeric = '0123456789';
    let suffix = '';
    for (let i = 0; i < 2; i++) suffix += numeric[Math.floor(Math.random() * numeric.length)];
    return `sing${suffix}`;
}

function isValidUuid(str) {
    const s = (str || '').trim();
    return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(s);
}

function validateBean(bean) {
    if (!bean || typeof bean !== 'object') throw new Error('Некорректная ссылка');
    const p = bean.proto;
    const requireHost = () => { if (!bean.host) throw new Error(p + ': отсутствует host'); };
    const requirePort = () => { if (!Number.isFinite(bean.port) || bean.port <= 0) throw new Error(p + ': некорректный port'); };
    switch (p) {
        case 'vless':
        case 'vmess':
            requireHost(); requirePort();
            if (!bean.auth?.uuid) throw new Error(p + ': отсутствует UUID');
            if (!isValidUuid(bean.auth.uuid)) throw new Error(p + ': некорректный UUID');
            break;
        case 'trojan':
            requireHost(); requirePort();
            if (!bean.auth?.password) throw new Error('trojan: отсутствует пароль');
            break;
        case 'ss':
            requireHost(); requirePort();
            if (!bean.ss?.method || !bean.ss?.password) throw new Error('shadowsocks: отсутствует method/password');
            break;
        case 'socks':
        case 'http':
            requireHost(); requirePort();
            break;
        case 'hy2':
            requireHost(); requirePort();
            if (!bean.auth?.password) throw new Error('hysteria2: отсутствует пароль');
            break;
        case 'tuic':
            requireHost(); requirePort();
            if (!bean.auth?.uuid || !isValidUuid(bean.auth.uuid)) throw new Error('tuic: некорректный UUID');
            if (!bean.auth?.password) throw new Error('tuic: отсутствует пароль');
            break;
        default:
            throw new Error('Неизвестный протокол: ' + p);
    }
}

function parseTunSpec(tunSpec) {
    const items = (tunSpec || '')
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
    return items;
}

function parseLink(input) {
    const trimmed = input.trim();
    const scheme = trimmed.split(':', 1)[0].toLowerCase();
    if (scheme === 'vmess') return parseVMess(trimmed);
    if (scheme === 'vless') return parseVLESS(trimmed);
    if (scheme === 'trojan') return parseTrojan(trimmed);
    if (scheme === 'ss') return parseSS(trimmed);
    if (scheme.startsWith('socks')) return parseSocksHttp(trimmed);
    if (scheme === 'http' || scheme === 'https') return parseSocksHttp(trimmed);
    if (scheme === 'hy2' || scheme === 'hysteria2') return parseHysteria2(trimmed);
    if (scheme === 'tuic') return parseTUIC(trimmed);
    throw new Error('Неизвестная ссылка: ' + scheme);
}

function parseSocksHttp(urlStr) {
    const u = new URL(urlStr);
    const query = getQuery(u);
    const isHTTP = u.protocol.startsWith('http');
    const isSocks4 = u.protocol.startsWith('socks4');
    const bean = {
        proto: isHTTP ? 'http' : 'socks',
        host: u.hostname,
        port: asInt(u.port, isHTTP ? 443 : 1080),
        name: decodeURIComponent(u.hash.replace('#', '')),
        socks: {
            type: isHTTP ? 'http' : (isSocks4 ? 'socks4' : 'socks5'),
            username: decodeURIComponent(u.username || ''),
            password: decodeURIComponent(u.password || '')
        },
        stream: {
            network: 'tcp',
            security: isHTTP ? 'tls' : (query.get('security') || '').toLowerCase(),
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
    return {
        proto: 'trojan',
        host: u.hostname,
        port: asInt(u.port, 443),
        name: decodeURIComponent(u.hash.replace('#', '')),
        auth: {password: decodeURIComponent(u.username || '')},
        stream: buildStreamFromQuery(q, true)
    };
}

function parseVLESS(urlStr) {
    const u = new URL(urlStr);
    if (u.protocol !== 'vless:') throw new Error('Требуется ссылка вида vless://');
    const q = getQuery(u);
    return {
        proto: 'vless',
        host: u.hostname,
        port: asInt(u.port, 443),
        name: decodeURIComponent(u.hash.replace('#', '')),
        auth: {
            uuid: decodeURIComponent(u.username || '').trim(),
            flow: (q.get('flow') || '').replace(/-udp443$/, '').replace(/^none$/, '')
        },
        stream: buildStreamFromQuery(q, false)
    };
}

function parseVMess(urlStr) {
    const payload = urlStr.slice('vmess://'.length);
    const decoded = atob(payload || '');
    const obj = tryJSON(decoded);
    if (obj) {
        const net = (obj.net || '').toLowerCase();
        const type = net === 'h2' ? 'http' : (net || 'tcp');
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
        return {
            proto: 'vmess',
            host: obj.add || 'localhost',
            port: asInt(obj.port, 443),
            name: obj.ps || '',
            auth: {uuid: obj.id, security: obj.scy || 'auto'},
            stream
        };
    }
    const u = new URL(urlStr);
    const q = getQuery(u);
    return {
        proto: 'vmess',
        host: u.hostname,
        port: asInt(u.port, 443),
        name: decodeURIComponent(u.hash.replace('#', '')),
        auth: {uuid: decodeURIComponent(u.username || ''), security: q.get('encryption') || 'auto'},
        stream: buildStreamFromQuery(q, false)
    };
}

function parseSS(urlStr) {
    const u = new URL(urlStr);
    const name = decodeURIComponent(u.hash.replace('#', ''));
    let method = u.username, password = u.password;
    if (!password && u.username) {
        const dec = decodeBase64Url(u.username);
        if (dec.includes(':')) {
            const i = dec.indexOf(':'), a = dec.slice(0, i), b = dec.slice(i + 1);
            method = a;
            password = b;
        }
    }
    const q = getQuery(u);
    return {
        proto: 'ss',
        host: u.hostname,
        port: asInt(u.port, 0),
        name,
        ss: {method, password, uot: 0, plugin: q.get('plugin') || '', pluginOpts: ''},
        stream: {network: 'tcp', security: ''}
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
            hopInterval: asInt(q.get('hop_interval') || '10', 10),
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
            disableSni: q.get('disable_sni') === '1'
        }
    };
}

function buildStreamFromQuery(q, isTrojan) {
    let type = (q.get('type') || 'tcp').toLowerCase();
    if (type === 'h2') type = 'http';
    const security = (q.get('security') || (isTrojan ? 'tls' : '')).toLowerCase().replace('reality', 'tls').replace('none', '');
    const sni = q.get('sni') || q.get('peer') || '';
    const alpn = splitCSV(q.get('alpn') || '');
    const allowInsecure = q.has('allowInsecure');
    const fp = q.get('fp') || '';
    const reality = {pbk: q.get('pbk') || '', sid: (q.get('sid') || '').split(',')[0] || '', spx: q.get('spx') || ''};
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
        packet_encoding: ''
    };
    if (type === 'ws') {
        stream.path = q.get('path') || '';
        stream.host = q.get('host') || '';
    } else if (type === 'http') {
        stream.path = q.get('path') || '';
        stream.host = (q.get('host') || '').replace(/\|/g, ',');
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
            } else if (stream.network === 'http') {
                if (stream.path) t.path = stream.path;
                if (stream.host) t.host = splitCSV(stream.host).map(s => s);
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
        if (Number.isFinite(bean.hysteria2?.hopInterval)) outbound.hop_interval = bean.hysteria2.hopInterval + 's';
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
    } else throw new Error('Не поддерживается sing-box: ' + bean.proto);
    const tls = commonTLS();
    if (tls) outbound.tls = tls;
    if (bean.stream) applyTransport(outbound, bean.stream);
    return outbound;
}

function buildSingBoxInbounds(opts) {
    const inbounds = [];
    if (opts.addTun) {
        const specs = parseTunSpec(opts.tunName || '');
        const ifaces = specs.length ? specs.map(x => x.name) : [generateIfaceName()];
        for (let i = 0; i < ifaces.length; i++) {
            const name = ifaces[i];
            const tag = ifaces.length > 1 ? `tun-in-${name}` : 'tun-in';
            const octet = ifaces.length > 1 ? (i === 0 ? 1 : i * 10) : 1;
            const cidr = ifaces.length > 1 ? `${`172.19.0.${octet}`}/30` : '172.19.0.1/32';
            inbounds.push({type: 'tun', tag, interface_name: name, address: [cidr], stack: 'gvisor'});
        }
    }
    if (opts.addSocks) {
        inbounds.push({
            tag: 'mixed-in',
            type: 'mixed',
            listen: '127.0.0.1',
            listen_port: 2080,
            sniff: true,
            sniff_override_destination: false
        });
    }
    return inbounds;
}

function buildSingBoxFullConfig(outbound, opts) {
    return {
        log: {level: 'info'},
        inbounds: buildSingBoxInbounds(opts),
        outbounds: [
            Object.assign({tag: 'proxy'}, outbound),
            {tag: 'direct', type: 'direct'},
            {tag: 'bypass', type: 'direct'},
            {tag: 'block', type: 'block'}
        ],
        route: {
            rules: [],
            final: 'proxy'
        },
        experimental: {
            cache_file: {enabled: true},
            clash_api: {
                external_controller: '[::]:9090',
                external_ui: 'ui',
                external_ui_download_detour: 'direct',
                access_control_allow_private_network: true,
                secret: opts?.genClashSecret ? generateSecretHex32() : ''
            }
        }
    };
}

function buildSingBoxFullConfigMulti(outboundsWithTags, opts) {
    const tags = outboundsWithTags.map(ob => ob.tag);
    const inbounds = buildSingBoxInbounds(opts);
    const managementOutbounds = [];
    const routeRules = [];
    const suffixFromInbound = (tag) => {
        const m = (tag || '').match(/^(.*?)-in(?:-(.*))?$/);
        if (!m) return tag;
        return m[2] || m[1];
    };
    let firstDetourTag = '';
    const tunModes = new Map();
    if (opts && opts.addTun) {
        const specs = parseTunSpec(opts.tunName || '');
        for (const s of specs) tunModes.set(s.name, s.mode);
    }
    for (const inbound of inbounds) {
        const suffix = suffixFromInbound(inbound.tag);
        const mode = inbound.tag.startsWith('tun-in') ? (tunModes.get(suffix) || 'select') : 'select';
        const selectTag = `select-${suffix}`;
        const autoTag = `auto-${suffix}`;
        if (mode === 'auto') {
            managementOutbounds.push({
                type: 'urltest',
                tag: autoTag,
                outbounds: tags,
                url: 'https://www.gstatic.com/generate_204',
                interval: '3m',
                tolerance: 50,
                idle_timeout: '30m',
                interrupt_exist_connections: false
            });
            routeRules.push({ inbound: inbound.tag, outbound: autoTag });
            if (!firstDetourTag) firstDetourTag = autoTag;
        } else {
            const selectorOutbounds = [...tags];
            const defaultTag = selectorOutbounds[0] || 'direct';
            managementOutbounds.push({type: 'selector', tag: selectTag, outbounds: selectorOutbounds, default: defaultTag, interrupt_exist_connections: false});
            routeRules.push({ inbound: inbound.tag, outbound: selectTag });
            if (!firstDetourTag) firstDetourTag = selectTag;
        }
    }
    const outbounds = [
        ...managementOutbounds,
        ...outboundsWithTags,
        {tag: 'direct', type: 'direct'},
        {tag: 'bypass', type: 'direct'},
        {tag: 'block', type: 'block'}
    ];
    return {
        log: {level: 'info'},
        inbounds,
        outbounds,
        route: {rules: routeRules, final: firstDetourTag || 'direct'},
        experimental: {
            cache_file: {enabled: true},
            clash_api: {
                external_controller: '[::]:9090',
                external_ui: 'ui',
                external_ui_download_detour: 'direct',
                access_control_allow_private_network: true,
                secret: opts?.genClashSecret ? generateSecretHex32() : ''
            }
        }
    };
}

function buildXrayOutbound(bean) {
    const s = bean.stream || {};
    const network = s.network || 'tcp';
    const streamSettings = {network: network === 'http' ? 'xhttp' : network};
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
        streamSettings.wsSettings = {};
        if (s.path) streamSettings.wsSettings.path = s.path;
        if (s.host) streamSettings.wsSettings.headers = {Host: s.host};
    } else if (streamSettings.network === 'xhttp') {
        streamSettings.xhttpSettings = {};
        if (s.host) streamSettings.xhttpSettings.host = s.host;
        if (s.path) streamSettings.xhttpSettings.path = s.path;
    } else if (streamSettings.network === 'grpc') {
        streamSettings.grpcSettings = {};
        if (s.path) streamSettings.grpcSettings.serviceName = s.path;
    } else if (streamSettings.network === 'tcp' && s.headerType === 'http') {
        streamSettings.tcpSettings = {header: {type: 'http', request: {headers: {Host: s.host}}}};
        if (s.path) streamSettings.tcpSettings.header.request.path = [s.path];
    }
    let outbound = null;
    if (bean.proto === 'vmess') {
        outbound = {
            protocol: 'vmess',
            tag: 'proxy',
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
            tag: 'proxy',
            settings: {vnext: [{address: bean.host, port: bean.port, users: [user]}]}
        };
    } else if (bean.proto === 'trojan') outbound = {
        protocol: 'trojan',
        tag: 'proxy',
        settings: {servers: [{address: bean.host, port: bean.port, password: bean.auth.password}]}
    }; else if (bean.proto === 'ss') outbound = {
        protocol: 'shadowsocks',
        tag: 'proxy',
        settings: {servers: [{address: bean.host, port: bean.port, method: bean.ss.method, password: bean.ss.password}]}
    }; else if (bean.proto === 'socks' || bean.proto === 'http') {
        const s = {address: bean.host, port: bean.port};
        if (bean.socks?.username && bean.socks?.password) {
            s.users = [{user: bean.socks.username, pass: bean.socks.password}];
        }
        outbound = {protocol: bean.proto, tag: 'proxy', settings: {servers: [s]}};
    } else if (bean.proto === 'hy2' || bean.proto === 'tuic') {
        throw new Error(bean.proto + ' не поддерживается в Xray. Используйте sing-box.');
    } else {
        throw new Error('Xray: Неизвестный протокол ' + bean.proto);
    }
    outbound.streamSettings = streamSettings;
    return outbound;
}

function buildXrayFullConfig(outbound) {
    return {
        log: {loglevel: 'warning'},
        inbounds: [{tag: 'socks-in', port: 1080, listen: '127.0.0.1', protocol: 'socks', settings: {udp: true}}],
        outbounds: [outbound, {tag: 'direct', protocol: 'freedom'}, {tag: 'block', protocol: 'blackhole'}]
    };
}

function buildXrayFullConfigMulti(outbounds) {
    return {
        log: {loglevel: 'warning'},
        inbounds: [{tag: 'socks-in', port: 1080, listen: '127.0.0.1', protocol: 'socks', settings: {udp: true}}],
        outbounds: [...outbounds, {tag: 'direct', protocol: 'freedom'}, {tag: 'block', protocol: 'blackhole'}]
    };
}
