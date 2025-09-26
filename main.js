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
    return s.replace(/[^A-Za-z0-9_\-\.]/g, '-').slice(0, 64) || 'proxy';
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
    const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';
    let suffix = '';
    for (let i = 0; i < 3; i++) suffix += alphabet[Math.floor(Math.random() * alphabet.length)];
    return `tun-${suffix}`;
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
            host: obj.add,
            port: asInt(obj.port, 443),
            name: obj.ps || '',
            auth: {uuid: obj.id, aid: asInt(obj.aid, 0), security: obj.scy || 'auto'},
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
        auth: {uuid: decodeURIComponent(u.username || ''), aid: 0, security: q.get('encryption') || 'auto'},
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
        port: asInt(u.port, 0),
        name: decodeURIComponent(u.hash.replace('#', '')),
        quic: {
            type: 'hysteria2',
            password: pwd,
            upMbps: 0,
            downMbps: 0,
            hopPort: q.get('mport') || '',
            hopInterval: asInt(q.get('hop_interval') || '0', 0),
            obfsPassword: q.get('obfs-password') || '',
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
        quic: {
            type: 'tuic',
            uuid: decodeURIComponent(u.username || ''),
            password: decodeURIComponent(u.password || ''),
            congestionControl: q.get('congestion_control') || '',
            alpn: q.get('alpn') || '',
            sni: q.get('sni') || '',
            udpRelayMode: q.get('udp_relay_mode') || '',
            allowInsecure: (q.get('allow_insecure') || '') === '1',
            disableSni: (q.get('disable_sni') || '') === '1',
            zeroRtt: (q.get('zero_rtt') || '') === '1',
            uos: (q.get('udp_over_stream') || '') === '1',
            heartbeat: q.get('heartbeat') || ''
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
        const isReality = !!(bean.stream.reality && bean.stream.reality.pbk);
        const hasTlsHints = !!(bean.stream.sni || (bean.stream.alpn && bean.stream.alpn.length) || bean.stream.fp);
        const needTls = bean.stream.security === 'tls' || isReality || (['vless', 'vmess'].includes(bean.proto) && hasTlsHints);
        if (!needTls) return undefined;
        const tls = {enabled: true};
        if (bean.stream.allowInsecure) tls.insecure = true;
        if (bean.stream.sni) tls.server_name = bean.stream.sni;
        if (bean.stream.alpn && bean.stream.alpn.length) tls.alpn = bean.stream.alpn;
        if (isReality) {
            tls.reality = {enabled: true, public_key: bean.stream.reality.pbk, short_id: bean.stream.reality.sid || ''};
            if (!bean.stream.fp) tls.utls = {enabled: true, fingerprint: 'random'};
        }
        if (bean.stream.fp) tls.utls = {enabled: true, fingerprint: bean.stream.fp};
        return tls;
    };

    function applyTransport(outbound, stream) {
        if (stream.network !== 'tcp') {
            const t = {type: stream.network};
            if (stream.network === 'ws') {
                if (stream.host) t.headers = {Host: stream.host};
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
        alter_id: bean.auth.aid || 0,
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
        outbound.password = bean.quic.password;
    } else if (bean.proto === 'tuic') {
        const tls = commonTLS() || {enabled: true};
        outbound = {type: 'tuic', server: bean.host, server_port: bean.port || 443, tls};
        if (bean.quic.uuid) outbound.uuid = bean.quic.uuid;
        if (bean.quic.password) outbound.password = bean.quic.password;
        if (bean.quic.congestionControl) outbound.congestion_control = bean.quic.congestionControl;
        if (bean.quic.uos) outbound.udp_over_stream = true; else if (bean.quic.udpRelayMode) outbound.udp_relay_mode = bean.quic.udpRelayMode;
        if (bean.quic.zeroRtt) outbound.zero_rtt_handshake = true;
        if (bean.quic.heartbeat) outbound.heartbeat = bean.quic.heartbeat;
    } else throw new Error('Пока не поддерживается для sing-box: ' + bean.proto);
    const tls = commonTLS();
    if (tls) outbound.tls = tls;
    if (bean.stream) applyTransport(outbound, bean.stream);
    return outbound;
}

function buildSingBoxInbounds(opts) {
    const inbounds = [];
    if (opts.addTun) {
        const iface = (opts.tunName || generateIfaceName()).trim() || generateIfaceName();
        inbounds.push({type: 'tun', tag: 'tun-in', interface_name: iface, address: ['172.19.0.1/32'], stack: 'gvisor'});
        return inbounds;
    }
    inbounds.push({
        tag: 'mixed-in',
        type: 'mixed',
        listen: '127.0.0.1',
        listen_port: 2080,
        sniff: true,
        sniff_override_destination: false,
        domain_strategy: ''
    });
    return inbounds;
}

function buildSingBoxFullConfig(outbound, opts) {
    return {
        log: {level: 'info'},
        inbounds: buildSingBoxInbounds(opts),
        outbounds: [
            Object.assign({tag: 'proxy', domain_strategy: ''}, outbound),
            {tag: 'direct', type: 'direct'},
            {tag: 'bypass', type: 'direct'},
            {tag: 'block', type: 'block'}
        ],
        route: {
            rules: [],
            final: 'proxy'
        },
        dns: {
            independent_cache: true,
            servers: [
                {
                    tag: 'dns-direct',
                    address: 'https://doh.pub/dns-query',
                    address_resolver: 'dns-local',
                    strategy: '',
                    detour: 'direct'
                },
                {tag: 'dns-local', address: 'local', detour: 'direct'}
            ],
            rules: [{outbound: 'any', server: 'dns-direct'}]
        }
    };
}

function buildSingBoxFullConfigMulti(outboundsWithTags, opts) {
    const tags = outboundsWithTags.map(ob => ob.tag);
    const outbounds = [
        {type: 'selector', tag: 'select', outbounds: tags, default: 'auto', interrupt_exist_connections: false},
        {
            type: 'urltest',
            tag: 'auto',
            outbounds: tags,
            url: 'https://www.gstatic.com/generate_204',
            interval: '3m',
            tolerance: 50,
            idle_timeout: '30m',
            interrupt_exist_connections: false
        },
        ...outboundsWithTags,
        {tag: 'direct', type: 'direct'},
        {tag: 'bypass', type: 'direct'},
        {tag: 'block', type: 'block'}
    ];
    return {
        log: {level: 'info'},
        inbounds: buildSingBoxInbounds(opts),
        outbounds,
        route: {rules: [], final: 'select'},
        dns: {
            independent_cache: true,
            servers: [
                {
                    tag: 'dns-direct',
                    address: 'https://doh.pub/dns-query',
                    address_resolver: 'dns-local',
                    strategy: '',
                    detour: 'direct'
                },
                {tag: 'dns-local', address: 'local', detour: 'direct'}
            ],
            rules: [{outbound: 'any', server: 'dns-direct'}]
        }
    };
}

function buildXrayOutbound(bean) {
    const streamSettings = {network: (bean.stream.network || 'tcp')};
    const hasReality = !!(bean.stream.reality && bean.stream.reality.pbk);
    const sec = hasReality ? 'reality' : (bean.stream.security === 'tls' ? 'tls' : '');
    if (sec === 'tls') {
        streamSettings.security = 'tls';
        streamSettings.tlsSettings = {};
        if (bean.stream.sni) streamSettings.tlsSettings.serverName = bean.stream.sni;
        if (bean.stream.alpn && bean.stream.alpn.length) streamSettings.tlsSettings.alpn = bean.stream.alpn;
        if (bean.stream.fp) streamSettings.tlsSettings.fingerprint = bean.stream.fp;
        if (bean.stream.allowInsecure) streamSettings.tlsSettings.allowInsecure = true;
    } else if (sec === 'reality') {
        streamSettings.security = 'reality';
        streamSettings.realitySettings = {show: false, publicKey: bean.stream.reality.pbk};
        if (bean.stream.reality.sid) streamSettings.realitySettings.shortId = bean.stream.reality.sid;
        if (bean.stream.sni) streamSettings.realitySettings.serverName = bean.stream.sni;
        if (bean.stream.fp) streamSettings.realitySettings.fingerprint = bean.stream.fp;
    }
    if (streamSettings.network === 'ws') {
        streamSettings.wsSettings = {};
        if (bean.stream.path) streamSettings.wsSettings.path = bean.stream.path;
        if (bean.stream.host) streamSettings.wsSettings.headers = {Host: bean.stream.host};
    } else if (streamSettings.network === 'http') {
        streamSettings.httpSettings = {};
        if (bean.stream.host) streamSettings.httpSettings.host = splitCSV(bean.stream.host);
        if (bean.stream.path) streamSettings.httpSettings.path = bean.stream.path;
    } else if (streamSettings.network === 'grpc') {
        streamSettings.grpcSettings = {};
        if (bean.stream.path) streamSettings.grpcSettings.serviceName = bean.stream.path;
    } else if (streamSettings.network === 'tcp' && bean.stream.headerType === 'http') {
        streamSettings.tcpSettings = {header: {type: 'http', request: {headers: {Host: splitCSV(bean.stream.host)}}}};
        if (bean.stream.path) streamSettings.tcpSettings.header.request.path = [bean.stream.path];
    }
    let outbound = null;
    if (bean.proto === 'vmess') outbound = {
        protocol: 'vmess',
        tag: 'proxy',
        settings: {
            vnext: [{
                address: bean.host,
                port: bean.port,
                users: [{id: bean.auth.uuid, alterId: bean.auth.aid || 0, security: bean.auth.security || 'auto'}]
            }]
        }
    }; else if (bean.proto === 'vless') {
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
    } else if (bean.proto === 'hy2' || bean.proto === 'tuic') throw new Error('Xray: ' + bean.proto + ' не поддерживается'); else throw new Error('Xray: Ошибка ' + bean.proto);
    outbound.streamSettings = streamSettings;
    return outbound;
}

function buildXrayFullConfig(outbound) {
    return {
        log: {loglevel: 'warning'},
        inbounds: [{tag: 'socks-in', port: 1080, listen: '127.0.0.1', protocol: 'socks', settings: {udp: true}}],
        outbounds: [outbound, {tag: 'direct', protocol: 'freedom'}, {tag: 'block', protocol: 'blackhole'}],
        routing: {rules: []}
    };
}

function buildXrayFullConfigMulti(outbounds) {
    return {
        log: {loglevel: 'warning'},
        inbounds: [{tag: 'socks-in', port: 1080, listen: '127.0.0.1', protocol: 'socks', settings: {udp: true}}],
        outbounds: [...outbounds, {tag: 'direct', protocol: 'freedom'}, {tag: 'block', protocol: 'blackhole'}],
        routing: {rules: []}
    };
}
