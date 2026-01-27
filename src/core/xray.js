import { asInt, decodeBase64Url, URLTEST, URLTEST_INTERVAL } from '../main.js';

function buildXrayOutbound(bean) {
    const s = bean.stream || {};
    const network = s.network || 'tcp';
    let streamSettings = {network: (network === 'http' || network === 'h2') ? 'xhttp' : network};

    if (bean.proto === 'hy2') {
        const h = bean.hysteria2 || {};
        const alpn = (h.alpn || '').split(',').map(x => x.trim()).filter(Boolean);
        streamSettings = {
            network: 'hysteria',
            security: 'tls',
            tlsSettings: {
                serverName: h.sni || undefined,
                alpn: alpn.length ? alpn : undefined,
                pinnedPeerCertSha256: (h.pinnedPeerCertSha256 || '').trim() || undefined,
                verifyPeerCertByName: (h.verifyPeerCertByName || '').trim() || undefined,
            },
            hysteriaSettings: {
                version: 2,
                auth: bean.auth?.password || '',
            }
        };
        const congestion = (h.congestion || '').trim();
        if (congestion) {
            streamSettings.hysteriaSettings.congestion = congestion.toLowerCase();
        }
        const hopPort = (h.hopPort || '').toString().trim();
        const hopIntervalRaw = (h.hopInterval || '').toString().trim();
        let hopInterval = 0;
        let hopIntervalRange = '';
        if (hopIntervalRaw) {
            if (/^\d+$/.test(hopIntervalRaw)) {
                hopInterval = asInt(hopIntervalRaw, 0);
            } else {
                const m = hopIntervalRaw.match(/^(\d+)\s*-\s*(\d+)$/);
                if (m && m[1] && m[2]) hopIntervalRange = `${m[1]}-${m[2]}`;
            }
        }
        if (hopPort || hopInterval || hopIntervalRange) {
            streamSettings.hysteriaSettings.udphop = {};
            if (hopPort) streamSettings.hysteriaSettings.udphop.port = hopPort;
            if (hopIntervalRange) streamSettings.hysteriaSettings.udphop.interval = hopIntervalRange;
            else if (hopInterval) streamSettings.hysteriaSettings.udphop.interval = hopInterval;
        }
        if (h.obfsPassword) {
            streamSettings.udpmasks = [{
                type: 'salamander',
                settings: {password: h.obfsPassword}
            }];
        }
        if (streamSettings.tlsSettings) {
            if (!streamSettings.tlsSettings.serverName) delete streamSettings.tlsSettings.serverName;
            if (!streamSettings.tlsSettings.alpn) delete streamSettings.tlsSettings.alpn;
            if (!streamSettings.tlsSettings.pinnedPeerCertSha256) delete streamSettings.tlsSettings.pinnedPeerCertSha256;
            if (!streamSettings.tlsSettings.verifyPeerCertByName) delete streamSettings.tlsSettings.verifyPeerCertByName;
            if (Object.keys(streamSettings.tlsSettings).length === 0) delete streamSettings.tlsSettings;
        }
    } else {
        const hasReality = !!(s.reality && s.reality.pbk);
        const sec = hasReality ? 'reality' : (s.security === 'tls' ? 'tls' : '');
        if (sec === 'tls') {
            streamSettings.security = 'tls';
            streamSettings.tlsSettings = {};
            if (s.sni) streamSettings.tlsSettings.serverName = s.sni;
            if (s.alpn && s.alpn.length) streamSettings.tlsSettings.alpn = s.alpn;
            if (s.fp) streamSettings.tlsSettings.fingerprint = s.fp;
            if (s.pinnedPeerCertSha256) streamSettings.tlsSettings.pinnedPeerCertSha256 = s.pinnedPeerCertSha256;
            if (s.verifyPeerCertByName) streamSettings.tlsSettings.verifyPeerCertByName = s.verifyPeerCertByName;
        } else if (sec === 'reality') {
            streamSettings.security = 'reality';
            streamSettings.realitySettings = {show: false, publicKey: s.reality.pbk};
            if (s.reality.sid) streamSettings.realitySettings.shortId = s.reality.sid;
            if (s.reality.spx) streamSettings.realitySettings.spiderX = s.reality.spx;
            if (s.reality.pqv) {
                const pqv = String(s.reality.pqv || '').trim();
                const decoded = decodeBase64Url(pqv);
                if (!decoded || decoded.length !== 1952) {
                    throw new Error('Xray REALITY pqv is invalid (expected base64url ML-DSA-65 public key)');
                }
                streamSettings.realitySettings.mldsa65Verify = pqv;
            }
            if (s.sni) streamSettings.realitySettings.serverName = s.sni;
            if (s.fp) streamSettings.realitySettings.fingerprint = s.fp;
        }
        if (streamSettings.network === 'ws') {
            streamSettings.wsSettings = {};
            if (s.host) streamSettings.wsSettings.host = s.host;
            let wsPath = s.path || '';
            if (s.wsEarlyData) {
                let ed = 0;
                if (typeof s.wsEarlyData === 'object') {
                    ed = asInt(s.wsEarlyData.max_early_data ?? s.wsEarlyData.maxEarlyData, 0);
                } else {
                    ed = asInt(s.wsEarlyData, 0);
                }
                if (ed > 0 && !/\bed=/.test(wsPath)) {
                    if (!wsPath) wsPath = '/';
                    wsPath += (wsPath.includes('?') ? '&' : '?') + `ed=${ed}`;
                }
            }
            if (wsPath) streamSettings.wsSettings.path = wsPath;
        } else if (streamSettings.network === 'xhttp') {
            streamSettings.xhttpSettings = {};
            if (s.host) streamSettings.xhttpSettings.host = s.host;
            if (s.path) streamSettings.xhttpSettings.path = s.path;
            if (s.xhttpMode) streamSettings.xhttpSettings.mode = s.xhttpMode; else streamSettings.xhttpSettings.mode = 'stream-up';
            const xmux = s.xhttpXmux || {};
            const hasXmux = Object.values(xmux).some(v => v !== '' && v !== 0);
            if (hasXmux) {
                streamSettings.xhttpSettings.xmux = {};
                if (xmux.max_concurrency) streamSettings.xhttpSettings.xmux.maxConcurrency = xmux.max_concurrency;
                if (xmux.max_connections) streamSettings.xhttpSettings.xmux.maxConnections = xmux.max_connections;
                if (xmux.c_max_reuse_times) streamSettings.xhttpSettings.xmux.cMaxReuseTimes = xmux.c_max_reuse_times;
                if (xmux.h_max_request_times) streamSettings.xhttpSettings.xmux.hMaxRequestTimes = xmux.h_max_request_times;
                if (xmux.h_max_reusable_secs) streamSettings.xhttpSettings.xmux.hMaxReusableSecs = xmux.h_max_reusable_secs;
                if (xmux.h_keep_alive_period) streamSettings.xhttpSettings.xmux.hKeepAlivePeriod = xmux.h_keep_alive_period;
            }
        } else if (streamSettings.network === 'grpc') {
            streamSettings.grpcSettings = {};
            if (s.path) streamSettings.grpcSettings.serviceName = s.path;
            if (s.authority) streamSettings.grpcSettings.authority = s.authority;
            if (s.grpcUserAgent) streamSettings.grpcSettings.user_agent = s.grpcUserAgent;
        } else if (streamSettings.network === 'httpupgrade') {
            streamSettings.httpupgradeSettings = {};
            if (s.host) streamSettings.httpupgradeSettings.host = s.host;
            if (s.path) streamSettings.httpupgradeSettings.path = s.path;
        } else if (streamSettings.network === 'tcp' && s.headerType === 'http') {
            streamSettings.tcpSettings = {header: {type: 'http', request: {headers: {Host: s.host}}}};
            if (s.path) streamSettings.tcpSettings.header.request.path = [s.path];
        }
        if (streamSettings.network === 'xhttp' && streamSettings.tlsSettings && Array.isArray(streamSettings.tlsSettings.alpn)) {
            streamSettings.tlsSettings.alpn = streamSettings.tlsSettings.alpn.filter(v => (v || '').toLowerCase() !== 'http/1.1');
            if (streamSettings.tlsSettings.alpn.length === 0) delete streamSettings.tlsSettings.alpn;
        }
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
        const enc = (bean.auth && typeof bean.auth.encryption === 'string' && bean.auth.encryption.trim())
            ? bean.auth.encryption.trim()
            : 'none';
        const user = { id: bean.auth.uuid, encryption: enc };
        if (bean.auth.flow) user.flow = bean.auth.flow;
        outbound = {
            protocol: 'vless',
            tag: (bean.name || 'vless'),
            settings: { vnext: [{ address: bean.host, port: bean.port, users: [user] }] }
        };
    } else if (bean.proto === 'trojan') outbound = {
        protocol: 'trojan',
        tag: (bean.name || 'trojan'),
        settings: { servers: [{ address: bean.host, port: bean.port, password: bean.auth.password }] }
    }; else if (bean.proto === 'ss') outbound = {
        protocol: 'shadowsocks',
        tag: (bean.name || 'ss'),
        settings: {
            servers: [{
                address: bean.host,
                port: bean.port,
                method: bean.ss.method,
                password: bean.ss.password,
                uot: Number.isFinite(bean.ss?.uot) && bean.ss.uot > 0,
                uotVersion: Number.isFinite(bean.ss?.uot) && bean.ss.uot > 0 ? bean.ss.uot : 0,
            }]
        }
    }; else if (bean.proto === 'socks' || bean.proto === 'http') {
        const s = { address: bean.host, port: bean.port };
        if (bean.socks?.username && bean.socks?.password) {
            s.users = [{ user: bean.socks.username, pass: bean.socks.password }];
        }
        outbound = { protocol: bean.proto, tag: (bean.name || bean.proto), settings: { servers: [s] } };
    } else if (bean.proto === 'hy2') {
        outbound = {
            protocol: 'hysteria',
            tag: (bean.name || 'hy2'),
            settings: {
                version: 2,
                address: bean.host,
                port: bean.port || 443
            }
        };
    } else if (bean.proto === 'tuic') {
        throw new Error(bean.proto + ' not supported in Xray');
    } else {
        throw new Error('Unknown protocol: ' + bean.proto);
    }
    outbound.streamSettings = streamSettings;
    return outbound;
}

function buildXrayTunInbounds(opts, outboundsCount) {
    const addTun = !!(opts && opts.addTun);
    if (!addTun) return [];
    if (!Number.isFinite(outboundsCount) || outboundsCount <= 0) return [];
    const enableBalancer = !!(opts && opts.enableBalancer);
    const count = (!enableBalancer && outboundsCount > 1) ? outboundsCount : 1;
    const ifaces = Array.from({ length: count }, (_, i) => `xraytun${i}`);
    const tunInbounds = [];

    for (let i = 0; i < ifaces.length; i++) {
        const name = ifaces[i] || 'xraytun0';
        const tag = `tun-in-${name}`;
        const inbound = {
            tag,
            port: 0,
            protocol: 'tun',
            settings: { name }
        };
        tunInbounds.push(inbound);
    }

    return tunInbounds;
}

function buildXrayConfig(outbounds, opts) {
    if (!Array.isArray(outbounds)) outbounds = [outbounds];
    const xraySocks = (opts && opts.addSocks === undefined) ? true : !!(opts && opts.addSocks);
    if (outbounds.length === 1) {
        const config = {
            log: { loglevel: 'warning' },
            inbounds: xraySocks ? [{ tag: 'socks-in', port: 1080, listen: '127.0.0.1', protocol: 'socks', settings: { udp: true } }] : [],
            outbounds: [outbounds[0], { tag: 'direct', protocol: 'freedom' }, { tag: 'block', protocol: 'blackhole' }]
        };
        const tunInbounds = buildXrayTunInbounds(opts, outbounds.length);
        if (tunInbounds.length) {
            config.inbounds = [...tunInbounds, ...config.inbounds];
            config.routing = {
                rules: [{ inboundTag: tunInbounds.map(x => x.tag).filter(Boolean), outboundTag: outbounds[0].tag || 'proxy' }]
            };
        } else if (!xraySocks) {
            throw new Error('Xray: at least one inbound (TUN or SOCKS) is required');
        }
        return config;
    }
    const basePort = 1080;
    const enableBalancer = !!(opts && opts.enableBalancer);
    const tunInbounds = buildXrayTunInbounds(opts, outbounds.length);
    const inbounds = xraySocks
        ? (enableBalancer
            ? [{ tag: 'socks-in', port: basePort, listen: '127.0.0.1', protocol: 'socks', settings: { udp: true } }]
            : outbounds.map((ob, idx) => ({
                tag: `socks-in-${idx + 1}`,
                port: basePort + idx,
                listen: '127.0.0.1',
                protocol: 'socks',
                settings: { udp: true }
            })))
        : [];
    if (tunInbounds.length) {
        inbounds.unshift(...tunInbounds);
    }
    const rules = [];
    if (xraySocks) {
        if (enableBalancer) {
            rules.push({ inboundTag: ['socks-in'], balancerTag: 'auto' });
        } else {
            rules.push(...outbounds.map((ob, idx) => ({
                inboundTag: [`socks-in-${idx + 1}`],
                outboundTag: ob.tag || 'proxy'
            })));
        }
    }
    if (tunInbounds.length) {
        if (enableBalancer) {
            rules.unshift({ inboundTag: tunInbounds.map(x => x.tag).filter(Boolean), balancerTag: 'auto' });
        } else {
            const tags = outbounds.map(ob => ob.tag).filter(Boolean);
            for (let i = tunInbounds.length - 1; i >= 0; i--) {
                const obTag = tags[i] || tags[0] || 'proxy';
                rules.unshift({ inboundTag: [tunInbounds[i].tag], outboundTag: obTag });
            }
        }
    }
    if (!rules.length) {
        throw new Error('Xray: at least one inbound (TUN or SOCKS) is required');
    }
    const routing = enableBalancer
        ? {
            rules,
            balancers: [{
                tag: 'auto',
                selector: outbounds.map(ob => ob.tag).filter(Boolean),
                strategy: { type: 'leastPing' }
            }]
        }
        : { rules };
    const config = {
        log: { loglevel: 'warning' },
        inbounds,
        outbounds: [...outbounds, { tag: 'direct', protocol: 'freedom' }, { tag: 'block', protocol: 'blackhole' }],
        routing
    };
    if (enableBalancer) {
        const selector = outbounds.map(ob => ob.tag).filter(Boolean);
        config.observatory = {
            subjectSelector: selector,
            probeURL: URLTEST,
            probeInterval: URLTEST_INTERVAL,
            enableConcurrency: selector.length > 8
        };
    }
    return config;
}

export {
    buildXrayOutbound,
    buildXrayConfig,
};
