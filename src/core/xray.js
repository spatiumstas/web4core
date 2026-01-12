import { asInt, URLTEST, URLTEST_INTERVAL } from '../main.js';

function buildXrayOutbound(bean) {
    const s = bean.stream || {};
    const network = s.network || 'tcp';
    const streamSettings = { network: (network === 'http' || network === 'h2') ? 'xhttp' : network };
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
        streamSettings.realitySettings = { show: false, publicKey: s.reality.pbk };
        if (s.reality.sid) streamSettings.realitySettings.shortId = s.reality.sid;
        if (s.sni) streamSettings.realitySettings.serverName = s.sni;
        if (s.fp) streamSettings.realitySettings.fingerprint = s.fp;
    }
    if (streamSettings.network === 'ws') {
        streamSettings.wsSettings = {};
        if (s.host) streamSettings.wsSettings.headers = { Host: s.host };
        if (s.path) streamSettings.wsSettings.path = s.path;
        if (s.wsEarlyData) {
            let maxEarlyData = 0;
            let earlyDataHeaderName = '';
            if (typeof s.wsEarlyData === 'object') {
                maxEarlyData = asInt(s.wsEarlyData.max_early_data ?? s.wsEarlyData.maxEarlyData, 0);
                earlyDataHeaderName = s.wsEarlyData.early_data_header_name || s.wsEarlyData.earlyDataHeaderName || '';
            } else {
                maxEarlyData = asInt(s.wsEarlyData, 0);
            }
            if (maxEarlyData > 0) streamSettings.wsSettings.maxEarlyData = maxEarlyData;
            if (earlyDataHeaderName) streamSettings.wsSettings.earlyDataHeaderName = earlyDataHeaderName;
        }
    } else if (streamSettings.network === 'xhttp') {
        streamSettings.xhttpSettings = {};
        if (s.host) streamSettings.xhttpSettings.host = s.host;
        if (s.path) streamSettings.xhttpSettings.path = s.path;
        if (s.xhttpMode) streamSettings.xhttpSettings.mode = s.xhttpMode; else streamSettings.xhttpSettings.mode = 'stream-up';
    } else if (streamSettings.network === 'grpc') {
        streamSettings.grpcSettings = {};
        if (s.path) streamSettings.grpcSettings.serviceName = s.path;
        if (s.authority) streamSettings.grpcSettings.authority = s.authority;
    } else if (streamSettings.network === 'tcp' && s.headerType === 'http') {
        streamSettings.tcpSettings = { header: { type: 'http', request: { headers: { Host: s.host } } } };
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
        const user = { id: bean.auth.uuid, encryption: 'none' };
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
        settings: { servers: [{ address: bean.host, port: bean.port, method: bean.ss.method, password: bean.ss.password }] }
    }; else if (bean.proto === 'socks' || bean.proto === 'http') {
        const s = { address: bean.host, port: bean.port };
        if (bean.socks?.username && bean.socks?.password) {
            s.users = [{ user: bean.socks.username, pass: bean.socks.password }];
        }
        outbound = { protocol: bean.proto, tag: (bean.name || bean.proto), settings: { servers: [s] } };
    } else if (bean.proto === 'hy2' || bean.proto === 'tuic') {
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
