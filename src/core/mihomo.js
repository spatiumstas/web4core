import { computeTag, validateBean, URLTEST, PROXY_FETCH_INTERVAL, SUB_REFRESH_INTERVAL } from '../main.js';

const FASTEST_GROUP_NAME = '⚡ Fastest';
const GLOBAL_GROUP_NAME = 'GLOBAL';
const PER_PROXY_GROUP_PREFIX = '🔒 ';

function sanitizeProviderName(name) {
    const raw = String(name || '').trim().toLowerCase();
    if (!raw) return '';
    const cleaned = raw
        .replace(/^www\./, '')
        .replace(/[^a-z0-9._-]+/g, '-')
        .replace(/[._-]{2,}/g, '-')
        .replace(/^[._-]+|[._-]+$/g, '');
    return cleaned.slice(0, 48);
}

function computeProviderName(url, index, total, used) {
    let base = '';
    try {
        const u = new URL(String(url || '').trim());
        base = sanitizeProviderName(u.hostname || '');
    } catch {
    }
    if (!base) {
        base = total === 1 ? 'my_subscription' : `subscription_${index + 1}`;
    }
    let name = base;
    let i = 2;
    while (used.has(name)) {
        name = `${base}-${i++}`;
    }
    used.add(name);
    return name;
}

function attachPerProxySelectGroup(groups, proxy) {
    const groupName = `${PER_PROXY_GROUP_PREFIX}${proxy.name}`;
    groups.push({
        name: groupName,
        type: 'select',
        proxies: [proxy.name, 'REJECT']
    });
    proxy._groupName = groupName;
}

function buildMihomoProxy(bean) {
    const s = bean.stream || {};
    const base = { name: bean.name || computeTag(bean, new Set()), type: '', server: bean.host, port: bean.port };
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
                const ro = { 'public-key': s.reality.pbk };
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
            if (s.host) obj['ws-opts'].headers = { Host: s.host };
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
            if (s.authority) obj['grpc-opts'].authority = s.authority;
            if (s.grpcUserAgent) obj['grpc-opts']['grpc-user-agent'] = s.grpcUserAgent;
        } else if (s.network === 'tcp' && s.headerType === 'http') {
            obj.network = 'tcp';
            const httpOpts = {};
            if (s.path) {
                httpOpts.path = [s.path].filter(Boolean);
            }
            if (s.host) {
                httpOpts.headers = { 
                    Host: Array.isArray(s.host) ? s.host : [s.host] 
                };
            }
            obj['http-opts'] = httpOpts;
        } else {
            obj.network = 'tcp';
        }
    };
    if (bean.proto === 'vmess') {
        const p = { ...base, type: 'vmess', uuid: bean.auth.uuid, cipher: bean.auth.security || 'auto', alterId: 0 };
        applyTls(p);
        applyNetwork(p);
        applyCommon(p);
        return p;
    }
    if (bean.proto === 'vless') {
        const p = { ...base, type: 'vless', uuid: bean.auth.uuid, encryption: 'none' };
        if (bean.auth.flow) p.flow = bean.auth.flow;
        if (bean.auth.flow && bean.auth.flow.includes('vision')) {
            p.udp = true;
        }
        applyTls(p);
        applyNetwork(p);
        applyCommon(p);
        return p;
    }
    if (bean.proto === 'trojan') {
        const p = { ...base, type: 'trojan', password: bean.auth.password };
        applyTls(p);
        applyNetwork(p);
        applyCommon(p);
        return p;
    }
    if (bean.proto === 'ss') {
        const p = { ...base, type: 'ss', cipher: bean.ss.method, password: bean.ss.password };
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
        const p = { ...base, type: 'http' };
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
        const p = { ...base, type: 'socks5' };
        if (bean.socks?.username) p.username = bean.socks.username;
        if (bean.socks?.password) p.password = bean.socks.password;
        applyCommon(p);
        return p;
    }
    if (bean.proto === 'hy2') {
        const p = { ...base, type: 'hysteria2', password: bean.auth.password };
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
        const p = { ...base, type: 'tuic' };
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
    if (bean.proto === 'wireguard') {
        const wg = bean.wireguard || {};
        const peers = Array.isArray(wg.peers) ? wg.peers : [];
        const hasPeers = peers.length > 0;
        const mapPeer = (peer) => {
            if (!peer || typeof peer !== 'object') return null;
            const out = { server: peer.server, port: peer.port };
            if (peer.publicKey) out['public-key'] = peer.publicKey;
            if (peer.preSharedKey) out['pre-shared-key'] = peer.preSharedKey;
            if (Array.isArray(peer.allowedIPs) && peer.allowedIPs.length) out['allowed-ips'] = peer.allowedIPs;
            if (peer.reserved !== undefined) out.reserved = peer.reserved;
            return out;
        };
        const p = {
            name: bean.name || computeTag(bean, new Set()),
            type: 'wireguard',
            server: bean.host,
            port: bean.port,
            'private-key': wg.privateKey,
            udp: true,
        };
        if (wg.ip) p.ip = wg.ip;
        if (wg.ipv6) p.ipv6 = wg.ipv6;
        if (wg.publicKey) p['public-key'] = wg.publicKey;
        if (wg.preSharedKey) p['pre-shared-key'] = wg.preSharedKey;
        if (Array.isArray(wg.allowedIPs) && wg.allowedIPs.length) p['allowed-ips'] = wg.allowedIPs;
        if (Number.isFinite(wg.mtu)) p.mtu = wg.mtu;
        if (Number.isFinite(wg.persistentKeepalive) && wg.persistentKeepalive > 0) p['persistent-keepalive'] = wg.persistentKeepalive;
        if (wg.reserved !== undefined) p.reserved = wg.reserved;
        if (hasPeers) p.peers = peers.map(mapPeer).filter(Boolean);
        if (wg['amnezia-wg-option'] && typeof wg['amnezia-wg-option'] === 'object') {
            p['amnezia-wg-option'] = wg['amnezia-wg-option'];
        }
        applyCommon(p);
        return p;
    }
    if (bean.proto === 'masque') {
        const mq = bean.masque || {};
        const p = {
            ...base,
            type: 'masque'
        };
        if (mq.privateKey) p['private-key'] = mq.privateKey;
        if (mq.publicKey) p['public-key'] = mq.publicKey;
        if (mq.ip) p.ip = mq.ip;
        if (mq.ipv6) p.ipv6 = mq.ipv6;
        if (mq.uri) p.uri = mq.uri;
        if (mq.sni) p.sni = mq.sni;
        if (Number.isFinite(mq.mtu) && mq.mtu > 0) p.mtu = mq.mtu;
        if (mq.udp === true) p.udp = true;
        if (mq.congestionController) p['congestion-controller'] = mq.congestionController;
        if (Number.isFinite(mq.cwnd) && mq.cwnd > 0) p.cwnd = mq.cwnd;
        if (mq.remoteDnsResolve) p['remote-dns-resolve'] = true;
        if (Array.isArray(mq.dns) && mq.dns.length) p.dns = mq.dns;
        applyCommon(p);
        return p;
    }
    throw new Error('Not supported by Mihomo: ' + bean.proto);
}

function deduplicateProxies(beans) {
    const toKeyPart = (v) => {
        if (v === null || v === undefined) return '';
        if (Array.isArray(v)) return v.map(toKeyPart).join(',');
        return String(v);
    };
    const stableObjectKey = (obj) => {
        if (!obj || typeof obj !== 'object') return '';
        const keys = Object.keys(obj).sort();
        return keys.map(k => `${k}=${toKeyPart(obj[k])}`).join('&');
    };
    const wireguardExtraKey = (wg) => {
        const peers = Array.isArray(wg?.peers) ? wg.peers : [];
        const peersKey = peers.map(p => {
            const allowed = Array.isArray(p?.allowedIPs) ? p.allowedIPs.map(toKeyPart).join(',') : '';
            const reserved = (p && p.reserved !== undefined) ? toKeyPart(p.reserved) : '';
            return [
                toKeyPart(p?.server),
                toKeyPart(p?.port),
                toKeyPart(p?.publicKey),
                toKeyPart(p?.preSharedKey),
                allowed,
                reserved
            ].join('|');
        }).join(';');
        const dns = Array.isArray(wg?.dns) ? wg.dns.map(toKeyPart).join(',') : '';
        const allowedIPs = Array.isArray(wg?.allowedIPs) ? wg.allowedIPs.map(toKeyPart).join(',') : '';
        return [
            `pk=${toKeyPart(wg?.privateKey)}`,
            `pub=${toKeyPart(wg?.publicKey)}`,
            `psk=${toKeyPart(wg?.preSharedKey)}`,
            `ip=${toKeyPart(wg?.ip)}`,
            `ipv6=${toKeyPart(wg?.ipv6)}`,
            `allowed=${allowedIPs}`,
            `res=${toKeyPart(wg?.reserved)}`,
            `mtu=${toKeyPart(wg?.mtu)}`,
            `keepalive=${toKeyPart(wg?.persistentKeepalive)}`,
            `udp=${toKeyPart(wg?.udp)}`,
            `remoteDnsResolve=${toKeyPart(wg?.remoteDnsResolve)}`,
            `dns=${dns}`,
            `refreshServerIPInterval=${toKeyPart(wg?.refreshServerIPInterval)}`,
            `workers=${toKeyPart(wg?.workers)}`,
            `awg=${stableObjectKey(wg?.['amnezia-wg-option'])}`,
            `peers=${peersKey}`
        ].join('&');
    };
    const seen = new Set();
    return beans.filter(b => {
        const auth = b.auth?.uuid || b.auth?.password || b.ss?.password || b.socks?.username || '';
        const network = b.stream?.network || 'tcp';
        const security = b.stream?.security || '';
        const flow = b.auth?.flow || '';
        const pqv = b.stream?.reality?.pqv || '';
        const pqvKey = pqv ? pqv.substring(0, 50) : '';
        let extra = '';
        if (b.proto === 'wireguard') {
            extra = wireguardExtraKey(b.wireguard || {});
        }
        const key = `${b.proto}|${b.host}|${b.port}|${auth}|${network}|${security}|${flow}|${pqvKey}|${extra}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    });
}

function buildMihomoConfig(beans, opts) {
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
    const usePerProxyPort = !!(opts && opts.perProxyPort);
    const groups = [];
    
    if (usePerProxyPort) {
        proxies.forEach(p => {
            attachPerProxySelectGroup(groups, p);
        });
        const groupNames = proxies.map(p => p._groupName);
        groups.push({
            name: GLOBAL_GROUP_NAME,
            type: 'select',
            proxies: groupNames.length > 0 ? [...groupNames, 'REJECT'] : ['REJECT']
        });
    } else {
        if (names.length > 1) {
            groups.push({
                name: FASTEST_GROUP_NAME,
                type: 'url-test',
                proxies: names,
                url: URLTEST,
                interval: PROXY_FETCH_INTERVAL
            });
            groups.push({
                name: GLOBAL_GROUP_NAME,
                type: 'select',
                proxies: [FASTEST_GROUP_NAME, 'REJECT']
            });
        } else {
            const only = names[0] || 'REJECT';
            groups.push({
                name: GLOBAL_GROUP_NAME,
                type: 'select',
                proxies: [only, 'REJECT']
            });
        }
    }
    
    const basePort = (opts && opts.basePort) || 7890;
    const listeners = [];
    if (usePerProxyPort && proxies.length > 0) {
        for (let i = 0; i < proxies.length; i++) {
            const port = basePort + i;
            const targetGroup = proxies[i]._groupName || proxies[i].name;
            listeners.push({
                name: `socks-${proxies[i].name}`,
                type: 'socks',
                port: port,
                proxy: targetGroup
            });
        }
    }
    const config = {
        'allow-lan': false,
        mode: 'rule',
        'log-level': 'info',
        proxies,
        'proxy-groups': groups,
        rules: [`MATCH,${GLOBAL_GROUP_NAME}`]
    };
    if (!usePerProxyPort) {
        config['mixed-port'] = basePort;
    } else if (listeners.length > 0) {
        config.listeners = listeners;
    }
    return config;
}

function buildMihomoSubscriptionConfig(subscriptionUrls, extraBeans, opts) {
    if (!Array.isArray(subscriptionUrls) || subscriptionUrls.length === 0) {
        throw new Error('At least one subscription URL is required');
    }

    const providers = {};
    const providerNames = [];
    const usedProviderNames = new Set();
    subscriptionUrls.forEach((url, index) => {
        const providerName = computeProviderName(url, index, subscriptionUrls.length, usedProviderNames);
        providers[providerName] = {
            type: 'http',
            url: url,
            interval: SUB_REFRESH_INTERVAL,
            __comments: {
                interval: 'Subscription refresh interval'
            },
            'health-check': {
                enable: true,
                interval: PROXY_FETCH_INTERVAL,
                url: URLTEST,
                'expected-status': 204,
                __comments: {
                    interval: 'Health-check interval'
                }
            }
        };
        providerNames.push(providerName);
    });

    const groups = [{
        name: FASTEST_GROUP_NAME,
        type: 'url-test',
        use: providerNames,
        url: URLTEST,
        interval: PROXY_FETCH_INTERVAL,
        tolerance: 50,
        __comments: {
            interval: 'Latency probe interval (seconds)',
            tolerance: 'Switch threshold (ms)'
        }
    }];

    groups.push({
        name: GLOBAL_GROUP_NAME,
        type: 'select',
        proxies: [FASTEST_GROUP_NAME, 'REJECT']
    });

    if (providerNames.length > 1) {
        providerNames.forEach((providerName) => {
            groups.push({
                name: `SUB-${providerName}`,
                type: 'select',
                use: [providerName]
            });
        });
    }

    const usePerProxyPort = !!(opts && opts.perProxyPort);
    const fastestGroup = groups.find(g => g && g.name === FASTEST_GROUP_NAME && g.type === 'url-test');
    const extraProxies = [];
    if (Array.isArray(extraBeans) && extraBeans.length > 0) {
        extraBeans.forEach(bean => {
            validateBean(bean);
            const p = buildMihomoProxy(bean);
            extraProxies.push(p);
            if (usePerProxyPort) {
                attachPerProxySelectGroup(groups, p);
            } else {
                if (fastestGroup) {
                    if (!Array.isArray(fastestGroup.proxies)) fastestGroup.proxies = [];
                    if (!fastestGroup.proxies.includes(p.name)) fastestGroup.proxies.push(p.name);
                }
            }
        });
    }
    const basePort = (opts && opts.basePort) || 7890;
    const listeners = [];
    if (usePerProxyPort) {
        const buildSocksListener = (name, proxy, port) => ({
            name: `socks-${name}`,
            type: 'socks',
            port,
            proxy
        });
        let portIdx = 0;
        if (providerNames.length > 1) {
            providerNames.forEach(providerName => {
                listeners.push(buildSocksListener(`SUB-${providerName}`, `SUB-${providerName}`, basePort + portIdx++));
            });
        } else {
            listeners.push(buildSocksListener(FASTEST_GROUP_NAME, FASTEST_GROUP_NAME, basePort + portIdx++));
        }
        extraProxies.forEach(p => {
            const targetGroup = p._groupName || p.name;
            listeners.push(buildSocksListener(p.name, targetGroup, basePort + portIdx++));
        });
    }

    const rules = [`MATCH,${GLOBAL_GROUP_NAME}`];
    return { providers, groups, rules, proxies: extraProxies, listeners };
}

export {
    buildMihomoProxy,
    buildMihomoConfig,
    buildMihomoSubscriptionConfig,
};
