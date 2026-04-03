import { computeTag, validateBean, URLTEST, PROXY_FETCH_INTERVAL, SUB_REFRESH_INTERVAL } from '../main.js';

const FASTEST_GROUP_NAME = '⚡ Fastest';
const GLOBAL_GROUP_NAME = 'GLOBAL';
const PER_PROXY_GROUP_PREFIX = '🔒 ';

function getPerProxyGroupName(proxyName) {
    return `${PER_PROXY_GROUP_PREFIX}${proxyName}`;
}

function uniqueTargets(...parts) {
    const out = [];
    const seen = new Set();
    parts.flat().forEach((item) => {
        const name = String(item || '').trim();
        if (!name || seen.has(name)) return;
        seen.add(name);
        out.push(name);
    });
    return out;
}

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

function isPerProxyListenerMode(opts) {
    return !!(opts && (opts.perProxyPort || opts.perProxyListeners));
}

function attachPerProxySelectGroup(groups, proxy) {
    const groupName = getPerProxyGroupName(proxy.name);
    groups.push({
        name: groupName,
        type: 'select',
        proxies: [proxy.name, 'REJECT']
    });
    return groupName;
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
            if (Number.isFinite(s.grpcPingInterval) && s.grpcPingInterval > 0) {
                obj['grpc-opts']['ping-interval'] = s.grpcPingInterval;
            }
            if (Number.isFinite(s.grpcMaxConnections) && s.grpcMaxConnections > 0) {
                obj['grpc-opts']['max-connections'] = s.grpcMaxConnections;
            }
            if (Number.isFinite(s.grpcMinStreams) && s.grpcMinStreams >= 0) {
                obj['grpc-opts']['min-streams'] = s.grpcMinStreams;
            }
            if (Number.isFinite(s.grpcMaxStreams) && s.grpcMaxStreams >= 0) {
                obj['grpc-opts']['max-streams'] = s.grpcMaxStreams;
            }
        } else if (s.network === 'xhttp') {
            obj.network = 'xhttp';
            obj['xhttp-opts'] = {};
            if (s.path) obj['xhttp-opts'].path = s.path;
            if (s.host) obj['xhttp-opts'].host = s.host;
            if (s.xhttpMode) obj['xhttp-opts'].mode = s.xhttpMode;
            else obj['xhttp-opts'].mode = 'stream-up';
            obj['xhttp-opts']['x-padding-bytes'] = '100-1000';

            if (Number.isFinite(s.xhttpScMaxEachPostBytes) && s.xhttpScMaxEachPostBytes > 0) {
                obj['xhttp-opts']['sc-max-each-post-bytes'] = s.xhttpScMaxEachPostBytes;
            }

            const xmux = s.xhttpXmux || {};
            const reuseSettings = {};
            if (xmux.max_connections) reuseSettings['max-connections'] = xmux.max_connections;
            if (xmux.max_concurrency) reuseSettings['max-concurrency'] = xmux.max_concurrency;
            if (xmux.c_max_reuse_times) reuseSettings['c-max-reuse-times'] = xmux.c_max_reuse_times;
            if (xmux.h_max_request_times) reuseSettings['h-max-request-times'] = xmux.h_max_request_times;
            if (xmux.h_max_reusable_secs) reuseSettings['h-max-reusable-secs'] = xmux.h_max_reusable_secs;
            if (Object.keys(reuseSettings).length) {
                obj['xhttp-opts']['reuse-settings'] = reuseSettings;
            }

            const download = s.xhttpDownload || {};
            const hasDownload = Object.values(download).some(v => v !== '' && v !== 0);
            if (hasDownload) {
                obj['xhttp-opts']['download-settings'] = {};
                if (download.host) obj['xhttp-opts']['download-settings'].host = download.host;
                if (download.path) obj['xhttp-opts']['download-settings'].path = download.path;
                if (download.x_padding_bytes) obj['xhttp-opts']['download-settings']['x-padding-bytes'] = download.x_padding_bytes;
                if (download.sc_max_each_post_bytes) {
                    obj['xhttp-opts']['download-settings']['sc-max-each-post-bytes'] = download.sc_max_each_post_bytes;
                }
                if (download.server) obj['xhttp-opts']['download-settings'].server = download.server;
                if (download.server_port) obj['xhttp-opts']['download-settings'].port = download.server_port;

                const dx = download.xmux || {};
                const downloadReuseSettings = {};
                if (dx.max_connections) downloadReuseSettings['max-connections'] = dx.max_connections;
                if (dx.max_concurrency) downloadReuseSettings['max-concurrency'] = dx.max_concurrency;
                if (dx.c_max_reuse_times) downloadReuseSettings['c-max-reuse-times'] = dx.c_max_reuse_times;
                if (dx.h_max_request_times) downloadReuseSettings['h-max-request-times'] = dx.h_max_request_times;
                if (dx.h_max_reusable_secs) downloadReuseSettings['h-max-reusable-secs'] = dx.h_max_reusable_secs;
                if (Object.keys(downloadReuseSettings).length) {
                    obj['xhttp-opts']['download-settings']['reuse-settings'] = downloadReuseSettings;
                }
            }
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
    if (bean.proto === 'mieru') {
        const mieru = bean.mieru || {};
        const p = {
            name: bean.name || computeTag(bean, new Set()),
            type: 'mieru',
            server: bean.host,
            transport: mieru.transport || 'TCP',
            username: mieru.username,
            password: mieru.password,
        };
        if (mieru.server_ports) p['port-range'] = mieru.server_ports;
        else p.port = bean.port;
        if (mieru.multiplexing) p.multiplexing = mieru.multiplexing;
        if (mieru.handshake_mode) p['handshake-mode'] = mieru.handshake_mode;
        if (mieru.traffic_pattern) p['traffic-pattern'] = mieru.traffic_pattern;
        applyCommon(p);
        return p;
    }
    if (bean.proto === 'trusttunnel') {
        const tt = bean.trusttunnel || {};
        const p = {
            ...base,
            type: 'trusttunnel',
            username: tt.username,
            password: tt.password,
        };
        if (s.sni) p.sni = s.sni;
        if (s.alpn && s.alpn.length) p.alpn = s.alpn;
        if (s.allowInsecure) p['skip-cert-verify'] = true;
        if (s.fp) p['client-fingerprint'] = s.fp;
        if (tt.fingerprint) p.fingerprint = tt.fingerprint;
        if (tt.certificate) p.certificate = tt.certificate;
        if (tt.privateKey) p['private-key'] = tt.privateKey;
        const echConfig = (s.ech?.config || s.ech?.configList || '').trim();
        const echQueryServerName = (s.ech?.queryServerName || '').trim();
        if (echConfig || echQueryServerName) {
            p['ech-opts'] = { enable: true };
            if (echConfig) p['ech-opts'].config = echConfig;
            if (echQueryServerName) p['ech-opts']['query-server-name'] = echQueryServerName;
        }
        if (tt.healthCheck) p['health-check'] = true;
        if (tt.quic) p.quic = true;
        if (tt.congestionController) p['congestion-controller'] = tt.congestionController;
        if (Number.isFinite(tt.cwnd) && tt.cwnd > 0) p.cwnd = tt.cwnd;
        if (Number.isFinite(tt.maxConnections) && tt.maxConnections > 0) p['max-connections'] = tt.maxConnections;
        if (Number.isFinite(tt.minStreams) && tt.minStreams >= 0) p['min-streams'] = tt.minStreams;
        if (Number.isFinite(tt.maxStreams) && tt.maxStreams >= 0) p['max-streams'] = tt.maxStreams;
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
    const usePerProxyListeners = isPerProxyListenerMode(opts);
    const usePerProxyPort = !!(opts && opts.perProxyPort);
    const addSocks = !opts || opts.addSocks !== false;
    const groups = [];

    if (usePerProxyListeners) {
        proxies.forEach(p => {
            attachPerProxySelectGroup(groups, p);
        });
        const groupNames = proxies.map(p => getPerProxyGroupName(p.name));
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
                proxies: uniqueTargets(FASTEST_GROUP_NAME, names, 'REJECT')
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
    if (addSocks && usePerProxyPort && proxies.length > 0) {
        for (let i = 0; i < proxies.length; i++) {
            const port = basePort + i;
            const targetGroup = usePerProxyListeners ? getPerProxyGroupName(proxies[i].name) : proxies[i].name;
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
    if (addSocks && !usePerProxyPort) {
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

    const usePerProxyListeners = isPerProxyListenerMode(opts);
    const usePerProxyPort = !!(opts && opts.perProxyPort);
    const groups = [];
    if (!usePerProxyListeners) {
        groups.push({
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
        });
    }

    if (usePerProxyListeners || usePerProxyPort) {
        providerNames.forEach((providerName) => {
            groups.push({
                name: `SUB-${providerName}`,
                type: 'select',
                use: [providerName]
            });
        });
    }

    const addSocks = !opts || opts.addSocks !== false;
    const fastestGroup = !usePerProxyListeners
        ? groups.find(g => g && g.name === FASTEST_GROUP_NAME && g.type === 'url-test')
        : null;
    const extraProxies = [];
    if (Array.isArray(extraBeans) && extraBeans.length > 0) {
        extraBeans.forEach(bean => {
            validateBean(bean);
            const p = buildMihomoProxy(bean);
            extraProxies.push(p);
            if (usePerProxyListeners) {
                attachPerProxySelectGroup(groups, p);
            } else {
                if (fastestGroup) {
                    if (!Array.isArray(fastestGroup.proxies)) fastestGroup.proxies = [];
                    if (!fastestGroup.proxies.includes(p.name)) fastestGroup.proxies.push(p.name);
                }
            }
        });
    }

    if (usePerProxyListeners) {
        const globalTargets = providerNames.map(providerName => `SUB-${providerName}`);
        extraProxies.forEach((p) => {
            const targetGroup = getPerProxyGroupName(p.name);
            if (targetGroup) globalTargets.push(targetGroup);
        });
        groups.push({
            name: GLOBAL_GROUP_NAME,
            type: 'select',
            proxies: globalTargets.length > 0 ? [...globalTargets, 'REJECT'] : ['REJECT']
        });
    } else {
        const fastestTargets = fastestGroup && Array.isArray(fastestGroup.proxies)
            ? [...fastestGroup.proxies]
            : [];
        groups.push({
            name: GLOBAL_GROUP_NAME,
            type: 'select',
            proxies: uniqueTargets(FASTEST_GROUP_NAME, fastestTargets, 'REJECT'),
            use: providerNames
        });
    }

    const basePort = (opts && opts.basePort) || 7890;
    const listeners = [];
    if (addSocks && usePerProxyPort) {
        const buildSocksListener = (name, proxy, port) => ({
            name: `socks-${name}`,
            type: 'socks',
            port,
            proxy
        });
        let portIdx = 0;
        providerNames.forEach(providerName => {
            listeners.push(buildSocksListener(`SUB-${providerName}`, `SUB-${providerName}`, basePort + portIdx++));
        });
        extraProxies.forEach(p => {
            const targetGroup = getPerProxyGroupName(p.name);
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
