import { generateSecretHex32, parseTunSpec, splitCSV, URLTEST, URLTEST_INTERVAL } from '../main.js';

function buildSingBoxOutbound(bean, opts) {
    const useExtended = !!(opts && opts.useExtended) || !!bean?._useExtended;
    const commonTLS = () => {
        const s = bean.stream || {};
        const isReality = !!(s.reality && s.reality.pbk);
        const hasTlsHints = !!(s.sni || (s.alpn && s.alpn.length) || s.fp);
        const needTls = s.security === 'tls' || isReality || (['vless', 'vmess'].includes(bean.proto) && hasTlsHints);
        if (!needTls) return undefined;
        const tls = { enabled: true };
        if (s.allowInsecure) tls.insecure = true;
        if (s.sni) tls.server_name = s.sni;
        if (s.alpn && s.alpn.length) tls.alpn = s.alpn;
        if (isReality) {
            tls.reality = { enabled: true, public_key: s.reality.pbk, short_id: s.reality.sid || '' };
            if (!s.fp) tls.utls = { enabled: true, fingerprint: 'random' };
        }
        if (s.fp) tls.utls = { enabled: true, fingerprint: s.fp };
        return tls;
    };

    function applyTransport(outbound, stream, packetEncoding) {
        if (stream.network !== 'tcp') {
            const t = { type: stream.network };
            if (stream.network === 'ws') {
                const hostHeader = stream.host || stream.sni || '';
                if (hostHeader) t.headers = { Host: hostHeader };
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
                if (!useExtended) return;
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
                if (stream.authority) t.authority = stream.authority;
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
                headers: { Host: splitCSV(stream.host) }
            };
        }
        if (outbound.type === 'vmess' || outbound.type === 'vless') {
            if (packetEncoding) outbound.packet_encoding = packetEncoding;
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
        outbound = { type: 'vless', server: bean.host, server_port: bean.port, uuid: bean.auth.uuid };
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
    }; else if (bean.proto === 'anytls') {
        outbound = {
            type: 'anytls',
            server: bean.host,
            server_port: bean.port || 443,
            password: bean.auth.password
        };
    } else if (bean.proto === 'socks' || bean.proto === 'http') {
        outbound = { type: bean.proto, server: bean.host, server_port: bean.port };
        if (bean.socks?.type === 'socks4') outbound.version = '4';
        if (bean.socks?.username && bean.socks?.password) {
            outbound.username = bean.socks.username;
            outbound.password = bean.socks.password;
        }
    } else if (bean.proto === 'hy2') {
        const h = bean.hysteria2 || {};
        const tlsFromStream = commonTLS();
        const alpn = splitCSV(h.alpn || '').filter(Boolean);
        const tls = Object.assign({ enabled: true }, tlsFromStream || {});
        if (h.allowInsecure) tls.insecure = true;
        if (h.sni) tls.server_name = h.sni;
        if (alpn.length) tls.alpn = alpn;
        else if (!Array.isArray(tls.alpn) || tls.alpn.length === 0) tls.alpn = ['h3'];
        outbound = { type: 'hysteria2', server: bean.host, server_port: bean.port || 443, tls };
        outbound.password = bean.auth.password;
        if (bean.hysteria2?.obfsPassword) {
            outbound.obfs = { type: 'salamander', password: bean.hysteria2.obfsPassword };
        }
        if (bean.hysteria2?.hopPort) {
            const raw = String(bean.hysteria2.hopPort || '').trim();
            const parts = raw.split(',').map(s => s.trim()).filter(Boolean);
            const ranges = parts.map(p => p.includes('-') ? p.replace('-', ':') : p);
            if (ranges.length) {
                outbound.server_ports = ranges;
                delete outbound.server_port;
            }
        }
        if (bean.hysteria2?.hopInterval) {
            const hi = String(bean.hysteria2.hopInterval).trim();
            const hasUnit = /(?:ms|s|m|h|d)$/i.test(hi);
            outbound.hop_interval = hasUnit ? hi : (/^\d+$/.test(hi) ? hi + 's' : hi);
        } else {
            outbound.hop_interval = '10s';
        }
    } else if (bean.proto === 'tuic') {
        const t = bean.tuic || {};
        const tlsFromStream = commonTLS();
        const alpn = splitCSV(t.alpn || '').filter(Boolean);
        const tls = Object.assign({ enabled: true }, tlsFromStream || {});
        if (t.allowInsecure) tls.insecure = true;
        if (t.disableSni) tls.disable_sni = true;
        if (t.sni) tls.server_name = t.sni;
        if (alpn.length) tls.alpn = alpn;
        outbound = { type: 'tuic', server: bean.host, server_port: bean.port || 443, tls };
        if (bean.tuic?.token) outbound.token = bean.tuic.token;
        else {
            if (bean.auth.uuid) outbound.uuid = bean.auth.uuid;
            if (bean.auth.password) outbound.password = bean.auth.password;
        }
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

    if (bean.proto === 'ss') {
        const ss = bean.ss || {};
        const uotVersion = (typeof ss.uot === 'number' && Number.isFinite(ss.uot)) ? ss.uot : 0;
        const smuxEnabled = !!(ss.smux && ss.smux.enabled);
        if (smuxEnabled && uotVersion > 0) {
            throw new Error('shadowsocks: udp-over-tcp conflicts with multiplex');
        }
        outbound.udp_over_tcp = uotVersion > 0 ? { enabled: true, version: uotVersion } : false;

        if (ss.plugin) {
            outbound.plugin = ss.plugin;
            if (ss.pluginOpts) {
                if (typeof ss.pluginOpts === 'string') {
                    const s = ss.pluginOpts.trim();
                    if (s) outbound.plugin_opts = s;
                } else if (typeof ss.pluginOpts === 'object') {
                    const parts = [];
                    for (const [k, v] of Object.entries(ss.pluginOpts)) {
                        const key = String(k || '').trim();
                        if (!key) continue;
                        if (v === true) {
                            parts.push(key);
                        } else if (v === false || v === undefined || v === null) {
                            continue;
                        } else {
                            const val = String(v).trim();
                            if (!val) continue;
                            parts.push(`${key}=${val}`);
                        }
                    }
                    if (parts.length) outbound.plugin_opts = parts.join(';');
                }
            }
        }

        if (smuxEnabled) {
            const smux = ss.smux || {};
            const protocol = String(smux.protocol || '').trim() || 'smux';
            outbound.multiplex = { enabled: true, protocol };
            const ms = smux['max-streams'];
            if (Number.isFinite(ms) && ms > 0) outbound.multiplex.max_streams = ms;
        }
    }

    const tls = commonTLS();
    if (tls) outbound.tls = tls;
    if (bean.stream) {
        const packetEncoding = (bean.stream && bean.stream.packet_encoding)
            ? bean.stream.packet_encoding
            : ((useExtended && outbound.type === 'vless') ? 'xudp' : '');
        applyTransport(outbound, bean.stream, packetEncoding);
    }
    return outbound;
}

function buildSingBoxInbounds(opts) {
    const inbounds = [];
    const androidMode = !!opts.androidMode;
    if (opts.addTun) {
        const specs = parseTunSpec(opts.tunName || '');
        const ifaces = specs.length ? specs.map(x => x.name) : ['singtun0'];
        for (let i = 0; i < ifaces.length; i++) {
            const name = ifaces[i];
            const tag = ifaces.length > 1 ? `tun-in-${name}` : 'tun-in';
            const octet = ifaces.length > 1 ? (i === 0 ? 1 : i * 10) : 1;
            const baseAddr = `172.19.0.${octet}`;
            const prefix = (ifaces.length > 1 || androidMode) ? 30 : 32;
            const cidr = `${baseAddr}/${prefix}`;
            const tun = {
                type: 'tun',
                tag,
                interface_name: name,
                address: [cidr],
                stack: 'gvisor',
                auto_route: androidMode ? true : false,
                strict_route: androidMode ? true : false
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

function buildSingBoxWireGuardEndpoint(bean) {
    if (!bean || bean.proto !== 'wireguard') throw new Error('wireguard bean required');
    const wg = bean.wireguard || {};

    const ensureCidrPrefix = (raw) => {
        const s = String(raw || '').trim();
        if (!s) return '';
        if (s.includes('/')) return s;
        const isIPv4 = (() => {
            const parts = s.split('.');
            if (parts.length !== 4) return false;
            for (const p of parts) {
                if (!/^\d+$/.test(p)) return false;
                const n = parseInt(p, 10);
                if (!(n >= 0 && n <= 255)) return false;
            }
            return true;
        })();
        if (isIPv4) return `${s}/32`;
        const isIPv6Like = s.includes(':') && /^[0-9a-fA-F:.]+$/.test(s);
        if (isIPv6Like) return `${s}/128`;
        return s;
    };

    const mapPeer = (p) => {
        if (!p || typeof p !== 'object') return null;
        const out = {
            address: p.server || '',
            port: p.port || 0,
        };
        if (p.publicKey) out.public_key = p.publicKey;
        if (p.preSharedKey) out.pre_shared_key = p.preSharedKey;
        if (Array.isArray(p.allowedIPs) && p.allowedIPs.length) out.allowed_ips = p.allowedIPs;
        if (Number.isFinite(wg.persistentKeepalive) && wg.persistentKeepalive > 0) {
            out.persistent_keepalive_interval = wg.persistentKeepalive;
        }
        if (p.reserved !== undefined) out.reserved = p.reserved;
        if (!out.address || !out.port) return null;
        return out;
    };

    const addr = [];
    if (Array.isArray(wg.addresses) && wg.addresses.length) {
        const normalized = wg.addresses.map(ensureCidrPrefix).filter(Boolean);
        if (normalized.length) addr.push(...normalized);
    }
    if (addr.length === 0) {
        if (wg.ip) addr.push(ensureCidrPrefix(wg.ip));
        if (wg.ipv6) addr.push(ensureCidrPrefix(wg.ipv6));
    }

    const peers = Array.isArray(wg.peers) && wg.peers.length ? wg.peers : [{
        server: bean.host,
        port: bean.port,
        publicKey: wg.publicKey,
        preSharedKey: wg.preSharedKey,
        allowedIPs: wg.allowedIPs,
        reserved: wg.reserved
    }];

    const ep = {
        type: 'wireguard',
        tag: bean.name || 'wireguard',
        system: false,
        mtu: Number.isFinite(wg.mtu) ? wg.mtu : undefined,
        address: addr,
        private_key: wg.privateKey,
        peers: peers.map(mapPeer).filter(Boolean),
    };
    if (ep.mtu === undefined) delete ep.mtu;
    return ep;
}

function buildSingBoxConfig(outboundsWithTags, opts) {
    const effectiveOpts = Object.assign({}, opts || {});
    const endpointTags = (effectiveOpts && Array.isArray(effectiveOpts.endpoints))
        ? effectiveOpts.endpoints.map(e => e?.tag).filter(Boolean)
        : [];
    const tags = [...outboundsWithTags.map(ob => ob.tag), ...endpointTags];
    if (effectiveOpts.addTun && effectiveOpts.perTunMixed && !String(effectiveOpts.tunName || '').trim()) {
        const count = tags.length;
        if (count > 1 && !effectiveOpts.androidMode) {
            const names = Array.from({ length: count }, (_, i) => `singtun${i}`);
            effectiveOpts.tunName = names.map(n => `${n}:select`).join(',');
        }
    }

    const inbounds = buildSingBoxInbounds(effectiveOpts);
    const managementOutbounds = [];
    const routeRules = [];
    const hasMany = tags.length > 1;
    const tunSpecs = parseTunSpec(effectiveOpts?.tunName || '');
    const tunIndexByName = new Map(tunSpecs.map((t, idx) => [t.name, idx]));
    const inboundTagFor = (name) => (tunSpecs.length > 1 ? `tun-in-${name}` : 'tun-in');
    const mixedInboundTagFor = (name) => (tunSpecs.length > 1 ? `mixed-in-${name}` : 'mixed-in');
    const defaultOutboundForTun = (name) => {
        if (!tags.length) return 'direct';
        const idx = tunIndexByName.has(name) ? tunIndexByName.get(name) : 0;
        const safeIdx = Number.isFinite(idx) && idx >= 0 ? idx : 0;
        return tags[safeIdx % tags.length] || (tags[0] || 'direct');
    };
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
                url: URLTEST,
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
        const globalAutoAvailable = createdGlobalAuto === true;
        const autoNames = tunSpecs.filter(t => t.mode === 'auto').map(t => t.name);
        const selectNames = tunSpecs.filter(t => t.mode === 'select').map(t => t.name);

        for (const name of autoNames) {
            if (hasMany) {
                managementOutbounds.push({
                    type: 'urltest',
                    tag: `auto-${name}`,
                    outbounds: tags,
                    url: URLTEST,
                    interval: URLTEST_INTERVAL,
                    tolerance: 50,
                    idle_timeout: '30m',
                    interrupt_exist_connections: false
                });
                routeRules.push({ inbound: inboundTagFor(name), outbound: `auto-${name}` });
            } else {
                const onlyTag = tags[0] || 'direct';
                routeRules.push({ inbound: inboundTagFor(name), outbound: onlyTag });
            }
        }
        for (const name of selectNames) {
            if (hasMany) {
                const outs = globalAutoAvailable ? ['auto', ...tags] : [...tags];
                const def = globalAutoAvailable ? defaultOutboundForTun(name) : defaultOutboundForTun(name);
                managementOutbounds.push({
                    type: 'selector',
                    tag: `select-${name}`,
                    outbounds: outs,
                    default: def,
                    interrupt_exist_connections: false
                });
                routeRules.push({ inbound: inboundTagFor(name), outbound: `select-${name}` });
            } else {
                const onlyTag = tags[0] || 'direct';
                routeRules.push({ inbound: inboundTagFor(name), outbound: onlyTag });
            }
        }

        if (effectiveOpts.addSocks && effectiveOpts.perTunMixed) {
            for (const name of autoNames) {
                const onlyTag = tags[0] || 'direct';
                routeRules.push({ inbound: mixedInboundTagFor(name), outbound: hasMany ? `auto-${name}` : onlyTag });
            }
            for (const name of selectNames) {
                const onlyTag = tags[0] || 'direct';
                routeRules.push({ inbound: mixedInboundTagFor(name), outbound: hasMany ? `select-${name}` : onlyTag });
            }
        } else if (effectiveOpts.addSocks) {
            const firstTun = tunSpecs[0];
            if (firstTun) {
                const onlyTag = tags[0] || 'direct';
                const outbound = hasMany
                    ? (firstTun.mode === 'auto' ? `auto-${firstTun.name}` : `select-${firstTun.name}`)
                    : onlyTag;
                routeRules.push({ inbound: 'mixed-in', outbound });
            }
        }
    }

    if (effectiveOpts?.androidMode) {
        routeRules.unshift({ protocol: 'dns', action: 'hijack-dns' });
        routeRules.unshift({ action: 'sniff' });
    }

    routeRules.push({ ip_version: 6, outbound: 'block' });
    const outbounds = [
        { tag: 'direct', type: 'direct' },
        { tag: 'block', type: 'block' },
        ...managementOutbounds,
        ...outboundsWithTags
    ];
    const experimental = {};
    if (!effectiveOpts?.androidMode) {
        experimental.cache_file = { enabled: true };
        experimental.clash_api = {
            external_controller: '[::]:9090',
            external_ui: 'ui',
            external_ui_download_detour: 'direct',
            access_control_allow_private_network: true,
            secret: effectiveOpts?.genClashSecret ? generateSecretHex32() : ''
        };
    }
    const config = {
        log: { level: 'info' },
        inbounds,
        outbounds,
        route: { rules: routeRules, final: (createdGlobalSelector ? 'select' : 'direct') }
    };
    if (effectiveOpts && Array.isArray(effectiveOpts.endpoints) && effectiveOpts.endpoints.length > 0) {
        config.endpoints = effectiveOpts.endpoints;
    }
    if (Object.keys(experimental).length > 0) {
        config.experimental = experimental;
    }

    const dnsServers = (effectiveOpts?.useExtended ? buildDNSServers(effectiveOpts?.dnsBeans || []) : []);
    if (dnsServers.length > 0) {
        config.dns = { servers: dnsServers };
        config.route.default_domain_resolver = dnsServers[0]?.tag || '';
    } else if (effectiveOpts?.androidMode) {
        config.dns = {
            servers: [
                {
                    type: 'local',
                    tag: 'local'
                }
            ],
            strategy: 'ipv4_only'
        };
        config.route.default_domain_resolver = 'local';
    }

    if (effectiveOpts?.androidMode) {
        config.route.auto_detect_interface = true;
        config.route.override_android_vpn = true;
    }

    if (effectiveOpts?.useExtended) {
        if (!config.experimental) config.experimental = {};
        config.experimental.unified_delay = { enabled: true };
    }

    return config;
}

export {
    buildSingBoxOutbound,
    buildSingBoxWireGuardEndpoint,
    buildSingBoxConfig,
};


