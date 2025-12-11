function parseWireGuardConf(confText, nameHint) {
    const text = String(confText || '').replace(/\r\n/g, '\n');
    const lines = text.split('\n');
    let section = '';
    const iface = {};
    const peers = [];
    let curPeer = null;

    const cleanLine = (ln) => {
        let s = (ln || '').trim();
        if (!s) return '';
        const hash = s.indexOf('#');
        const semi = s.indexOf(';');
        const cut = (hash === -1) ? semi : (semi === -1 ? hash : Math.min(hash, semi));
        if (cut !== -1) s = s.slice(0, cut).trim();
        return s;
    };
    const splitKV = (ln) => {
        const i = ln.indexOf('=');
        if (i === -1) return null;
        const k = ln.slice(0, i).trim();
        const v = ln.slice(i + 1).trim();
        if (!k) return null;
        return {k, v};
    };
    const parseCsv = (v) => String(v || '').split(',').map(x => x.trim()).filter(Boolean);
    const parseAddrList = (v) => parseCsv(v).map(x => x.replace(/\s+/g, '')).filter(Boolean);

    const setAwgOpt = (target, key, value) => {
        const k = String(key || '').trim().toLowerCase();
        const map = {
            jc: 'jc',
            jmin: 'jmin',
            jmax: 'jmax',
            s1: 's1',
            s2: 's2',
            s3: 's3',
            s4: 's4',
            h1: 'h1',
            h2: 'h2',
            h3: 'h3',
            h4: 'h4',
            i1: 'i1',
            i2: 'i2',
            i3: 'i3',
            i4: 'i4',
            i5: 'i5',
            j1: 'j1',
            j2: 'j2',
            j3: 'j3',
            itime: 'itime',
        };
        if (!map[k]) return false;
        if (!target['amnezia-wg-option']) target['amnezia-wg-option'] = {};
        const outKey = map[k];
        const raw = String(value || '').trim();
        const numericKeys = new Set(['jc', 'jmin', 'jmax', 's1', 's2', 's3', 's4', 'itime']);
        if (numericKeys.has(outKey) && /^-?\d+$/.test(raw)) {
            target['amnezia-wg-option'][outKey] = parseInt(raw, 10);
        } else {
            target['amnezia-wg-option'][outKey] = raw;
        }
        return true;
    };

    const parseReserved = (v) => {
        const s = String(v || '').trim();
        if (!s) return undefined;
        if (s.includes(',')) {
            const parts = parseCsv(s);
            const nums = parts
                .map(x => (/^\d+$/.test(x) ? parseInt(x, 10) : NaN))
                .filter(n => Number.isInteger(n) && n >= 0 && n <= 255);
            return nums.length ? nums : undefined;
        }
        return s;
    };

    for (const rawLine of lines) {
        const ln = cleanLine(rawLine);
        if (!ln) continue;
        const secMatch = ln.match(/^\[([^\]]+)\]$/);
        if (secMatch) {
            section = (secMatch[1] || '').trim().toLowerCase();
            if (section === 'peer') {
                curPeer = {};
                peers.push(curPeer);
            } else {
                curPeer = null;
            }
            continue;
        }
        const kv = splitKV(ln);
        if (!kv) continue;
        const key = kv.k.trim();
        const value = kv.v;
        const keyLower = key.toLowerCase();

        if (setAwgOpt(iface, key, value)) continue;

        if (section === 'interface') {
            if (keyLower === 'privatekey') iface.privateKey = value;
            else if (keyLower === 'address') iface.addresses = parseAddrList(value);
            else if (keyLower === 'dns') iface.dns = parseCsv(value);
            else if (keyLower === 'mtu') iface.mtu = /^\d+$/.test(value) ? parseInt(value, 10) : undefined;
            else if (keyLower === 'name') iface.name = value;
        } else if (section === 'peer' && curPeer) {
            if (keyLower === 'publickey') curPeer.publicKey = value;
            else if (keyLower === 'presharedkey') curPeer.preSharedKey = value;
            else if (keyLower === 'allowedips') curPeer.allowedIPs = parseAddrList(value);
            else if (keyLower === 'endpoint') curPeer.endpoint = value;
            else if (keyLower === 'persistentkeepalive') curPeer.persistentKeepalive = /^\d+$/.test(value) ? parseInt(value, 10) : undefined;
            else if (keyLower === 'reserved') {
                curPeer.reserved = parseReserved(value);
            } else {
                setAwgOpt(iface, key, value);
            }
        }
    }

    const chosenPeer = peers[0] || {};
    const {host, port} = parseAddrHostPort(chosenPeer.endpoint || '', 51820);
    const addrs = Array.isArray(iface.addresses) ? iface.addresses : [];
    const ipv4Raw = addrs.find(a => /^(\d{1,3}\.){3}\d{1,3}(\/\d+)?$/.test(a));
    const ipv6Raw = addrs.find(a => /:/.test(a));
    const ipv4 = ipv4Raw ? ipv4Raw.split('/')[0] : '';
    const ipv6 = ipv6Raw ? ipv6Raw.split('/')[0] : '';

    const nameBase = (iface.name || nameHint || 'WireGuard').toString().trim();
    const name = nameBase ? nameBase.replace(/\.(conf|wg|awg)$/i, '') : 'WireGuard';

    const wgPeers = peers.map(p => {
        const ap = parseAddrHostPort(p.endpoint || '', 51820);
        return {
            server: ap.host,
            port: ap.port,
            publicKey: p.publicKey || '',
            preSharedKey: p.preSharedKey || '',
            allowedIPs: Array.isArray(p.allowedIPs) ? p.allowedIPs : [],
            reserved: p.reserved
        };
    }).filter(p => p.server && p.port);

    const keepalive = peers.map(p => p.persistentKeepalive).find(v => Number.isFinite(v));

    const hasIpv6 = !!ipv6;
    const peer0 = wgPeers[0] || {};
    const allowed0 = Array.isArray(peer0.allowedIPs) ? peer0.allowedIPs.slice() : [];
    const allowedFiltered0 = hasIpv6 ? allowed0 : allowed0.filter(x => !String(x || '').includes(':'));
    const peersFiltered = wgPeers.map(peer => {
        const a = Array.isArray(peer.allowedIPs) ? peer.allowedIPs : [];
        const allowedFiltered = hasIpv6 ? a : a.filter(x => !String(x || '').includes(':'));
        return Object.assign({}, peer, {allowedIPs: allowedFiltered});
    });

    const bean = {
        proto: 'wireguard',
        name,
        host: peer0.server || host,
        port: peer0.port || port,
        ipVersion: hasIpv6 ? '' : 'ipv4',
        wireguard: {
            ip: ipv4 || '',
            ipv6: ipv6 || '',
            privateKey: iface.privateKey || '',
            publicKey: peer0.publicKey || (chosenPeer.publicKey || ''),
            preSharedKey: peer0.preSharedKey || (chosenPeer.preSharedKey || ''),
            allowedIPs: allowedFiltered0.length ? allowedFiltered0 : (chosenPeer.allowedIPs || []),
            reserved: peer0.reserved !== undefined ? peer0.reserved : chosenPeer.reserved,
            peers: peersFiltered.length >= 2 ? peersFiltered : undefined,
            dns: Array.isArray(iface.dns) && iface.dns.length ? iface.dns : [],
            remoteDnsResolve: Array.isArray(iface.dns) && iface.dns.length ? true : false,
            mtu: iface.mtu,
            persistentKeepalive: keepalive
        }
    };
    if (iface['amnezia-wg-option']) {
        bean.wireguard['amnezia-wg-option'] = iface['amnezia-wg-option'];
    }
    return bean;
}

try {
    if (typeof globalThis !== 'undefined') {
        globalThis.web4core = Object.assign({}, globalThis.web4core || {}, {
            parseWireGuardConf,
        });
    }
} catch {
}


