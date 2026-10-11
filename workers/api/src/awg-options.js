import { randomInt } from './random.js';

export const WARP_IPS = Object.freeze([11, 21, 31, 41, 51, 61, 71, 81, 91, 14, 24, 34, 44, 54, 64, 74, 84, 94, 101, 105, 106, 205, 215, 1].map(last => `162.159.192.${last}`));
export const WARP_PORTS = Object.freeze([854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942, 943, 945, 946, 955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1843, 2371, 2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886]);
const ADVANCED = { ContentPaddingAddition: '10-100', RekeyAfterTime: '100-120', RekeyTimeout: '3-7', RejectAfterTime: '150-180', KeepaliveTimeout: '5-15', MaxHandshakeAttempts: '15-20' };
const AWG_KEYS = ['Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4', 'I1', 'I2', 'I3', 'I4', 'I5', ...Object.keys(ADVANCED), 'RandomTrailers', 'DisableCookies', 'HeaderProtectionKey'];

export function setConfigFields(config, section, fields) {
    const eol = config.includes('\r\n') ? '\r\n' : '\n';
    const lines = config.split(/\r?\n/);
    const start = lines.findIndex(line => line.trim() === `[${section}]`);
    if (start < 0) throw new Error(`Missing ${section} section.`);
    let end = start + 1;
    while (end < lines.length && !/^\s*\[/.test(lines[end])) end++;
    const keys = new Set(Object.keys(fields).map(key => key.toLowerCase()));
    const body = lines.slice(start + 1, end).filter(line => {
        const match = /^\s*([^=\s]+)\s*=/.exec(line);
        return !match || !keys.has(match[1].toLowerCase());
    });
    let insert = body.length;
    while (insert > 0 && !body[insert - 1].trim()) insert--;
    body.splice(insert, 0, ...Object.entries(fields).filter(([, value]) => value !== null && value !== undefined && value !== '').map(([key, value]) => `${key} = ${value}`));
    lines.splice(start + 1, end - start - 1, ...body);
    return lines.join(eol);
}

// Fixed WARP-compatible parameters; only the AWG version changes the format.
export function applyAwgOptions(config, { version }, domainPackets = null) {
    const fields = Object.fromEntries(AWG_KEYS.map(key => [key, null]));
    Object.assign(fields, { Jc: 4, Jmin: 40, Jmax: 70, S1: 0, S2: 0, H1: 1, H2: 2, H3: 3, H4: 4 });
    if (version !== '1.5') {
        fields.S3 = fields.S4 = 0;
        if (!Array.isArray(domainPackets) || domainPackets.length !== 5 || domainPackets.some(packet => typeof packet !== 'string' || !/^<b 0x(?:[0-9a-f]{2})+>$/.test(packet))) {
            throw new Error('Real I1-I5 domain packets are required.');
        }
        domainPackets.forEach((packet, index) => { fields[`I${index + 1}`] = packet; });
    }
    if (version === '3.0' || version === '3.1') Object.assign(fields, ADVANCED);
    if (version === '3.1') {
        fields.RandomTrailers = 'on';
        fields.DisableCookies = 'on';
    }
    Object.assign(fields, { DNS: '1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001', MTU: 1280 });
    config = setConfigFields(config, 'Interface', fields);
    const endpoint = `${WARP_IPS[randomInt(0, WARP_IPS.length - 1)]}:${WARP_PORTS[randomInt(0, WARP_PORTS.length - 1)]}`;
    return setConfigFields(config, 'Peer', { Endpoint: endpoint, PersistentKeepalive: 25 });
}
