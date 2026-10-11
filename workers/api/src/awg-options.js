import { generateCps, hexToCps, randomInt } from '../../../src/core/warp-cps.js';
import { normalizeWarpOptions } from '../../../src/core/warp-options.js';

// Skiro1/warp-awg-gen endpoint.go, same pinned revision as warp-cps.js.
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

export function profileCps(version, options, domainPackets = null) {
    if (version === '1.5' || options.transport === 'none') return [];
    const packets = domainPackets ? [...domainPackets] : generateCps(options.mask);
    if (options.from_hex) packets[0] = hexToCps(options.from_hex);
    for (let i = 0; i < 5; i++) if (Object.hasOwn(options.cps, `i${i + 1}`)) packets[i] = options.cps[`i${i + 1}`];
    return packets;
}

export function applyAwgOptions(config, { version, options: input = {} }, domainPackets = null) {
    const options = normalizeWarpOptions(input);
    const fields = Object.fromEntries(AWG_KEYS.map(key => [key, null]));
    if (options.transport !== 'none') {
        for (const key of ['Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'H1', 'H2', 'H3', 'H4']) fields[key] = options.awg[key.toLowerCase()];
        if (version !== '1.5') {
            fields.S3 = options.awg.s3;
            fields.S4 = options.awg.s4;
        }
        profileCps(version, options, domainPackets).forEach((packet, index) => { fields[`I${index + 1}`] = packet; });
        if (version === '3.0' || version === '3.1') Object.assign(fields, ADVANCED);
        if (version === '3.1') {
            fields.RandomTrailers = options.random_trailers ? 'on' : 'off';
            fields.DisableCookies = options.disable_cookies ? 'on' : 'off';
        }
    }
    Object.assign(fields, { DNS: options.dns, MTU: options.mtu });
    config = setConfigFields(config, 'Interface', fields);
    // Worker-side TCP probing cannot measure the user's UDP path. Never label
    // this as a fastest-endpoint scan, and do not trust third-party DNS pools.
    const endpoint = options.endpoint || `${WARP_IPS[randomInt(0, WARP_IPS.length - 1)]}:${WARP_PORTS[randomInt(0, WARP_PORTS.length - 1)]}`;
    return setConfigFields(config, 'Peer', { Endpoint: endpoint, PersistentKeepalive: options.keepalive });
}
