import { hexToCps, validateCps } from './warp-cps.js';

export const DEFAULT_DNS = '1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001';
export const DEFAULT_AWG = Object.freeze({ jc: 4, jmin: 40, jmax: 70, s1: 0, s2: 0, s3: 0, s4: 0, h1: '1', h2: '2', h3: '3', h4: '4' });

function object(value, name) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${name} must be an object.`);
    return value;
}
function keys(value, allowed, name) {
    object(value, name);
    if (Object.keys(value).some(key => !allowed.includes(key))) throw new Error(`Unknown ${name} option.`);
}
function integer(value, min, max, name) {
    if (!Number.isInteger(value) || value < min || value > max) throw new Error(`${name} must be an integer from ${min} to ${max}.`);
    return value;
}
function string(value, max, name) {
    if (typeof value !== 'string' || value.length > max || /[\r\n\0]/.test(value)) throw new Error(`Invalid ${name}.`);
    return value.trim();
}
export function isIPv4(value) {
    return typeof value === 'string' && /^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$/.test(value) && value.split('.').every(x => Number(x) <= 255);
}
export function isIPv6(value) {
    if (typeof value !== 'string' || !value.includes(':') || !/^[0-9a-f:.]+$/i.test(value)) return false;
    try { return new URL(`http://[${value}]/`).hostname.startsWith('['); } catch { return false; }
}
export function normalizeEndpoint(value) {
    value = string(value, 300, 'endpoint');
    if (!value) return '';
    const match = /^(\[[0-9a-f:.]+\]|[a-z0-9.-]+):([0-9]{1,5})$/i.exec(value);
    if (!match || Number(match[2]) < 1 || Number(match[2]) > 65535) throw new Error('Endpoint must be host:port or [IPv6]:port.');
    const host = match[1];
    const valid = host.startsWith('[') ? isIPv6(host.slice(1, -1)) :
        isIPv4(host) || (host.length <= 253 && !/^[\d.]+$/.test(host) && host.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label)));
    if (!valid) throw new Error('Invalid endpoint host.');
    return `${host.toLowerCase()}:${Number(match[2])}`;
}
function headerRange(value) {
    value = typeof value === 'number' ? String(value) : string(value, 32, 'AWG header');
    if (!/^\d+(?:-\d+)?$/.test(value)) throw new Error('AWG headers must be integers or inclusive ranges.');
    const [low, high = low] = value.split('-').map(Number);
    integer(low, 0, 0xffffffff, 'AWG header');
    integer(high, low, 0xffffffff, 'AWG header');
    return [low, high];
}
export function normalizeWarpOptions(input = {}) {
    keys(input, ['license_key', 'dns', 'endpoint', 'keepalive', 'mtu', 'transport', 'mask', 'from_hex', 'awg', 'cps', 'random_trailers', 'disable_cookies'], 'generator');
    const options = {
        license_key: string(input.license_key ?? '', 256, 'WARP+ license'),
        dns: string(input.dns ?? DEFAULT_DNS, 300, 'DNS'),
        endpoint: normalizeEndpoint(input.endpoint ?? ''),
        keepalive: integer(input.keepalive ?? 25, 0, 65535, 'Keepalive'),
        mtu: integer(input.mtu ?? 1280, 576, 9000, 'MTU'),
        transport: input.transport ?? '',
        mask: input.mask ?? 'random',
        from_hex: input.from_hex ?? '',
        awg: { ...DEFAULT_AWG },
        cps: {},
        random_trailers: input.random_trailers ?? true,
        disable_cookies: input.disable_cookies ?? true,
    };
    if (options.license_key && !/^[a-z0-9-]+$/i.test(options.license_key)) throw new Error('Invalid WARP+ license.');
    if (!['', 'quic', 'dns', 'sip', 'none'].includes(options.transport)) throw new Error('Invalid transport.');
    if (!['random', 'quic', 'dns', 'sip', 'none'].includes(options.mask)) throw new Error('Invalid CPS mask.');
    if (typeof options.random_trailers !== 'boolean' || typeof options.disable_cookies !== 'boolean') throw new Error('AWG 3.1 flags must be boolean.');
    if (options.transport && options.transport !== 'none' && input.mask === undefined) options.mask = options.transport;
    const dns = options.dns.split(',').map(x => x.trim());
    if (!dns.length || dns.some(x => !isIPv4(x) && !isIPv6(x))) throw new Error('DNS must contain comma-separated IP addresses.');
    options.dns = dns.join(', ');
    if (options.from_hex) options.from_hex = hexToCps(options.from_hex).slice(5, -1);
    else if (typeof options.from_hex !== 'string') throw new Error('Invalid hex dump.');
    if (input.awg !== undefined) {
        keys(input.awg, Object.keys(DEFAULT_AWG), 'AWG');
        for (const [key, value] of Object.entries(input.awg)) {
            if (value == null) continue;
            options.awg[key] = key.startsWith('h') ? String(value) : integer(value, 0, key === 'jc' ? 10 : key.startsWith('s') ? 64 : 1280, key);
        }
    }
    if (options.awg.jmin > options.awg.jmax) throw new Error('Jmin must not exceed Jmax.');
    const ranges = ['h1', 'h2', 'h3', 'h4'].map(key => headerRange(options.awg[key]));
    for (let i = 0; i < ranges.length; i++) for (let j = 0; j < i; j++) {
        if (ranges[i][0] <= ranges[j][1] && ranges[j][0] <= ranges[i][1]) throw new Error('AWG header ranges must not overlap.');
    }
    if (input.cps !== undefined) {
        keys(input.cps, ['i1', 'i2', 'i3', 'i4', 'i5'], 'CPS');
        for (const [key, value] of Object.entries(input.cps)) if (value != null) options.cps[key] = validateCps(value);
    }
    return options;
}
