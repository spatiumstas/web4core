const PREFIXES = ['162.159.192.', '162.159.195.'];
const PORTS = [500, 1701, 2408, 4500];

function randomInt(min, max) {
    const size = max - min + 1;
    const limit = 0x100000000 - (0x100000000 % size);
    const bytes = new Uint32Array(1);
    do { crypto.getRandomValues(bytes); } while (bytes[0] >= limit);
    return min + bytes[0] % size;
}

function range(lowMin, lowMax, highMin, highMax) {
    return `${randomInt(lowMin, lowMax)}-${randomInt(highMin, highMax)}`;
}

// Replace fields only in the requested section, preserving other sections.
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
    body.splice(insert, 0, ...Object.entries(fields).map(([key, value]) => `${key} = ${value}`));
    lines.splice(start + 1, end - start - 1, ...body);
    return lines.join(eol);
}

export function applyAwgOptions(config, { version }) {
    if (version === '3.0' || version === '3.1') {
        const fields = {
            ContentPaddingAddition: range(5, 49, 50, 110),
            RekeyAfterTime: range(90, 105, 115, 130),
            RekeyTimeout: range(5, 7, 8, 13),
            RejectAfterTime: range(170, 180, 190, 200),
            KeepaliveTimeout: range(5, 10, 11, 15),
            MaxHandshakeAttempts: range(18, 24, 25, 33),
        };
        if (version === '3.1') {
            fields.RandomTrailers = 'on';
            fields.DisableCookies = 'on';
        }
        config = setConfigFields(config, 'Interface', fields);
    }
    const host = PREFIXES[randomInt(0, PREFIXES.length - 1)] + randomInt(1, 10);
    return setConfigFields(config, 'Peer', { Endpoint: `${host}:${PORTS[randomInt(0, PORTS.length - 1)]}` });
}
