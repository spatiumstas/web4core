export function normalizeAmneziaDomain(value) {
    if (value == null) return '';
    if (typeof value !== 'string') throw new Error('Domain must be a string.');
    const raw = value.trim();
    if (!raw) return '';
    if (/[\s/:@?#\\]/u.test(raw)) throw new Error('Enter a domain without a scheme, port, or path.');
    let domain;
    try { domain = new URL(`https://${raw}`).hostname.replace(/\.$/, ''); }
    catch { throw new Error('Invalid domain.'); }
    const labels = domain.split('.');
    if (domain.length > 253 || labels.length < 2 || /^\d+$/.test(labels.at(-1)) ||
        labels.some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
        throw new Error('Invalid domain. For example: example.com');
    }
    return domain;
}

export function validateAmneziaRequest(body) {
    if (!['1.5', '2.0', '3.0', '3.1'].includes(body?.version)) throw new Error('Supported versions are AWG 1.5, 2.0, 3.0 and 3.1.');
    return { version: body.version, domain: normalizeAmneziaDomain(body.domain) };
}
