// Shared request validation. Domains become SNI bytes only; they are never fetched.
export function normalizeAmneziaDomain(value) {
    if (typeof value !== 'string') throw new Error('Укажите домен для I1.');
    const raw = value.trim();
    if (!raw || /[\s/:@?#\\]/u.test(raw)) throw new Error('Введите домен без протокола, порта и пути.');
    let domain;
    try { domain = new URL(`https://${raw}`).hostname.replace(/\.$/, ''); }
    catch { throw new Error('Некорректный домен.'); }
    const labels = domain.split('.');
    if (domain.length > 253 || labels.length < 2 || /^\d+$/.test(labels.at(-1)) ||
        labels.some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
        throw new Error('Некорректный домен. Например: example.com');
    }
    return domain;
}

export function validateAmneziaRequest(body) {
    if (body?.version !== '1.5' && body?.version !== '2.0') throw new Error('Поддерживаются AWG 1.5 и AWG 2.0.');
    return { version: body.version, domain: normalizeAmneziaDomain(body.domain) };
}
