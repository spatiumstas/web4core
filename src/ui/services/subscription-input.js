export function splitMihomoSubscriptionInput(raw) {
    const lines = String(raw || '').split(/\r?\n/).map(s => s.trim()).filter(Boolean);
    const subUrls = [];
    const proxyLines = [];
    for (const line of lines) {
        if (/^https?:\/\//i.test(line)) {
            try {
                const u = new URL(line);
                const hasCreds = !!(u.username || u.password);
                (hasCreds ? proxyLines : subUrls).push(line);
            } catch {
                proxyLines.push(line);
            }
        } else {
            proxyLines.push(line);
        }
    }
    return { subUrls, proxyText: proxyLines.join('\n') };
}

export function detectSubscriptionUrl(raw) {
    const lines = (raw || '').split(/\r?\n/).map(s => s.trim()).filter(Boolean);
    const subUrls = [];
    const others = [];
    for (const line of lines) {
        if (!line) continue;
        if (!/^https?:\/\//i.test(line) || /@/.test(line)) {
            others.push(line);
            continue;
        }
        try {
            const p = new URL(line).pathname || '';
            if (p && p !== '/') subUrls.push(line);
            else others.push(line);
        } catch {
            others.push(line);
        }
    }
    return { subUrls, others };
}

export function countMihomoPerProxyTargets(subUrls, extraBeans) {
    const providerCount = Array.isArray(subUrls) ? subUrls.length : 0;
    const extraCount = Array.isArray(extraBeans) ? extraBeans.filter(Boolean).length : 0;
    return providerCount + extraCount;
}

export function countSingboxRouteTargets(beans) {
    if (!Array.isArray(beans)) return 0;
    return beans.filter(bean => bean && bean.proto !== 'sdns').length;
}
