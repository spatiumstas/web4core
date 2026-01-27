function toYamlScalar(value, key) {
    if (value === null || value === undefined) return '';
    if (typeof value === 'boolean') return value ? 'true' : 'false';
    if (typeof value === 'number') return String(value);
    const s = String(value);
    if (key === 'grpc-service-name') {
        return '"' + s.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
    }
    if (/^[A-Za-z0-9_.:@#\-]+$/.test(s)) return s;
    return '"' + s.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
}

function toYAML(obj, indent = 0) {
    const space = '  '.repeat(indent);
    if (Array.isArray(obj)) {
        return obj.map(item => {
            if (item && typeof item === 'object') {
                const body = toYAML(item, indent + 1);
                const lines = body.split('\n');
                const indentPrefix = '  '.repeat(indent + 1);
                const firstLine = (lines[0] || '').replace(new RegExp('^' + indentPrefix), '');
                const rest = lines.slice(1).join('\n');
                return space + '- ' + firstLine + (rest ? '\n' + rest : '');
            }
            return space + '- ' + toYamlScalar(item, null);
        }).join('\n');
    }
    if (obj && typeof obj === 'object') {
        const lines = [];
        const comments = (obj.__comments && typeof obj.__comments === 'object') ? obj.__comments : null;
        for (const [k, v] of Object.entries(obj)) {
            if (v === undefined) continue;
            if (k === '__comments') continue;
            if (v && typeof v === 'object') {
                const child = toYAML(v, indent + 1);
                lines.push(space + k + ':');
                if (child) {
                    lines.push(child);
                }
            } else {
                lines.push(space + k + ': ' + toYamlScalar(v, k));
                if (comments && typeof comments[k] === 'string' && comments[k].trim()) {
                    lines.push(space + '# ' + comments[k].trim());
                }
            }
        }
        return lines.join('\n');
    }
    return space + toYamlScalar(obj, null);
}

function upsertSection(lines, key, sectionYaml) {
    const findSection = () => {
        const start = lines.findIndex(l => new RegExp('^' + key + '\\s*:\\s*$', 'i').test(l));
        if (start === -1) return {start: -1, end: -1};
        let end = start + 1;
        while (end < lines.length) {
            if (/^[^\s#][^:]*:\s*/.test(lines[end])) break;
            end++;
        }
        return {start, end};
    };

    const {start, end} = findSection();

    const inject = [
        key + ':',
        ...toYAML(sectionYaml, 1).split('\n'),
        ''
    ];

    if (start === -1) {
        if (lines.length && lines.at(-1) !== '') lines.push('');
        lines.push(...inject);
    } else {
        lines.splice(start, end - start, ...inject);
    }
}

function overlayMihomoYaml(baseYamlText, proxies, groups, providers, rules, listeners) {
    const text = (baseYamlText || '').replace(/\r\n/g, '\n');
    const lines = text.split('\n');

    if (Array.isArray(proxies) && proxies.length > 0) {
        upsertSection(lines, 'proxies', proxies);
    }

    if (Array.isArray(groups) && groups.length > 0) {
        upsertSection(lines, 'proxy-groups', groups);
    }

    if (providers && typeof providers === 'object' && Object.keys(providers).length > 0) {
        upsertSection(lines, 'proxy-providers', providers);
    }

    if (Array.isArray(rules) && rules.length > 0) {
        upsertSection(lines, 'rules', rules);
    }

    if (Array.isArray(listeners) && listeners.length > 0) {
        upsertSection(lines, 'listeners', listeners);

        const hasSocksListener = listeners.some(
            l => l && typeof l === 'object' && String(l.type || '').toLowerCase() === 'socks'
        );

        if (hasSocksListener) {
            const mixedPortIndex = lines.findIndex(l => /^mixed-port\s*:/i.test(l));
            if (mixedPortIndex !== -1) {
                lines.splice(mixedPortIndex, 1);
            }
        }
    }
    return lines.join('\n');
}

const MIHOMO_DEFAULT_TEMPLATE = [
    'mixed-port: 7890',
    'allow-lan: false',
    'tcp-concurrent: true',
    'mode: rule',
    'log-level: info',
    'ipv6: false',
    'unified-delay: true',
    'profile:',
    '  store-selected: true',
    '  store-fake-ip: true',
    '',
    'proxy-groups:',
    'rules:',
    '  - "MATCH,GLOBAL"'
].join('\n');

function buildMihomoYaml(proxies, groups, providers, rules, listeners, opts) {
    opts = opts || {};
    const webUI = opts.webUI === true;
    const tunOpt = opts.tun;
    let template = MIHOMO_DEFAULT_TEMPLATE;
    if (webUI) {
        const lines = template.split('\n');
        const ipv6Index = lines.findIndex(l => /^ipv6\s*:/i.test(l));
        if (ipv6Index !== -1) {
            lines.splice(ipv6Index + 1, 0,
                'external-controller: 0.0.0.0:9090',
                'external-ui: ui',
                'external-ui-url: https://github.com/MetaCubeX/metacubexd/releases/latest/download/compressed-dist.tgz',
                'secret: '
            );
            template = lines.join('\n');
        }
    }
    if (tunOpt) {
        const lines = template.split('\n');
        const proxiesIndex = lines.findIndex(l => /^proxy-groups\s*:/i.test(l));
        const mode = (tunOpt && typeof tunOpt === 'object' && tunOpt.mode) ? String(tunOpt.mode) : 'tun';
        if (mode === 'listeners') {
            const buildTunListener = (idx, proxyName) => {
                const offset = idx * 4 + 1;
                const oct3 = Math.floor(offset / 256);
                const oct4 = offset % 256;
                const inet4 = `198.19.${oct3}.${oct4}/30`;
                const out = {
                    name: `mihomo-tun-${idx + 1}`,
                    type: 'tun',
                    device: `mitun${idx}`,
                    stack: 'gvisor',
                    'auto-route': false,
                    'auto-detect-interface': false,
                    'inet4-address': [inet4],
                };
                if (proxyName) out.proxy = proxyName;
                return out;
            };

            const tunListeners = [];
            const proxyList = Array.isArray(proxies) ? proxies : [];
            const providerKeys = (providers && typeof providers === 'object') ? Object.keys(providers) : [];

            const targets = [];
            if (providerKeys.length > 0) {
                if (providerKeys.length > 1) {
                    providerKeys.forEach(pn => pn && targets.push(`SUB-${pn}`));
                } else {
                    const fastestGroup = Array.isArray(groups)
                        ? groups.find(g => g?.type === 'url-test' && Array.isArray(g.use))
                        : null;
                    const name = (fastestGroup && fastestGroup.name) ? fastestGroup.name : 'PROXY';
                    targets.push(name);
                }
                proxyList.forEach(p => p?.name && targets.push(p.name));
            } else {
                proxyList.forEach(p => p?.name && targets.push(p.name));
            }

            targets.forEach((name, idx) => {
                tunListeners.push(buildTunListener(idx, name));
            });

            const merged = Array.isArray(listeners) ? listeners.slice() : [];
            merged.push(...tunListeners);
            listeners = merged;
        } else {
            const tun = {
                enable: true,
                stack: 'gvisor',
                'auto-route': false,
                'auto-detect-interface': true,
                device: 'mitun0',
            };
            const inject = [
                'tun:',
                ...toYAML(tun, 1).split('\n'),
                ''
            ];
            if (proxiesIndex !== -1) {
                lines.splice(proxiesIndex, 0, ...inject);
            } else {
                lines.push(...inject);
            }
            template = lines.join('\n');
        }
    }
    return overlayMihomoYaml(template, proxies, groups, providers, rules, listeners);
}

export {
    buildMihomoYaml,
};
