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
        for (const [k, v] of Object.entries(obj)) {
            if (v === undefined) continue;
            if (v && typeof v === 'object') {
                const child = toYAML(v, indent + 1);
                if (child) {
                    lines.push(space + k + ':');
                    lines.push(child);
                } else {
                    lines.push(space + k + ': {}');
                }
            } else {
                lines.push(space + k + ': ' + toYamlScalar(v, k));
            }
        }
        return lines.join('\n');
    }
    return space + toYamlScalar(obj, null);
}

function overlayMihomoYaml(baseYamlText, proxies, groups, providers, rules, listeners) {
    const text = (baseYamlText || '').replace(/\r\n/g, '\n');
    const lines = text.split('\n');
    const findSection = (key) => {
        const start = lines.findIndex(l => new RegExp('^' + key + '\\s*:\\s*$', 'i').test(l));
        if (start === -1) return {start: -1, end: -1};
        let end = start + 1;
        while (end < lines.length) {
            const ln = lines[end];
            if (/^[^\s#][^:]*:\s*/.test(ln)) break;
            end++;
        }
        return {start, end};
    };
    const replaceSection = (key, sectionYaml) => {
        const {start, end} = findSection(key);
        const inject = (key + ':\n' + toYAML(sectionYaml, 1));
        if (start === -1) {
            lines.push('', inject);
        } else {
            lines.splice(start, end - start, ...inject.split('\n'));
        }
    };
    replaceSection('proxies', proxies);
    replaceSection('proxy-groups', groups);
    if (providers) replaceSection('proxy-providers', providers);
    if (rules) replaceSection('rules', rules);
    if (listeners && listeners.length > 0) {
        replaceSection('listeners', listeners);
        const mixedPortIndex = lines.findIndex(l => /^mixed-port\s*:/i.test(l));
        if (mixedPortIndex !== -1) {
            lines.splice(mixedPortIndex, 1);
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
    'proxies:',
    'proxy-groups:',
    'rules:',
    '  - "MATCH,PROXY"'
].join('\n');

function buildMihomoYaml(proxies, groups, providers, rules, listeners, opts) {
    opts = opts || {};
    const webUI = opts.webUI === true;
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
    return overlayMihomoYaml(template, proxies, groups, providers, rules, listeners);
}

try {
    if (typeof globalThis !== 'undefined') {
        globalThis.web4core = Object.assign({}, globalThis.web4core || {}, {
            buildMihomoYaml,
        });
    }
} catch {
}


