import test from 'node:test';
import assert from 'node:assert/strict';
import { buildMihomoSubscriptionConfig } from '../../src/core/mihomo.js';
import { buildMihomoYaml } from '../../src/core/yaml.js';
import { buildFromRequest } from '../../src/build.js';

const urls = ['https://example.com/one', 'https://example.org/two'];
for (const perProxyListeners of [false, true]) test(`exclude-filter applies to every subscription (per-proxy: ${perProxyListeners})`, () => {
    const cfg = buildMihomoSubscriptionConfig(urls, [], { excludeFilter: ' 🇷🇺 ', perProxyListeners });
    assert.equal(Object.keys(cfg.providers).length, 2);
    for (const provider of Object.values(cfg.providers)) assert.equal(provider['exclude-filter'], '🇷🇺');
});

test('blank filter is omitted; YAML preserves regex, quotes and control characters', () => {
    for (const excludeFilter of [undefined, '', '   ', '🇷🇺', '(?i)ru|russia', 'false', 'a\\d+|"quote"|\'single\'', 'a\nb']) {
        const cfg = buildMihomoSubscriptionConfig(urls, [], { excludeFilter });
        const yaml = buildMihomoYaml(cfg.proxies, cfg.groups, cfg.providers, cfg.rules, cfg.listeners);
        const values = [...yaml.matchAll(/^\s+exclude-filter: (.*)$/gm)].map(match => JSON.parse(match[1]));
        assert.deepEqual(values, excludeFilter?.trim() ? [excludeFilter.trim(), excludeFilter.trim()] : []);
    }
});

test('public build API forwards the option only in Mihomo subscription mode', () => {
    const result = buildFromRequest({ core: 'mihomo', input: urls.join('\n'), options: { mihomoSubscriptionMode: true, excludeFilter: '🇷🇺' } });
    assert.equal(result.kind, 'yaml');
    assert.equal((result.data.match(/exclude-filter: "🇷🇺"/g) || []).length, 2);
    const direct = buildFromRequest({ core: 'mihomo', input: 'socks://user:pass@example.com:1080', options: { excludeFilter: '🇷🇺' } });
    assert(!direct.data.includes('exclude-filter:'));
});
