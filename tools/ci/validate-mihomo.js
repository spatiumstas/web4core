const fs = require('fs');

const {
  loadWeb4core,
  splitLinksFromEnv,
  safeLinkLabel,
  execOrThrow,
} = require('./runtimeSandbox');

function writeYaml(p, text) {
  fs.writeFileSync(p, String(text || ''));
}

function pickMihomoCompatibleLink(web4core, links) {
  for (const l of links) {
    try {
      const b = (web4core.buildBeansFromInput(l) || [])[0];
      if (!b) continue;
      if (b.proto === 'sdns') continue;
      if (b.proto === 'socks' && b.socks && b.socks.type === 'socks4') continue;
      return l;
    } catch {}
  }
  return '';
}

function buildYaml(web4core, input, options, wgBeans) {
  const out = web4core.buildFromRequest({ core: 'mihomo', input, options, wgBeans });
  if (!out || out.kind !== 'yaml') throw new Error('Unexpected output kind for Mihomo');
  return out.data;
}

function testLatestMihomoFixtures(web4core, links) {
  const fixtures = links.filter((line) => /#fixture-[^\s#]+$/i.test(line));
  assert(fixtures.length > 0, 'CONFIGS is missing Mihomo feature fixtures');

  for (const link of fixtures) {
    const beans = web4core.buildBeansFromInput(link);
    const bean = beans && beans[0];
    assert(bean, `Fixture did not produce a bean: ${link}`);
    web4core.validateBean(bean);
    const yaml = buildYaml(web4core, link, { webUI: false, addTun: false });

    if (bean.name === 'fixture-hy2-hop-range') {
      assert(/\n    ports: 20000-20100\n/.test(yaml), 'HY2 fixture: missing ports range');
      assert(/\n    hop-interval: 10-20\n/.test(yaml), 'HY2 fixture: missing hop interval range');
      assert(/\n    obfs: gecko\n/.test(yaml), 'HY2 fixture: missing gecko obfs');
      assert(/\n    handshake-timeout: 12\n/.test(yaml), 'HY2 fixture: missing handshake timeout');
    } else if (bean.name === 'fixture-grpc-max-connections') {
      assert(/\n      max-connections: 1\n/.test(yaml), 'gRPC fixture: missing max-connections');
    } else if (bean.name === 'fixture-grpc-min-streams') {
      assert(/\n      min-streams: 2\n/.test(yaml), 'gRPC fixture: missing min-streams');
    } else if (bean.name === 'fixture-grpc-max-streams') {
      assert(/\n      max-streams: 8\n/.test(yaml), 'gRPC fixture: missing max-streams');
    } else if (bean.name === 'fixture-xhttp-full') {
      assert(/\n      no-grpc-header: true\n/.test(yaml), 'XHTTP fixture: missing no-grpc-header');
      assert(/\n      session-table: abcdefghijklmnopqrstuvwxyz\n/.test(yaml), 'XHTTP fixture: missing session-table');
      assert(/\n      reuse-settings:\n/.test(yaml), 'XHTTP fixture: missing reuse-settings');
      assert(/\n      download-settings:\n/.test(yaml), 'XHTTP fixture: missing download-settings');
      assert(/\n        server: download\.example\.test\n/.test(yaml), 'XHTTP fixture: missing download server');
    } else if (bean.name === 'fixture-anytls-v11930') {
      assert(/\n    type: anytls\n/.test(yaml), 'AnyTLS fixture: outbound was not generated');
      assert(/\n    client-metadata: web4core-test\n/.test(yaml), 'AnyTLS fixture: missing client metadata');
    } else if (bean.name === 'fixture-masque-v11930') {
      assert(/\n    network: h2\n/.test(yaml), 'MASQUE fixture: missing network');
      assert(/\n    handshake-timeout: 30\n/.test(yaml), 'MASQUE fixture: missing handshake timeout');
      assert(/\n    ip-stack:\n/.test(yaml), 'MASQUE fixture: missing ip-stack');
    }

    const label = String(bean.name || 'fixture').replace(/[^a-z0-9_-]+/gi, '_');
    validateMihomoYaml(yaml, `mihomo_fixture_${label}.yaml`);
  }
  console.log(`✅ Mihomo config fixtures ok (${fixtures.length})`);
}

function testAmneziaWgV31Fixture(web4core, conf) {
  assert(conf.trim(), 'WG_CONF is empty; AmneziaWG v3.1 fixture is required');
  const bean = web4core.parseWireGuardConf(conf, 'wg-ci.conf');
  web4core.validateBean(bean);
  const awg = bean.wireguard && bean.wireguard['amnezia-wg-option'];
  assert(awg && awg.version === 3, 'AmneziaWG v3.1 fixture: missing version');
  assert(awg['header-protection-key'], 'AmneziaWG v3.1 fixture: missing header-protection-key');
  assert(awg['random-trailers'] === true, 'AmneziaWG v3.1 fixture: missing random-trailers');
  assert(awg['disable-cookies'] === true, 'AmneziaWG v3.1 fixture: missing disable-cookies');
  assert(bean.wireguard.ipStack && bean.wireguard.ipStack.mode === 'mips', 'AmneziaWG v3.1 fixture: missing ip-stack mode');

  const config = web4core.buildMihomoConfig([bean], { addSocks: true });
  const yaml = web4core.buildMihomoYaml(
    config.proxies,
    config['proxy-groups'],
    null,
    config.rules,
    config.listeners,
    { addSocks: true },
  );
  assert(/\n      version: 3\n/.test(yaml), 'AmneziaWG v3.1 fixture: YAML missing version');
  assert(/\n      random-trailers: true\n/.test(yaml), 'AmneziaWG v3.1 fixture: YAML missing random-trailers');
  assert(/\n    ip-stack:\n/.test(yaml), 'AmneziaWG v3.1 fixture: YAML missing ip-stack');
  validateMihomoYaml(yaml, 'mihomo_fixture_amneziawg_v31.yaml');
  console.log('✅ Mihomo AmneziaWG v3.1 fixture ok');
}

function validateMihomoYaml(yamlText, fileName) {
  writeYaml(fileName, yamlText);
  execOrThrow(`mihomo -t -f ${fileName}`);
  fs.unlinkSync(fileName);
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function main() {
  const web4core = loadWeb4core();
  const rawLinks = splitLinksFromEnv('CONFIGS');
  if (!rawLinks.length) throw new Error('CONFIGS is empty (no test links)');
  testLatestMihomoFixtures(web4core, rawLinks);

  const wgConf = process.env.WG_CONF || '';
  testAmneziaWgV31Fixture(web4core, wgConf);

  const compatibleLinks = rawLinks.filter((l) => {
    try {
      const b = (web4core.buildBeansFromInput(l) || [])[0];
      if (!b) return false;
      if (b.proto === 'sdns') return false;
      if (b.proto === 'socks' && b.socks && b.socks.type === 'socks4') return false;
      return true;
    } catch {
      return false;
    }
  });

  console.log('Found', compatibleLinks.length, 'Mihomo-compatible links');
  if (!compatibleLinks.length) throw new Error('No Mihomo-compatible links in CONFIGS');

  let wgBean = null;
  if (wgConf.trim() && typeof web4core.parseWireGuardConf === 'function') {
    wgBean = web4core.parseWireGuardConf(wgConf, 'wg-ci.conf');
    web4core.validateBean(wgBean);
  }

  let fail = 0;

  // 1) Single-proxy configs: baseline + per-proxy port + tun
  for (let i = 0; i < compatibleLinks.length; i++) {
    const linkLine = compatibleLinks[i];
    try {
      const label = safeLinkLabel(linkLine, i);
      console.log(`Testing Mihomo config ${i + 1}/${compatibleLinks.length}: ${label}`);

      // baseline
      {
        const y = buildYaml(web4core, linkLine, { webUI: true, addTun: false }, wgBean ? [wgBean] : []);
        validateMihomoYaml(y, `mihomo_${i}_basic.yaml`);
      }

      // per-proxy port
      {
        const y = buildYaml(web4core, linkLine, { webUI: false, perProxyPort: true, addTun: false }, wgBean ? [wgBean] : []);
        validateMihomoYaml(y, `mihomo_${i}_perport.yaml`);
      }

      // tun: section mode
      {
        const y = buildYaml(web4core, linkLine, { webUI: true, addTun: true, mihomoPerProxyTun: false }, wgBean ? [wgBean] : []);
        validateMihomoYaml(y, `mihomo_${i}_tun.yaml`);
      }

      // tun: listeners mode (per-proxy tun)
      {
        const y = buildYaml(web4core, linkLine, { webUI: true, addTun: true, mihomoPerProxyTun: true }, wgBean ? [wgBean] : []);
        validateMihomoYaml(y, `mihomo_${i}_tun_listeners.yaml`);
      }

      console.log(`✅ Mihomo ok: ${label}`);
    } catch (e) {
      fail++;
      console.log(`❌ Mihomo failed (${i + 1}/${compatibleLinks.length})`);
      console.log(String(e && e.message ? e.message : e));
    }
  }

  // 2) Multi-config (all beans) through buildFromRequest (normal mode)
  try {
    const inputAll = compatibleLinks.join('\n');
    const y = buildYaml(web4core, inputAll, { webUI: true, addTun: false }, wgBean ? [wgBean] : []);
    validateMihomoYaml(y, 'mihomo_all.yaml');
    console.log('✅ Mihomo multi-all ok');
  } catch (e) {
    fail++;
    console.log('❌ Mihomo multi-all failed');
    console.log(String(e && e.message ? e.message : e));
  }

  // 3) Inbound split contract: tun-only is valid, both-off must throw
  try {
    const sample = compatibleLinks[0];
    const tunOnlyYaml = buildYaml(web4core, sample, {
      webUI: false,
      addTun: true,
      addSocks: false,
      mihomoPerProxyTun: false,
    }, wgBean ? [wgBean] : []);
    assert(/(^|\n)tun:\n/.test(tunOnlyYaml), 'tun-only Mihomo config: expected top-level tun section');
    assert(!/(^|\n)mixed-port:\s*/.test(tunOnlyYaml), 'tun-only Mihomo config: mixed-port must be absent when SOCKS5 is disabled');
    validateMihomoYaml(tunOnlyYaml, 'mihomo_tun_only.yaml');

    let bothOffError = '';
    try {
      buildYaml(web4core, sample, {
        webUI: false,
        addTun: false,
        addSocks: false,
      }, wgBean ? [wgBean] : []);
    } catch (e) {
      bothOffError = String(e && e.message ? e.message : e);
    }
    assert(/enable at least one inbound/i.test(bothOffError), 'Mihomo both-off config: expected explicit inbound validation error');
    console.log('✅ Mihomo inbound split contract ok');
  } catch (e) {
    fail++;
    console.log('❌ Mihomo inbound split contract failed');
    console.log(String(e && e.message ? e.message : e));
  }

  // 4) Subscription mode (proxy-providers)
  try {
    const extra = pickMihomoCompatibleLink(web4core, compatibleLinks);
    const inputSub = [
      'https://example.com/subscription-1',
      'https://example.com/subscription-2',
      extra ? extra : '',
    ].filter(Boolean).join('\n');

    const y = buildYaml(web4core, inputSub, {
      mihomoSubscriptionMode: true,
      perProxyPort: true,
      webUI: true,
      addTun: true,
      mihomoPerProxyTun: true,
    }, wgBean ? [wgBean] : []);

    validateMihomoYaml(y, 'mihomo_subscription.yaml');
    assert(/\n    empty-fallback: REJECT\n/.test(y), 'Mihomo subscription-mode: expected fail-closed empty fallback');
    assert(/\n    proxy: DIRECT\n/.test(y), 'Mihomo subscription-mode: expected DIRECT provider bootstrap');
    console.log('✅ Mihomo subscription-mode ok');
  } catch (e) {
    fail++;
    console.log('❌ Mihomo subscription-mode failed');
    console.log(String(e && e.message ? e.message : e));
  }

  if (wgBean) {
    console.log('✅ Mihomo WireGuard bean parsed');
  } else {
    console.log('ℹ️ No WG_CONF provided; WireGuard coverage reduced');
  }

  console.log(`\n📊 Mihomo results: ${fail ? 'FAIL' : 'OK'} (${fail} failed groups)`);
  if (fail) process.exit(1);
}

main();

