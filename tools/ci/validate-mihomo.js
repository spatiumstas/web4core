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
      if (['sdns', 'anytls'].includes(b.proto)) continue;
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

function validateMihomoYaml(yamlText, fileName) {
  writeYaml(fileName, yamlText);
  execOrThrow(`mihomo -t -f ${fileName}`);
  fs.unlinkSync(fileName);
}

function main() {
  const web4core = loadWeb4core();
  const rawLinks = splitLinksFromEnv('CONFIGS');
  if (!rawLinks.length) throw new Error('CONFIGS is empty (no test links)');

  const compatibleLinks = rawLinks.filter((l) => {
    try {
      const b = (web4core.buildBeansFromInput(l) || [])[0];
      if (!b) return false;
      if (['sdns', 'anytls'].includes(b.proto)) return false;
      if (b.proto === 'socks' && b.socks && b.socks.type === 'socks4') return false;
      return true;
    } catch {
      return false;
    }
  });

  console.log('Found', compatibleLinks.length, 'Mihomo-compatible links');
  if (!compatibleLinks.length) throw new Error('No Mihomo-compatible links in CONFIGS');

  const wgConf = process.env.WG_CONF || '';
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

  // 3) Subscription mode (proxy-providers)
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

