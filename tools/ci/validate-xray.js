const fs = require('fs');

const {
  loadWeb4core,
  splitLinksFromEnv,
  safeLinkLabel,
  execOrThrow,
} = require('./runtimeSandbox');

function writeJson(p, obj) {
  fs.writeFileSync(p, JSON.stringify(obj, null, 2));
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function buildXrayConfig(web4core, input) {
  const out = web4core.buildFromRequest
    ? web4core.buildFromRequest({ core: 'xray', input, options: { addTun: false, addSocks: true } })
    : { kind: 'json', data: web4core.buildXrayConfig(web4core.buildXrayOutbound((web4core.buildBeansFromInput(input) || [])[0]), { addTun: false, addSocks: true }) };
  if (!out || out.kind !== 'json') throw new Error('Unexpected output kind for Xray');
  return out.data;
}

function testXhttpXmuxFixture(web4core, links) {
  const fixture = links.find((line) => line.includes('#fixture-xhttp-full'));
  assert(fixture, 'CONFIGS is missing fixture-xhttp-full');
  const cfg = buildXrayConfig(web4core, fixture);
  const outbound = cfg.outbounds.find((item) => item.tag === 'fixture-xhttp-full');
  const xmux = outbound && outbound.streamSettings && outbound.streamSettings.xhttpSettings && outbound.streamSettings.xhttpSettings.xmux;

  assert(xmux, 'XHTTP fixture: missing xmux settings');
  assert(xmux.maxConcurrency === 8, 'XHTTP fixture: maxConcurrency was not preserved');
  assert(!Object.hasOwn(xmux, 'maxConnections'), 'XHTTP fixture: Xray must not receive maxConnections with maxConcurrency');
  console.log('✅ Xray XHTTP xmux compatibility fixture ok');
}

function main() {
  const web4core = loadWeb4core();
  const allLinks = splitLinksFromEnv('CONFIGS');
  if (!allLinks.length) throw new Error('CONFIGS is empty (no test links)');

  const links = allLinks.filter((l) => (
    !l.startsWith('tuic://') &&
    !l.startsWith('anytls://') &&
    !l.startsWith('masque://') &&
    !l.startsWith('tt://') &&
    !l.startsWith('mieru://') &&
    !l.startsWith('sdns://')
  ));
  console.log(`Found ${links.length} test links (excluding tuic/anytls/masque/tt/mieru/sdns for Xray)`);
  if (!links.length) throw new Error('No Xray-compatible links in CONFIGS');
  testXhttpXmuxFixture(web4core, links);

  let ok = 0;
  let fail = 0;

  for (let i = 0; i < links.length; i++) {
    const link = links[i];
    const label = safeLinkLabel(link, i);
    console.log(`Testing Xray config ${i + 1}/${links.length}: ${label}`);

    try {
      const cfg = buildXrayConfig(web4core, link);

      const f = `test_xray_${i}.json`;
      writeJson(f, cfg);
      execOrThrow(`xray -test -config ${f}`);
      fs.unlinkSync(f);
      ok++;
      console.log(`✅ Xray ok: ${label}`);
    } catch (e) {
      fail++;
      console.log(`❌ Xray failed: ${label}`);
      console.log(String(e && e.message ? e.message : e));
    }
  }

  try {
    const inputAll = links.join('\n');
    const out = web4core.buildFromRequest({ core: 'xray', input: inputAll, options: { addTun: false, addSocks: true } });
    if (!out || out.kind !== 'json') throw new Error('Unexpected output kind for Xray multi-all');
    const f = 'test_xray_multi_all.json';
    writeJson(f, out.data);
    execOrThrow(`xray -test -config ${f}`);
    fs.unlinkSync(f);
    console.log('✅ Xray multi-all ok');

    const outBal = web4core.buildFromRequest({ core: 'xray', input: inputAll, options: { enableBalancer: true, addTun: false, addSocks: true } });
    if (!outBal || outBal.kind !== 'json') throw new Error('Unexpected output kind for Xray multi-all balancer');
    const f2 = 'test_xray_multi_all_balancer.json';
    writeJson(f2, outBal.data);
    execOrThrow(`xray -test -config ${f2}`);
    fs.unlinkSync(f2);
    console.log('✅ Xray multi-all (balancer) ok');
  } catch (e) {
    console.log('❌ Xray multi-all failed');
    console.log(String(e && e.message ? e.message : e));
    fail++;
  }

  console.log(`\n📊 Xray results: ${ok} ok, ${fail} failed`);
  if (fail) process.exit(1);
}

main();

