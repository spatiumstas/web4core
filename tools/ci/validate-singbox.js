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

function buildConfig(web4core, input, options, wgBeans) {
  if (typeof web4core.buildFromRequest === 'function') {
    const out = web4core.buildFromRequest({ core: 'singbox', input, options, wgBeans });
    if (!out || out.kind !== 'json') throw new Error('Unexpected buildFromRequest output kind for singbox');
    return out.data;
  }
  const beans = input.trim() ? web4core.buildBeansFromInput(input.trim()) : [];
  const used = new Set();
  const outbounds = beans.map((b) => Object.assign({ tag: web4core.computeTag(b, used) }, web4core.buildSingBoxOutbound(b)));
  return web4core.buildSingBoxConfig(outbounds, options || {});
}

function runBinaryOnce({ bin, configFile, startupRegex }) {
  const cmd = `bash -lc 'tmp=$(mktemp); ${bin} run -c ${configFile} >$tmp 2>&1 & pid=$!; sleep 2; kill $pid || true; cat $tmp; rm -f $tmp'`;
  const out = execOrThrow(cmd);
  if (!startupRegex.test(out)) {
    throw new Error(`${bin} did not report start\n--- LOG START ---\n${out}\n--- LOG END ---`);
  }
}

function checkConfig(bin, configFile) {
  execOrThrow(`${bin} check -c ${configFile}`);
}

function smokeRunSingBox(bin, startupRegex, configObj, tagHint) {
  const runObj = JSON.parse(JSON.stringify(configObj));
  runObj.inbounds = [{ tag: 'mixed-in', type: 'mixed', listen: '127.0.0.1', listen_port: 2080 }];
  const firstSelector = (runObj.outbounds || []).find((o) => o.type === 'selector')?.tag;
  runObj.route = runObj.route || {};
  runObj.route.final = firstSelector || runObj.route.final || 'direct';

  const runFile = `run_singbox_${tagHint}.json`;
  writeJson(runFile, runObj);
  runBinaryOnce({
    bin,
    configFile: runFile,
    startupRegex,
  });
  fs.unlinkSync(runFile);
}

function loadOptionalWgBean(web4core) {
  const wgConf = process.env.WG_CONF || '';
  if (!wgConf.trim() || typeof web4core.parseWireGuardConf !== 'function') return null;
  const wgBean = web4core.parseWireGuardConf(wgConf, 'wg-ci.conf');
  web4core.validateBean(wgBean);
  return wgBean;
}

function runCommonSuite({ runnerName, bin, startupRegex, useExtended }) {
  const web4core = loadWeb4core();
  const linksAll = splitLinksFromEnv('CONFIGS');
  if (!linksAll.length) throw new Error('CONFIGS is empty (no test links)');
  const links = linksAll.filter((l) => {
    const s = String(l || '');
    if (s.startsWith('masque://')) return false;
    if (s.includes('#Test-Hysteria2-HopInterval-Range')) return false;
    if (/[?&]hop_interval=\d+\s*-\s*\d+(?:[&#]|$)/i.test(s)) return false;
    return true;
  });
  if (!links.length) throw new Error('No sing-box-compatible links in CONFIGS after filtering core-specific cases');

  const wgBean = loadOptionalWgBean(web4core);

  let ok = 0;
  let fail = 0;

  const primaryLink = links[0];

  for (let i = 0; i < links.length; i++) {
    const link = links[i];
    const label = safeLinkLabel(link, i);
    console.log(`Testing ${runnerName} config ${i + 1}/${links.length}: ${label}`);

    try {
      const cfg1 = buildConfig(web4core, link, {
        useExtended,
        addTun: true,
        addSocks: true,
        tunName: 'tun0',
      });
      const f1 = `test_singbox_${i}_basic.json`;
      writeJson(f1, cfg1);
      checkConfig(bin, f1);
      smokeRunSingBox(bin, startupRegex, cfg1, `${runnerName}_${i}_basic`);
      fs.unlinkSync(f1);

      const multiInput = `${link}\n${link}`;
      const cfg2 = buildConfig(web4core, multiInput, {
        useExtended,
        addTun: true,
        addSocks: true,
        tunName: 'tun0:select,tun1:auto',
        perTunMixed: true,
        detour: true,
        genClashSecret: true,
      }, wgBean ? [wgBean] : []);
      const f2 = `test_singbox_${i}_opts.json`;
      writeJson(f2, cfg2);
      checkConfig(bin, f2);
      smokeRunSingBox(bin, startupRegex, cfg2, `${runnerName}_${i}_opts`);
      fs.unlinkSync(f2);

      const androidCfg = buildConfig(web4core, multiInput, {
        useExtended,
        addTun: true,
        addSocks: true,
        tunName: 'tun0',
        androidMode: true,
      }, wgBean ? [wgBean] : []);
      if (!androidCfg?.route?.override_android_vpn) {
        throw new Error('androidMode: expected route.override_android_vpn = true');
      }

      ok++;
      console.log(`✅ ${runnerName} ok: ${label}`);
    } catch (e) {
      fail++;
      console.log(`❌ ${runnerName} failed: ${label}`);
      console.log(String(e && e.message ? e.message : e));
    }
  }

  try {
    const inputAll = links.join('\n');
    const cfg = buildConfig(web4core, inputAll, { useExtended, addTun: true, addSocks: true, tunName: 'tun0,tun1' }, wgBean ? [wgBean] : []);
    const f = `test_${runnerName}_multi_all.json`;
    writeJson(f, cfg);
    checkConfig(bin, f);
    smokeRunSingBox(bin, startupRegex, cfg, `${runnerName}_multi_all`);
    fs.unlinkSync(f);
    console.log(`✅ ${runnerName} multi-all ok`);
  } catch (e) {
    console.log(`❌ ${runnerName} multi-all failed`);
    console.log(String(e && e.message ? e.message : e));
    fail++;
  }

  if (wgBean) {
    try {
      const cfg = buildConfig(web4core, primaryLink, { useExtended, addTun: true, addSocks: true, tunName: 'tun0' }, [wgBean]);
      const f = `test_${runnerName}_wireguard.json`;
      writeJson(f, cfg);
      checkConfig(bin, f);
      smokeRunSingBox(bin, startupRegex, cfg, `${runnerName}_wireguard`);
      fs.unlinkSync(f);
      console.log(`✅ ${runnerName} WireGuard ok`);
    } catch (e) {
      console.log(`❌ ${runnerName} WireGuard failed`);
      console.log(String(e && e.message ? e.message : e));
      fail++;
    }
  } else {
    console.log(`ℹ️ No WG_CONF provided; skipping ${runnerName} WireGuard test`);
  }

  console.log(`\n📊 ${runnerName} results: ${ok} ok, ${fail} failed`);
  if (fail) process.exit(1);
  return { web4core, links, wgBean };
}

function runExtendedExtras(web4core, links, bin, startupRegex) {
  const mieruJson = process.env.MIERU_JSON || '';
  const sdnsLink = process.env.SDNS_LINK || '';
  const xhttpLink = process.env.XHTTP_LINK || '';

  const baseLink = links.find((l) => !l.startsWith('mieru://') && !l.startsWith('sdns://')) || links[0];

  let fail = 0;

  if (mieruJson.trim()) {
    try {
      const cfg = buildConfig(web4core, mieruJson, { useExtended: true, addTun: true, addSocks: true });
      const f = 'mieru-config.json';
      writeJson(f, cfg);
      checkConfig(bin, f);
      smokeRunSingBox(bin, startupRegex, cfg, `extended_mieru`);
      fs.unlinkSync(f);
      console.log('✅ Mieru ok');
    } catch (e) {
      fail++;
      console.log('❌ Mieru failed');
      console.log(String(e && e.message ? e.message : e));
    }
  } else {
    console.log('ℹ️ No MIERU_JSON provided; skipping Mieru test');
  }

  if (sdnsLink.trim()) {
    try {
      const input = `${sdnsLink.trim()}\n${baseLink}`;
      const cfg = buildConfig(web4core, input, { useExtended: true, addTun: true, addSocks: true });
      const f = 'sdns-combo-config.json';
      writeJson(f, cfg);
      checkConfig(bin, f);
      smokeRunSingBox(bin, startupRegex, cfg, `extended_sdns_combo`);
      fs.unlinkSync(f);
      console.log('✅ SDNS combo ok');
    } catch (e) {
      fail++;
      console.log('❌ SDNS combo failed');
      console.log(String(e && e.message ? e.message : e));
    }
  } else {
    console.log('ℹ️ No SDNS_LINK provided; skipping SDNS test');
  }

  if (xhttpLink.trim()) {
    try {
      const cfg = buildConfig(web4core, xhttpLink.trim(), { useExtended: true, addTun: true, addSocks: true });
      const f = 'xhttp-config.json';
      writeJson(f, cfg);
      checkConfig(bin, f);
      smokeRunSingBox(bin, startupRegex, cfg, `extended_xhttp`);
      fs.unlinkSync(f);
      console.log('✅ XHTTP ok');
    } catch (e) {
      fail++;
      console.log('❌ XHTTP failed');
      console.log(String(e && e.message ? e.message : e));
    }
  } else {
    console.log('ℹ️ No XHTTP_LINK provided; skipping XHTTP test');
  }

  if (fail) process.exit(1);
}

function main() {
  const args = process.argv.slice(2);
  const extended = args.includes('--extended');
  if (!extended) {
    runCommonSuite({
      runnerName: 'sing-box',
      bin: 'sing-box',
      startupRegex: /(sing-box started|tcp server started at 127\.0\.0\.1:2080)/,
      useExtended: false,
    });
    return;
  }

  const ctx = runCommonSuite({
    runnerName: 'sing-box-extended',
    bin: '/usr/local/bin/sing-box-extended',
    startupRegex: /(sing-box started|server started|inbound\/.*server started|tcp server started at 127\.0\.0\.1:2080)/,
    useExtended: true,
  });
  runExtendedExtras(ctx.web4core, ctx.links, '/usr/local/bin/sing-box-extended', /(sing-box started|server started|inbound\/.*server started|tcp server started at 127\.0\.0\.1:2080)/);
}

main();
