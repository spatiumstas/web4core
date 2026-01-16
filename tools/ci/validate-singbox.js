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

function smokeRunSingBox(configObj, tagHint) {
  const runObj = JSON.parse(JSON.stringify(configObj));
  runObj.inbounds = [{ tag: 'mixed-in', type: 'mixed', listen: '127.0.0.1', listen_port: 2080 }];
  const firstSelector = (runObj.outbounds || []).find((o) => o.type === 'selector')?.tag;
  runObj.route = runObj.route || {};
  runObj.route.final = firstSelector || runObj.route.final || 'direct';

  const runFile = `run_singbox_${tagHint}.json`;
  writeJson(runFile, runObj);
  const cmd = `bash -lc 'tmp=$(mktemp); sing-box run -c ${runFile} >$tmp 2>&1 & pid=$!; sleep 2; kill $pid || true; cat $tmp; rm -f $tmp'`;
  const out = execOrThrow(cmd);
  if (!/(sing-box started|tcp server started at 127\\.0\\.0\\.1:2080)/.test(out)) {
    throw new Error(`sing-box did not report start\n--- LOG START ---\n${out}\n--- LOG END ---`);
  }
  fs.unlinkSync(runFile);
}

function main() {
  const web4core = loadWeb4core();
  const links = splitLinksFromEnv('CONFIGS');
  if (!links.length) throw new Error('CONFIGS is empty (no test links)');

  const wgConf = process.env.WG_CONF || '';
  let wgBean = null;
  if (wgConf.trim() && typeof web4core.parseWireGuardConf === 'function') {
    wgBean = web4core.parseWireGuardConf(wgConf, 'wg-ci.conf');
    web4core.validateBean(wgBean);
  }

  let ok = 0;
  let fail = 0;

  const primaryLink = links[0];

  for (let i = 0; i < links.length; i++) {
    const link = links[i];
    const label = safeLinkLabel(link, i);
    console.log(`Testing sing-box config ${i + 1}/${links.length}: ${label}`);

    try {
      const cfg1 = buildConfig(web4core, link, {
        addTun: true,
        addSocks: true,
        tunName: 'tun0',
      });
      const f1 = `test_singbox_${i}_basic.json`;
      writeJson(f1, cfg1);
      execOrThrow(`sing-box check -c ${f1}`);
      smokeRunSingBox(cfg1, `${i}_basic`);
      fs.unlinkSync(f1);

      const multiInput = `${link}\n${link}`;
      const cfg2 = buildConfig(web4core, multiInput, {
        addTun: true,
        addSocks: true,
        tunName: 'tun0:select,tun1:auto',
        perTunMixed: true,
        detour: true,
        genClashSecret: true,
      }, wgBean ? [wgBean] : []);
      const f2 = `test_singbox_${i}_opts.json`;
      writeJson(f2, cfg2);
      execOrThrow(`sing-box check -c ${f2}`);
      smokeRunSingBox(cfg2, `${i}_opts`);
      fs.unlinkSync(f2);

      const androidCfg = buildConfig(web4core, multiInput, {
        addTun: true,
        addSocks: true,
        tunName: 'tun0',
        androidMode: true,
      }, wgBean ? [wgBean] : []);
      if (!androidCfg?.route?.override_android_vpn) {
        throw new Error('androidMode: expected route.override_android_vpn = true');
      }

      ok++;
      console.log(`✅ sing-box ok: ${label}`);
    } catch (e) {
      fail++;
      console.log(`❌ sing-box failed: ${label}`);
      console.log(String(e && e.message ? e.message : e));
    }
  }

  try {
    const inputAll = links.join('\n');
    const cfg = buildConfig(web4core, inputAll, { addTun: true, addSocks: true, tunName: 'tun0,tun1' }, wgBean ? [wgBean] : []);
    const f = 'test_singbox_multi_all.json';
    writeJson(f, cfg);
    execOrThrow(`sing-box check -c ${f}`);
    smokeRunSingBox(cfg, 'multi_all');
    fs.unlinkSync(f);
    console.log('✅ sing-box multi-all ok');
  } catch (e) {
    console.log('❌ sing-box multi-all failed');
    console.log(String(e && e.message ? e.message : e));
    fail++;
  }

  if (wgBean) {
    try {
      const cfg = buildConfig(web4core, primaryLink, { addTun: true, addSocks: true, tunName: 'tun0' }, [wgBean]);
      const f = 'test_singbox_wireguard.json';
      writeJson(f, cfg);
      execOrThrow(`sing-box check -c ${f}`);
      fs.unlinkSync(f);
      console.log('✅ sing-box WireGuard ok');
    } catch (e) {
      console.log('❌ sing-box WireGuard failed');
      console.log(String(e && e.message ? e.message : e));
      fail++;
    }
  } else {
    console.log('ℹ️ No WG_CONF provided; skipping sing-box WireGuard test');
  }

  console.log(`\n📊 sing-box results: ${ok} ok, ${fail} failed`);
  if (fail) process.exit(1);
}

main();

