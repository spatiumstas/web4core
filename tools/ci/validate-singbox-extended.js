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

function runExtended(configFile) {
  const cmd = `bash -lc 'tmp=$(mktemp); /usr/local/bin/sing-box-extended run -c ${configFile} >$tmp 2>&1 & pid=$!; sleep 2; kill $pid || true; cat $tmp; rm -f $tmp'`;
  const out = execOrThrow(cmd);
  if (!/(sing-box started|server started|inbound\/.*server started|tcp server started at)/.test(out)) {
    throw new Error(`sing-box-extended did not report start\n--- LOG START ---\n${out}\n--- LOG END ---`);
  }
}

function main() {
  const web4core = loadWeb4core();
  const links = splitLinksFromEnv('CONFIGS');
  if (!links.length) throw new Error('CONFIGS is empty (no test links)');

  const mieruJson = process.env.MIERU_JSON || '';
  const sdnsLink = process.env.SDNS_LINK || '';
  const xhttpLink = process.env.XHTTP_LINK || '';

  let fail = 0;
  let ok = 0;

  // 1) Existing config links
  for (let i = 0; i < links.length; i++) {
    const link = links[i];
    const label = safeLinkLabel(link, i);
    console.log(`Testing sing-box-extended config ${i + 1}/${links.length}: ${label}`);

    try {
      const out = web4core.buildFromRequest({ core: 'singbox', input: link, options: { useExtended: true, addTun: false, addSocks: true } });
      if (!out || out.kind !== 'json') throw new Error('Unexpected output kind for singbox extended');
      const f = `test_extended_${i}.json`;
      writeJson(f, out.data);
      runExtended(f);
      fs.unlinkSync(f);
      ok++;
      console.log(`✅ extended ok: ${label}`);
    } catch (e) {
      fail++;
      console.log(`❌ extended failed: ${label}`);
      console.log(String(e && e.message ? e.message : e));
    }
  }

  const baseLink = links.find((l) => !l.startsWith('mieru://') && !l.startsWith('sdns://')) || links[0];

  // 2) Mieru JSON
  if (mieruJson.trim()) {
    try {
      const out = web4core.buildFromRequest({ core: 'singbox', input: mieruJson, options: { useExtended: true, addTun: false, addSocks: true } });
      if (!out || out.kind !== 'json') throw new Error('Unexpected output kind for Mieru');
      const f = 'mieru-config.json';
      writeJson(f, out.data);
      runExtended(f);
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

  // 3) SDNS
  if (sdnsLink.trim()) {
    try {
      const input = `${sdnsLink.trim()}\n${baseLink}`;
      const out = web4core.buildFromRequest({ core: 'singbox', input, options: { useExtended: true, addTun: false, addSocks: true } });
      if (!out || out.kind !== 'json') throw new Error('Unexpected output kind for SDNS combo');
      const f = 'sdns-combo-config.json';
      writeJson(f, out.data);
      runExtended(f);
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

  // 4) XHTTP
  if (xhttpLink.trim()) {
    try {
      const out = web4core.buildFromRequest({ core: 'singbox', input: xhttpLink.trim(), options: { useExtended: true, addTun: false, addSocks: true } });
      if (!out || out.kind !== 'json') throw new Error('Unexpected output kind for XHTTP');
      const f = 'xhttp-config.json';
      writeJson(f, out.data);
      runExtended(f);
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

  console.log(`\n📊 sing-box-extended results: ${ok} ok, ${fail} failed`);
  if (fail) process.exit(1);
}

main();

