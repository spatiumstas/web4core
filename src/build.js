import { buildBeansFromInput, computeTag, getAllowedCoreProtocols, validateBean } from './main.js';
import { buildSingBoxConfig, buildSingBoxOutbound, buildSingBoxWireGuardEndpoint } from './core/singbox.js';
import { buildXrayConfig, buildXrayOutbound } from './core/xray.js';
import { buildMihomoConfig, buildMihomoSubscriptionConfig } from './core/mihomo.js';
import { buildMihomoYaml } from './core/yaml.js';

function assertCoreSupports(beans, core, label, options) {
  const allowed = new Set(getAllowedCoreProtocols(core, options));
  const unsupported = new Set();
  for (const b of (Array.isArray(beans) ? beans : [])) {
    const p = b?.proto;
    if (!p) continue;
    if (!allowed.has(p)) unsupported.add(p);
  }
  if (unsupported.size) {
    throw new Error(`${label} does not support: ${Array.from(unsupported).join(', ')}`);
  }
}

function splitLines(raw) {
  return String(raw || '')
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function splitMihomoSubscriptionInput(raw) {
  const lines = splitLines(raw);
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

export function buildFromRequest(req) {
  const core = String(req?.core || '').toLowerCase();
  const input = String(req?.input || '');
  const optionsIn = (req && typeof req.options === 'object' && req.options) ? req.options : {};
  const options = Object.assign({}, optionsIn);
  const wgBeans = Array.isArray(req?.wgBeans) ? req.wgBeans : [];

  if (!core) throw new Error('Missing core');
  if (core !== 'singbox' && core !== 'xray' && core !== 'mihomo') throw new Error('Invalid core: ' + core);

  if (core === 'singbox') {
    if (options.addTun === undefined) options.addTun = true;
    if (options.addSocks === undefined) options.addSocks = true;
    if (options.webUI === undefined) options.webUI = false;
  } else if (core === 'xray') {
    if (options.addTun === undefined) options.addTun = false;
    if (options.addSocks === undefined) options.addSocks = true;
  } else if (core === 'mihomo') {
    if (options.webUI === undefined) options.webUI = true;
    if (options.addTun === undefined) options.addTun = false;
  }

  const beans = input.trim() ? buildBeansFromInput(input.trim()) : [];
  const allBeans = beans.slice();
  if (wgBeans.length) allBeans.push(...wgBeans);
  if (!allBeans.length) throw new Error('No valid links or profiles provided');

  allBeans.forEach(validateBean);

  if (core === 'xray' || core === 'mihomo') {
    assertCoreSupports(allBeans, core, core === 'xray' ? 'Xray' : 'Mihomo', options);
  }

  if (core === 'singbox') {
    const useExtended = !!options.useExtended;
    if (!useExtended) {
      const hasExtendedOnly = allBeans.some((b) => b.proto === 'mieru' || b.proto === 'sdns');
      if (hasExtendedOnly) throw new Error('Enable Extended to generate Mieru/SDNS configurations');
    }

    const dnsBeans = useExtended ? allBeans.filter((b) => b.proto === 'sdns') : [];
    const wgBeans = allBeans.filter((b) => b.proto === 'wireguard');
    const outboundBeans = allBeans.filter((b) => b.proto !== 'sdns' && b.proto !== 'wireguard');
    const used = new Set();
    const endpoints = wgBeans.map((b) => {
      const tag = computeTag(b, used);
      return Object.assign({ tag }, buildSingBoxWireGuardEndpoint(Object.assign({}, b, { name: tag })));
    });

    const outbounds = outboundBeans.map((b) => {
      const ob = buildSingBoxOutbound(b, { useExtended: !!useExtended });
      const tag = computeTag(b, used);
      return Object.assign({ tag }, ob);
    });

    const detour = !!options.detour;
    if (detour && outbounds.length > 1) {
      const mainTag = outbounds[0].tag;
      for (let i = 1; i < outbounds.length; i++) outbounds[i].detour = mainTag;
    }

    const cfg = buildSingBoxConfig(outbounds, {
      addTun: !!options.addTun,
      addSocks: !!options.addSocks,
      perTunMixed: !!options.perTunMixed,
      tunName: String(options.tunName || ''),
      genClashSecret: !!options.genClashSecret,
      useExtended: !!useExtended,
      androidMode: !!options.androidMode,
      dnsBeans,
      endpoints,
    });

    return { kind: 'json', data: cfg };
  }

  if (core === 'xray') {
    let cfg;
    const addTun = !!options.addTun;
    const addSocks = !!options.addSocks;
    if (!addTun && !addSocks) {
      throw new Error('Xray: enable at least one inbound (TUN or SOCKS5)');
    }
    if (allBeans.length === 1) {
      cfg = buildXrayConfig(buildXrayOutbound(allBeans[0]), { addTun, addSocks });
    } else {
      const used = new Set();
      const outbounds = allBeans.map((b) => {
        const ob = buildXrayOutbound(b);
        ob.tag = computeTag(b, used);
        return ob;
      });
      cfg = buildXrayConfig(outbounds, { enableBalancer: !!options.enableBalancer, addTun, addSocks });
    }
    return { kind: 'json', data: cfg };
  }

  // mihomo
  const webUI = !!options.webUI;
  const perProxyPort = !!options.perProxyPort;
  const addTun = !!options.addTun;
  const mihomoTunOpts = addTun ? { mode: (options.mihomoPerProxyTun ? 'listeners' : 'tun') } : null;

  const subMode = !!options.mihomoSubscriptionMode;
  if (subMode) {
    const { subUrls, proxyText } = splitMihomoSubscriptionInput(input);
    if (!subUrls.length) {
      throw new Error('Provide one or more HTTP(S) URLs for Mihomo subscription (one per line)');
    }
    const extraBeans = [];
    if (proxyText.trim()) extraBeans.push(...buildBeansFromInput(proxyText));
    if (wgBeans.length) extraBeans.push(...wgBeans);
    extraBeans.forEach(validateBean);
    assertCoreSupports(extraBeans, core, 'Mihomo', options);

    const cfg = buildMihomoSubscriptionConfig(subUrls, extraBeans, { perProxyPort });
    const yaml = buildMihomoYaml(cfg.proxies, cfg.groups, cfg.providers, cfg.rules, cfg.listeners, {
      webUI,
      tun: mihomoTunOpts,
    });
    return { kind: 'yaml', data: yaml };
  }

  const outBeans = allBeans.filter((b) => b.proto !== 'mieru' && b.proto !== 'sdns');
  const cfg = buildMihomoConfig(outBeans, { perProxyPort });
  const yaml = buildMihomoYaml(cfg.proxies, cfg['proxy-groups'], null, cfg.rules, cfg.listeners, {
    webUI,
    tun: mihomoTunOpts,
  });
  return { kind: 'yaml', data: yaml };
}


