const el = {
    coreToggle: document.getElementById('coreToggle'),
    coreItems: Array.from(document.querySelectorAll('#coreToggle .labels [data-core]')),
    outBlock: document.getElementById('outBlock'),
    errorBlock: document.getElementById('errorBlock'),
    errorText: document.getElementById('errorText'),
    links: document.getElementById('links'),
    tunName: document.getElementById('tunName'),
    gen: document.getElementById('gen'),
    btnCopy: document.getElementById('btnCopy'),
    btnDownload: document.getElementById('btnDownload'),
    cbTun: document.getElementById('cbTun'),
    cbSocks: document.getElementById('cbSocks'),
    cbExtended: document.getElementById('cbExtended'),
    cbClashSecret: document.getElementById('cbClashSecret'),
    cbMihomoSub: document.getElementById('cbMihomoSub'),
    cbMihomoTun: document.getElementById('cbMihomoTun'),
    cbMihomoPerProxyTun: document.getElementById('cbMihomoPerProxyTun'),
    cbMihomoPerProxyPort: document.getElementById('cbMihomoPerProxyPort'),
    cbMihomoWebUI: document.getElementById('cbMihomoWebUI'),
    cbDetour: document.getElementById('cbDetour'),
    lblMihomoSub: document.getElementById('lblMihomoSub'),
    lblMihomoTun: document.getElementById('lblMihomoTun'),
    lblMihomoPerProxyTun: document.getElementById('lblMihomoPerProxyTun'),
    lblMihomoPerProxyPort: document.getElementById('lblMihomoPerProxyPort'),
    lblMihomoWebUI: document.getElementById('lblMihomoWebUI'),
    cbXrayBalancer: document.getElementById('cbXrayBalancer'),
    lblXrayBalancer: document.getElementById('lblXrayBalancer'),
    cbXrayTun: document.getElementById('cbXrayTun'),
    lblXrayTun: document.getElementById('lblXrayTun'),
    cbXraySocks: document.getElementById('cbXraySocks'),
    lblXraySocks: document.getElementById('lblXraySocks'),
    cbPerTunMixed: document.getElementById('cbPerTunMixed'),
    lblPerTunMixed: document.getElementById('lblPerTunMixed'),
    cbAndroidMode: document.getElementById('cbAndroidMode'),
    lblAndroidMode: document.getElementById('lblAndroidMode'),
    lblDetour: document.getElementById('lblDetour'),
    out: document.getElementById('out'),
    btnChevron: document.getElementById('btnChevron'),
    settingsPanel: document.getElementById('settingsPanel'),
    btnWgUpload: document.getElementById('btnWgUpload'),
    wgFile: document.getElementById('wgFile'),
};

const state = {
    core: 'singbox',
    wgBeans: []
};

const header = document.getElementById('asciiHeader');
const MSG_SUB_URL = 'Provide one or more HTTP(S) URLs for Mihomo subscription (one per line)';
const MSG_SUB_EMPTY = 'Subscription returned no valid links';
const MSG_SUB_FETCH = (m) => 'Failed to fetch subscription: ' + (m || '');
const MSG_NO_LINKS = 'No valid links or profiles provided';
const MSG_EXTENDED_ENABLE = 'Enable Extended to generate Mieru/SDNS configurations';

const PLACEHOLDER_SINGBOX_BASE = [
    'subscription links',
    'vless://...',
    'vmess://...',
    'trojan://...',
    'ss://...',
    'socks://...',
    'http://user:pass@host:port',
    'hy2://...',
    'tuic://...',
    'anytls://...'
];
const PLACEHOLDER_SINGBOX_EXTENDED = [
    'mieru://... (or json)',
    'sdns://...'
];
const PLACEHOLDER_XRAY = [
    'subscription links',
    'vless://...',
    'vmess://...',
    'trojan://...',
    'ss://...',
    'socks://...',
    'http://user:pass@host:port',
    'hy2://...'
];
const PLACEHOLDER_MIHOMO = [
    'subscription links',
    'vless://...',
    'vmess://...',
    'trojan://...',
    'ss://...',
    'socks://...',
    'http://user:pass@host:port',
    'hy2://...',
    'tuic://...',
    'masque://...'
];

function updateLinksPlaceholder() {
    if (!el.links) return;
    const core = getCore();
    const useExtended = !!el.cbExtended?.checked;

    let lines;
    if (core === 'singbox') {
        lines = useExtended
            ? [...PLACEHOLDER_SINGBOX_BASE, ...PLACEHOLDER_SINGBOX_EXTENDED]
            : PLACEHOLDER_SINGBOX_BASE;
    } else if (core === 'xray') {
        lines = PLACEHOLDER_XRAY;
    } else if (core === 'mihomo') {
        lines = PLACEHOLDER_MIHOMO;
    }
    el.links.placeholder = lines.join('\n') + '\n';
}

const toggleHidden = (node, hidden) => {
    if (node) node.classList.toggle('is-hidden', hidden);
};
const setMihomoPerProxyTunVisible = (visible) => {
    const show = !!visible;
    if (!show && el.cbMihomoPerProxyTun?.checked) {
        el.cbMihomoPerProxyTun.checked = false;
    }
    toggleHidden(el.lblMihomoPerProxyTun, !show);
};
const setError = (msg) => {
    el.errorText.textContent = msg || '';
};
const setGenerateEnabled = (enabled) => {
    if (!el.gen) return;
    el.gen.disabled = !enabled;
    toggleHidden(el.gen, !enabled);
};
const setInputLoading = (loading) => {
    if (!el.links) return;
    el.links.classList.toggle('input-loading', !!loading);
};
const renderOutput = (text, isYaml) => {
    el.out.value = text || '';
    setError('');
    el.outBlock.classList.remove('hidden');
};
const hideOutput = () => {
    el.outBlock.classList.add('hidden');
};
const scrollOutIntoView = () => {
    const block = el.outBlock;
    if (block && block.scrollIntoView) block.scrollIntoView({ behavior: 'smooth', block: 'center', inline: 'nearest' });
    if (el.out && el.out.focus) {
        try {
            el.out.focus({ preventScroll: true });
        } catch {
        }
    }
};

const updateWgButtonState = (count) => {
    if (!el.btnWgUpload) return;
    const span = el.btnWgUpload.querySelector('span');
    if (span) span.textContent = count > 0 ? `WireGuard (${count})` : 'WireGuard';
    el.btnWgUpload.classList.toggle('is-active', count > 0);
};

function getCore() {
    return state.core;
}

function setCore(core) {
    state.core = core;
    el.coreToggle.setAttribute('data-core', core);

    const items = Array.isArray(el.coreItems) ? el.coreItems : [];
    const idx = Math.max(0, items.findIndex((n) => n?.dataset?.core === core));
    el.coreToggle.style.setProperty('--core-count', String(items.length || 3));
    el.coreToggle.style.setProperty('--core-index', String(idx));
    items.forEach((n, i) => {
        const selected = n?.dataset?.core === core;
        n.setAttribute('aria-checked', String(selected));
        n.tabIndex = selected ? 0 : -1;
    });

    const hideSing = core !== 'singbox';
    const cbTunLabel = el.cbTun?.parentElement;
    const cbSocksLabel = el.cbSocks?.parentElement;
    const cbClashSecretLabel = el.cbClashSecret?.parentElement;
    const cbExtendedLabel = el.cbExtended?.parentElement;
    toggleHidden(cbTunLabel, hideSing);
    toggleHidden(cbSocksLabel, hideSing);
    toggleHidden(cbClashSecretLabel, hideSing);
    toggleHidden(cbExtendedLabel, hideSing);
    toggleHidden(el.lblXrayTun, core !== 'xray');
    toggleHidden(el.lblXraySocks, core !== 'xray');
    toggleHidden(el.tunName?.parentElement || el.tunName, hideSing);
    toggleHidden(el.lblMihomoSub, core !== 'mihomo');
    toggleHidden(el.lblMihomoTun, core !== 'mihomo');
    setMihomoPerProxyTunVisible(false);
    toggleHidden(el.lblMihomoPerProxyPort, core !== 'mihomo');
    toggleHidden(el.lblMihomoWebUI, core !== 'mihomo');
    toggleHidden(el.btnWgUpload, core !== 'mihomo' && core !== 'singbox');
    toggleHidden(el.lblPerTunMixed, hideSing);
    toggleHidden(el.lblAndroidMode, hideSing);
    toggleHidden(el.lblDetour, hideSing);
    toggleHidden(el.lblXrayBalancer, core !== 'xray');
    updateLinksPlaceholder();

    if (core !== 'mihomo' && core !== 'singbox') {
        state.wgBeans = [];
        if (el.wgFile) el.wgFile.value = '';
        updateWgButtonState(0);
    }
    updateWgButtonState(Array.isArray(state.wgBeans) ? state.wgBeans.length : 0);
}

function isMihomoSubscriptionMode() {
    return getCore() === 'mihomo' && !!el.cbMihomoSub?.checked;
}

document.addEventListener('keydown', function (e) {
    if ((e.ctrlKey || e.metaKey) && e.code === 'KeyS') {
        e.preventDefault();
        el.gen?.click();
    }
});

if (el.coreToggle) {
    el.coreToggle.addEventListener('click', (e) => {
        const target = e.target && e.target.closest ? e.target.closest('[data-core]') : null;
        const core = target && target.dataset ? target.dataset.core : '';
        if (!core) return;
        e.stopPropagation();
        setCore(core);
        validateField(false);
    });
}

if (el.btnChevron && el.settingsPanel) {
    el.btnChevron.addEventListener('click', () => {
        const collapsed = el.settingsPanel.classList.toggle('settings-panel--collapsed');
        el.btnChevron.setAttribute('aria-expanded', String(!collapsed));
    });
}

function setupCheckboxValidation() {
    if (!el.cbTun || !el.cbSocks) return;

    const enforceAtLeastOne = (a, b) => {
        if (!a || !b) return;
        a.addEventListener('change', () => {
            if (!a.checked && !b.checked) b.checked = true;
        });
        b.addEventListener('change', () => {
            if (!a.checked && !b.checked) a.checked = true;
        });
    };

    enforceAtLeastOne(el.cbTun, el.cbSocks);
    enforceAtLeastOne(el.cbXrayTun, el.cbXraySocks);

    if (el.cbMihomoTun && el.cbMihomoPerProxyTun) {
        el.cbMihomoPerProxyTun.addEventListener('change', () => {
            if (el.cbMihomoPerProxyTun.checked) el.cbMihomoTun.checked = true;
        });
        el.cbMihomoTun.addEventListener('change', () => {
            if (!el.cbMihomoTun.checked) el.cbMihomoPerProxyTun.checked = false;
            validateField(false);
        });
    }

    const revalidateOnChange = [
        el.cbExtended,
        el.cbDetour,
        el.cbMihomoSub,
        el.cbMihomoTun,
        el.cbMihomoPerProxyTun,
        el.cbMihomoPerProxyPort,
        el.cbMihomoWebUI,
        el.cbPerTunMixed,
        el.cbAndroidMode,
        el.cbXrayBalancer,
        el.cbXrayTun,
        el.cbXraySocks,
    ];

    revalidateOnChange.forEach(cb => {
        cb?.addEventListener('change', () => {
            validateField(false);
            updateLinksPlaceholder();
        });
    });
}

function splitMihomoSubscriptionInput(raw) {
    const lines = String(raw || '').split(/\r?\n/).map(s => s.trim()).filter(Boolean);
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

function parseAndValidateProxyText(proxyText) {
    const text = String(proxyText || '').trim();
    if (!text) return [];
    const proxyBeans = globalThis.web4core.buildBeansFromInput(text);
    proxyBeans.forEach(globalThis.web4core.validateBean);
    return proxyBeans;
}

function validateField(showOutput) {
    const raw = el.links.value;
    const hasText = !!raw.trim();
    const tunName = el.tunName.value.trim();
    const core = getCore();
    const addTun = core === 'xray'
        ? !!el.cbXrayTun?.checked
        : (core === 'mihomo' ? !!el.cbMihomoTun?.checked : !!el.cbTun?.checked);
    const addSocks = core === 'xray'
        ? !!el.cbXraySocks?.checked
        : (core === 'mihomo' ? true : !!el.cbSocks?.checked);
    const genClashSecret = !!el.cbClashSecret?.checked;
    const useExtended = !!el.cbExtended?.checked;
    const subMihomo = isMihomoSubscriptionMode();
    const webUI = getCore() === 'mihomo' ? !!el.cbMihomoWebUI?.checked : false;
    const mihomoTunEnabled = getCore() === 'mihomo' ? !!el.cbMihomoTun?.checked : false;
    const mihomoPerProxyTun = getCore() === 'mihomo' ? !!el.cbMihomoPerProxyTun?.checked : false;
    const mihomoTunOpts = mihomoTunEnabled ? { mode: (mihomoPerProxyTun ? 'listeners' : 'tun') } : null;
    try {
        const wgBeans = Array.isArray(state.wgBeans) ? state.wgBeans : [];
        if (!hasText && wgBeans.length === 0) {
            setGenerateEnabled(false);
            setError('');
            hideOutput();
            el.links.classList.remove('input-error');
            return false;
        }
        if (subMihomo) {
            const { subUrls, proxyText } = splitMihomoSubscriptionInput(raw);
            const validHttpUrls = subUrls.length > 0;
            const hasExtraProxies = wgBeans.length > 0 || !!proxyText?.trim();
            const shouldShowPerProxyTun = subUrls.length > 1 || (validHttpUrls && hasExtraProxies);
            setMihomoPerProxyTunVisible(mihomoTunEnabled && shouldShowPerProxyTun);
            if (!showOutput) {
                setError(validHttpUrls ? '' : MSG_SUB_URL);
                if (validHttpUrls && proxyText) {
                    try {
                        const proxyBeans = parseAndValidateProxyText(proxyText);
                        setGenerateEnabled(true);
                        el.links.classList.remove('input-error');
                        return { subUrls, proxyBeans };
                    } catch (e) {
                        setError(e && e.message ? e.message : String(e));
                        setGenerateEnabled(false);
                        el.links.classList.add('input-error');
                        hideOutput();
                        return false;
                    }
                }
                setGenerateEnabled(validHttpUrls);
                el.links.classList.toggle('input-error', !validHttpUrls);
                if (!validHttpUrls) hideOutput();
                return validHttpUrls ? { subUrls } : false;
            }
            if (!validHttpUrls) throw new Error(MSG_SUB_URL);

            const extraBeans = wgBeans.slice();
            extraBeans.push(...parseAndValidateProxyText(proxyText));

            const config = globalThis.web4core?.buildMihomoSubscriptionConfig(subUrls, extraBeans, {
                perProxyPort: !!el.cbMihomoPerProxyPort?.checked
            });
            if (!config) throw new Error('Failed to build subscription config');

            const yaml = globalThis.web4core?.buildMihomoYaml(config.proxies, config.groups, config.providers, config.rules, config.listeners, { webUI, tun: mihomoTunOpts });
            renderOutput(yaml, true);
            setGenerateEnabled(true);
            el.links.classList.remove('input-error');
            return true;
        }

        const beans = hasText ? globalThis.web4core.buildBeansFromInput(raw) : [];
        if (wgBeans.length) beans.push(...wgBeans);
        if (!beans.length) throw new Error(MSG_NO_LINKS);
        beans.forEach(globalThis.web4core.validateBean);

        {
            const core = getCore();
            const opts = { useExtended };
            const allowedArr = globalThis.web4core?.getAllowedCoreProtocols
                ? globalThis.web4core.getAllowedCoreProtocols(core, opts)
                : [];
            const allowed = new Set(allowedArr);
            const unsupported = Array.from(new Set(beans.map(b => b?.proto).filter(p => p && !allowed.has(p))));
            if (unsupported.length) {
                const label = (core === 'xray') ? 'Xray' : (core === 'mihomo' ? 'Mihomo' : core);
                throw new Error(label + ' does not support: ' + unsupported.join(', '));
            }
        }
        if (getCore() === 'mihomo') {
            const outBeans = beans.filter(b => !['mieru', 'sdns'].includes(b.proto));
            setMihomoPerProxyTunVisible(!!mihomoTunEnabled && outBeans.length > 1);
        } else {
            setMihomoPerProxyTunVisible(false);
        }

        if (!useExtended && getCore() === 'singbox') {
            const hasExtendedOnly = beans.some(b => b.proto === 'mieru' || b.proto === 'sdns');
            if (hasExtendedOnly) throw new Error(MSG_EXTENDED_ENABLE);
        }

        if (!showOutput) {
            setError('');
            setGenerateEnabled(true);
            el.links.classList.remove('input-error');
            const perTunMixed = !!el.cbPerTunMixed?.checked;
            const androidMode = !!el.cbAndroidMode?.checked;
            return { beans, tunName, addTun, addSocks, perTunMixed, genClashSecret, useExtended, androidMode };
        }

        {
            const core = getCore();
            const perTunMixed = !!el.cbPerTunMixed?.checked;
            const androidMode = !!el.cbAndroidMode?.checked;
            const detour = !!el.cbDetour?.checked;
            const enableBalancer = !!el.cbXrayBalancer?.checked;
            const perProxyPort = !!el.cbMihomoPerProxyPort?.checked;
            const mihomoSubscriptionMode = isMihomoSubscriptionMode();

            const result = globalThis.web4core.buildFromRequest({
                core,
                input: raw,
                wgBeans: Array.isArray(state.wgBeans) ? state.wgBeans : [],
                options: {
                    addTun,
                    addSocks,
                    perTunMixed,
                    tunName,
                    genClashSecret,
                    useExtended,
                    androidMode,
                    detour,
                    enableBalancer,
                    webUI,
                    mihomoPerProxyTun,
                    perProxyPort,
                    mihomoSubscriptionMode,
                }
            });

            if (result.kind === 'yaml') {
                renderOutput(result.data, true);
            } else {
                renderOutput(JSON.stringify(result.data, null, 2), false);
            }
            setGenerateEnabled(true);
            el.links.classList.remove('input-error');
            return true;
        }

        return false;
    } catch (e) {
        setError((e && e.message ? e.message : String(e)));
        setGenerateEnabled(false);
        if (showOutput) hideOutput();
        el.links.classList.add('input-error');
        return false;
    }
}

function debounce(fn, wait) {
    let t = 0;
    return (...args) => {
        clearTimeout(t);
        t = setTimeout(() => fn(...args), wait);
    };
}

if (el.wgFile) {
    el.wgFile.addEventListener('change', async () => {
        const files = Array.from(el.wgFile.files || []);
        if (files.length === 0) {
            state.wgBeans = [];
            updateWgButtonState(0);
            validateField(false);
            return;
        }
        try {
            const beans = await Promise.all(files.map(async (file) => {
                const text = await file.text();
                const bean = globalThis.web4core?.parseWireGuardConf?.(text, file.name);
                if (!bean) throw new Error(`Failed to parse WireGuard file: ${file.name}`);
                return bean;
            }));
            state.wgBeans = beans;
            updateWgButtonState(beans.length);
            validateField(false);
        } catch (e) {
            state.wgBeans = [];
            updateWgButtonState(0);
            setError((e && e.message) ? e.message : 'Failed to load WireGuard file');
            validateField(false);
        }
    });
}

if (el.btnWgUpload && el.wgFile) {
    el.btnWgUpload.addEventListener('click', () => {
        el.wgFile.click();
    });
}

function assertNoProtocols(beans, list, label) {
    if (!Array.isArray(list) || list.length === 0) return;
    const unsupported = beans.filter(b => list.includes(b.proto));
    if (unsupported.length) {
        const names = Array.from(new Set(unsupported.map(b => b.proto))).join(', ');
        throw new Error(label + ' does not support: ' + names);
    }
}

function detectSubscriptionUrl(raw) {
    const lines = (raw || '').split(/\r?\n/).map(s => s.trim()).filter(Boolean);
    const subUrls = [];
    const others = [];
    for (const line of lines) {
        if (!line) continue;
        if (!/^https?:\/\//i.test(line) || /@/.test(line)) {
            others.push(line);
            continue;
        }
        try {
            const p = new URL(line).pathname || '';
            if (p && p !== '/') subUrls.push(line);
            else others.push(line);
        } catch {
            others.push(line);
        }
    }
    return { subUrls, others };
}

el.gen.addEventListener('click', () => {
    const raw = (el.links?.value || '').trim();
    const det = detectSubscriptionUrl(raw);
    const hasSub = Array.isArray(det.subUrls) && det.subUrls.length > 0;
    const skipBecauseMihomoProvider = isMihomoSubscriptionMode();
    if (hasSub && !skipBecauseMihomoProvider && globalThis.web4core?.fetchSubscription) {
        setGenerateEnabled(false);
        setInputLoading(true);
        setError('');
        const subPromises = det.subUrls.map(u => globalThis.web4core.fetchSubscription(u));
        Promise.all(subPromises).then(texts => {
            const merged = [];
            for (const text of texts) {
                if (!text) throw new Error(MSG_SUB_EMPTY);
                merged.push(...text.split(/\r?\n/).map(s => s.trim()).filter(Boolean));
            }
            const combined = [...det.others, ...merged].join('\n');
            if (!combined.trim()) throw new Error(MSG_SUB_EMPTY);
            el.links.value = combined;
            validateField(true);
            scrollOutIntoView();
        }).catch((e) => {
            const msg = (e && e.message) ? e.message : 'Network error';
            setError(MSG_SUB_FETCH(msg));
            hideOutput();
            el.links.classList.add('input-error');
        }).finally(() => {
            setGenerateEnabled(true);
            setInputLoading(false);
        });
        return;
    }
    const ok = validateField(true);
    if (ok) scrollOutIntoView();
});

el.btnCopy.addEventListener('click', () => {
    const text = el.out.value || '';
    if (!text) return;

    const copySuccess = () => {
        const useEl = el.btnCopy.querySelector('use');
        if (useEl) {
            useEl.setAttribute('href', '#check-mark-small');
            setTimeout(() => {
                useEl.setAttribute('href', '#copy');
            }, 2000);
        }
    };

    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(copySuccess).catch(err => {
            console.error('Clipboard write failed:', err);
            fallbackCopy(text);
        });
    } else {
        fallbackCopy(text);
    }

    function fallbackCopy(txt) {
        try {
            const textarea = document.createElement('textarea');
            textarea.value = txt;
            textarea.setAttribute('readonly', '');
            textarea.style.position = 'fixed';
            textarea.style.top = '0';
            textarea.style.left = '-9999px';
            textarea.style.opacity = '0';
            textarea.style.pointerEvents = 'none';
            document.body.appendChild(textarea);
            textarea.select();
            textarea.setSelectionRange(0, textarea.value.length);
            document.execCommand('copy');
            document.body.removeChild(textarea);
            copySuccess();
        } catch (e) {
            console.error('Fallback copy failed:', e);
        }
    }
});

el.btnDownload.addEventListener('click', () => {
    const isYaml = getCore() === 'mihomo';
    const text = el.out.value || '';
    const blob = new Blob([typeof TextEncoder !== 'undefined' ? new TextEncoder().encode(text) : text], { type: (isYaml ? 'text/yaml' : 'application/json') + ';charset=utf-8' });
    const a = Object.assign(document.createElement('a'), { href: URL.createObjectURL(blob), download: getCore() === 'singbox' ? 'singbox_config.json' : (getCore() === 'xray' ? 'xray_config.json' : 'mihomo_config.yaml') });
    a.click();
    URL.revokeObjectURL(a.href);
});

setupCheckboxValidation();

function getDefaultCore() {
    const items = Array.isArray(el.coreItems) ? el.coreItems : [];
    const first = items[0]?.dataset?.core || '';
    return first;
}

state.core = getDefaultCore();
setCore(state.core);
updateLinksPlaceholder();
validateField(false);

el.links.addEventListener('input', debounce(() => {
    validateField(false);
}, 150));
el.links.addEventListener('blur', () => {
    validateField(false);
});

if (header) header.addEventListener('click', function (e) {
    const t = e && e.target && e.target.closest ? e.target.closest('a,button,input,textarea,select,label') : null;
    if (t) return;
    setTimeout(() => location.reload(), 0);
});

(function () {
    const m = new Date().getMonth();
    if (m !== 11 && m !== 0 && m !== 1) return;
    if (window.matchMedia?.('(prefers-reduced-motion: reduce)').matches) return;
    if (document.getElementById('snowfall')) return;

    const r = (a, b) => Math.random() * (b - a) + a;
    const glyphs = ['❄', '✻', '✼', '❅', '❆'];

    const root = document.body.appendChild(Object.assign(document.createElement('div'), {id: 'snowfall', className: 'snowfall'}));
    root.setAttribute('aria-hidden', 'true');

    const frag = document.createDocumentFragment();
    for (let i = 0; i < 16; i++) {
        const flake = document.createElement('div');
        flake.className = 'snowfall__flake';
        flake.style.cssText =
            `left:${r(0, 100).toFixed(2)}vw;` +
            `animation-duration:${r(10, 20).toFixed(2)}s;` +
            `animation-delay:${r(-14, 0).toFixed(2)}s;` +
            `--snowfall-size:${r(10, 18).toFixed(1)}px;` +
            `--snowfall-opacity:${r(0.35, 0.9).toFixed(2)};` +
            `--snowfall-sway:${r(10, 28).toFixed(1)}px;`;

        const glyph = document.createElement('span');
        glyph.className = 'snowfall__glyph';
        glyph.textContent = glyphs[Math.floor(r(0, glyphs.length))];

        flake.appendChild(glyph);
        frag.appendChild(flake);
    }
    root.appendChild(frag);
})();
