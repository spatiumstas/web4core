const el = {
    coreToggle: document.getElementById('coreToggle'),
    lblSing: document.getElementById('lblSing'),
    lblXray: document.getElementById('lblXray'),
    lblMihomo: document.getElementById('lblMihomo'),
    outBlock: document.getElementById('outBlock'),
    errorBlock: document.getElementById('errorBlock'),
    errorText: document.getElementById('errorText'),
    links: document.getElementById('links'),
    tunName: document.getElementById('tunName'),
    gen: document.getElementById('gen'),
    btnReverse: document.getElementById('btnReverse'),
    btnCopy: document.getElementById('btnCopy'),
    btnDownload: document.getElementById('btnDownload'),
    cbTun: document.getElementById('cbTun'),
    cbSocks: document.getElementById('cbSocks'),
    cbExtended: document.getElementById('cbExtended'),
    cbClashSecret: document.getElementById('cbClashSecret'),
    cbMihomoSub: document.getElementById('cbMihomoSub'),
    cbMihomoPerProxyPort: document.getElementById('cbMihomoPerProxyPort'),
    cbDetour: document.getElementById('cbDetour'),
    lblMihomoSub: document.getElementById('lblMihomoSub'),
    lblMihomoPerProxyPort: document.getElementById('lblMihomoPerProxyPort'),
    cbXrayBalancer: document.getElementById('cbXrayBalancer'),
    lblXrayBalancer: document.getElementById('lblXrayBalancer'),
    cbPerTunMixed: document.getElementById('cbPerTunMixed'),
    lblPerTunMixed: document.getElementById('lblPerTunMixed'),
    cbAndroidMode: document.getElementById('cbAndroidMode'),
    lblAndroidMode: document.getElementById('lblAndroidMode'),
    lblDetour: document.getElementById('lblDetour'),
    out: document.getElementById('out'),
    btnSettings: document.getElementById('btnSettings'),
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
const MSG_REVERSE_UNAVAILABLE = 'Reverse converter is not available';
const MSG_REVERSE_EMPTY = 'No links generated from config';
const MSG_REVERSE_FAILED = 'Reverse failed';

const toggleHidden = (node, hidden) => {
    if (node) node.classList.toggle('is-hidden', hidden);
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
    if (block && block.scrollIntoView) block.scrollIntoView({behavior: 'smooth', block: 'center', inline: 'nearest'});
    if (el.out && el.out.focus) {
        try {
            el.out.focus({preventScroll: true});
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
    el.coreToggle.setAttribute('aria-checked', core === 'singbox');
    const hideSing = core !== 'singbox';
    const cbTunLabel = el.cbTun?.parentElement;
    const cbSocksLabel = el.cbSocks?.parentElement;
    const cbClashSecretLabel = el.cbClashSecret?.parentElement;
    const cbExtendedLabel = el.cbExtended?.parentElement;
    toggleHidden(cbTunLabel, hideSing);
    toggleHidden(cbSocksLabel, hideSing);
    toggleHidden(cbClashSecretLabel, hideSing);
    toggleHidden(cbExtendedLabel, hideSing);
    toggleHidden(el.tunName?.parentElement || el.tunName, hideSing);
    toggleHidden(el.lblMihomoSub, core !== 'mihomo');
    toggleHidden(el.lblMihomoPerProxyPort, core !== 'mihomo');
    toggleHidden(el.btnWgUpload, core !== 'mihomo');
    toggleHidden(el.lblPerTunMixed, hideSing);
    toggleHidden(el.lblAndroidMode, hideSing);
    toggleHidden(el.lblDetour, hideSing);
    toggleHidden(el.lblXrayBalancer, core !== 'xray');

    if (core !== 'mihomo') {
        state.wgBeans = [];
        if (el.wgFile) el.wgFile.value = '';
        updateWgButtonState(0);
    }
    updateWgButtonState(Array.isArray(state.wgBeans) ? state.wgBeans.length : 0);

    try {
        localStorage.setItem('core', core);
    } catch (e) {
    }
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

el.lblSing.addEventListener('click', (e) => {
    e.stopPropagation();
    setCore('singbox');
    validateField(false);
});
el.lblXray.addEventListener('click', (e) => {
    e.stopPropagation();
    setCore('xray');
    validateField(false);
});
el.lblMihomo.addEventListener('click', (e) => {
    e.stopPropagation();
    setCore('mihomo');
    validateField(false);
});

if (el.btnSettings && el.settingsPanel) {
    const STORAGE_KEY = 'settings_expanded';

    try {
        const saved = localStorage.getItem(STORAGE_KEY);
        if (saved === 'true') {
            el.settingsPanel.classList.remove('settings-panel--collapsed');
            el.btnSettings.setAttribute('aria-expanded', 'true');
        } else {
            el.settingsPanel.classList.add('settings-panel--collapsed');
            el.btnSettings.setAttribute('aria-expanded', 'false');
        }
    } catch (e) {
    }

    el.btnSettings.addEventListener('click', () => {
        const collapsed = el.settingsPanel.classList.toggle('settings-panel--collapsed');
        el.btnSettings.setAttribute('aria-expanded', String(!collapsed));
        try {
            localStorage.setItem(STORAGE_KEY, String(!collapsed));
        } catch (e) {
        }
    });
}

function setupCheckboxValidation() {
    if (!el.cbTun || !el.cbSocks) return;
    el.cbTun.addEventListener('change', () => {
        if (!el.cbTun.checked && !el.cbSocks.checked) el.cbSocks.checked = true;
    });
    el.cbSocks.addEventListener('change', () => {
        if (!el.cbTun.checked && !el.cbSocks.checked) el.cbTun.checked = true;
    });

    const revalidateOnChange = [
        el.cbExtended,
        el.cbDetour,
        el.cbMihomoSub,
        el.cbMihomoPerProxyPort,
        el.cbPerTunMixed,
        el.cbAndroidMode,
        el.cbXrayBalancer,
    ];

    revalidateOnChange.forEach(cb => {
        cb?.addEventListener('change', () => {
            validateField(false);
        });
    });
}

function validateField(showOutput) {
    const raw = el.links.value;
    const hasText = !!raw.trim();
    const tunName = el.tunName.value.trim();
    const addTun = !!el.cbTun?.checked;
    const addSocks = !!el.cbSocks?.checked;
    const genClashSecret = !!el.cbClashSecret?.checked;
    const useExtended = !!el.cbExtended?.checked;
    const subMihomo = isMihomoSubscriptionMode();
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
            const lines = raw.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
            const validHttpUrls = lines.length > 0 && lines.every(line => /^https?:\/\//i.test(line) && !/@/.test(line));
            if (!showOutput) {
                setError(validHttpUrls ? '' : MSG_SUB_URL);
                setGenerateEnabled(validHttpUrls);
                el.links.classList.toggle('input-error', !validHttpUrls);
                if (!validHttpUrls) hideOutput();
                return validHttpUrls ? {subUrls: lines} : false;
            }
            if (!validHttpUrls) throw new Error(MSG_SUB_URL);

            const extraBeans = wgBeans.slice();
            const config = globalThis.web4core?.buildMihomoSubscriptionConfig(lines, extraBeans);
            if (!config) throw new Error('Failed to build subscription config');

            const yaml = (globalThis.web4core?.buildMihomoYaml || (() => ''))(config.proxies || [], config.groups, config.providers, config.rules, null);
            renderOutput(yaml, true);
            setGenerateEnabled(true);
            el.links.classList.remove('input-error');
            return true;
        }

        const beans = hasText ? globalThis.web4core.buildBeansFromInput(raw) : [];
        if (wgBeans.length) beans.push(...wgBeans);
        if (!beans.length) throw new Error(MSG_NO_LINKS);
        beans.forEach(globalThis.web4core.validateBean);

        assertNoProtocols(beans, getCore() === 'xray' ? ['hy2', 'tuic', 'mieru', 'sdns'] : [], 'Xray');
        if (getCore() === 'mihomo') assertNoProtocols(beans, ['mieru', 'sdns'], 'Mihomo');

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
            return {beans, tunName, addTun, addSocks, perTunMixed, genClashSecret, useExtended, androidMode};
        }

        if (getCore() === 'singbox') {
            const perTunMixed = !!el.cbPerTunMixed?.checked;
            const useDetour = !!el.cbDetour?.checked;
            const androidMode = !!el.cbAndroidMode?.checked;
            const opts = {addTun, addSocks, perTunMixed, tunName, genClashSecret, useExtended, androidMode};
            const used = new Set();
            const dnsBeans = useExtended ? beans.filter(b => b.proto === 'sdns') : [];
            const outboundBeans = beans.filter(b => b.proto !== 'sdns');
            const outbounds = outboundBeans.map(b => {
                const ob = globalThis.web4core.buildSingBoxOutbound(b, {useExtended: !!useExtended});
                const tag = globalThis.web4core.computeTag(b, used);
                return Object.assign({tag}, ob);
            });
            if (useDetour && outbounds.length > 1) {
                const mainTag = outbounds[0].tag;
                for (let i = 1; i < outbounds.length; i++) {
                    outbounds[i].detour = mainTag;
                }
            }
            opts.dnsBeans = dnsBeans;
            const finalConfig = globalThis.web4core.buildSingBoxConfig(outbounds, opts);
            renderOutput(JSON.stringify(finalConfig, null, 2), false);
            setGenerateEnabled(true);
            el.links.classList.remove('input-error');
            return true;
        }

        if (getCore() === 'xray') {
            let finalConfig;
            if (beans.length === 1) finalConfig = globalThis.web4core.buildXrayConfig(globalThis.web4core.buildXrayOutbound(beans[0]), {});
            else {
                const used = new Set();
                const outbounds = beans.map(b => {
                    const ob = globalThis.web4core.buildXrayOutbound(b);
                    ob.tag = globalThis.web4core.computeTag(b, used);
                    return ob;
                });
                const enableBalancer = !!el.cbXrayBalancer?.checked;
                finalConfig = globalThis.web4core.buildXrayConfig(outbounds, {enableBalancer});
            }
            renderOutput(JSON.stringify(finalConfig, null, 2), false);
            setGenerateEnabled(true);
            el.links.classList.remove('input-error');
            return true;
        }

        if (getCore() === 'mihomo') {
            const outBeans = beans.filter(b => !['mieru', 'sdns'].includes(b.proto));
            const perProxyPort = !!el.cbMihomoPerProxyPort?.checked;
            const yamlObj = globalThis.web4core.buildMihomoConfig(outBeans, {perProxyPort, basePort: 7890});
            const yaml = globalThis.web4core.buildMihomoYaml(yamlObj.proxies, yamlObj['proxy-groups'], null, null, yamlObj.listeners);
            renderOutput(yaml, true);
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
    return {subUrls, others};
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

el.btnCopy.addEventListener('click', async () => {
    try {
        await navigator.clipboard.writeText(el.out.value || '');
        const useEl = el.btnCopy.querySelector('use');
        useEl.setAttribute('href', '#check-mark-small');
        setTimeout(() => {
            useEl.setAttribute('href', '#copy');
        }, 3000);
    } catch {
    }
});

el.btnDownload.addEventListener('click', () => {
    const isYaml = getCore() === 'mihomo';
    const blob = new Blob([el.out.value || ''], {type: isYaml ? 'text/yaml' : 'application/json'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = (getCore() === 'singbox' ? 'singbox_config.json' : (getCore() === 'xray' ? 'xray_config.json' : 'mihomo_config.yaml'));
    a.click();
    URL.revokeObjectURL(url);
});

setupCheckboxValidation();
try {
    const savedCore = localStorage.getItem('core');
    if (savedCore === 'singbox' || savedCore === 'xray' || savedCore === 'mihomo') {
        state.core = savedCore;
    }
} catch (e) {
}
setCore(state.core);
validateField(false);

function parseOutboundsJson(text) {
    const t = (text || '').trim();
    if (!t || (t[0] !== '{' && t[0] !== '[')) return null;
    try {
        const obj = JSON.parse(t);
        if (!obj || typeof obj !== 'object' || !Array.isArray(obj.outbounds) || obj.outbounds.length === 0) {
            return null;
        }
        return obj;
    } catch {
        return null;
    }
}

function looksLikeJsonConfig(text) {
    return !!parseOutboundsJson(text);
}

function isReverseOnlyJson(text) {
    const obj = parseOutboundsJson(text);
    return !!(obj && !obj.profiles);
}

function toggleReverseVisibility() {
    if (!el.btnReverse) return;
    const raw = (el.links?.value || '').trim();
    const show = looksLikeJsonConfig(raw);
    el.btnReverse.classList.toggle('is-hidden', !show);
}

const triggerLiveValidation = () => {
    if (el.links && isReverseOnlyJson(el.links.value)) return;
    validateField(false);
};

if (el.links) {
    const handleJsonMode = () => {
        const raw = (el.links.value || '').trim();
        const reverseOnly = isReverseOnlyJson(raw);
        if (reverseOnly) {
            setGenerateEnabled(false);
            setError('');
            hideOutput();
            el.links.classList.remove('input-error');
        }
    };
    const updateJsonUiState = () => {
        toggleReverseVisibility();
        handleJsonMode();
    };
    el.links.addEventListener('input', debounce(() => {
        triggerLiveValidation();
        updateJsonUiState();
    }, 150));
    el.links.addEventListener('blur', () => {
        triggerLiveValidation();
        updateJsonUiState();
    });
    updateJsonUiState();
}

if (header) header.addEventListener('click', function () {
    localStorage.clear();
    setTimeout(() => location.reload(), 0);
});
