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
    lblMihomoSub: document.getElementById('lblMihomoSub'),
    cbXrayBalancer: document.getElementById('cbXrayBalancer'),
    lblXrayBalancer: document.getElementById('lblXrayBalancer'),
    cbPerTunMixed: document.getElementById('cbPerTunMixed'),
    lblPerTunMixed: document.getElementById('lblPerTunMixed'),
    out: document.getElementById('out')
};

const state = {
    core: 'singbox'
};

const MSG_SUB_URL = 'Provide a single HTTP(S) URL for Mihomo subscription';
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
    if (el.gen) el.gen.disabled = !enabled;
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
    toggleHidden(el.tunName, hideSing);
    toggleHidden(el.lblMihomoSub, core !== 'mihomo');
    toggleHidden(el.lblPerTunMixed, hideSing);
    toggleHidden(el.lblXrayBalancer, true);
}

function isMihomoSubscriptionMode() {
    return getCore() === 'mihomo' && !!document.getElementById('cbMihomoSub')?.checked;
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

let dragging = false, startX = 0, moved = false, suppressClick = false;
el.coreToggle.addEventListener('mousedown', (e) => {
    dragging = true;
    moved = false;
    startX = e.clientX;
});
window.addEventListener('mouseup', () => {
    if (dragging && moved) {
        suppressClick = true;
        setTimeout(() => suppressClick = false, 0);
    }
    dragging = false;
});
window.addEventListener('mousemove', (e) => {
    if (!dragging) return;
    const dx = e.clientX - startX;
    if (dx > 10) {
        setCore('xray');
        moved = true;
    }
    if (dx < -10) {
        setCore('singbox');
        moved = true;
    }
});

function setupCheckboxValidation() {
    if (!el.cbTun || !el.cbSocks) return;
    el.cbTun.addEventListener('change', () => {
        if (!el.cbTun.checked && !el.cbSocks.checked) el.cbSocks.checked = true;
    });
    el.cbSocks.addEventListener('change', () => {
        if (!el.cbTun.checked && !el.cbSocks.checked) el.cbTun.checked = true;
    });
    el.cbExtended?.addEventListener('change', () => {
        validateField(false);
    });
    el.cbMihomoSub?.addEventListener('change', () => {
        validateField(false);
    });
    el.cbPerTunMixed?.addEventListener('change', () => {
        validateField(false);
    });
    el.cbXrayBalancer?.addEventListener('change', () => {
        validateField(false);
    });
}

function validateField(showOutput) {
    const raw = el.links.value;
    const tunName = el.tunName.value.trim();
    const addTun = !!el.cbTun?.checked;
    const addSocks = !!el.cbSocks?.checked;
    const genClashSecret = !!el.cbClashSecret?.checked;
    const useExtended = !!el.cbExtended?.checked;
    const subMihomo = isMihomoSubscriptionMode();
    try {
        if (!raw.trim()) {
            setGenerateEnabled(false);
            setError('');
            hideOutput();
            el.links.classList.remove('input-error');
            return false;
        }
        if (subMihomo) {
            const lines = raw.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
            const validSingleHttp = lines.length === 1 && /^https?:\/\//i.test(lines[0]) && !/@/.test(lines[0]);
            if (!showOutput) {
                setError(validSingleHttp ? '' : MSG_SUB_URL);
                setGenerateEnabled(validSingleHttp);
                el.links.classList.toggle('input-error', !validSingleHttp);
                if (!validSingleHttp) hideOutput();
                return validSingleHttp ? {subUrl: lines[0]} : false;
            }
            if (!validSingleHttp) throw new Error(MSG_SUB_URL);
            const providers = {my_subscription: {type: 'http', url: lines[0], interval: 3600}};
            const groups = [{name: 'PROXY', type: 'select', use: ['my_subscription']}];
            const yaml = (globalThis.web4core?.buildMihomoYaml || (() => ''))([], groups, providers, ['MATCH,PROXY']);
            renderOutput(yaml, true);
            setGenerateEnabled(true);
            el.links.classList.remove('input-error');
            return true;
        }

        const beans = globalThis.web4core.buildBeansFromInput(raw);
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
            const showBalancer = (getCore() === 'xray' && Array.isArray(beans) && beans.length >= 2);
            toggleHidden(el.lblXrayBalancer, !showBalancer);
            return {beans, tunName, addTun, addSocks, perTunMixed, genClashSecret, useExtended};
        }

        if (getCore() === 'singbox') {
            const perTunMixed = !!el.cbPerTunMixed?.checked;
            const opts = {addTun, addSocks, perTunMixed, tunName, genClashSecret, useExtended};
            const used = new Set();
            const dnsBeans = useExtended ? beans.filter(b => b.proto === 'sdns') : [];
            const outboundBeans = beans.filter(b => b.proto !== 'sdns');
            const outbounds = outboundBeans.map(b => {
                b._useExtended = !!useExtended;
                const ob = globalThis.web4core.buildSingBoxOutbound(b);
                const tag = globalThis.web4core.computeTag(b, used);
                return Object.assign({tag}, ob);
            });
            opts.dnsBeans = dnsBeans;
            const finalConfig = globalThis.web4core.buildSingBoxConfig(outbounds, opts);
            renderOutput(JSON.stringify(finalConfig, null, 2), false);
            setGenerateEnabled(true);
            el.links.classList.remove('input-error');
            return true;
        }

        if (getCore() === 'xray') {
            const showBalancer = (Array.isArray(beans) && beans.length >= 2);
            toggleHidden(el.lblXrayBalancer, !showBalancer);
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
            const yamlObj = globalThis.web4core.buildMihomoConfig(outBeans);
            const yaml = globalThis.web4core.buildMihomoYaml(yamlObj.proxies, yamlObj['proxy-groups']);
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
    if (lines.length !== 1) return {isSub: false, url: ''};
    const u = lines[0];
    if (!/^https?:\/\//i.test(u) || /@/.test(u)) return {isSub: false, url: ''};
    try {
        const p = new URL(u).pathname || '';
        return {isSub: (p && p !== '/'), url: u};
    } catch {
        return {isSub: false, url: ''};
    }
}

el.gen.addEventListener('click', () => {
    const raw = (el.links?.value || '').trim();
    const det = detectSubscriptionUrl(raw);
    const shouldTreatAsSub = det.isSub;
    const skipBecauseMihomoProvider = isMihomoSubscriptionMode();
    if (shouldTreatAsSub && !skipBecauseMihomoProvider && globalThis.web4core?.fetchSubscription) {
        setGenerateEnabled(false);
        setError('');
        globalThis.web4core.fetchSubscription(det.url).then(text => {
            if (!text) throw new Error(MSG_SUB_EMPTY);
            el.links.value = text;
            validateField(true);
            scrollOutIntoView();
        }).catch((e) => {
            const msg = (e && e.message) ? e.message : 'Network error';
            setError(MSG_SUB_FETCH(msg));
            hideOutput();
            el.links.classList.add('input-error');
        }).finally(() => {
            setGenerateEnabled(true);
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
setGenerateEnabled(true);
setCore(state.core);

function looksLikeJsonConfig(text) {
    const t = (text || '').trim();
    if (!t || (t[0] !== '{' && t[0] !== '[')) return false;
    try {
        const obj = JSON.parse(t);
        return obj && typeof obj === 'object' && Array.isArray(obj.outbounds) && obj.outbounds.length > 0;
    } catch {
        return false;
    }
}

function isReverseOnlyJson(text) {
    const t = (text || '').trim();
    if (!t || (t[0] !== '{' && t[0] !== '[')) return false;
    try {
        const obj = JSON.parse(t);
        return !!(obj && typeof obj === 'object' && Array.isArray(obj.outbounds) && obj.outbounds.length > 0 && !obj.profiles);
    } catch {
        return false;
    }
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
        setGenerateEnabled(!(reverseOnly || !raw));
        if (reverseOnly) {
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
if (el.btnReverse) {
    toggleReverseVisibility();
    el.btnReverse.addEventListener('click', () => {
        const raw = (el.links?.value || '').trim();
        try {
            const rev = globalThis.web4core?.reverseConvert;
            if (!rev) throw new Error(MSG_REVERSE_UNAVAILABLE);
            const text = rev(raw);
            if (!text) throw new Error(MSG_REVERSE_EMPTY);
            renderOutput(text, false);
            el.links.classList.remove('input-error');
            scrollOutIntoView();
        } catch (e) {
            setError((e && e.message) ? e.message : MSG_REVERSE_FAILED);
            hideOutput();
            el.links.classList.add('input-error');
        }
    });
}

const header = document.getElementById('asciiHeader');
if (header) header.addEventListener('click', function () {
    location.reload();
});

if (!state.core) setCore('singbox');


