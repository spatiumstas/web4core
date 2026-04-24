import { el } from '../dom.js';
import { state } from '../state.js';
import { MSG_EXTENDED_ENABLE, MSG_NO_LINKS, MSG_SUB_URL } from '../constants.js';
import {
    buildBeansFromInput,
    buildFromRequest,
    buildMihomoSubscriptionConfig,
    buildMihomoYaml,
    getAllowedCoreProtocols,
    validateBean,
} from '../services/web4core-api.js';
import {
    countMihomoPerProxyTargets,
    countSingboxRouteTargets,
    splitMihomoSubscriptionInput,
} from '../services/subscription-input.js';
import { getCore, isMihomoSubscriptionMode } from '../components/core-toggle.js';
import { getUrlTest } from '../components/url-test-picker.js';
import {
    hideOutput,
    markInputError,
    renderOutput,
    setError,
    setGenerateEnabled,
} from '../components/output-panel.js';
import {
    setMihomoPerProxyPortVisible,
    setMihomoPerProxyTunVisible,
    setSingboxPerProxyTunVisible,
} from '../components/settings-panel.js';

function parseAndValidateProxyText(proxyText) {
    const text = String(proxyText || '').trim();
    if (!text) return [];
    const proxyBeans = buildBeansFromInput(text);
    proxyBeans.forEach(validateBean);
    return proxyBeans;
}

function getFormOptions(core) {
    const addTun = core === 'xray'
        ? !!el.cbXrayTun?.checked
        : (core === 'mihomo' ? !!el.cbMihomoTun?.checked : !!el.cbTun?.checked);
    const addSocks = core === 'xray'
        ? !!el.cbXraySocks?.checked
        : (core === 'mihomo' ? !!el.cbMihomoSocks?.checked : !!el.cbSocks?.checked);

    const mihomoTunEnabled = core === 'mihomo' ? !!el.cbMihomoTun?.checked : false;
    const mihomoPerProxyTun = core === 'mihomo' ? !!el.cbMihomoPerProxyTun?.checked : false;
    const mihomoSocksEnabled = core === 'mihomo' ? !!el.cbMihomoSocks?.checked : false;

    return {
        tunName: el.tunName?.value.trim() || '',
        addTun,
        addSocks,
        genClashSecret: !!el.cbClashSecret?.checked,
        useExtended: !!el.cbExtended?.checked,
        webUI: core === 'mihomo' ? !!el.cbMihomoWebUI?.checked : false,
        mihomoTunEnabled,
        mihomoPerProxyTun,
        mihomoSocksEnabled,
        mihomoTunOpts: mihomoTunEnabled ? { mode: (mihomoPerProxyTun ? 'listeners' : 'tun') } : null,
        urlTest: getUrlTest(),
    };
}

function syncVisibilityForBeans(core, beans, options) {
    if (core === 'mihomo') {
        const outBeans = beans.filter(b => b.proto !== 'sdns');
        const targetCount = countMihomoPerProxyTargets([], outBeans);
        setMihomoPerProxyTunVisible(!!options.mihomoTunEnabled && targetCount > 1);
        setMihomoPerProxyPortVisible(!!options.mihomoSocksEnabled && targetCount > 1);
        setSingboxPerProxyTunVisible(false);
    } else {
        setMihomoPerProxyTunVisible(false);
        setMihomoPerProxyPortVisible(false);
        setSingboxPerProxyTunVisible(core === 'singbox' && !!options.addTun && countSingboxRouteTargets(beans) > 1);
    }
}

function assertProtocolSupport(core, beans, useExtended) {
    const allowedArr = getAllowedCoreProtocols(core, { useExtended });
    const allowed = new Set(allowedArr);
    const unsupported = Array.from(new Set(beans.map(b => b?.proto).filter(p => p && !allowed.has(p))));
    if (unsupported.length) {
        const label = (core === 'xray') ? 'Xray' : (core === 'mihomo' ? 'Mihomo' : core);
        throw new Error(label + ' does not support: ' + unsupported.join(', '));
    }
}

function validateMihomoSubscriptionMode(raw, showOutput, options) {
    const wgBeans = Array.isArray(state.wgBeans) ? state.wgBeans : [];
    const { subUrls, proxyText } = splitMihomoSubscriptionInput(raw);
    const validHttpUrls = subUrls.length > 0;

    if (!showOutput) {
        setError(validHttpUrls ? '' : MSG_SUB_URL);
        if (validHttpUrls && proxyText) {
            try {
                const proxyBeans = parseAndValidateProxyText(proxyText);
                const targetCount = countMihomoPerProxyTargets(subUrls, [...wgBeans, ...proxyBeans]);
                setMihomoPerProxyTunVisible(options.mihomoTunEnabled && targetCount > 1);
                setMihomoPerProxyPortVisible(options.mihomoSocksEnabled && targetCount > 1);
                setGenerateEnabled(true);
                markInputError(false);
                return { subUrls, proxyBeans };
            } catch (e) {
                setError(e && e.message ? e.message : String(e));
                setGenerateEnabled(false);
                markInputError(true);
                hideOutput();
                return false;
            }
        }
        const targetCount = countMihomoPerProxyTargets(subUrls, wgBeans);
        setMihomoPerProxyTunVisible(options.mihomoTunEnabled && targetCount > 1);
        setMihomoPerProxyPortVisible(options.mihomoSocksEnabled && targetCount > 1);
        setGenerateEnabled(validHttpUrls);
        markInputError(!validHttpUrls);
        if (!validHttpUrls) hideOutput();
        return validHttpUrls ? { subUrls } : false;
    }

    if (!validHttpUrls) throw new Error(MSG_SUB_URL);

    const extraBeans = wgBeans.slice();
    extraBeans.push(...parseAndValidateProxyText(proxyText));
    const perProxyPort = !!el.cbMihomoPerProxyPort?.checked;

    const config = buildMihomoSubscriptionConfig(subUrls, extraBeans, {
        addSocks: options.mihomoSocksEnabled,
        perProxyPort,
        perProxyListeners: perProxyPort || options.mihomoPerProxyTun,
        urlTest: options.urlTest,
    });
    if (!config) throw new Error('Failed to build subscription config');

    const yaml = buildMihomoYaml(
        config.proxies,
        config.groups,
        config.providers,
        config.rules,
        config.listeners,
        { webUI: options.webUI, tun: options.mihomoTunOpts, addSocks: options.mihomoSocksEnabled },
    );

    renderOutput(yaml);
    setGenerateEnabled(true);
    markInputError(false);
    return true;
}

export function validateField(showOutput) {
    const raw = el.links?.value || '';
    const hasText = !!raw.trim();
    const core = getCore();
    const options = getFormOptions(core);

    try {
        const wgBeans = Array.isArray(state.wgBeans) ? state.wgBeans : [];
        if (!hasText && wgBeans.length === 0) {
            setMihomoPerProxyTunVisible(false);
            setMihomoPerProxyPortVisible(false);
            setSingboxPerProxyTunVisible(false);
            setGenerateEnabled(false);
            setError('');
            hideOutput();
            markInputError(false);
            return false;
        }

        if (isMihomoSubscriptionMode()) {
            return validateMihomoSubscriptionMode(raw, showOutput, options);
        }

        const beans = hasText ? buildBeansFromInput(raw) : [];
        if (wgBeans.length) beans.push(...wgBeans);
        if (!beans.length) throw new Error(MSG_NO_LINKS);
        beans.forEach(validateBean);

        assertProtocolSupport(core, beans, options.useExtended);
        syncVisibilityForBeans(core, beans, options);

        if (!options.useExtended && core === 'singbox') {
            const hasExtendedOnly = beans.some(b => b.proto === 'mieru' || b.proto === 'sdns');
            if (hasExtendedOnly) throw new Error(MSG_EXTENDED_ENABLE);
        }

        if (!showOutput) {
            setError('');
            setGenerateEnabled(true);
            markInputError(false);
            return {
                beans,
                tunName: options.tunName,
                addTun: options.addTun,
                addSocks: options.addSocks,
                perTunMixed: !!el.cbPerTunMixed?.checked,
                genClashSecret: options.genClashSecret,
                useExtended: options.useExtended,
                androidMode: !!el.cbAndroidMode?.checked,
            };
        }

        const result = buildFromRequest({
            core,
            input: raw,
            wgBeans: Array.isArray(state.wgBeans) ? state.wgBeans : [],
            options: {
                addTun: options.addTun,
                addSocks: options.addSocks,
                perTunMixed: !!el.cbPerTunMixed?.checked,
                tunName: options.tunName,
                genClashSecret: options.genClashSecret,
                useExtended: options.useExtended,
                androidMode: !!el.cbAndroidMode?.checked,
                detour: !!el.cbDetour?.checked,
                enableBalancer: !!el.cbXrayBalancer?.checked,
                webUI: options.webUI,
                mihomoPerProxyTun: options.mihomoPerProxyTun,
                perProxyPort: !!el.cbMihomoPerProxyPort?.checked,
                mihomoSubscriptionMode: isMihomoSubscriptionMode(),
                urlTest: options.urlTest,
            },
        });

        if (result.kind === 'yaml') {
            renderOutput(result.data);
        } else {
            renderOutput(JSON.stringify(result.data, null, 2));
        }
        setGenerateEnabled(true);
        markInputError(false);
        return true;
    } catch (e) {
        setError((e && e.message ? e.message : String(e)));
        setGenerateEnabled(false);
        if (showOutput) hideOutput();
        markInputError(true);
        return false;
    }
}
