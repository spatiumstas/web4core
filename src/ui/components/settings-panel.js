import { el } from '../dom.js';
import { state } from '../state.js';
import { toggleHidden } from '../utils/dom-utils.js';

export function setMihomoPerProxyTunVisible(visible) {
    const show = !!visible;
    if (!show && el.cbMihomoPerProxyTun?.checked) {
        el.cbMihomoPerProxyTun.checked = false;
    }
    toggleHidden(el.lblMihomoPerProxyTun, !show);
}

export function setMihomoPerProxyPortVisible(visible) {
    const show = !!visible;
    if (!show && el.cbMihomoPerProxyPort?.checked) {
        el.cbMihomoPerProxyPort.checked = false;
    }
    toggleHidden(el.lblMihomoPerProxyPort, !show);
}

export function setSingboxPerProxyTunVisible(visible) {
    const show = !!visible;
    if (!show && el.cbPerTunMixed?.checked) {
        el.cbPerTunMixed.checked = false;
    }
    toggleHidden(el.lblPerTunMixed, !show);
}

export function setSettingsVisibilityForCore(core) {
    const hideSing = core !== 'singbox';
    toggleHidden(el.cbTun?.parentElement, hideSing);
    toggleHidden(el.cbSocks?.parentElement, hideSing);
    toggleHidden(el.cbClashSecret?.parentElement, hideSing);
    toggleHidden(el.cbExtended?.parentElement, hideSing);
    toggleHidden(el.tunName?.parentElement || el.tunName, hideSing);
    toggleHidden(el.lblAndroidMode, hideSing);
    toggleHidden(el.lblDetour, hideSing);

    toggleHidden(el.lblXrayTun, core !== 'xray');
    toggleHidden(el.lblXraySocks, core !== 'xray');
    toggleHidden(el.lblXrayBalancer, core !== 'xray');

    toggleHidden(el.lblMihomoSub, core !== 'mihomo');
    toggleHidden(el.lblMihomoSocks, core !== 'mihomo');
    toggleHidden(el.lblMihomoTun, core !== 'mihomo');
    toggleHidden(el.lblMihomoWebUI, core !== 'mihomo');
    setMihomoPerProxyTunVisible(false);
    setMihomoPerProxyPortVisible(false);

    toggleHidden(el.btnWgUpload, core !== 'mihomo' && core !== 'singbox');
    setSingboxPerProxyTunVisible(false);
}

export function initSettingsPanel({ validateField, updatePlaceholder, closeUrlTestMenu }) {
    if (el.btnChevron && el.settingsPanel) {
        el.btnChevron.addEventListener('click', () => {
            if (state.urlTestMenuOpen) closeUrlTestMenu?.();
            const collapsed = el.settingsPanel.classList.toggle('settings-panel--collapsed');
            el.btnChevron.setAttribute('aria-expanded', String(!collapsed));
        });
    }

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
    enforceAtLeastOne(el.cbMihomoTun, el.cbMihomoSocks);

    if (el.cbTun && el.cbPerTunMixed) {
        el.cbPerTunMixed.addEventListener('change', () => {
            if (el.cbPerTunMixed.checked) el.cbTun.checked = true;
            validateField(false);
        });
        el.cbTun.addEventListener('change', () => {
            if (!el.cbTun.checked) el.cbPerTunMixed.checked = false;
            validateField(false);
        });
    }

    el.cbSocks?.addEventListener('change', () => validateField(false));

    if (el.cbMihomoTun && el.cbMihomoPerProxyTun) {
        el.cbMihomoPerProxyTun.addEventListener('change', () => {
            if (el.cbMihomoPerProxyTun.checked) el.cbMihomoTun.checked = true;
        });
        el.cbMihomoTun.addEventListener('change', () => {
            if (!el.cbMihomoTun.checked) el.cbMihomoPerProxyTun.checked = false;
            validateField(false);
        });
    }

    if (el.cbMihomoSocks && el.cbMihomoPerProxyPort) {
        el.cbMihomoPerProxyPort.addEventListener('change', () => {
            if (el.cbMihomoPerProxyPort.checked) el.cbMihomoSocks.checked = true;
            validateField(false);
        });
        el.cbMihomoSocks.addEventListener('change', () => {
            if (!el.cbMihomoSocks.checked) el.cbMihomoPerProxyPort.checked = false;
            validateField(false);
        });
    }

    [
        el.cbExtended,
        el.cbDetour,
        el.cbMihomoSub,
        el.cbMihomoSocks,
        el.cbMihomoTun,
        el.cbMihomoPerProxyTun,
        el.cbMihomoPerProxyPort,
        el.cbMihomoWebUI,
        el.cbPerTunMixed,
        el.cbAndroidMode,
        el.cbXrayBalancer,
        el.cbXrayTun,
        el.cbXraySocks,
    ].forEach(cb => {
        cb?.addEventListener('change', () => {
            validateField(false);
            updatePlaceholder();
        });
    });
}
