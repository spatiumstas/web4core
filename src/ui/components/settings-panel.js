import { el } from '../dom.js';
import { state } from '../state.js';
import { toggleHidden } from '../utils/dom-utils.js';
import { createChoicePicker } from './choice-picker.js';

const DEFAULT_MIHOMO_TUN_STACK = 'gvisor';
const MIHOMO_TUN_STACKS = [
    { value: DEFAULT_MIHOMO_TUN_STACK, label: 'gVisor' },
    { value: 'system', label: 'System' },
    { value: 'mixed', label: 'Mixed' },
    { value: 'mips', label: 'MIPS' },
];
let mihomoTunStackPicker;

export function getMihomoTunStack() {
    return mihomoTunStackPicker?.getValue() || DEFAULT_MIHOMO_TUN_STACK;
}

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

function syncExcludeFilterVisibility(core = state.core) {
    const hidden = core !== 'mihomo' || !el.cbMihomoSub?.checked;
    toggleHidden(el.mihomoExcludeFilterField, hidden);
    toggleHidden(el.mihomoDeviceModelField, hidden);
}

function syncMihomoTunStackVisibility(core = state.core) {
    toggleHidden(el.mihomoTunStackField, core !== 'mihomo' || !el.cbMihomoTun?.checked);
}

export function setSettingsVisibilityForCore(core) {
    if (core !== 'mihomo') mihomoTunStackPicker?.setOpen(false);
    syncExcludeFilterVisibility(core);
    syncMihomoTunStackVisibility(core);
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
    setMihomoPerProxyTunVisible(false);
    setMihomoPerProxyPortVisible(false);

    toggleHidden(el.btnWgUpload, core !== 'mihomo' && core !== 'singbox');
    setSingboxPerProxyTunVisible(false);
}

export function initSettingsPanel({ validateField, updatePlaceholder, closeUrlTestMenu }) {
    mihomoTunStackPicker = createChoicePicker({
        button: el.mihomoTunStackButton,
        buttonLabel: el.mihomoTunStackText,
        menu: el.mihomoTunStackMenu,
        choices: MIHOMO_TUN_STACKS,
        initialValue: DEFAULT_MIHOMO_TUN_STACK,
        compact: true,
        itemTitle: choice => choice.title || '',
        buttonTitle: choice => choice.title || `${choice.buttonLabel || choice.label} TUN stack`,
        onChange: () => validateField(false),
    });
    el.cbMihomoSub?.addEventListener('change', () => syncExcludeFilterVisibility());
    el.mihomoExcludeFilter?.addEventListener('input', () => {
        el.outBlock?.classList.add('hidden');
        validateField(false);
    });
    el.mihomoDeviceModel?.addEventListener('input', () => {
        el.outBlock?.classList.add('hidden');
        validateField(false);
    });
    if (el.btnChevron && el.settingsPanel) {
        el.btnChevron.addEventListener('click', () => {
            closeUrlTestMenu?.();
            mihomoTunStackPicker?.setOpen(false);
            const collapsed = el.settingsPanel.classList.toggle('settings-panel--collapsed');
            el.btnChevron.setAttribute('aria-expanded', String(!collapsed));
            el.settingsPanel.inert = collapsed;
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
            if (!el.cbMihomoTun.checked) mihomoTunStackPicker?.setOpen(false);
            syncMihomoTunStackVisibility();
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
