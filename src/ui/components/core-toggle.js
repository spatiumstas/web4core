import { el } from '../dom.js';
import { state } from '../state.js';
import { setSettingsVisibilityForCore } from './settings-panel.js';
import { resetWireGuardUploads, updateWgButtonState } from './wireguard-upload.js';

export function getCore() {
    return state.core;
}

export function getDefaultCore() {
    const items = Array.isArray(el.coreItems) ? el.coreItems : [];
    return items[0]?.dataset?.core || 'singbox';
}

export function isMihomoSubscriptionMode() {
    return getCore() === 'mihomo' && !!el.cbMihomoSub?.checked;
}

export function setCore(core) {
    state.core = core;
    el.coreToggle?.setAttribute('data-core', core);

    const items = Array.isArray(el.coreItems) ? el.coreItems : [];
    const idx = Math.max(0, items.findIndex((n) => n?.dataset?.core === core));
    el.coreToggle?.style.setProperty('--core-count', String(items.length || 3));
    el.coreToggle?.style.setProperty('--core-index', String(idx));

    items.forEach((n) => {
        const selected = n?.dataset?.core === core;
        n.setAttribute('aria-checked', String(selected));
        n.tabIndex = selected ? 0 : -1;
    });

    setSettingsVisibilityForCore(core);

    if (core !== 'mihomo' && core !== 'singbox') {
        resetWireGuardUploads();
    }
    updateWgButtonState(Array.isArray(state.wgBeans) ? state.wgBeans.length : 0);
}

export function initCoreToggle({ validateField, updatePlaceholder }) {
    el.coreToggle?.addEventListener('click', (e) => {
        const target = e.target?.closest?.('[data-core]');
        const core = target?.dataset?.core || '';
        if (!core) return;
        e.stopPropagation();
        setCore(core);
        updatePlaceholder();
        validateField(false);
    });
}
