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
    el.coreToggle?.addEventListener('keydown', (event) => {
        const items = el.coreItems;
        const index = items.indexOf(document.activeElement);
        if (index < 0) return;
        let next;
        if (event.key === 'ArrowRight' || event.key === 'ArrowDown') next = (index + 1) % items.length;
        if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') next = (index - 1 + items.length) % items.length;
        if (event.key === 'Home') next = 0;
        if (event.key === 'End') next = items.length - 1;
        if (next === undefined) return;
        event.preventDefault();
        setCore(items[next].dataset.core);
        items[next].focus();
        updatePlaceholder();
        validateField(false);
    });
    el.coreToggle?.addEventListener('click', (e) => {
        const target = e.target?.closest?.('[role="radio"][data-core]');
        const core = target?.dataset?.core || '';
        if (!core) return;
        e.stopPropagation();
        setCore(core);
        updatePlaceholder();
        validateField(false);
    });
}
