import { el } from '../dom.js';
import { state } from '../state.js';
import { getUrlTestChoices as getRuntimeUrlTestChoices } from '../services/web4core-api.js';
import { createChoicePicker } from './choice-picker.js';

const FALLBACK_LOGO = '<svg viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="10" fill="var(--primary)"/></svg>';
let picker;

function normalizeChoice(choice) {
    if (!choice) return null;
    if (Array.isArray(choice)) {
        return {
            label: String(choice[0] || '').trim(),
            value: String(choice[1] || '').trim(),
            icon: String(choice[2] || '').trim() || FALLBACK_LOGO,
        };
    }
    if (typeof choice === 'object') {
        const value = String(choice.url || '').trim();
        return {
            label: String(choice.label || value).trim(),
            value,
            icon: String(choice.logo || '').trim() || FALLBACK_LOGO,
        };
    }
    const value = String(choice).trim();
    return value ? { label: value, value, icon: FALLBACK_LOGO } : null;
}

export function setUrlTest(url) {
    const value = String(url || '').trim();
    state.urlTest = value || state.urlTestChoices[0]?.value || '';
    picker?.setValue(state.urlTest);
    el.urlTestButton?.classList.toggle('is-active', !!state.urlTest);
}

export function getUrlTest() {
    return String(state.urlTest || '').trim();
}

export function setUrlTestMenuOpen(open) {
    picker?.setOpen(open);
}

export function initUrlTestPicker({ validateField }) {
    state.urlTestChoices = getRuntimeUrlTestChoices().map(normalizeChoice).filter(choice => choice?.value);
    if (!el.urlTestButton || !el.urlTestMenu || !state.urlTestChoices.length) return;
    if (!state.urlTest) state.urlTest = state.urlTestChoices[0].value;
    picker = createChoicePicker({
        button: el.urlTestButton,
        menu: el.urlTestMenu,
        choices: state.urlTestChoices,
        initialValue: state.urlTest,
        itemTitle: choice => choice.value,
        buttonTitle: choice => choice.value || 'Ping service',
        onChange: value => {
            state.urlTest = value;
            validateField(false);
        },
        onOpenChange: open => { state.urlTestMenuOpen = open; },
    });
    el.urlTestButton.classList.toggle('is-active', !!state.urlTest);
}
