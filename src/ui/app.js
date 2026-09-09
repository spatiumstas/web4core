import { initAmneziaPanel } from './components/amnezia-panel.js';
import { el } from './dom.js';
import { state } from './state.js';
import { debounce } from './utils/dom-utils.js';
import { getCore, getDefaultCore, initCoreToggle, setCore } from './components/core-toggle.js';
import { updateLinksPlaceholder } from './components/placeholders.js';
import { initSettingsPanel } from './components/settings-panel.js';
import { initUrlTestPicker, setUrlTestMenuOpen } from './components/url-test-picker.js';
import { initWireGuardUpload } from './components/wireguard-upload.js';
import { initOutputActions } from './components/output-panel.js';
import { initGenerateController } from './controllers/generate.js';
import { validateField } from './controllers/validation.js';
import { initHeaderReload } from './effects/header-reload.js';
import { initShortcuts } from './effects/shortcuts.js';

function updatePlaceholder() {
    updateLinksPlaceholder(getCore(), !!el.cbExtended?.checked);
}

function initTextValidation() {
    el.links?.addEventListener('input', debounce(() => validateField(false), 150));
    el.links?.addEventListener('blur', () => validateField(false));
}

function initApp() {
    initShortcuts();
    initAmneziaPanel();
    initCoreToggle({ validateField, updatePlaceholder });
    initSettingsPanel({
        validateField,
        updatePlaceholder,
        closeUrlTestMenu: () => setUrlTestMenuOpen(false),
    });
    initUrlTestPicker({ validateField });
    initWireGuardUpload({ validateField });
    initOutputActions({ getCore });
    initGenerateController();
    initTextValidation();
    initHeaderReload();

    state.core = getDefaultCore();
    setCore(state.core);
    updatePlaceholder();
    validateField(false);
}

initApp();
