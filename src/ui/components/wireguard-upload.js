import { el } from '../dom.js';
import { state } from '../state.js';
import { parseWireGuardConf } from '../services/web4core-api.js';
import { setError } from './output-panel.js';

export function updateWgButtonState(count) {
    if (!el.btnWgUpload) return;
    const span = el.btnWgUpload.querySelector('span');
    if (span) span.textContent = count > 0 ? `WireGuard (${count})` : 'WireGuard';
    el.btnWgUpload.classList.toggle('is-active', count > 0);
}

export function resetWireGuardUploads() {
    state.wgBeans = [];
    if (el.wgFile) el.wgFile.value = '';
    updateWgButtonState(0);
}

export function initWireGuardUpload({ validateField }) {
    el.wgFile?.addEventListener('change', async () => {
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
                const bean = parseWireGuardConf(text, file.name);
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

    if (el.btnWgUpload && el.wgFile) {
        el.btnWgUpload.addEventListener('click', () => el.wgFile.click());
    }
}
