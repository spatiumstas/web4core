import { el } from '../dom.js';
import { toggleHidden } from '../utils/dom-utils.js';

export function setError(msg) {
    if (el.errorText) el.errorText.textContent = msg || '';
}

export function setGenerateEnabled(enabled) {
    if (!el.gen) return;
    el.gen.disabled = !enabled;
    toggleHidden(el.gen, !enabled);
}

export function setInputLoading(loading) {
    if (!el.links) return;
    el.links.classList.toggle('input-loading', !!loading);
}

export function renderOutput(text) {
    if (el.out) el.out.value = text || '';
    setError('');
    el.outBlock?.classList.remove('hidden');
}

export function hideOutput() {
    el.outBlock?.classList.add('hidden');
}

export function scrollOutIntoView() {
    const block = el.outBlock;
    if (block?.scrollIntoView) {
        block.scrollIntoView({ behavior: 'smooth', block: 'center', inline: 'nearest' });
    }
    if (el.out?.focus) {
        try {
            el.out.focus({ preventScroll: true });
        } catch {
            // Older Safari does not support preventScroll.
        }
    }
}

export function markInputError(enabled) {
    el.links?.classList.toggle('input-error', !!enabled);
}

function fallbackCopy(txt, onSuccess) {
    try {
        const textarea = document.createElement('textarea');
        textarea.value = txt;
        textarea.setAttribute('readonly', '');
        textarea.style.position = 'fixed';
        textarea.style.top = '0';
        textarea.style.left = '-9999px';
        textarea.style.opacity = '0';
        textarea.style.pointerEvents = 'none';
        document.body.appendChild(textarea);
        textarea.select();
        textarea.setSelectionRange(0, textarea.value.length);
        document.execCommand('copy');
        document.body.removeChild(textarea);
        onSuccess();
    } catch (e) {
        console.error('Fallback copy failed:', e);
    }
}

export function initOutputActions({ getCore }) {
    el.btnCopy?.addEventListener('click', () => {
        const text = el.out?.value || '';
        if (!text) return;

        const copySuccess = () => {
            const useEl = el.btnCopy?.querySelector('use');
            if (useEl) {
                useEl.setAttribute('href', '#check-mark-small');
                setTimeout(() => useEl.setAttribute('href', '#copy'), 2000);
            }
        };

        if (navigator.clipboard?.writeText) {
            navigator.clipboard.writeText(text).then(copySuccess).catch(err => {
                console.error('Clipboard write failed:', err);
                fallbackCopy(text, copySuccess);
            });
        } else {
            fallbackCopy(text, copySuccess);
        }
    });

    el.btnDownload?.addEventListener('click', () => {
        const core = getCore();
        const isYaml = core === 'mihomo';
        const text = el.out?.value || '';
        const blob = new Blob([
            typeof TextEncoder !== 'undefined' ? new TextEncoder().encode(text) : text
        ], { type: (isYaml ? 'text/yaml' : 'application/json') + ';charset=utf-8' });
        const download = core === 'singbox'
            ? 'singbox_config.json'
            : (core === 'xray' ? 'xray_config.json' : 'mihomo_config.yaml');
        const a = Object.assign(document.createElement('a'), {
            href: URL.createObjectURL(blob),
            download,
        });
        a.click();
        URL.revokeObjectURL(a.href);
    });
}
