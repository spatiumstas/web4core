import { el } from '../dom.js';

export function setError(msg) {
    if (el.errorText) el.errorText.textContent = msg || '';
}

export function setGenerateEnabled(enabled) {
    if (!el.gen) return;
    el.gen.disabled = !enabled;
    el.gen.classList.remove('is-hidden');
}

export function setInputLoading(loading) {
    if (!el.links) return;
    el.links.classList.toggle('input-loading', !!loading);
    el.links.setAttribute('aria-busy', String(!!loading));
    if (el.gen) el.gen.value = loading ? 'Generating…' : 'Generate config';
}

export function renderOutput(text) {
    if (el.out) el.out.value = text || '';
    const format = document.getElementById('outputFormat');
    if (format) format.textContent = el.coreToggle?.dataset.core === 'mihomo' ? 'YAML' : 'JSON';
    setError('');
    el.outBlock?.classList.remove('hidden');
}

export function hideOutput() {
    el.outBlock?.classList.add('hidden');
}

export function scrollOutIntoView() {
    const block = el.outBlock;
    if (block?.scrollIntoView) {
        block.scrollIntoView({ behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'instant' : 'smooth', block: 'center', inline: 'nearest' });
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
    el.links?.setAttribute('aria-invalid', String(!!enabled));
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
            const label = document.getElementById('copyLabel');
            if (label) {
                label.textContent = 'Copied';
                setTimeout(() => { label.textContent = 'Copy'; }, 2000);
            }
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
