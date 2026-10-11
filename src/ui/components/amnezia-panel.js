import { normalizeAmneziaDomain } from '../../core/amnezia.js';
import { renderQr } from './qr-renderer.js';
import { createConfigQrSeries, QrCapacityError } from './config-qr.js';

export function initAmneziaPanel() {
    const panel = document.getElementById('amneziaPanel');
    const domain = document.getElementById('amneziaDomain');
    const status = document.getElementById('amneziaStatus');
    const output = document.getElementById('amneziaOutput');
    const config = document.getElementById('amneziaConfig');
    const version = document.getElementById('amneziaVersion');
    const generate = document.getElementById('amneziaGenerate');
    const copy = document.getElementById('amneziaCopy');
    const copyLabel = copy.querySelector('span');
    const copyIcon = copy.querySelector('use');
    let copyTimer;
    const resetCopy = () => {
        clearTimeout(copyTimer);
        copyLabel.textContent = 'Copy';
        copyIcon.setAttribute('href', '#copy');
    };
    const qrToggle = document.getElementById('amneziaQrToggle');
    const qr = document.getElementById('amneziaQr');
    const qrCanvas = document.getElementById('amneziaQrCanvas');
    const qrState = document.getElementById('amneziaQrState');
    const qrNavigation = document.getElementById('amneziaQrNavigation');
    const qrPrevious = document.getElementById('amneziaQrPrevious');
    const qrNext = document.getElementById('amneziaQrNext');
    const qrPage = document.getElementById('amneziaQrPage');
    const qrHint = document.getElementById('amneziaQrHint');
    let qrSeries = [];
    let qrIndex = 0;
    let stopQrAnimation;
    const clearQr = () => {
        stopQrAnimation?.();
        stopQrAnimation = undefined;
        qr.classList.remove('is-generating');
        document.body.classList.remove('qr-dialog-open');
        qrCanvas.width = qrCanvas.height = 0;
        qrSeries = [];
        qrIndex = 0;
        qrNavigation.classList.add('hidden');
    };
    const resetQr = () => {
        if (qr.open) qr.close();
        clearQr();
    };
    qr.addEventListener('close', clearQr);
    document.getElementById('amneziaQrClose').addEventListener('click', resetQr);
    qr.addEventListener('click', event => {
        const bounds = qr.getBoundingClientRect();
        if (event.target === qr && (event.clientX < bounds.left || event.clientX > bounds.right ||
            event.clientY < bounds.top || event.clientY > bounds.bottom)) resetQr();
    });
    let filename = '';
    let pending = false;
    const setStatus = (message = '', error = false) => {
        status.textContent = message;
        status.classList.toggle('is-error', error);
    };
    const resetOutput = () => {
        resetCopy();
        setStatus();
        output.classList.add('hidden');
        config.value = '';
        resetQr();
    };
    domain.addEventListener('input', () => {
        domain.classList.remove('input-error');
        domain.setAttribute('aria-invalid', 'false');
        resetOutput();
    });
    const updateVersionHint = () => {
        document.getElementById('amneziaExperimental').classList.toggle('hidden', !version.value.startsWith('3.'));
    };
    updateVersionHint();
    const versionPicker = document.getElementById('amneziaVersionPicker');
    const versionMenu = document.getElementById('amneziaVersionMenu');
    const versionItems = [...versionMenu.querySelectorAll('[data-awg-version]')];
    const setVersionMenuOpen = (open, last = false) => {
        versionMenu.classList.toggle('hidden', !open);
        version.setAttribute('aria-expanded', String(open));
        if (open) {
            const selected = versionItems.find(item => item.dataset.awgVersion === version.value);
            (last ? versionItems.at(-1) : selected || versionItems[0]).focus();
        }
    };
    // Keep pointer activation from blurring the menu before click toggles it.
    // Safari can report a null relatedTarget when clicking a button's SVG.
    version.addEventListener('pointerdown', event => {
        if (event.button === 0) event.preventDefault();
    });
    version.addEventListener('click', () => {
        const open = versionMenu.classList.contains('hidden');
        setVersionMenuOpen(open);
        if (!open) version.focus();
    });
    version.addEventListener('keydown', event => {
        if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
            event.preventDefault();
            setVersionMenuOpen(true, event.key === 'ArrowUp');
        }
    });
    for (const item of versionItems) item.addEventListener('click', () => {
        if (pending) return;
        if (version.value !== item.dataset.awgVersion) {
            version.value = item.dataset.awgVersion;
            document.getElementById('amneziaVersionText').textContent = `AWG ${version.value}`;
            for (const option of versionItems) {
                const selected = option === item;
                option.classList.toggle('is-selected', selected);
                option.setAttribute('aria-checked', String(selected));
            }
            resetOutput();
            updateVersionHint();
        }
        setVersionMenuOpen(false);
        version.focus();
    });
    versionMenu.addEventListener('keydown', event => {
        const index = versionItems.indexOf(document.activeElement);
        let next;
        if (event.key === 'ArrowDown') next = (index + 1) % versionItems.length;
        if (event.key === 'ArrowUp') next = (index - 1 + versionItems.length) % versionItems.length;
        if (event.key === 'Home') next = 0;
        if (event.key === 'End') next = versionItems.length - 1;
        if (next !== undefined) {
            event.preventDefault();
            versionItems[next].focus();
        }
        if (event.key === 'Escape') {
            event.preventDefault();
            setVersionMenuOpen(false);
            version.focus();
        }
        if (event.key === 'Tab') version.focus();
    });
    document.addEventListener('pointerdown', event => {
        if (!versionPicker.contains(event.target)) setVersionMenuOpen(false);
    });
    versionPicker.addEventListener('focusout', event => {
        if (!versionPicker.contains(event.relatedTarget)) setVersionMenuOpen(false);
    });
    generate.addEventListener('click', async () => {
        if (pending) return;
        let host;
        try { host = normalizeAmneziaDomain(domain.value); }
        catch (error) {
            setStatus(error.message, true);
            domain.classList.add('input-error');
            domain.setAttribute('aria-invalid', 'true');
            domain.focus();
            return;
        }
        domain.value = host;
        const selectedVersion = version.value;
        pending = true;
        resetCopy();
        setVersionMenuOpen(false);
        domain.disabled = true;
        version.disabled = generate.disabled = true;
        panel.setAttribute('aria-busy', 'true');
        output.classList.add('hidden');
        config.value = '';
        resetQr();
        setStatus();
        generate.textContent = 'Generating…';
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 30000);
        try {
            const endpoint = document.querySelector('meta[name="amnezia-api"]').content;
            const response = await fetch(endpoint, {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ version: selectedVersion, domain: host }),
                signal: controller.signal, cache: 'no-store', credentials: 'omit',
            });
            const result = await response.json();
            if (!response.ok) throw new Error(result.error || 'Could not generate the configuration.');
            if (typeof result.content !== 'string' || !result.content.startsWith('[Interface]') ||
                !/^\[Peer\]$/m.test(result.content)) {
                throw new Error('The server returned an invalid configuration.');
            }
            config.value = result.content;
            filename = `amnezia-awg-${selectedVersion}.conf`;
            document.getElementById('amneziaFormat').textContent = `AWG ${selectedVersion}`;
            output.classList.remove('hidden');
            setStatus('');
            if (!panel.classList.contains('hidden')) config.focus({ preventScroll: true });
        } catch (error) {
            setStatus(error.name === 'AbortError' ? 'Request timed out. Please try again.'
                : error instanceof TypeError || error instanceof SyntaxError
                    ? 'API unavailable. Check your connection to Cloudflare and try again.' : error.message, true);
        } finally {
            clearTimeout(timeout);
            pending = false;
            domain.disabled = false;
            version.disabled = generate.disabled = false;
            generate.textContent = 'Generate config';
            panel.setAttribute('aria-busy', 'false');
        }
    });
    const showQrFrame = (animate = false) => {
        stopQrAnimation?.();
        qr.classList.toggle('is-generating', animate);
        qrPrevious.disabled = qrIndex === 0;
        qrNext.disabled = qrIndex === qrSeries.length - 1;
        qrPage.textContent = `${qrIndex + 1} / ${qrSeries.length}`;
        qrCanvas.setAttribute('aria-label', qrSeries.length > 1
            ? `Amnezia configuration QR code ${qrIndex + 1} of ${qrSeries.length}` : 'Amnezia configuration QR code');
        const readyText = qrSeries.length > 1 ? `Scan code ${qrIndex + 1} of ${qrSeries.length}` : 'Ready to scan';
        qrState.textContent = animate ? 'Assembling QR code…' : readyText;
        stopQrAnimation = renderQr(qrCanvas, qrSeries[qrIndex], {
            animate,
            onReady: () => {
                qr.classList.remove('is-generating');
                qrState.textContent = readyText;
            },
        });
    };
    const onQrError = error => {
        resetQr();
        setStatus(error instanceof QrCapacityError
            ? 'The configuration is too large for QR import. Download the .conf file instead.'
            : 'Could not display the QR code. Try again or download the .conf file.', true);
    };
    const changeQrFrame = offset => {
        if (!qr.open || qrIndex + offset < 0 || qrIndex + offset >= qrSeries.length) return;
        qrIndex += offset;
        try { showQrFrame(); } catch (error) { onQrError(error); }
    };
    qrPrevious.addEventListener('click', () => changeQrFrame(-1));
    qrNext.addEventListener('click', () => changeQrFrame(1));
    qrToggle.addEventListener('click', () => {
        if (!config.value || qr.open) return;
        try {
            document.getElementById('amneziaQrFormat').textContent = document.getElementById('amneziaFormat').textContent;
            qrSeries = createConfigQrSeries(config.value);
            qrIndex = 0;
            const multiple = qrSeries.length > 1;
            qrNavigation.classList.toggle('hidden', !multiple);
            qrHint.classList.toggle('hidden', multiple);
            if (multiple) qr.removeAttribute('aria-describedby');
            else qr.setAttribute('aria-describedby', qrHint.id);
            const animate = !window.matchMedia('(prefers-reduced-motion: reduce)').matches;
            showQrFrame(animate);
            document.body.classList.add('qr-dialog-open');
            qr.showModal();
        } catch (error) { onQrError(error); }
    });
    copy.addEventListener('click', async () => {
        if (!config.value) return;
        try {
            if (navigator.clipboard?.writeText) await navigator.clipboard.writeText(config.value);
            else {
                config.focus();
                config.select();
                if (!document.execCommand('copy')) throw new Error('copy failed');
            }
            clearTimeout(copyTimer);
            copyLabel.textContent = 'Copied';
            copyIcon.setAttribute('href', '#check-mark-small');
            copyTimer = setTimeout(resetCopy, 2000);
        } catch { setStatus('Could not copy. Select and copy the configuration manually.', true); }
    });
    document.getElementById('amneziaDownload').addEventListener('click', () => {
        if (!config.value) return;
        const url = URL.createObjectURL(new Blob([config.value], { type: 'application/octet-stream' }));
        const link = Object.assign(document.createElement('a'), { href: url, download: filename });
        document.body.append(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    });
}
