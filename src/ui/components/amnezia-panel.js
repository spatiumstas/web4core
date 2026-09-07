import { normalizeAmneziaDomain } from '../../core/amnezia.js';

export function initAmneziaPanel() {
    const panel = document.getElementById('amneziaPanel');
    const domain = document.getElementById('amneziaDomain');
    const status = document.getElementById('amneziaStatus');
    const output = document.getElementById('amneziaOutput');
    const config = document.getElementById('amneziaConfig');
    const buttons = [...panel.querySelectorAll('[data-awg-version]')];
    const copy = document.getElementById('amneziaCopy');
    let filename = '';
    let pending = false;
    const setStatus = (message = '', error = false) => {
        status.textContent = message;
        status.classList.toggle('is-error', error);
    };
    domain.addEventListener('input', () => {
        domain.classList.remove('input-error');
        domain.setAttribute('aria-invalid', 'false');
        setStatus();
        output.classList.add('hidden');
        config.value = '';
    });
    for (const button of buttons) button.addEventListener('click', async () => {
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
        pending = true;
        domain.disabled = true;
        buttons.forEach(item => { item.disabled = true; });
        panel.setAttribute('aria-busy', 'true');
        output.classList.add('hidden');
        config.value = '';
        setStatus('Генерация…');
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 30000);
        try {
            const endpoint = document.querySelector('meta[name="amnezia-api"]').content;
            const response = await fetch(endpoint, {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ version: button.dataset.awgVersion, domain: host }),
                signal: controller.signal, cache: 'no-store', credentials: 'omit',
            });
            const result = await response.json();
            if (!response.ok) throw new Error(result.error || 'Не удалось создать конфигурацию.');
            if (typeof result.content !== 'string' || !result.content.startsWith('[Interface]') || !result.content.includes('\nI1 = ')) {
                throw new Error('Сервер вернул некорректную конфигурацию.');
            }
            config.value = result.content;
            filename = `amnezia-awg-${button.dataset.awgVersion}.conf`;
            document.getElementById('amneziaFormat').textContent = `AWG ${button.dataset.awgVersion}`;
            output.classList.remove('hidden');
            setStatus();
            if (!panel.classList.contains('hidden')) config.focus({ preventScroll: true });
        } catch (error) {
            setStatus(error.name === 'AbortError' ? 'Время ожидания истекло. Попробуйте ещё раз.'
                : error instanceof TypeError || error instanceof SyntaxError
                    ? 'API недоступен. Проверьте подключение и попробуйте ещё раз.' : error.message, true);
        } finally {
            clearTimeout(timeout);
            pending = false;
            domain.disabled = false;
            buttons.forEach(item => { item.disabled = false; });
            panel.setAttribute('aria-busy', 'false');
        }
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
            setStatus('Скопировано.');
        } catch { setStatus('Не удалось скопировать. Выделите и скопируйте конфигурацию вручную.', true); }
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
