import { normalizeWarpOptions } from '../../core/warp-options.js';

// Secrets stay in this panel's memory, never in localStorage or sessionStorage.
export function initWarpGeneratorOptions(panel, onChange) {
    const details = document.createElement('details');
    details.className = 'warp-generator-options';
    details.innerHTML = `
        <summary>Generator settings</summary>
        <div class="field-heading"><label for="warpLicense">WARP+ license (optional)</label></div>
        <input id="warpLicense" class="input" type="password" autocomplete="off" spellcheck="false" placeholder="Leave empty for free WARP">
        <div class="field-heading"><label for="warpEndpoint">Endpoint (optional)</label></div>
        <input id="warpEndpoint" class="input" type="text" autocomplete="off" spellcheck="false" placeholder="engage.cloudflareclient.com:2408">
        <p class="field-hint">Automatic selection uses the upstream IP/port pool. It is not a connectivity or latency test.</p>
        <div class="field-heading"><label for="warpTransport">Packet settings</label></div>
        <select id="warpTransport" class="input">
            <option value="cps">WARP CPS captures (default)</option>
            <option value="no-cps">AWG without automatic CPS</option>
            <option value="none">Plain WireGuard (no AWG fields)</option>
        </select>
        <div class="field-heading"><label for="warpAdvanced">Advanced options (JSON)</label></div>
        <textarea id="warpAdvanced" class="input" rows="4" spellcheck="false" placeholder='{"awg":{"jc":4},"mtu":1280}'></textarea>
        <p class="field-hint">Supports dns, mtu, keepalive, mask, transport, awg (J/S/H), cps (I1–I5), from_hex, random_trailers and disable_cookies. Explicit JSON values override the controls above. Nonstandard S/H values may prevent WARP handshakes.</p>
        <label><input id="warpFresh" type="checkbox"> Register a new WARP device</label>
        <p id="warpCacheHint" class="field-hint">Registration reuse is available when the API has caching enabled. A cache token stays only in this tab's memory.</p>
    `;
    const hint = panel.querySelector(':scope > .field-hint');
    if (hint) hint.textContent = 'Profiles are generated locally by this API using Skiro1/warp-awg-gen logic, without an external configuration generator.';
    panel.insertBefore(details, document.getElementById('amneziaStatus'));
    const get = id => details.querySelector(`#${id}`);
    const license = get('warpLicense');
    const endpoint = get('warpEndpoint');
    const transport = get('warpTransport');
    const advanced = get('warpAdvanced');
    const fresh = get('warpFresh');
    const cacheHint = get('warpCacheHint');
    let token = '';
    let previousLicense = '';
    const onInput = () => { advanced.setCustomValidity(''); onChange(); };
    details.addEventListener('input', onInput);
    details.addEventListener('change', onInput);
    const credit = document.createElement('p');
    credit.className = 'field-hint';
    const link = document.createElement('a');
    link.href = 'https://github.com/Skiro1/warp-awg-gen';
    link.target = '_blank'; link.rel = 'noopener noreferrer';
    link.textContent = 'Generator source: Skiro1/warp-awg-gen (MIT)';
    credit.append(link); details.append(credit);
    return {
        read() {
            let extra;
            try { extra = advanced.value.trim() ? JSON.parse(advanced.value) : {}; }
            catch {
                details.open = true; advanced.focus();
                throw new Error('Advanced options must be valid JSON.');
            }
            if (!extra || typeof extra !== 'object' || Array.isArray(extra)) throw new Error('Advanced options must be a JSON object.');
            const options = normalizeWarpOptions({
                license_key: license.value.trim(), endpoint: endpoint.value.trim(),
                ...(transport.value === 'none' ? { transport: 'none' } : transport.value === 'no-cps' ? { mask: 'none' } : {}),
                ...extra,
            });
            const freshRegistration = fresh.checked || (Boolean(token) && Boolean(options.license_key) && options.license_key !== previousLicense);
            return { options, freshRegistration, registrationCache: freshRegistration ? '' : token };
        },
        remember(result, request) {
            token = typeof result.registrationCache === 'string' ? result.registrationCache : '';
            previousLicense = request.options.license_key;
            fresh.checked = false;
            cacheHint.textContent = token
                ? `Registration ${result.cached ? 'reused' : 'saved for reuse'} in this tab. Closing or reloading the tab clears it.`
                : 'API caching is disabled: each generation registers a new WARP device.';
        },
        setBusy(busy) {
            for (const element of details.querySelectorAll('input, select, textarea')) element.disabled = busy;
        },
    };
}
