import { el } from '../dom.js';
import { state } from '../state.js';
import { getUrlTestChoices as getRuntimeUrlTestChoices } from '../services/web4core-api.js';

function normalizeUrlTestChoice(choice) {
    if (!choice) return null;
    if (Array.isArray(choice)) {
        return {
            label: String(choice[0] || '').trim(),
            url: String(choice[1] || '').trim(),
            logo: String(choice[2] || '').trim(),
        };
    }
    if (typeof choice === 'object') {
        return {
            label: String(choice.label || choice.url || '').trim(),
            url: String(choice.url || '').trim(),
            logo: String(choice.logo || '').trim(),
        };
    }
    const url = String(choice || '').trim();
    return url ? { label: url, url, logo: '' } : null;
}

function runtimeChoices() {
    return getRuntimeUrlTestChoices().map(normalizeUrlTestChoice).filter((choice) => choice && choice.url);
}

function fallbackUrlTestLogo() {
    return '<svg viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="10" fill="var(--primary)"/></svg>';
}

function ensureUrlTestMenuMounted() {
    if (!el.urlTestMenu || state.urlTestMenuMounted) return;
    document.body.appendChild(el.urlTestMenu);
    state.urlTestMenuMounted = true;
}

function syncUrlTestMenuSelection() {
    if (!el.urlTestMenu) return;
    const items = Array.from(el.urlTestMenu.querySelectorAll('.probe-menu__item'));
    for (const item of items) {
        const selected = item.dataset.urlTest === state.urlTest;
        item.classList.toggle('is-selected', selected);
        item.setAttribute('aria-checked', String(selected));
        item.tabIndex = selected ? 0 : -1;
    }
}

function focusSelectedUrlTestItem(last = false) {
    if (!el.urlTestMenu) return;
    const items = Array.from(el.urlTestMenu.querySelectorAll('.probe-menu__item'));
    if (!items.length) return;
    const selected = items.find((item) => item.dataset.urlTest === state.urlTest);
    const target = last ? (items[items.length - 1] || selected || items[0]) : (selected || items[0]);
    target?.focus();
}

function positionUrlTestMenu() {
    if (!state.urlTestMenuOpen || !el.urlTestMenu || !el.urlTestButton) return;
    const gap = window.innerWidth <= 600 ? 8 : 10;
    const buttonRect = el.urlTestButton.getBoundingClientRect();
    const menu = el.urlTestMenu;

    menu.style.visibility = 'hidden';
    menu.style.left = '0px';
    menu.style.top = '0px';
    menu.style.maxHeight = '';

    const menuRect = menu.getBoundingClientRect();
    let left = buttonRect.left;
    left = Math.max(gap, Math.min(left, window.innerWidth - gap - menuRect.width));

    let top = buttonRect.bottom + gap;
    const availableBelow = window.innerHeight - top - gap;
    const availableAbove = buttonRect.top - gap * 2;
    if (availableBelow < 140 && availableAbove > availableBelow) {
        const height = Math.min(menuRect.height, availableAbove);
        top = Math.max(gap, buttonRect.top - gap - height);
        menu.style.maxHeight = `${Math.floor(Math.max(140, height))}px`;
    } else {
        menu.style.maxHeight = `${Math.floor(Math.max(140, Math.min(260, availableBelow)))}px`;
    }

    menu.style.left = `${Math.round(left)}px`;
    menu.style.top = `${Math.round(top)}px`;
    menu.style.visibility = '';
}

function scheduleUrlTestMenuPosition() {
    requestAnimationFrame(positionUrlTestMenu);
}

function onUrlTestPointerDown(event) {
    const target = event.target;
    if (el.urlTestMenu?.contains(target) || el.urlTestButton?.contains(target)) return;
    setUrlTestMenuOpen(false);
}

function onUrlTestMenuKeydown(event) {
    if (!el.urlTestMenu) return;
    const items = Array.from(el.urlTestMenu.querySelectorAll('.probe-menu__item'));
    if (!items.length) return;
    const activeIndex = items.indexOf(document.activeElement);

    switch (event.key) {
        case 'ArrowDown': {
            event.preventDefault();
            const nextIndex = activeIndex >= 0 ? (activeIndex + 1) % items.length : 0;
            items[nextIndex]?.focus();
            break;
        }
        case 'ArrowUp': {
            event.preventDefault();
            const nextIndex = activeIndex >= 0 ? (activeIndex - 1 + items.length) % items.length : (items.length - 1);
            items[nextIndex]?.focus();
            break;
        }
        case 'Home':
            event.preventDefault();
            items[0]?.focus();
            break;
        case 'End':
            event.preventDefault();
            items[items.length - 1]?.focus();
            break;
        case 'Escape':
            event.preventDefault();
            setUrlTestMenuOpen(false);
            el.urlTestButton?.focus();
            break;
        case 'Tab':
            setUrlTestMenuOpen(false);
            break;
        default:
            break;
    }
}

function buildUrlTestMenu({ validateField }) {
    if (!el.urlTestMenu) return;
    el.urlTestMenu.innerHTML = '';

    for (const choice of state.urlTestChoices) {
        const item = document.createElement('button');
        item.type = 'button';
        item.className = 'probe-menu__item';
        item.setAttribute('role', 'menuitemradio');
        item.dataset.urlTest = choice.url;
        item.dataset.service = (choice.label || '').trim().toLowerCase();
        item.setAttribute('aria-checked', 'false');
        item.title = choice.url;

        const badge = document.createElement('span');
        badge.className = 'probe-menu__badge';
        badge.setAttribute('aria-hidden', 'true');
        badge.innerHTML = choice.logo || fallbackUrlTestLogo();

        const text = document.createElement('span');
        text.className = 'probe-menu__text';

        const title = document.createElement('span');
        title.className = 'probe-menu__title';
        title.textContent = choice.label || choice.url;

        const check = document.createElement('span');
        check.className = 'probe-menu__check';
        check.setAttribute('aria-hidden', 'true');
        check.textContent = '✓';

        text.appendChild(title);
        item.appendChild(badge);
        item.appendChild(text);
        item.appendChild(check);
        item.addEventListener('click', () => {
            setUrlTest(choice.url);
            setUrlTestMenuOpen(false);
            validateField(false);
            try {
                el.urlTestButton?.focus({ preventScroll: true });
            } catch {
                el.urlTestButton?.focus();
            }
        });
        el.urlTestMenu.appendChild(item);
    }
    syncUrlTestMenuSelection();
}

export function setUrlTest(url) {
    state.urlTest = String(url || '').trim();
    if (!state.urlTest && state.urlTestChoices.length > 0) state.urlTest = state.urlTestChoices[0].url;
    syncUrlTestMenuSelection();
    if (el.urlTestButton) {
        el.urlTestButton.title = state.urlTest || 'Ping service';
        el.urlTestButton.classList.toggle('is-active', !!state.urlTest);
    }
}

export function getUrlTest() {
    return String(state.urlTest || '').trim();
}

export function setUrlTestMenuOpen(open) {
    state.urlTestMenuOpen = !!open;
    if (el.urlTestButton) el.urlTestButton.setAttribute('aria-expanded', String(state.urlTestMenuOpen));
    if (!el.urlTestMenu) return;

    if (state.urlTestMenuOpen) {
        ensureUrlTestMenuMounted();
        el.urlTestMenu.classList.remove('hidden');
        document.body.classList.add('probe-menu-open');
        scheduleUrlTestMenuPosition();
        document.addEventListener('pointerdown', onUrlTestPointerDown, true);
        window.addEventListener('resize', scheduleUrlTestMenuPosition);
        window.addEventListener('scroll', scheduleUrlTestMenuPosition, true);
        requestAnimationFrame(() => focusSelectedUrlTestItem(false));
    } else {
        el.urlTestMenu.classList.add('hidden');
        document.body.classList.remove('probe-menu-open');
        document.removeEventListener('pointerdown', onUrlTestPointerDown, true);
        window.removeEventListener('resize', scheduleUrlTestMenuPosition);
        window.removeEventListener('scroll', scheduleUrlTestMenuPosition, true);
    }
}

export function initUrlTestPicker({ validateField }) {
    if (!el.urlTestButton || !el.urlTestMenu) return;
    state.urlTestChoices = runtimeChoices();
    if (!state.urlTestChoices.length) return;
    if (!state.urlTest) state.urlTest = state.urlTestChoices[0].url;

    ensureUrlTestMenuMounted();
    buildUrlTestMenu({ validateField });
    setUrlTest(state.urlTest);

    el.urlTestMenu.addEventListener('keydown', onUrlTestMenuKeydown);
    el.urlTestButton.addEventListener('click', (event) => {
        event.preventDefault();
        event.stopPropagation();
        setUrlTestMenuOpen(!state.urlTestMenuOpen);
    });
    el.urlTestButton.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' || event.key === ' ' || event.key === 'ArrowDown') {
            event.preventDefault();
            if (!state.urlTestMenuOpen) setUrlTestMenuOpen(true);
            else focusSelectedUrlTestItem(false);
            return;
        }
        if (event.key === 'ArrowUp') {
            event.preventDefault();
            if (!state.urlTestMenuOpen) setUrlTestMenuOpen(true);
            requestAnimationFrame(() => focusSelectedUrlTestItem(true));
            return;
        }
        if (event.key === 'Escape' && state.urlTestMenuOpen) {
            event.preventDefault();
            setUrlTestMenuOpen(false);
        }
    });
}
