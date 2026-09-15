function positionMenu(button, menu) {
    const gap = window.innerWidth <= 600 ? 8 : 10;
    const buttonRect = button.getBoundingClientRect();
    menu.style.visibility = 'hidden';
    menu.style.left = '0px';
    menu.style.top = '0px';
    menu.style.maxHeight = '';

    const menuRect = menu.getBoundingClientRect();
    const left = Math.max(gap, Math.min(buttonRect.left, window.innerWidth - gap - menuRect.width));
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

export function createChoicePicker({
    button,
    buttonLabel,
    menu,
    choices,
    initialValue,
    icon = choice => choice.icon || '',
    itemTitle = choice => choice.title || '',
    buttonTitle = choice => itemTitle(choice),
    buttonText = choice => choice.buttonLabel || choice.label,
    onChange,
    onOpenChange,
    compact = false,
}) {
    if (!button || !menu || !Array.isArray(choices) || !choices.length) return null;
    let value = choices.some(choice => choice.value === initialValue) ? initialValue : choices[0].value;
    let open = false;
    let menuItems = [];

    const selectedChoice = () => choices.find(choice => choice.value === value) || choices[0];
    const focusSelected = (last = false) => {
        const selected = menuItems.find(item => item.dataset.choice === value);
        (last ? menuItems.at(-1) : selected || menuItems[0])?.focus();
    };
    const schedulePosition = () => requestAnimationFrame(() => {
        if (open) positionMenu(button, menu);
    });
    const sync = () => {
        for (const item of menuItems) {
            const selected = item.dataset.choice === value;
            item.classList.toggle('is-selected', selected);
            item.setAttribute('aria-checked', String(selected));
            item.tabIndex = selected ? 0 : -1;
        }
        const choice = selectedChoice();
        if (buttonLabel) buttonLabel.textContent = buttonText(choice);
        button.title = buttonTitle(choice);
    };
    const setOpen = nextOpen => {
        open = !!nextOpen;
        button.setAttribute('aria-expanded', String(open));
        menu.classList.toggle('hidden', !open);
        onOpenChange?.(open);
        if (open) {
            schedulePosition();
            document.addEventListener('pointerdown', onOutsidePointerDown, true);
            window.addEventListener('resize', schedulePosition);
            window.addEventListener('scroll', schedulePosition, true);
            requestAnimationFrame(() => focusSelected(false));
        } else {
            document.removeEventListener('pointerdown', onOutsidePointerDown, true);
            window.removeEventListener('resize', schedulePosition);
            window.removeEventListener('scroll', schedulePosition, true);
        }
    };
    const setValue = (nextValue, emit = false) => {
        const choice = choices.find(option => option.value === nextValue) || choices[0];
        value = choice.value;
        sync();
        if (emit) onChange?.(value, choice);
    };
    function onOutsidePointerDown(event) {
        if (!menu.contains(event.target) && !button.contains(event.target)) setOpen(false);
    }

    menu.innerHTML = '';
    const hasIcons = choices.some(choice => !!icon(choice));
    menu.classList.toggle('probe-menu--text-only', !hasIcons);
    menu.classList.toggle('probe-menu--compact', compact);
    for (const choice of choices) {
        const item = document.createElement('button');
        item.type = 'button';
        item.className = 'probe-menu__item';
        item.setAttribute('role', 'menuitemradio');
        item.setAttribute('aria-checked', 'false');
        item.dataset.choice = choice.value;
        item.title = itemTitle(choice);
        const choiceIcon = icon(choice);
        if (hasIcons) {
            const badge = document.createElement('span');
            badge.className = 'probe-menu__badge';
            badge.setAttribute('aria-hidden', 'true');
            badge.innerHTML = choiceIcon;
            item.appendChild(badge);
        }
        const text = document.createElement('span');
        text.className = 'probe-menu__text';
        const title = document.createElement('span');
        title.className = 'probe-menu__title';
        title.textContent = choice.label;
        text.appendChild(title);
        const check = document.createElement('span');
        check.className = 'probe-menu__check';
        check.setAttribute('aria-hidden', 'true');
        check.textContent = '✓';
        item.append(text, check);
        item.addEventListener('click', () => {
            setValue(choice.value, true);
            setOpen(false);
            try { button.focus({ preventScroll: true }); }
            catch { button.focus(); }
        });
        menu.appendChild(item);
    }
    menuItems = Array.from(menu.querySelectorAll('.probe-menu__item'));
    document.body.appendChild(menu);
    menu.addEventListener('keydown', event => {
        const activeIndex = menuItems.indexOf(document.activeElement);
        let next;
        if (event.key === 'ArrowDown') next = activeIndex >= 0 ? (activeIndex + 1) % menuItems.length : 0;
        if (event.key === 'ArrowUp') next = activeIndex >= 0 ? (activeIndex - 1 + menuItems.length) % menuItems.length : menuItems.length - 1;
        if (event.key === 'Home') next = 0;
        if (event.key === 'End') next = menuItems.length - 1;
        if (next !== undefined) {
            event.preventDefault();
            menuItems[next]?.focus();
        } else if (event.key === 'Escape') {
            event.preventDefault();
            setOpen(false);
            button.focus();
        } else if (event.key === 'Tab') setOpen(false);
    });
    button.addEventListener('click', event => {
        event.preventDefault();
        event.stopPropagation();
        setOpen(!open);
    });
    button.addEventListener('keydown', event => {
        if (event.key === 'Enter' || event.key === ' ' || event.key === 'ArrowDown' || event.key === 'ArrowUp') {
            event.preventDefault();
            if (!open) setOpen(true);
            requestAnimationFrame(() => focusSelected(event.key === 'ArrowUp'));
        } else if (event.key === 'Escape' && open) {
            event.preventDefault();
            setOpen(false);
        }
    });
    setValue(value);
    return { getValue: () => value, setValue, setOpen, isOpen: () => open };
}
