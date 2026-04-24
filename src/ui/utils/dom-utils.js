export function toggleHidden(node, hidden) {
    if (node) node.classList.toggle('is-hidden', hidden);
}

export function debounce(fn, wait) {
    let t = 0;
    return (...args) => {
        clearTimeout(t);
        t = setTimeout(() => fn(...args), wait);
    };
}
