// Rejection sampling avoids the signed-overflow/modulo-bias issue in the Go helper.
export function randomInt(min, max) {
    const size = max - min + 1;
    if (!Number.isSafeInteger(size) || size < 1 || size > 0x100000000) throw new RangeError('Invalid random range.');
    const limit = 0x100000000 - (0x100000000 % size);
    const value = new Uint32Array(1);
    do { crypto.getRandomValues(value); } while (value[0] >= limit);
    return min + value[0] % size;
}

export function randomHex(length) {
    return Array.from(crypto.getRandomValues(new Uint8Array(length)), byte => byte.toString(16).padStart(2, '0')).join('');
}
