/*
 * Verifikasi tanda tangan Ed25519 (RFC 8032) — hanya verifikasi, tanpa dependensi.
 * Dipakai versi HP untuk memeriksa kunci lisensi secara offline.
 * Memakai BigInt + crypto.subtle (SHA-512), tersedia di semua browser HP modern.
 */
(function (root) {
  'use strict';
  const P = 2n ** 255n - 19n;
  const L = 2n ** 252n + 27742317777372353535851937790883648493n;
  const mod = (a, m) => { m = m || P; const r = a % m; return r >= 0n ? r : r + m; };
  const pow = (b, e, m) => { m = m || P; let r = 1n; b = mod(b, m); while (e > 0n) { if (e & 1n) r = r * b % m; b = b * b % m; e >>= 1n; } return r; };
  const inv = a => pow(a, P - 2n);
  const D = mod(-121665n * inv(121666n));
  const SQRT_M1 = pow(2n, (P - 1n) / 4n);
  const BX = 15112221349535400772501151409588531511454012693041857206046113283949847762202n;
  const BY = 46316835694926478169428394003475163141307993866256225615783033603165251855960n;
  const BASE = [BX, BY, 1n, mod(BX * BY)];
  const ZERO = [0n, 1n, 1n, 0n];

  function add(p1, p2) {
    const [X1, Y1, Z1, T1] = p1, [X2, Y2, Z2, T2] = p2;
    const A = mod((Y1 - X1) * (Y2 - X2)), B = mod((Y1 + X1) * (Y2 + X2));
    const C = mod(2n * D * T1 * T2), DD = mod(2n * Z1 * Z2);
    const E = B - A, F = DD - C, G = DD + C, H = B + A;
    return [mod(E * F), mod(G * H), mod(F * G), mod(E * H)];
  }
  function mul(pt, n) {
    let r = ZERO, q = pt;
    while (n > 0n) { if (n & 1n) r = add(r, q); q = add(q, q); n >>= 1n; }
    return r;
  }
  function leInt(b) { let n = 0n; for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) + BigInt(b[i]); return n; }
  function decode(bytes) {
    const b = Uint8Array.from(bytes);
    const sign = b[31] >> 7; b[31] &= 127;
    const y = leInt(b);
    if (y >= P) return null;
    const y2 = y * y % P;
    const u = mod(y2 - 1n), v = mod(D * y2 + 1n);
    const uv = mod(u * inv(v));
    let x = pow(uv, (P + 3n) / 8n);
    if (mod(x * x - uv) !== 0n) { x = mod(x * SQRT_M1); if (mod(x * x - uv) !== 0n) return null; }
    if (x === 0n && sign) return null;
    if (Number(x & 1n) !== sign) x = P - x;
    return [x, y, 1n, mod(x * y)];
  }
  function encode(pt) {
    const zi = inv(pt[2]);
    const x = mod(pt[0] * zi);
    let y = mod(pt[1] * zi);
    const out = new Uint8Array(32);
    for (let i = 0; i < 32; i++) { out[i] = Number(y & 255n); y >>= 8n; }
    if (x & 1n) out[31] |= 128;
    return out;
  }
  function concat() {
    let n = 0; for (const a of arguments) n += a.length;
    const out = new Uint8Array(n); let o = 0;
    for (const a of arguments) { out.set(a, o); o += a.length; }
    return out;
  }
  /** @returns {Promise<boolean>} */
  async function edVerify(msg, sig, pub) {
    try {
      msg = Uint8Array.from(msg); sig = Uint8Array.from(sig); pub = Uint8Array.from(pub);
      if (sig.length !== 64 || pub.length !== 32) return false;
      const A = decode(pub), Rb = sig.slice(0, 32), R = decode(Rb);
      if (!A || !R) return false;
      const S = leInt(sig.slice(32));
      if (S >= L) return false;
      const h = new Uint8Array(await root.crypto.subtle.digest('SHA-512', concat(Rb, pub, msg)));
      const k = mod(leInt(h), L);
      const lhs = encode(mul(BASE, S)), rhs = encode(add(R, mul(A, k)));
      for (let i = 0; i < 32; i++) if (lhs[i] !== rhs[i]) return false;
      return true;
    } catch (e) { return false; }
  }
  root.edVerify = edVerify;
})(typeof window !== 'undefined' ? window : globalThis);
