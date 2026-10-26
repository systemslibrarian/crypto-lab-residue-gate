// A-D-13. The x² mod N generator of Blum, Blum and Shub, and the Blum–Goldwasser
// probabilistic public-key encryption scheme built on it.
//
// Sources, read rather than summarised:
//   BBS   L. Blum, M. Blum, M. Shub, "A Simple Unpredictable Pseudo-Random Number
//         Generator", SIAM J. Comput. 15(2), May 1986, pp. 364–383. §4 (the generator
//         and its worked example, p. 368); §7 Lemma 1, Claims 1–3, Theorem 3 (pp. 372–374).
//   BG    M. Blum, S. Goldwasser, "An Efficient Probabilistic Public-Key Encryption
//         Scheme Which Hides All Partial Information", CRYPTO '84, LNCS 196,
//         pp. 289–299. "How to Encode m", Algorithm A, "How to Decode", Algorithm B
//         and the Decoding Lemma, pp. 293–294.
//   HAC   Menezes, van Oorschot, Vanstone, Handbook of Applied Cryptography, 1996.
//         Algorithm 5.40 and Note 5.41; Algorithms 8.55/8.56, Example 8.57, Note 8.58.
//
// THE THREE DIFFER BY ONE SQUARING, AND THAT IS NOT SMOOTHED OVER HERE.
//   BBS 1986 emits b_0 = parity(x_0): the seed-square itself emits a bit.
//   BG 1984 emits its first block from r², which is HAC's x_0.
//   HAC 5.40 / 8.56 emit from x_1 and let x_0 emit nothing.
// This file implements the HAC 8.56 convention, because it is the only one of the
// three with a complete published worked example (Example 8.57) carrying every
// intermediate, so it can be pinned as a known-answer test. `bbsBits` exposes BOTH
// conventions so the difference is executable rather than merely described.
//
// BG 1984 additionally requires p ≡ q ≡ 7 (mod 8) (it writes p = 8t+7). HAC 8.55
// requires only p ≡ q ≡ 3 (mod 4), and the Decoding Lemma needs nothing stronger:
// it uses only (u/p) = +1 ⟹ (u^((p+1)/4))² ≡ u (mod p). This file ENFORCES 3 (mod 4)
// and separately REPORTS whether 7 (mod 8) also holds.
//
// NOT a BBS credential or BBS+ signature scheme: the initials collide, the
// constructions are unrelated. NOT authenticated and NOT CCA-secure (HAC Note
// 8.58(iii)). Toy moduli are breakable by construction.
import {below, gcd, mod, pow, systemRandom, type Fill} from '../nt/bigint';
import {legendre} from '../nt/legendre';
import {crt, inverse} from '../nt/sqrt';
import {probablePrime} from '../nt/primes';

export interface BlumKey {p: bigint; q: bigint; n: bigint; a: bigint; b: bigint;}
export interface BlockSizes {k: number; h: number;}
export interface BGCiphertext {blocks: string[]; finalState: bigint; bitLength: number;}
export interface BGEncryption extends BGCiphertext {seed: bigint; seedState: bigint; states: bigint[]; keystream: string[]; plaintext: string;}

/** HAC 8.56 step 1(b): k = floor(lg n), h = floor(lg k). */
export function blockSizes(n: bigint): BlockSizes {
 if (n < 16n) throw Error('Modulus too small for a Blum–Goldwasser block size; use n ≥ 16.');
 const k = n.toString(2).length - 1;
 const h = k.toString(2).length - 1;
 if (h < 1) throw Error('Derived block width h < 1; the modulus is too small.');
 return {k, h};
}

/**
 * HAC 8.55, with the 1984 paper's stronger condition reported rather than imposed.
 * Each failure names the condition it violated.
 */
export function makeBlumKey(p: bigint, q: bigint): BlumKey & {sevenMod8: boolean} {
 if (p === q) throw Error('Blum primes must be distinct: p = q makes n a square and squaring is not a permutation of QR_n.');
 if (p < 3n || q < 3n) throw Error('Both primes must be at least 3.');
 if (mod(p, 4n) !== 3n) throw Error('p ≡ ' + mod(p, 4n) + ' (mod 4); HAC 8.55 requires p ≡ 3 (mod 4) so that (p+1)/4 is an integer.');
 if (mod(q, 4n) !== 3n) throw Error('q ≡ ' + mod(q, 4n) + ' (mod 4); HAC 8.55 requires q ≡ 3 (mod 4) so that (q+1)/4 is an integer.');
 if (!probablePrime(p, 40).prime) throw Error('p failed primality testing.');
 if (!probablePrime(q, 40).prime) throw Error('q failed primality testing.');
 const n = p * q;
 // ap + bq = 1, the identity HAC 8.56 step 2(e) recombines with.
 const b = inverse(mod(q, p), p); // bq ≡ 1 (mod p)
 const a = (1n - b * q) / p;      // exact: 1 − bq is divisible by p
 if (a * p + b * q !== 1n) throw Error('Failed to build a, b with ap + bq = 1.');
 return {p, q, n, a, b, sevenMod8: mod(p, 8n) === 7n && mod(q, 8n) === 7n};
}

/** 0 < r < n and gcd(r, n) = 1. A seed sharing a factor with n already factors it. */
export function validateSeed(r: bigint, n: bigint): void {
 if (r <= 0n || r >= n) throw Error('Seed r must satisfy 0 < r < n.');
 const g = gcd(r, n);
 if (g !== 1n) throw Error('Seed is not a unit: gcd(r, n) = ' + g + ', which already factors n.');
}

/** HAC 8.56 step 1(c): sample a fresh uniform unit r from Z_n^* by rejection. */
export function sampleSeed(n: bigint, fill: Fill = systemRandom): bigint {
 if (n < 2n) throw Error('Seed range is empty; use n ≥ 2.');
 for (;;) {
  const r = 1n + below(n - 1n, fill);
  if (gcd(r, n) === 1n) return r;
 }
}

/** x_0 = r² mod n. The SEED STATE, a quadratic residue; r is the PRE-SQUARE value. */
export function seedState(r: bigint, n: bigint): bigint {
 validateSeed(r, n);
 return r * r % n;
}

/** The h least significant bits of x, as an h-bit string, most significant bit first. */
export function extractBlock(x: bigint, h: number): string {
 if (h < 1 || h > 64) throw Error('Block width h must be 1–64 bits.');
 const v = x & ((1n << BigInt(h)) - 1n);
 return v.toString(2).padStart(h, '0');
}

/**
 * The BBS bit sequence, in BOTH published conventions.
 *
 * includeSeedBit = true  → BBS 1986 §4: b_i = parity(x_i) for i = 0, 1, 2, …
 *                          The seed-square x_0 DOES emit a bit.
 * includeSeedBit = false → HAC 5.40: z_i = lsb(x_i) for i = 1, 2, …
 *                          x_0 emits nothing.
 * The two differ by exactly one leading bit. That is the whole discrepancy.
 */
export function bbsBits(x0: bigint, n: bigint, count: number, includeSeedBit: boolean): {bits: string; states: bigint[]} {
 if (!Number.isInteger(count) || count < 0 || count > 4096) throw Error('Bit count must be an integer 0–4096.');
 const states: bigint[] = [];
 let bits = '';
 let x = mod(x0, n);
 if (includeSeedBit && count > 0) {states.push(x); bits += String(x & 1n);}
 while (bits.length < count) {x = x * x % n; states.push(x); bits += String(x & 1n);}
 return {bits, states};
}

/**
 * HAC 8.56 step 1. Encrypts a bit string under the public modulus alone.
 *
 * Bit order: blocks are taken left to right; p_i is the h least significant bits of
 * x_i written most significant bit first. HAC writes M as t complete h-bit blocks.
 * This lab's explicitly disclosed teaching adaptation permits one short final block:
 * it is XORed against the FIRST s bits of p_t, and the remaining keystream bits are
 * discarded and never reused. The plaintext bit length travels with the ciphertext,
 * so no bits are invented and none are lost.
 */
export function encryptBG(n: bigint, plaintext: string, r: bigint): BGEncryption {
 if (!/^[01]*$/.test(plaintext)) throw Error('The message must be a string of 0 and 1, possibly empty.');
 if (plaintext.length > 4096) throw Error('Use at most 4096 message bits in this interactive view.');
 const {h} = blockSizes(n);
 const x0 = seedState(r, n);
 const t = Math.ceil(plaintext.length / h);
 const states: bigint[] = [];
 const keystream: string[] = [];
 const blocks: string[] = [];
 let x = x0;
 for (let i = 1; i <= t; i++) {
  x = x * x % n;
  states.push(x);
  const key = extractBlock(x, h);
  keystream.push(key);
  const piece = plaintext.slice((i - 1) * h, i * h);
  // XOR position by position from the left; a short final block simply stops early.
  blocks.push([...piece].map((bit, j) => String(Number(bit) ^ Number(key[j]))).join(''));
 }
 return {blocks, finalState: x * x % n, bitLength: plaintext.length, seed: r, seedState: x0, states, keystream, plaintext};
}

/** Regenerate the keystream from a known state. PUBLIC: needs only n. */
export function keystreamFrom(x0: bigint, n: bigint, blockCount: number): {states: bigint[]; keystream: string[]} {
 const {h} = blockSizes(n);
 if (!Number.isInteger(blockCount) || blockCount < 0 || blockCount > 4096) throw Error('Block count must be an integer 0–4096.');
 const states: bigint[] = [];
 const keystream: string[] = [];
 let x = mod(x0, n);
 for (let i = 0; i < blockCount; i++) {x = x * x % n; states.push(x); keystream.push(extractBlock(x, h));}
 return {states, keystream};
}

/**
 * BBS 1986 Theorem 3, p. 373: one step BACKWARD. Needs the factors.
 *
 * Returns the unique quadratic residue y with y² ≡ x (mod n), by taking the
 * square root that is itself a quadratic residue modulo each prime and
 * recombining by CRT. Lemma 1 (p. 373) is what makes that root unique.
 */
export function previousState(x: bigint, p: bigint, q: bigint): bigint {
 const n = p * q;
 const v = mod(x, n);
 if (v === 0n || gcd(v, n) !== 1n) throw Error('Cannot step back from a value that is not a unit modulo n.');
 if (legendre(v, p) !== 1 || legendre(v, q) !== 1) throw Error('Refused: this value is not a quadratic residue modulo n, so it is not a state of the generator.');
 let rp = pow(v, (p + 1n) / 4n, p);
 let rq = pow(v, (q + 1n) / 4n, q);
 if (legendre(rp, p) !== 1) rp = mod(-rp, p);
 if (legendre(rq, q) !== 1) rq = mod(-rq, q);
 const y = crt(rp, p, rq, q);
 if (y * y % n !== v) throw Error('Square-back check failed while stepping backward.');
 return y;
}

/**
 * HAC 8.56 step 2(a)–(e): rewind `steps` squarings. This performs four modular
 * exponentiations: one exponent derivation modulo p−1 and q−1, then one
 * final-state exponentiation modulo p and q (HAC Note 8.59(iii)).
 *
 * d1 = ((p+1)/4)^steps mod (p−1), d2 = ((q+1)/4)^steps mod (q−1),
 * u = x^d1 mod p, v = x^d2 mod q, result = v·a·p + u·b·q mod n.
 *
 * For a ciphertext with t blocks the caller passes steps = t+1, because the
 * transmitted state is x_{t+1} and the target is x_0. An off-by-one here lands on
 * x_1 or x_{-1}, misaligns the recovered chain, and can corrupt plaintext blocks.
 */
export function rewind(x: bigint, key: BlumKey, steps: number): {x0: bigint; d1: bigint; d2: bigint; u: bigint; v: bigint} {
 const {p, q, n, a, b} = key;
 if (!Number.isInteger(steps) || steps < 1 || steps > 4097) throw Error('Rewind step count must be an integer 1–4097.');
 const value = mod(x, n);
 if (gcd(value, n) !== 1n) throw Error('Transmitted state is not a unit modulo n.');
 if (legendre(value, p) !== 1 || legendre(value, q) !== 1) throw Error('Refused: the transmitted state is not a quadratic residue modulo n, so no generator state squares to it.');
 const d1 = pow((p + 1n) / 4n, BigInt(steps), p - 1n);
 const d2 = pow((q + 1n) / 4n, BigInt(steps), q - 1n);
 const u = pow(value, d1, p);
 const v = pow(value, d2, q);
 return {x0: mod(v * a * p + u * b * q, n), d1, d2, u, v};
}

/** HAC 8.56 step 2. Recovers the plaintext from the ciphertext and the factors. */
export function decryptBG(cipher: BGCiphertext, key: BlumKey): {plaintext: string; seedState: bigint; states: bigint[]; keystream: string[]} {
 const {blocks, finalState, bitLength} = cipher;
 const {h} = blockSizes(key.n);
 const t = blocks.length;
 if (bitLength < 0 || bitLength > t * h || (t > 0 && bitLength <= (t - 1) * h)) throw Error('Ciphertext bit length does not match its block count.');
 if (!blocks.every((block, i) => /^[01]+$/.test(block) && block.length === (i === t - 1 ? bitLength - h * (t - 1) : h))) throw Error('Ciphertext blocks are not binary strings with the declared widths.');
 const {x0} = rewind(finalState, key, t + 1);
 const {states, keystream} = keystreamFrom(x0, key.n, t);
 const plaintext = blocks.map((block, i) => [...block].map((bit, j) => String(Number(bit) ^ Number(keystream[i][j]))).join('')).join('');
 if (plaintext.length !== bitLength) throw Error('Recovered bit length disagrees with the ciphertext.');
 return {plaintext, seedState: x0, states, keystream};
}

/** Flip one bit of one ciphertext block. Returns a NEW ciphertext; nothing is mutated. */
export function flipCipherBit(cipher: BGCiphertext, block: number, bit: number): BGCiphertext {
 if (!Number.isInteger(block) || block < 0 || block >= cipher.blocks.length) throw Error('Block index out of range.');
 const target = cipher.blocks[block];
 if (!Number.isInteger(bit) || bit < 0 || bit >= target.length) throw Error('Bit index out of range for that block.');
 const blocks = cipher.blocks.map((b, i) => i !== block ? b : b.slice(0, bit) + String(1 - Number(b[bit])) + b.slice(bit + 1));
 return {blocks, finalState: cipher.finalState, bitLength: cipher.bitLength};
}
