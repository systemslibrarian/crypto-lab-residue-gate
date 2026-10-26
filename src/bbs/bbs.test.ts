import {it, expect} from 'vitest';
import {readFileSync} from 'node:fs';
import {bbsBits, blockSizes, decryptBG, encryptBG, extractBlock, flipCipherBit, keystreamFrom, makeBlumKey, previousState, rewind, sampleSeed, seedState, validateSeed} from './bbs';

// ---------------------------------------------------------------------------
// An INDEPENDENT reference implementation. It shares no code with src/: its own
// modular exponentiation (square-and-multiply written here), its own extended
// Euclid, its own CRT. A production helper agreeing with itself proves nothing.
// ---------------------------------------------------------------------------
const refMod = (a: bigint, n: bigint): bigint => ((a % n) + n) % n;
function refPow(base: bigint, exp: bigint, n: bigint): bigint {
 let r = 1n, b = refMod(base, n), e = exp;
 while (e > 0n) {if (e % 2n === 1n) r = r * b % n; b = b * b % n; e /= 2n;}
 return r;
}
function refEgcd(a: bigint, b: bigint): [bigint, bigint, bigint] {
 if (b === 0n) return [a, 1n, 0n];
 const [g, x, y] = refEgcd(b, a % b);
 return [g, y, x - (a / b) * y];
}
/** Brute-force reference: every bit of x_i, recomputed from the seed each time. */
function refStates(r: bigint, n: bigint, count: number): bigint[] {
 const out: bigint[] = [];
 for (let i = 1; i <= count; i++) {
  // x_i = r^(2^(i+1)) mod n, computed by repeated squaring of r from scratch.
  let v = refMod(r, n);
  for (let s = 0; s < i + 1; s++) v = v * v % n;
  out.push(v);
 }
 return out;
}
function refBlocks(x: bigint, h: number): string {
 let s = '';
 for (let bit = h - 1; bit >= 0; bit--) s += String((x >> BigInt(bit)) & 1n);
 return s;
}

// ---------------------------------------------------------------------------
// Known-answer tests from the primary sources.
// ---------------------------------------------------------------------------

it('BBS 1986 section 4 worked example reproduces, in the paper’s own convention', () => {
 // N = 7*19 = 133, x_0 = 4. The paper prints the states and the bits 0 0 1 0 1 1.
 const n = 133n;
 const {bits, states} = bbsBits(4n, n, 6, true);
 expect(states).toEqual([4n, 16n, 123n, 100n, 25n, 93n]);
 expect(bits).toBe('001011');
 // The period is 6: squaring the last state returns to the seed.
 expect(states[5] * states[5] % n).toBe(4n);
 // HAC 5.40's convention drops the seed bit and is otherwise identical.
 const hac = bbsBits(4n, n, 6, false);
 // x_1..x_6 = 16, 123, 100, 25, 93, 4 (the chain wraps), parities 0,1,0,1,1,0.
 expect(hac.states).toEqual([16n, 123n, 100n, 25n, 93n, 4n]);
 expect(hac.bits).toBe('010110');
 // The two conventions are the same sequence, offset by exactly one bit.
 expect(bits.slice(1)).toBe(hac.bits.slice(0, 5));
});

it('HAC Example 8.57 reproduces every published intermediate', () => {
 const key = makeBlumKey(499n, 547n);
 expect(key.n).toBe(272953n);
 expect(key.a * key.p + key.b * key.q).toBe(1n);
 const {k, h} = blockSizes(key.n);
 expect([k, h]).toEqual([18, 4]);

 // The paper's seed: x_0 = 159201 = 399^2 mod n.
 expect(seedState(399n, key.n)).toBe(159201n);

 const plaintext = '1001' + '1100' + '0001' + '0000' + '1100';
 const enc = encryptBG(key.n, plaintext, 399n);
 expect(enc.seedState).toBe(159201n);
 expect(enc.states).toEqual([180539n, 193932n, 245613n, 130286n, 40632n]);
 expect(enc.keystream).toEqual(['1011', '1100', '1101', '1110', '1000']);
 expect(enc.blocks).toEqual(['0010', '0000', '1100', '1110', '0100']);
 expect(enc.finalState).toBe(139680n);

 // Decryption, including the published exponents and CRT halves.
 const back = rewind(enc.finalState, key, enc.blocks.length + 1);
 expect([back.d1, back.d2, back.u, back.v]).toEqual([463n, 337n, 20n, 24n]);
 expect(back.x0).toBe(159201n);
 expect(decryptBG(enc, key).plaintext).toBe(plaintext);
});

it('the independent reference agrees with the implementation on states and blocks', () => {
 const key = makeBlumKey(499n, 547n);
 const {h} = blockSizes(key.n);
 const enc = encryptBG(key.n, '1001110000010000110010', 399n);
 const reference = refStates(399n, key.n, enc.states.length);
 expect(enc.states).toEqual(reference);
 expect(enc.keystream).toEqual(reference.map(x => refBlocks(x & ((1n << BigInt(h)) - 1n), h)));
 // And the whole round trip, recomputed with the reference arithmetic only.
 const t = enc.blocks.length;
 const d1 = refPow((key.p + 1n) / 4n, BigInt(t + 1), key.p - 1n);
 const d2 = refPow((key.q + 1n) / 4n, BigInt(t + 1), key.q - 1n);
 const u = refPow(enc.finalState, d1, key.p);
 const v = refPow(enc.finalState, d2, key.q);
 const [, ap] = refEgcd(key.p, key.q);
 const bq = (1n - ap * key.p) / key.q;
 expect(ap * key.p + bq * key.q).toBe(1n);
 expect(refMod(v * ap * key.p + u * bq * key.q, key.n)).toBe(enc.seedState);
});

// ---------------------------------------------------------------------------
// Indexing, the thing most easily got wrong.
// ---------------------------------------------------------------------------

it('x_0 is the squared seed, emits no block, and the transmitted state is one past x_t', () => {
 const key = makeBlumKey(499n, 547n);
 const enc = encryptBG(key.n, '10011100', 399n);
 expect(enc.seed).toBe(399n);
 expect(enc.seedState).toBe(399n * 399n % key.n);
 // The first block comes from x_1, never from x_0.
 expect(enc.keystream[0]).toBe(extractBlock(enc.states[0], 4));
 expect(enc.states[0]).toBe(enc.seedState * enc.seedState % key.n);
 // The transmitted state is x_{t+1}: exactly one squaring past the last emitter.
 const last = enc.states[enc.states.length - 1];
 expect(enc.finalState).toBe(last * last % key.n);
 // And the rewind count is t+1, not t: t lands on x_1, t+2 lands before x_0.
 expect(rewind(enc.finalState, key, enc.blocks.length + 1).x0).toBe(enc.seedState);
 expect(rewind(enc.finalState, key, enc.blocks.length).x0).toBe(enc.states[0]);
 expect(rewind(enc.finalState, key, enc.blocks.length).x0).not.toBe(enc.seedState);
});

it('one backward step is the inverse of one squaring, on every state of a chain', () => {
 const key = makeBlumKey(19n, 23n);
 const enc = encryptBG(key.n, '0110100101', 7n);
 const chain = [enc.seedState, ...enc.states];
 for (let i = 1; i < chain.length; i++) expect(previousState(chain[i], key.p, key.q)).toBe(chain[i - 1]);
});

// ---------------------------------------------------------------------------
// Block handling, including the partial final block.
// ---------------------------------------------------------------------------

it('a partial final block loses no bits and invents none', () => {
 const key = makeBlumKey(499n, 547n);
 const {h} = blockSizes(key.n);
 expect(h).toBe(4);
 for (const length of [1, 2, 3, 4, 5, 7, 8, 9, 13, 16, 17]) {
  const plaintext = '1011001110100101101'.slice(0, length);
  const enc = encryptBG(key.n, plaintext, 399n);
  expect(enc.bitLength).toBe(length);
  expect(enc.blocks.length).toBe(Math.ceil(length / h));
  expect(enc.blocks.join('').length).toBe(length);
  const tail = enc.blocks[enc.blocks.length - 1];
  expect(tail.length).toBe(length - h * (enc.blocks.length - 1));
  // The short block XORs against the FIRST s bits of its keystream block.
  const key4 = enc.keystream[enc.keystream.length - 1];
  const piece = plaintext.slice(h * (enc.blocks.length - 1));
  expect(tail).toBe([...piece].map((b, j) => String(Number(b) ^ Number(key4[j]))).join(''));
  expect(decryptBG(enc, key).plaintext).toBe(plaintext);
 }
});

it('an empty message is supported and still transmits a usable final state', () => {
 const key = makeBlumKey(499n, 547n);
 const enc = encryptBG(key.n, '', 399n);
 expect(enc.blocks).toEqual([]);
 expect(enc.bitLength).toBe(0);
 // t = 0, so the transmitted state is x_1 = x_0², and one rewind step recovers x_0.
 expect(enc.finalState).toBe(enc.seedState * enc.seedState % key.n);
 const out = decryptBG(enc, key);
 expect(out.plaintext).toBe('');
 expect(out.seedState).toBe(enc.seedState);
});

it('round trips at the smallest usable Blum modulus and over many messages', () => {
 const key = makeBlumKey(3n, 7n);
 expect(key.n).toBe(21n);
 expect(blockSizes(key.n).h).toBe(2);
 for (let r = 1n; r < key.n; r++) {
  if (r % 3n === 0n || r % 7n === 0n) {expect(() => validateSeed(r, key.n)).toThrow('gcd'); continue;}
  for (const m of ['', '0', '1', '01', '101', '110101']) {
   const enc = encryptBG(key.n, m, r);
   expect(decryptBG(enc, key).plaintext).toBe(m);
  }
 }
});

// ---------------------------------------------------------------------------
// Seed and parameter domain.
// ---------------------------------------------------------------------------

it('the seed and modulus domain is enforced, each failure naming its condition', () => {
 expect(() => makeBlumKey(19n, 19n)).toThrow('distinct');
 expect(() => makeBlumKey(5n, 19n)).toThrow('p ≡ 1 (mod 4)');
 expect(() => makeBlumKey(19n, 13n)).toThrow('q ≡ 1 (mod 4)');
 // Composites chosen ≡ 3 (mod 4) so they reach the primality check rather than
 // being refused one step earlier by the residue condition.
 expect(() => makeBlumKey(15n, 19n)).toThrow('primality');
 expect(() => makeBlumKey(19n, 35n)).toThrow('primality');
 const key = makeBlumKey(19n, 23n);
 expect(() => validateSeed(0n, key.n)).toThrow('0 < r < n');
 expect(() => validateSeed(key.n, key.n)).toThrow('0 < r < n');
 expect(() => validateSeed(19n, key.n)).toThrow('gcd(r, n) = 19');
 expect(() => validateSeed(23n, key.n)).toThrow('gcd(r, n) = 23');
 expect(() => encryptBG(key.n, '102', 7n)).toThrow('0 and 1');
 expect(() => blockSizes(15n)).toThrow('too small');
});

it('fresh sender coins are rejection-sampled from the units with injectable randomness', () => {
 const draws = [[0, 18], [0, 4]]; // r=19 is rejected for n=437; r=5 is accepted.
 let calls = 0;
 const fill = (bytes: Uint8Array<ArrayBuffer>): void => {
  bytes.set(draws[calls++]);
 };
 expect(sampleSeed(437n, fill)).toBe(5n);
 expect(calls).toBe(2);
 expect(() => sampleSeed(1n, fill)).toThrow('range is empty');
});

it('the 1984 paper’s stronger 7 mod 8 condition is reported, not imposed', () => {
 // 19 ≡ 3 (mod 8) and 23 ≡ 7 (mod 8): a valid HAC key that is NOT a 1984-paper key.
 const mixed = makeBlumKey(19n, 23n);
 expect(mixed.sevenMod8).toBe(false);
 expect(decryptBG(encryptBG(mixed.n, '01101001', 7n), mixed).plaintext).toBe('01101001');
 // 7 ≡ 7 and 23 ≡ 7 (mod 8): both conditions hold.
 const strict = makeBlumKey(7n, 23n);
 expect(strict.sevenMod8).toBe(true);
 expect(decryptBG(encryptBG(strict.n, '0110', 5n), strict).plaintext).toBe('0110');
});

it('a state that is not a quadratic residue is refused rather than rewound', () => {
 const key = makeBlumKey(19n, 23n);
 // 2 is a unit mod 437 with Jacobi −1, so it is not a quadratic residue.
 expect(() => previousState(2n, key.p, key.q)).toThrow('not a quadratic residue');
 expect(() => rewind(2n, key, 3)).toThrow('not a quadratic residue');
 expect(() => previousState(19n, key.p, key.q)).toThrow('not a unit');
 expect(() => rewind(19n, key, 2)).toThrow('not a unit');
});

// ---------------------------------------------------------------------------
// Tampering and wrong keys. These are shown, never dressed up as detection.
// ---------------------------------------------------------------------------

it('flipping a ciphertext bit flips exactly that plaintext bit, with no detection', () => {
 const key = makeBlumKey(499n, 547n);
 const plaintext = '1001110000010000';
 const enc = encryptBG(key.n, plaintext, 399n);
 for (let block = 0; block < enc.blocks.length; block++) {
  for (let bit = 0; bit < enc.blocks[block].length; bit++) {
   const tampered = flipCipherBit(enc, block, bit);
   const out = decryptBG({...tampered, bitLength: enc.bitLength}, key);
   const index = block * 4 + bit;
   const expected = plaintext.slice(0, index) + String(1 - Number(plaintext[index])) + plaintext.slice(index + 1);
   // Exactly one bit differs, and decryption succeeds: there is nothing to reject with.
   expect(out.plaintext).toBe(expected);
   expect([...out.plaintext].filter((c, i) => c !== plaintext[i]).length).toBe(1);
  }
 }
 expect(() => flipCipherBit(enc, 99, 0)).toThrow('Block index');
 expect(() => flipCipherBit(enc, 0, 99)).toThrow('Bit index');
});

it('altering the transmitted final state changes the recovered message or is refused', () => {
 const key = makeBlumKey(499n, 547n);
 const plaintext = '1001110000010000';
 const enc = encryptBG(key.n, plaintext, 399n);
 let refused = 0, corrupted = 0;
 for (let delta = 1n; delta <= 40n; delta++) {
  const tampered = {blocks: enc.blocks, finalState: (enc.finalState + delta) % key.n, bitLength: enc.bitLength};
  try {
   const out = decryptBG(tampered, key);
   corrupted++;
   // When the altered state happens to be a residue, the recovered message changes.
   // The construction does not authenticate which sender produced it.
   expect(out.plaintext).not.toBe(plaintext);
   expect(out.seedState).not.toBe(enc.seedState);
  } catch (e) {
   refused++;
   expect(String(e)).toMatch(/not a quadratic residue|not a unit/);
  }
 }
 // Both outcomes are real at this size; the exhibit shows whichever occurs.
 expect(refused).toBeGreaterThan(0);
 expect(corrupted).toBeGreaterThan(0);
});

it('the validity guard rejects non-residues but accepts an altered valid residue without authenticating it', () => {
 const key = makeBlumKey(19n, 23n);
 const plaintext = '1001110000010000';
 const enc = encryptBG(key.n, plaintext, 5n);
 expect(enc.finalState).toBe(36n);
 expect(() => decryptBG({...enc, finalState: 37n}, key)).toThrow('not a quadratic residue');
 const accepted = decryptBG({...enc, finalState: 39n}, key);
 expect(accepted.plaintext).not.toBe(plaintext);
});

it('malformed binary blocks and declared widths are refused', () => {
 const key = makeBlumKey(19n, 23n);
 const enc = encryptBG(key.n, '1001110', 5n);
 expect(() => decryptBG({...enc, blocks: ['10x', ...enc.blocks.slice(1)]}, key)).toThrow('binary strings');
 expect(() => decryptBG({...enc, blocks: ['10', ...enc.blocks.slice(1)]}, key)).toThrow('declared widths');
});

it('the wrong factors decrypt to garbage rather than to the message', () => {
 const key = makeBlumKey(499n, 547n);
 const enc = encryptBG(key.n, '1001110000010000', 399n);
 const wrong = makeBlumKey(19n, 23n);
 // A key for a different modulus cannot even see the state as a residue of its own n.
 expect(() => decryptBG(enc, wrong)).toThrow();
 // And a correct modulus with swapped CRT coefficients loses the seed.
 const swapped = {...key, a: key.b, b: key.a};
 const out = (() => {try {return decryptBG(enc, swapped).plaintext;} catch {return null;}})();
 expect(out).not.toBe('1001110000010000');
});

// ---------------------------------------------------------------------------
// The claim the lesson is allowed to make about state disclosure.
// ---------------------------------------------------------------------------

it('a disclosed state yields its CURRENT block and every later block from n alone', () => {
 const key = makeBlumKey(499n, 547n);
 const enc = encryptBG(key.n, '1001110000010000110010', 399n);
 // Disclose x_2. Its own low bits are p_2; public forward squaring gives p_3 onward.
 const disclosed = enc.states[1];
 const forward = keystreamFrom(disclosed, key.n, enc.blocks.length - 2);
 const exposed = [extractBlock(disclosed, blockSizes(key.n).h), ...forward.keystream];
 expect(exposed).toEqual(enc.keystream.slice(1));
 expect(forward.keystream).toEqual(enc.keystream.slice(2));
 expect(forward.states).toEqual(enc.states.slice(2));
 // With the factors, the exact predecessor states return efficiently.
 expect(previousState(disclosed, key.p, key.q)).toBe(enc.states[0]);
 expect(previousState(enc.states[0], key.p, key.q)).toBe(enc.seedState);
});

it('the toy orbit cycles back publicly, so it promises no backward protection', () => {
 const key = makeBlumKey(19n, 23n);
 const enc = encryptBG(key.n, '1001110000010000', 5n);
 const disclosed = enc.states[1]; // x_2 = 384
 expect(disclosed).toBe(384n);
 let x = disclosed;
 for (let i = 0; i < 28; i++) x = x * x % key.n;
 expect(x).toBe(enc.seedState); // x_0 appears again after 28 public steps.
 x = x * x % key.n;
 expect(x).toBe(enc.states[0]); // then x_1.
});

it('module boundaries keep the private factors out of the public generator path', () => {
 const source = readFileSync('src/bbs/bbs.ts', 'utf8');
 // keystreamFrom and encryptBG are the public-side operations: they take n only.
 expect(/export function keystreamFrom\(x0: bigint, n: bigint/.test(source)).toBe(true);
 expect(/export function encryptBG\(n: bigint, plaintext: string, r: bigint\)/.test(source)).toBe(true);
 // The private operations take the key explicitly; nothing is held in module scope.
 expect(source).not.toMatch(/^let |^var /m);
});

it('the real 2048-bit session key encrypts and rewinds a stream', {timeout: 240000}, async () => {
 const {newOracle} = await import('../rabin/oracle');
 const o = newOracle();
 const n = o.publicKey.N;
 expect(o.publicKey.bits).toBe(2048);
 const info = o.bgInfo();
 // k = floor(lg n) = 2047 for a 2048-bit modulus, so h = floor(lg 2047) = 10.
 expect(info.k).toBe(2047);
 expect(info.h).toBe(10);
 const plaintext = '1001110000010000110010110';
 // The seed is drawn on the PUBLIC side: encryption needs nothing but n.
 const enc = encryptBG(n, plaintext, 123456789n);
 expect(enc.blocks.length).toBe(Math.ceil(plaintext.length / info.h));
 expect(enc.blocks.join('').length).toBe(plaintext.length);
 const out = o.bgDecrypt({blocks: enc.blocks, finalState: enc.finalState, bitLength: enc.bitLength});
 expect(out.plaintext).toBe(plaintext);
 expect(out.seedState).toBe(enc.seedState);
 // One backward step through the key holder, checked by squaring forward again.
 const back = o.bgPrevious(enc.states[0]);
 expect(back).toBe(enc.seedState);
 expect(back * back % n).toBe(enc.states[0]);
});
