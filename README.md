# Residue Gate

Quadratic residues · Goldwasser–Micali · Rabin · Blum–Goldwasser · chosen-ciphertext attacks

## What It Is

A browser-only laboratory for the gap between a public Jacobi symbol and private quadratic residuosity. Square actual numbers, encrypt bits, recover four Rabin roots, factor a modulus through a deliberately vulnerable root oracle, and run the Blum–Goldwasser stream. Anyone can advance that stream; efficient predecessor recovery is assumed hard at cryptographic sizes without the factors, while the lab’s deliberately tiny orbit is explicitly shown to cycle.

Built to the [Crypto Lab master template](https://github.com/systemslibrarian/crypto-lab/blob/main/audits/_MASTER-TEMPLATE.md); the original brief is included. Shared UI and accessibility machinery derives from MIT-licensed Crypto Lab siblings by Paul Clark.

## Exhibits

1. Roots modulo a prime, using the p ≡ 3 mod 4 shortcut or Tonelli–Shanks, with independent square-back checks.
2. A CRT residue grid and a scored square-or-pseudosquare game. Labels remain hidden until revealed.
3. Real randomized Goldwasser–Micali encryption, repeated ciphertexts, and public XOR malleability.
4. All four Rabin roots, canonical selection, redundant encoding, and randomized one-bit Rabin.
5. A root-oracle attack receiving only N and one answer. A recovered factor is independently multiplied back and can decrypt earlier GM ciphertexts under the deliberately shared session modulus.
6. The Blum–Blum–Shub `x² mod N` generator and Blum–Goldwasser encryption: a real state chain, live BBS/HAC indexing comparison, fresh rejection-sampled coins by default, emitted keystream blocks, transmitted final state, and the factor-assisted rewind. The rewind derives two exponents and applies them with two more modular exponentiations, as counted by HAC Note 8.59. State disclosure, seed reuse, ciphertext-bit tampering, rejected non-residue final states and accepted altered-residue final states are each demonstrated from the current run.

## When to Use It

Teach why public Jacobi +1 is insufficient to classify squares, and why one-wayness or correct decryption does not imply chosen-ciphertext security. Not for generating or handling production keys.

## Live Demo

[Residue Gate](https://systemslibrarian.github.io/crypto-lab-residue-gate/). Publication is gated by unit, browser claims, accessibility, and concrete mutation tests.

## What Can Go Wrong

- GM is malleable: multiplying by the public pseudosquare flips a bit.
- A canonical QR root oracle can expose factors through gcd(m − x, N).
- Redundancy **does not universally refuse** random squares. Some roots accidentally match; multiple matches are refused. The default toy query is a verified refusal, not a CCA-security proof.
- The quadratic residuosity assumption is an assumption. The page does not assert a proven equivalence to factoring.
- Plain deterministic Rabin, randomized one-bit Rabin, and CCA-secure encryption have distinct guarantees.
- The private factors remain in the session worker/closure. The attacker module cannot import them. The trusted educational root panel deliberately shows information the attack interface does not receive.
- Blum–Goldwasser is a stream cipher with **no authentication**. Flipping a ciphertext bit flips exactly that plaintext bit and nothing rejects it, because the scheme has nothing to reject with. HAC Note 8.58(iii) records that it also falls to a chosen-ciphertext attack, as Rabin does.
- Encryption normally samples a fresh uniform unit `r` by rejection and does not transmit it; the manual seed is a labelled reproducibility override. Reusing `r` repeats the stream and final state, so the executable negative control derives `c XOR c′ = m XOR m′` from two actual encryptions.
- Disclosing an internal generator state hands over **its current output block and every subsequent block** to anyone holding N. Exact predecessor recovery is a computational assumption at cryptographic sizes, not an information-theoretic promise. In the pinned `N = 437, r = 5` fixture, the orbit publicly returns from `x₂` to `x₀` after 28 forward squarings, so the page makes no backward-protection claim for that toy run.
- The original 1984 Blum–Goldwasser presentation requires `p,q ≡ 7 (mod 8)`. This lab implements HAC Algorithms 8.55–8.56, which require distinct probable primes `p,q ≡ 3 (mod 4)`, and names that difference in the learner view.
- The implementation refuses a final state outside `QR_N`; that is a ciphertext-validity guard, not sender authentication. A separate control substitutes a different valid quadratic residue and passes the guard; the learner view reports the plaintext actually recovered, and the pinned toy case changes it.
- The three published descriptions of this generator **do not share an indexing convention**, and they differ by one squaring. Experiment 6 runs HAC Algorithm 8.56 and says so on the page; BBS 1986 and Blum–Goldwasser 1984 each emit their first bit one state earlier.
- Bits that look random are not evidence of pseudorandomness, and this lab runs no statistical test that could be mistaken for a proof.
- Experiment 6 is **not** BBS credential signing or any BBS+ signature scheme. The initials collide; the constructions are unrelated.
- JavaScript BigInt is variable-time. No keys are persisted. Key regeneration terminates the old worker and retires old results.

## Real-World Usage

Quadratic residuosity underlies the historical Goldwasser–Micali construction and related proof systems. Rabin illustrates an unusually direct relationship between inversion and factoring, while exposing the separate problem of secure decryption interfaces.

Primary sources: Katz–Lindell, third edition §§9.1, 11.3 and 15.3; [HAC Chapter 2](https://cacr.uwaterloo.ca/hac/about/chap2.pdf) and [Chapter 3](https://cacr.uwaterloo.ca/hac/about/chap3.pdf). For experiment 6, read rather than summarised: [L. Blum, M. Blum and M. Shub, "A Simple Unpredictable Pseudo-Random Number Generator", *SIAM J. Comput.* **15**(2), May 1986, pp. 364–383](https://doi.org/10.1137/0215025) — §4 for the generator and its worked example at N = 133, §7 for Lemma 1, claims 1–3 and Theorem 3; [M. Blum and S. Goldwasser, "An Efficient Probabilistic Public-Key Encryption Scheme Which Hides All Partial Information", *CRYPTO '84*, LNCS **196**, pp. 289–299](https://doi.org/10.1007/3-540-39568-7_23) — "How to Encode m", Algorithms A and B and the Decoding Lemma, pp. 293–294; and [HAC Chapter 5](https://cacr.uwaterloo.ca/hac/about/chap5.pdf) Algorithm 5.40 with [Chapter 8](https://cacr.uwaterloo.ca/hac/about/chap8.pdf) Algorithms 8.55–8.56 and Example 8.57, which is pinned as a known-answer test down to every published intermediate. Source details and scope corrections appear in the page. The general-prime root implementation uses Tonelli–Shanks, a standard order-halving algorithm, instead of reproducing the brief's textbook pseudocode verbatim.

## How to Run Locally

Node 22 or newer:

```sh
npm ci
npm run dev
```

## Related Demos

[Hidden Bit](https://systemslibrarian.github.io/crypto-lab-hidden-bit/), [Factor Forge](https://systemslibrarian.github.io/crypto-lab-factor-forge/), [Prime Witness](https://systemslibrarian.github.io/crypto-lab-prime-witness/).

Source review used the exact sibling commits pinned in the brief. Existing roots, factoring and residuosity components overlap in primitives; this lab joins the residue classification, encryption, root selection and oracle break into one experiment. It does not claim those primitives were absent from the fleet.

## Build & Verify

```sh
npm test
npm run build
npx playwright install chromium
npm run test:e2e
npm run test:mutations
```

The suite contains 38 unit tests, including fresh 2048-bit key generation, exhaustive toy roots and oracle outcomes, GM round trips, module-boundary checks, deterministic testing of the rejection sampler, malformed-ciphertext guards, and the two published Blum–Goldwasser and BBS worked examples reproduced down to every intermediate. No coverage percentage is claimed. Twenty-two browser claims rederive roots, gcd factors, generator states, keystream blocks, the seed-reuse relation, disclosure boundary and BBS/HAC indexing from displayed data using arithmetic written in the test file, and reject stale asynchronous outcomes. Twenty-five concrete mutations must build, change bundle bytes, fail a named previously passing test, restore exactly, and pass again.

Production-build accessibility scans run at 1280 and 320 pixels through real success, reuse, disclosure, ciphertext tampering, non-residue refusal, accepted altered-residue and invalid-seed controls. The fleet's contrast and non-text oracles are preserved; no failed rule is disabled. Browser checks run in CI when no supported local browser-control surface is available.

The Actions workflow gates Pages deployment and Dependabot auto-merge on the entire suite, handles PRs and manual dispatch, and dispatches deployment after an automated merge.

## Performance

Prime generation and attacks run off-thread. The 2048-bit modulus is real; the explicitly labelled 437 toy fixture makes every residue and root inspectable. Batch measurements report actual outcomes, not a universal success/refusal probability. Timings belong to the executing browser.

The Crypto Lab catalog integration records this lab’s concept, level, source evidence and fleet automation. Playwright port 4223 is unique across all 223 registered configurations; strictPort is enforced and existing servers are never reused.

---

*One of the browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
