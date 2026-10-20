# Residue Gate

Quadratic residues · Goldwasser–Micali · Rabin · chosen-ciphertext attacks

## What It Is

A browser-only laboratory for the gap between a public Jacobi symbol and private quadratic residuosity. Square actual numbers, encrypt bits, recover four Rabin roots, and factor a modulus through a deliberately vulnerable root oracle.

Built to the [Crypto Lab master template](https://github.com/systemslibrarian/crypto-lab/blob/main/audits/_MASTER-TEMPLATE.md); the original brief is included. Shared UI and accessibility machinery derives from MIT-licensed Crypto Lab siblings by Paul Clark.

## Exhibits

1. Roots modulo a prime, using the p ≡ 3 mod 4 shortcut or Tonelli–Shanks, with independent square-back checks.
2. A CRT residue grid and a scored square-or-pseudosquare game. Labels remain hidden until revealed.
3. Real randomized Goldwasser–Micali encryption, repeated ciphertexts, and public XOR malleability.
4. All four Rabin roots, canonical selection, redundant encoding, and randomized one-bit Rabin.
5. A root-oracle attack receiving only N and one answer. A recovered factor is independently multiplied back and can decrypt earlier GM ciphertexts under the deliberately shared session modulus.

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
- JavaScript BigInt is variable-time. No keys are persisted. Key regeneration terminates the old worker and retires old results.

## Real-World Usage

Quadratic residuosity underlies the historical Goldwasser–Micali construction and related proof systems. Rabin illustrates an unusually direct relationship between inversion and factoring, while exposing the separate problem of secure decryption interfaces.

Primary sources: Katz–Lindell, third edition §§9.1, 11.3 and 15.3; [HAC Chapter 2](https://cacr.uwaterloo.ca/hac/about/chap2.pdf) and [Chapter 3](https://cacr.uwaterloo.ca/hac/about/chap3.pdf). Source details and scope corrections appear in the page. The general-prime root implementation uses Tonelli–Shanks, a standard order-halving algorithm, instead of reproducing the brief's textbook pseudocode verbatim.

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

The initial local run passed 17 tests, including fresh 2048-bit key generation, exhaustive toy roots and oracle outcomes, GM round trips, and module-boundary checks. No coverage percentage is claimed. Browser claims rederive roots and gcd factors from displayed data. Six concrete mutations must build, change bundle bytes, fail a named previously passing test, restore exactly, and pass again.

Production-build accessibility scans run at 1280 and 320 pixels through real success, refusal and disclosure controls. The fleet's contrast and non-text oracles are preserved; no failed rule is disabled. Browser checks run in CI when no supported local browser-control surface is available.

The Actions workflow gates Pages deployment and Dependabot auto-merge on the entire suite, handles PRs and manual dispatch, and dispatches deployment after an automated merge.

## Performance

Prime generation and attacks run off-thread. The 2048-bit modulus is real; the explicitly labelled 437 toy fixture makes every residue and root inspectable. Batch measurements report actual outcomes, not a universal success/refusal probability. Timings belong to the executing browser.

The Crypto Lab catalog integration records this lab’s concept, level, source evidence and fleet automation. Playwright port 4223 is unique across all 223 registered configurations; strictPort is enforced and existing servers are never reused.

---

*One of the browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
