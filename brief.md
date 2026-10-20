# Build brief — `crypto-lab-residue-gate`

**2026-10-20. Brief only; no repository exists yet.** Written against
`audits/_MASTER-TEMPLATE.md` (catalog `f48d9d2f2f06`). §0 through §6 apply unchanged.
Source of the gap: Katz–Lindell, *Introduction to Modern Cryptography* 3rd ed., §15.4
(Goldwasser–Micali) and §15.5 (Rabin).

**Verdict: new repository.**

```
NEW DEMO BRIEF
- Repo name:         crypto-lab-residue-gate
- Short name (H1):   Residue Gate
- Subtitle:          Quadratic residuosity · Goldwasser–Micali · Rabin
- One-liner:         Computes Jacobi symbols modulo N = pq without the factors, encrypts bits
                     with Goldwasser–Micali, encrypts with Rabin over a Blum integer, and then
                     factors that modulus with one chosen-ciphertext query to plain Rabin
                     decryption.
- Concept to teach:  Modulo N = pq anyone can compute the Jacobi symbol, but telling a square
                     from a pseudosquare, or taking a square root, needs the factors.
                     Goldwasser–Micali rests on the first gap, Rabin on the second. And Rabin's
                     "as hard as factoring" proof is the very fact that lets one decryption
                     query factor N.
- Primitives/spec:   Katz–Lindell 3rd ed. §15.4–15.5 (Construction 15.28, Lemma 15.35,
                     Proposition 15.37, Construction 15.39, Exercise 15.18); Goldwasser–Micali
                     1984; Rabin 1979 (MIT/LCS/TR-212); HAC Algorithm 2.149 (Jacobi), 3.36 and 3.44
                     (square roots), §8.3 Notes 8.13(ii) and 8.14(ii), Algorithms 8.50/8.51 (GM).
                     No standardized test vectors exist for either scheme (see Tests).
- Accent (--accent): [central assignment]
- Favicon emoji:     [central assignment]
- Category:          [central assignment]
- Section (suggested): public-key
- In scope:          Euler's criterion and square roots mod p; the Jacobi symbol by reciprocity
                     (no factors); QR_N versus pseudosquares on a CRT grid; GM keygen, encryption,
                     decryption, XOR homomorphism and ciphertext expansion; Blum primes; plain
                     Rabin with its four roots and two decryption rules (canonical QR root;
                     redundancy); Katz–Lindell Construction 15.39 (one-bit Rabin, CPA proof only);
                     the chosen-ciphertext attack that factors N.
- Non-goals:         Blum–Blum–Shub, Rabin–Williams signatures, Cocks IBE, Blum–Goldwasser,
                     any CCA-proven Rabin padding (named, not built), factoring N by any route
                     other than the oracle, Paillier, side channels, constant-time arithmetic.
```

## Overlap check — what I read, and what I found

Opened from source at the commits shown. Nothing below is from a card or a chip.

- **crypto-lab-factor-forge** `8fd7436210e0` — has `jacobi()` and `sqrtMod()` in
  `src/factor/bigint.ts` (lines 139, 161). They are used inside p+1 (`src/factor/pplus1.ts:112`)
  and the quadratic sieve (`src/factor/qs.ts:145`, which keeps only primes p where N is a
  quadratic residue). They are internal tools of factoring methods, not a residuosity exhibit.
  Its `src/verify/verify.ts` is the pattern to copy for the verifier: it imports no algorithm
  module, and `src/verify/verify.test.ts` (~line 54) reads that file's source to enforce this.
- **crypto-lab-hidden-bit** `734bd6ee7329` — cites Goldwasser–Micali (1984) in its
  "Definitions and primary sources" disclosure (`index.html:211`). Its game schemes
  (`src/schemes/`) are AES modes, ECDSA, Ed25519, ElGamal and RSA (OAEP, PSS, textbook).
  There is no GM scheme.
- **crypto-lab-rsa-educational** `bc479abe82b5` and **crypto-lab-rsa-forge** `925498c1f145` —
  RSA only. In both, "Rabin" appears only as Miller–Rabin.
- **crypto-lab-paillier-gate** `1e102ca4d6b3` — composite residuosity (DCR, `src/main.ts:160`),
  which is a different assumption from quadratic residuosity.
- **crypto-lab-accumulator** `8816733764c0` — puts g in the QR_N subgroup over safe primes
  (`src/core/primes.ts`, `src/ui/setup.ts:108`). It uses QR_N as a group and never decides
  residuosity.
- **crypto-lab-vdf** `b0bff11e8fe5`, **crypto-lab-time-lock-puzzle** `23c960a73386` —
  repeated squaring in RSA groups. Neither has square roots or residuosity tests.
- **crypto-lab-sm9-forge** `ea4293beb193` — uses a Legendre symbol once, to choose an
  extension-field constant (`src/sm9/params.ts:42`). Its "Jacobian" matches are point
  coordinates.
- **crypto-lab-corrupted-oracle** `3f6f2f4a2a5a` — its only "Jacobi" match is Jacobian
  coordinates in `dual-ec-drbg.ts`.

Before building, grep the sibling clones for `goldwasser|rabin (enc|crypt)|pseudosquare|jacobi`
and report anything that appeared after these commits.

## SCOPE — five acts

1. **Squares mod a prime.** Euler's criterion (Katz–Lindell Algorithm 15.18): exactly half of
   Z*_p are squares. Square roots: the p ≡ 3 (mod 4) shortcut x = a^((p+1)/4), and the
   general Katz–Lindell Algorithm 15.31 for p ≡ 1 (mod 4), stepped one halving at a time.
2. **Squares mod N = pq — the gap.** A toy Blum modulus drawn as a CRT grid Z*_p × Z*_q, with
   four quadrants set by (J_p, J_q). The Jacobi symbol, computed from N alone, picks out the
   two diagonal quadrants (+,+) and (−,−) but cannot say which is which.
   - **Game:** the page draws x with J_N(x) = +1 and the learner guesses "square" or
     "pseudosquare". The tally of right answers is measured, not asserted.
   - **"Reveal p":** colours the grid. Squaring is 4-to-1 (Katz–Lindell Example 15.22).
3. **Goldwasser–Micali**, at real size by default (2048-bit N; toy toggle).
   - Keygen per Construction 15.28: pk = (N, z) with z a uniform element of QNR^{+1}_N,
     sampled at keygen using the factors.
   - Encrypt a short bit string: every bit becomes one element of Z*_N. Show the expansion
     ratio, computed from the actual sizes.
   - Encrypt the same bit twice and get different ciphertexts. Multiply two ciphertexts and
     get the XOR. Decryption reads J_p(c) only.
   - In-page note: for a Blum N, z = N − 1 is a valid pseudosquare (follows from the proof
     of Proposition 15.37).
4. **Rabin.**
   - Blum primes p ≡ q ≡ 3 (mod 4). Encryption is c = m² mod N. Decryption finds all four
     roots via CRT (HAC Algorithm 3.44); at toy size they are drawn on the grid.
   - Two decryption rules, switchable:
     - **(a) canonical:** messages live in QR_N and decryption returns the unique root in
       QR_N (Proposition 15.37; the setting of Exercise 15.18).
     - **(b) redundancy:** the message carries a replicated tail and decryption returns the
       root that has it (HAC Note 8.14).
   - A disclosure panel shows Construction 15.39 (encrypt one bit as lsb(x) with x ∈ QR_N).
     The page states that Katz–Lindell's Theorem 15.40 proves it **CPA**-secure, and nothing
     more.
5. **The chosen-ciphertext break.**
   - The learner picks x, or presses "pick one with Jacobi −1", and submits c = x² to the
     real decryption oracle. It returns a root m. The page computes gcd(m − x, N) and
     multiplies the factor back to N (Lemma 15.35).
   - **Under rule (a):** one query always succeeds when J_N(x) = −1, because the returned
     root has Jacobi +1 and so cannot be ±x. Act 2's public Jacobi computation is what tells
     the attacker which x to send. A uniformly random x succeeds with probability 1/2:
     measure it over repeated queries, and exhaust it at toy size.
   - **Under rule (b):** a random x² has no root carrying the redundancy, so the oracle
     refuses and this attack fails (HAC Note 8.14(ii)).
   - The page says plainly: this blocks **this** attack and is not a CCA-security proof.
     Proven CCA security for Rabin comes from a padding with a proof (Boneh, CRYPTO 2001,
     random-oracle model). That is named and not built.
   - **Closing step:** the recovered p decrypts every GM ciphertext from Act 3, because
     deciding residuosity reduces to factoring. The page labels the shared modulus as a
     deliberate teaching choice, not something to do with real keys.

Non-goal notes (one line each, in-page): BBS, Rabin–Williams and Cocks IBE are listed as
"where this goes next". Paillier is a different residuosity assumption (link out). This
is not constant-time code.

## SECURITY / CORRECTNESS INVARIANTS

1. **Key boundary.** The private key exists only inside the oracle module's closure.
   - The attack module receives N and the oracle's return values, nothing else.
   - `src/nt/jacobi.ts` never imports a key or factor type.
   - Both rules are enforced by a source-reading test, using Factor Forge's
     `verify.test.ts` pattern.
2. **Nothing is shown that was not re-checked.** No factor is displayed until
   `src/verify/` has checked 1 < p < N, p · (N/p) = N, and N mod p = 0. Every displayed
   square root is squared back to c.
3. **Blum primes are enforced.** p ≡ q ≡ 3 (mod 4) and p ≠ q. Keygen fails closed otherwise
   and names the violated condition.
4. **Inputs to Z*_N are validated.** Every oracle input satisfies 0 < c < N and
   gcd(c, N) = 1, else it is refused. The refusal notes that a c with gcd > 1 already
   factors N.
5. **No security claim the construction does not have.** The page must not say
   "CCA-secure" about rule (b) or about Construction 15.39.
6. **The breakable mode is visible.** The plain-Rabin oracle (rule a) is a labelled toggle,
   marked as the breakable mode. The Act 5 default is rule (b).
7. **Randomness and lifetime.** All randomness comes from `crypto.getRandomValues`, with
   rejection sampling (no modulo bias). Keys live per session in memory and are never
   persisted.
8. **Sizes are labelled honestly.**
   - Toy grids are marked toy-scale.
   - Real keys default to 2048-bit N.
   - Timings are this browser's, never extrapolated.

## ARCHITECTURE

All number theory is hand-rolled on BigInt; the maths is the subject.

| Path | Holds |
|---|---|
| `src/nt/bigint.ts` | modpow, gcd, egcd, crt |
| `src/nt/legendre.ts` | Euler's criterion |
| `src/nt/jacobi.ts` | HAC Algorithm 2.149: binary reciprocity, no factors |
| `src/nt/sqrt.ts` | p ≡ 3 mod 4; Katz–Lindell Algorithm 15.31; CRT four roots |
| `src/nt/primes.ts` | Miller–Rabin and Blum-prime generation |
| `src/worker/keygen.worker.ts` | Keeps keygen off the main thread |
| `src/gm/gm.ts` | Goldwasser–Micali |
| `src/rabin/rabin.ts` | Encryption, rule a, rule b, Construction 15.39 |
| `src/rabin/oracle.ts` | Closure over sk; exports a query function only |
| `src/attack/cca.ts` | Sees N and the oracle only |
| `src/verify/verify.ts` | Multiply-back and square-back. Imports no scheme module |
| `src/ui/act1.ts` … `act5.ts` | The five acts |

No library is needed beyond Vite and the test stack.

## UI

- Plain-language intro (no maths): "Anyone can tell some numbers are not squares. Telling
  the rest apart takes a secret."
- Act 2's grid is the central picture. Acts 3–5 refer back to it: GM's ciphertexts land in
  one diagonal quadrant or the other, and Rabin's four roots are the four corners of one
  rectangle on it.
- Act 5 is the "aha":
  1. Press "pick x with Jacobi −1", which runs public maths only.
  2. Send x² to the oracle.
  3. Watch the returned root land in a different quadrant.
  4. Run the gcd.
  5. Watch p appear and multiply back to N.
- Rule toggle (a)/(b) beside the oracle. A query counter. A history table of queries with
  J_N(x) and outcome.
- The grid must reflow at 320 px. Offer 7 · 11 = 77 as the narrow-screen default and
  19 · 23 = 437 on wider screens.

## VISUAL SEMANTICS

- **Before "Reveal p":** the two Jacobi +1 quadrants share one pattern and the label
  "Jacobi +1 — cannot tell". Never pre-colour them; that would give the game away.
- **After reveal:** squares and pseudosquares get distinct patterns *and* text labels.
  Verify in grayscale.
- **Act 5 success under rule (a)** is ALARM: "DECRYPTED CORRECTLY — AND FACTORED".
- **Refusal under rule (b)** reads as integrity holding: "Refused — no root carries the
  redundancy". It sits beside a non-dismissable line: "This stops this attack. It is not a
  proof of chosen-ciphertext security."
- **GM bit flip** (see §4.1d): "DECRYPTED — AND FLIPPED".

## EDGE CASES

| Input | Fail-closed behaviour |
|---|---|
| Even N or N ≤ 1 to `jacobi()` | Throw with message |
| x = 0, x = ±1, x ≥ N in Act 5 | Normalise or refuse, with a tooltip on why ±1 teaches nothing |
| x with J_N(x) = +1 | Allowed. The page predicts "this query reveals nothing" before sending, then shows the oracle returned ±x |
| c not a square under rule (a) | Oracle refuses. Tooltip: a decryption oracle that says "not a residue" is itself a residuosity oracle, which would break GM under the same modulus |
| gcd(c, N) > 1 | Refused, with the note from invariant 4 |
| Non-Blum p from a custom-prime field | Refused, naming p mod 4 |
| Rule (a) plaintext not in QR_N | Refused at encryption, with the reason: rule (a) only decrypts messages that are squares. Text messages use rule (b) |
| GM plaintext not in {0,1}* | Refused. Empty message is allowed and shows zero ciphertext elements |
| Toy primes > the grid cap | The grid is disabled and the reason shown; the maths still runs |

## EXTENSION SEAMS

- `// [extension] point` in `src/nt/primes.ts`: Blum–Blum–Shub (x_{i+1} = x_i² mod N,
  output lsb) reuses Blum keygen and `sqrt.ts`.
- `// [extension] point` in `src/rabin/rabin.ts`: Rabin–Williams signatures.
- `// [extension] point` in `src/nt/jacobi.ts`: Cocks IBE (Jacobi-symbol decryption).

## Tests

**No standardized test vectors exist for Goldwasser–Micali or Rabin.** The suite therefore
pins worked examples from the textbook, plus independent re-derivations.

- **Worked-example KATs from Katz–Lindell 3rd ed.** (checked against book text):
  - Example 15.22: the square roots of 4 mod 15 are {2, 7, 8, 13}.
  - Example 15.30: √7 mod 29 = 23 (via 7⁴).
  - Example 15.33: √2 mod 17 = 6, with non-residue b = 3.
- **Exhaustive at toy N = 437 (19 · 23):**
  - For every x in Z*_N, `jacobi(x, N)` equals `legendre(x, 19) · legendre(x, 23)`. This is
    a different code path: Euler's criterion with the factors.
  - Counts: |Z*_N| = 396, |J+1| = 198, |QR_N| = 99, pseudosquares 99 (Proposition 15.23).
  - −1 is a pseudosquare.
  - Rule (a) succeeds for exactly half of all x in Z*_N.
  - These figures were computed for this brief; the test re-derives them and does not copy
    them.
- **Lemma 15.35 fixture at N = 437:** x = 2 (J = −1) returns m = 416, and
  gcd(414, 437) = 23 and gcd(418, 437) = 19.
- **Real-size N (seeded RNG in tests):**
  - Every root squared back equals c.
  - GM: decrypt(enc(b)) = b, decrypt(c₁c₂) = b₁⊕b₂, and decrypt(c · z) = ¬b.
  - Two encryptions of one bit differ.
  - Rule (b) refuses random x².
- **`e2e/claims.spec.ts` (§4.1b):**
  - Parse x, m and N from the Act 5 verdict and recompute gcd(m − x, N) in the test with its
    own BigInt code. Assert it equals the displayed factor and that the factor divides N.
  - Parse the game tally and assert it equals the rows it counts.
  - Retirement: changing x retires the old verdict, and the page says so.
- **§4.1c — one mutation per rendered verdict.** Each must turn a named test red. Run them
  from a script with concrete patches (verdict markers rule):
  1. Flip the sign step for n ≡ 3, 5 (mod 8) in `jacobi.ts`.
  2. Have the oracle return x instead of the QR root (the attack must then fail).
  3. Have GM decryption read J_N(c) instead of J_p(c) (every bit decrypts to 0).
  4. Make the verifier skip the multiply-back.
  5. Disable rule (b)'s redundancy check (the refusal test must fail).
  6. Hard-wire the game tally.
- **§4.1d negative claims**, each with its evidence fixture asserted green-then-violated:
  - **NEG-1:** "Rabin decryption that is correct, and a scheme whose one-wayness is proven
    equivalent to factoring, still give up the private key to one decryption query."
    - Fixture: rule (a). Every round-trip check is green, and the oracle's answer is a valid
      root (m² ≡ c).
    - Verdict: "DECRYPTED CORRECTLY — AND FACTORED".
  - **NEG-2:** "Goldwasser–Micali hides each bit from an eavesdropper but does not stop
    anyone flipping it."
    - Fixture: c · z decrypts cleanly to the other bit.
    - Verdict: "DECRYPTED — AND FLIPPED".

## Honesty notes for the page

- The arithmetic is real BigInt at real sizes. It is not constant-time.
- Toy grids are labelled toy-scale.
- GM is impractical: one element of Z*_N per plaintext bit. Show the ratio computed from
  the actual key.
- Katz–Lindell's comparison (§15.5.3): known chosen-ciphertext attacks on plain RSA recover
  messages, while the one on plain Rabin recovers the private key. The page says this in
  those words, scoped to the plain schemes.

## Links out (Related Demos)

- **Factor Forge** — what factoring looks like without an oracle. Its quadratic sieve keeps
  only primes where N is a residue.
- **Prime Witness** (same batch) — the nontrivial square root of 1 that factors N there is
  this lab's Lemma 15.35.
- **Hidden Bit** — the IND-CPA game GM was the first to satisfy.
- **Paillier Gate** — the other residuosity assumption.
- **Educational RSA** and **RSA Forge** — e coprime to φ(N), the sibling Rabin is not.
- **Accumulator**, **VDF** and **Time-Lock Puzzle** — QR_N and squaring as a group.

## Sources (verified 2026-10-20)

- Katz & Lindell, *Introduction to Modern Cryptography*, 3rd ed., CRC Press, 2021, ISBN
  9780815354369. §15.4–15.5, checked against the book text.
- S. Goldwasser, S. Micali, "Probabilistic encryption", *JCSS* 28(2):270–299, 1984.
  https://doi.org/10.1016/0022-0000(84)90070-9 — confirmed via
  https://people.csail.mit.edu/joanne/shafi-pubs.html
- M. O. Rabin, "Digitalized Signatures and Public-key Functions as Intractable as
  Factorization", MIT-LCS-TR-212, Jan. 1979. https://dspace.mit.edu/handle/1721.1/149499
- A. Menezes, P. van Oorschot, S. Vanstone, *Handbook of Applied Cryptography*, CRC Press,
  1996.
  - Algorithm 2.149 (§2.4.5): https://cacr.uwaterloo.ca/hac/about/chap2.pdf
  - Algorithms 3.34/3.36/3.44 and Fact 3.46: https://cacr.uwaterloo.ca/hac/about/chap3.pdf
  - Notes 8.13(ii), 8.14(ii) and Algorithms 8.50/8.51:
    https://cacr.uwaterloo.ca/hac/about/chap8.pdf
- D. Boneh, "Simplified OAEP for the RSA and Rabin functions", CRYPTO 2001, LNCS 2139,
  pp. 275–291. https://crypto.stanford.edu/~dabo/abstracts/saep.html
- L. Blum, M. Blum, M. Shub, "A simple unpredictable pseudo-random number generator", SIAM
  J. Comput. 15:364–383, 1986 (extension seam). https://cr.yp.to/bib/1986/blum.bibtex
- C. Cocks, "An Identity Based Encryption Scheme Based on Quadratic Residues", Cryptography
  and Coding 2001, LNCS 2260 (extension seam). https://doi.org/10.1007/3-540-45325-3_32
- H. C. Williams, "A modification of the RSA public-key encryption procedure", IEEE Trans.
  Inf. Theory 26(6), 1980 (extension seam) **[UNVERIFIED — publisher page did not load;
  check before use]**.
