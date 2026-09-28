# Varops primitives

Frozen calibration model **producer-normalize-v1**; coefficients are not finalized. It is the only implemented schedule; no build option is needed. **NEW** means a separately modeled component absent from BIP440 before fixed execution costs. Existing classes remain marked **No** when renamed or refined; this does not imply their old coefficients remain sufficient.

Degree is the maximum polynomial degree in the specified size/count features: 0 constant, 1 linear (possibly with an intercept), 2 quadratic. `W(n)` rounds bytes up to a multiple of eight; `u,v` are limb counts.

| Primitive | Short description | Degree | NEW |
| --- | --- | --- | --- |
| `F` | Common evaluator overhead per executed opcode; anchored by F-only groups (NOP, upgradable NOPs, CODESEPARATOR, ELSE, inactive flat/nested IF/ENDIF), with skipped NOPs as an unfitted diagnostic. | 0 | Yes |
| `PREP(n)` | Numeric operand preparation: fixed setup plus traversal of `W(n)`. | 1 | Yes |
| `NORMALIZE(n)` | Numeric result materialization only; allocation, insertion and release belong to PRODUCE. | 1 | Yes |
| `PRODUCE(n)` | Complete value creation/insertion/release lifetime; replaces COPY and RELEASE. | 1 | No |
| `READ(n)` | Scan/compare bytes; COMPARING, COMPARINGZERO and LENGTHCONV. | 1 | No |
| `ARITH(n)` | Word pass with a carry or borrow chain (add/subtract): each word waits for the previous one; ARITH. | 1 | No |
| `BIT(n)` | Word pass without a chain (bitwise logic, shifts): words are independent and vectorize; OTHER. Byte reversal is measured but priced by the covenant opcode BIP. | 1 | No |
| `MOVE(k)` | Move `k` stack entries without copying payloads; ROLL. | 1 | No |
| `MUL(u,v)` (`MULCORE` in data) | Complete multiplication: `a + b*u + c*u*v` over `u >= v` limbs, including internal scratch storage; the product is produced separately. | 2 | Yes |
| `DIVCORE(s,v)` | Complete prepared DIV/MOD, including normalization and scratch storage: constant + coefficient × `s` (per-row quotient estimate and correction) + coefficient × `s*v`. | 2 | Yes |
| `H256(n)` | SHA256 initialization, compression of each 64-byte block and finalization: `a + b*hashblockspan(n)`; refines HASH. | 1 | No |
| `H160(n)` | RIPEMD160 initialization, compression of each 64-byte block and finalization: `a + b*hashblockspan(n)`; refines HASH. | 1 | No |
| `H1(n)` | SHA1 initialization, compression of each 64-byte block and finalization: `a + b*hashblockspan(n)`; refines HASH. | 1 | No |
| `SIG` | Signature verification and fixed transaction-message preparation; SIGCHECK. | 0 | No |
| `TWEAK` | Public-key tweak operation. | 0 | Yes |

## Collection protocol

Run `python3 dev/varops/primitive-calibration/run_calibration.py` from the same clean, frozen commit on every machine (`python` on Windows). Defaults: 7 primitive epochs, 10 ms per batch, 100 ms for storage lifetimes; median, margin 1. Reference measurement retains 5 rounds, and normalization uses 100% of the local pre-v2 reference. Build uses up to 8 jobs; measurements remain serial. Progress is printed between fixtures approximately every 5 seconds.

Keep the existing fixture set, feature basis and 100× underprediction objective unchanged across machines. Preserve raw epochs. Repeat suspicious fixtures in separate processes before changing prices; isolated growth repeats do not replace mixed allocator-history coverage. These collection settings are a practical accuracy/runtime compromise, not a confidence guarantee. Combine only matching model/source/fixture sets; SIG remains fixed at 500,000. Validate any resulting schedule with `bench_varops` before adopting it.

## Postponed experimental extensions

Retain these implementation prices, fixtures and research; their finalization is outside the current BIP 440 model.

| Primitive | Short description | Degree | NEW |
| --- | --- | --- | --- |
| `OP_TX_SELECT(k)` | OP_TX selector setup plus traversal of `k` selected records/items. | 1 | Yes |
| `MACRO_DECODE(n)` | Body-byte charge on OP_MACRO declarations and OP_CALLMACRO references; fitted from a GetOp scan diagnostic. | 1 | Yes |

## Composition rules

- PRODUCE includes eventual release. Charge initial witness values once after immediate-success prescanning; do not charge moves, drops or in-place shrinkage as new producers.
- Numeric results pay `PRODUCE(W(n)) + NORMALIZE(n)`. MUL prepays full result/scratch production and only NORMALIZE at final output. DIVCORE includes its internal temporary storage. See the [storage ledger](storage-accounting.md).
- Remove standalone `ALLOC`: required allocation and growth belong to the relevant producer or operation, including scratch storage. Never omit or charge them twice.
- Scalar results use the same numeric-result formula. Ordinary LOCK checker overhead remains in F; operands still pay preparation/scanning costs.
- Retain PREP and NORMALIZE constants rather than inflating F for arithmetic. A fitted slope may be zero.
- `hashblockspan(n) = ((n + 72) / 64) * 64` is the padded message length processed by SHA1, SHA256 and RIPEMD160 (64-byte blocks, at least 9 bytes of padding and length). Each fixture size is fitted at its hash block span; a tagged SHA256 call counts `hashblockspan(6) + hashblockspan(64 + n)`.
- Hashes compose: HASH256 uses `H256(n) + H256(32)`; HASH160 uses `H256(n) + H160(32)`. Add F and any result work not already covered.
- Postponed macro research: MACRO_DECODE must not duplicate scanning included in F measurements; inactive regions require separate coverage checks.
- Final success checking pays PREP + READ once per script, with no separate FINAL primitive. Retain complete final-check timings as a composition diagnostic. Fixed-point SCALE is not a primitive.

Measure complete defined operations, including their storage lifetimes, then check compositions through `bench_varops`. Capacity and cache state are measurement conditions, never charge inputs. Prefer simple scaling and conservative coverage over exact fits to every timing fluctuation.

[Methodology](costing-methodology.md) · [Previous source audit and measurements](results/first-five-audit-20260922/README.md)

## Frozen collection and fitting

Run `run_calibration.py` without arguments. It builds a Release tree, collects only these 15 families (SIG stays a 500,000-unit policy price), preserves held-out lifetime checks and exports opcode compositions. OP_TX/macros and removed primitives remain available only through historical/focused probes.

From the checkout root, run `python3 dev/varops/primitive-calibration/run_calibration.py` (`python` on Windows). No arguments or environment variables are needed. In the research workspace, the result is `data/varopsData/primitive-calibration/producer-normalize-v1/varop-calibration.json`; in other checkout layouts it is `dev/varops/primitive-calibration/varop-calibration.json`. The runner prints the destination at startup and completion. Preserve each machine's result under a distinct filename before collecting another run; a successful run replaces that machine's previous output. Intermediate measurements stay under `calibration-intermediate/`.

Use the existing group/size-decade balanced squared-log fit with 100× underprediction penalty, predetermined nonnegative affine terms (F/TWEAK constant; DIVCORE fixed + rows + cells, with schedule maxima also taken over its fixed + cells fit). Normalize to `40B / (0.9 · T_pre)`: fits target 0.9× each machine's pre-v2 reference, and complete scripts must stay below the 1.0× hard limit. `fit_calibrations.py` derives this rate from each artifact's recorded `T_pre`, so artifacts collected at another target are rescaled rather than edited. Existing implementation coefficients are not automatically repriced. Keep fitted decimals; rounding is a later schedule-adoption step. Do not combine different model IDs, fixture sets or source revisions.

### Combination rule

Keep existing per-machine fits frozen when adding machines. For each predefined term use the maximum normalized coefficient across machines; this cannot lower a coefficient on machine-set expansion. Do not use the pooled joint fit for prices. Preserve it as a comparison. Per-machine underprediction can remain; whole-script checks are still decisive. SIG remains a fixed policy exception.

### Schedule rounding

After taking coefficientwise maxima across independent normalized machine fits, round fixed coefficients upward to multiples of **50 varops** and variable coefficients upward to **whole varops**. Zero and exact multiples stay unchanged. SIG stays **500,000**. Preserve raw decimal coefficients and measurements, report the rounding uplift, and do not refit after rounding. For example, `433.61 + 56.76 hashblockspan(n)` becomes `450 + 57 hashblockspan(n)`. Small slopes can increase substantially (e.g. PREP's `0.159540` becomes `1`); show this explicitly. Validate the resulting opcode compositions with `bench_varops` on every machine before finalization. Upward rounding is not an upper-bound guarantee.

The provisional 2026-09-28 implementation and BIP draft use the four-machine, seven-epoch maximum-coefficient schedule at the 0.9× target in `data/varopsData/0.4.0/joint-calibration.json` with this rule. M4's recorded benchmark-source hash discrepancy remains unresolved; new rounded prices still need multi-machine complete-script confirmation. Historical raw artifacts remain unchanged. PRODUCE/NORMALIZE is the only implemented storage schedule; postponed OP_TX/macro prices are unchanged.

Sampling includes empty/tiny values, word and power-of-two boundaries and known allocator-transition neighbours. ARITH separately measures carry-chain and full-borrow-chain inputs with equal/one-word second operands. Fixture preparation is outside kernel timers. Model-identification measurements are not full-workload confirmation.
