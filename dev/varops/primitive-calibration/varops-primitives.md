# Varops primitives

Frozen calibration model **producer-normalize-v1**; coefficients are not finalized. Collection uses the producer-lifetime build, not the ordinary schedule. **NEW** means a separately modeled component absent from BIP440 before fixed execution costs. Existing classes remain marked **No** when renamed or refined; this does not imply their old coefficients remain sufficient.

Degree is the maximum polynomial degree in the specified size/count features: 0 constant, 1 linear (possibly with an intercept), 2 quadratic. `W(n)` rounds bytes up to a multiple of eight; `u,v` are limb counts.

| Primitive | Short description | Degree | NEW |
| --- | --- | --- | --- |
| `F` | Common evaluator overhead per executed opcode; NOP anchor. | 0 | Yes |
| `PREP(n)` | Numeric operand preparation: fixed setup plus traversal of `W(n)`. | 1 | Yes |
| `NORMALIZE(n)` | Numeric result materialization only; allocation, insertion and release belong to PRODUCE. | 1 | Yes |
| `PRODUCE(n)` | Complete value creation/insertion/release lifetime; replaces COPY and RELEASE. | 1 | No |
| `READ(n)` | Scan/compare bytes; COMPARING, COMPARINGZERO and LENGTHCONV. | 1 | No |
| `ARITH(n)` | Add/subtract traversal with carry/borrow, including kernel setup; ARITH. | 1 | No |
| `BIT(n)` | Bitwise and shift traversal; OTHER. | 1 | No |
| `MOVE(k)` | Move `k` stack entries without copying payloads; ROLL. | 1 | No |
| `MULROW(v)` (`MUL` in data) | One row: `a + b*v`; full multiplication invokes this `u` times and separately charges accumulation. | 1 | Yes |
| `DIVCORE(s,v)` | Complete prepared DIV/MOD, including normalization and scratch storage: constant + coefficient × `s*v`, with no separate per-step term. | 2 | Yes |
| `H256(n)` | SHA256 initialization, processing and finalization; refines HASH. | 1 | No |
| `H160(n)` | RIPEMD160 initialization, processing and finalization; refines HASH. | 1 | No |
| `H1(n)` | SHA1 initialization, processing and finalization; refines HASH. | 1 | No |
| `SIG` | Signature verification and fixed transaction-message preparation; SIGCHECK. | 0 | No |
| `TWEAK` | Public-key tweak operation. | 0 | Yes |

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
- Hashes compose: HASH256 uses `H256(n) + H256(32)`; HASH160 uses `H256(n) + H160(32)`. Add F and any result work not already covered.
- Postponed macro research: MACRO_DECODE must not duplicate scanning included in F measurements; inactive regions require separate coverage checks.
- Final success checking pays PREP + READ once per script, with no separate FINAL primitive. Retain complete final-check timings as a composition diagnostic. Fixed-point SCALE is not a primitive.

Measure complete defined operations, including their storage lifetimes, then check compositions through `bench_varops`. Capacity and cache state are measurement conditions, never charge inputs. Prefer simple scaling and conservative coverage over exact fits to every timing fluctuation.

[Methodology](costing-methodology.md) · [Previous source audit and measurements](results/first-five-audit-20260922/README.md)

## Frozen collection and fitting

Run `run_calibration.py` without arguments. It builds with `GSR_PRODUCER_LIFETIME_EXPERIMENT`, collects only these 15 families (SIG stays a 500,000-unit policy price), preserves held-out lifetime checks and exports opcode compositions. OP_TX/macros and removed primitives remain available only through historical/focused probes.

The portable result is `data/varopsData/primitive-calibration/producer-normalize-v1/varop-calibration.json`. For another checkout layout, set `VAROPS_DATA_DIR` to the data directory first (including on Windows). Preserve each machine's result under a distinct filename before collecting another run; a successful run replaces that machine's previous output. Intermediate measurements stay under `calibration-intermediate/`.

Use the existing group/size-decade balanced squared-log fit with 100× underprediction penalty, predetermined nonnegative affine terms (F/TWEAK constant; DIVCORE fixed + cells). Normalize new datasets to `40B / T_pre` with acceptance below 1×; no additional 0.9 conversion. Existing implementation coefficients are not automatically repriced. Keep fitted decimals; rounding is a later schedule-adoption step. Do not combine different model IDs, fixture sets or source revisions.

Sampling includes empty/tiny values, word and power-of-two boundaries and known allocator-transition neighbours. ARITH separately measures carry-chain and full-borrow-chain inputs with equal/one-word second operands. Fixture preparation is outside kernel timers. Model-identification measurements are not full-workload confirmation.
