# Varops primitives

Proposed reduced model; coefficients are not finalized. **NEW** means a separately modeled component absent from BIP440 before fixed execution costs. Existing classes remain marked **No** when renamed or refined; this does not imply their old coefficients remain sufficient.

Degree is the maximum polynomial degree in the specified size/count features: 0 constant, 1 linear (possibly with an intercept), 2 quadratic. `W(n)` rounds bytes up to a multiple of eight; `u,v` are limb counts.

| Primitive | Short description | Degree | NEW |
| --- | --- | --- | --- |
| `F` | Common evaluator overhead per executed opcode; NOP anchor. | 0 | Yes |
| `PREP(n)` | Numeric operand preparation: fixed setup plus traversal of `W(n)`. | 1 | Yes |
| `OUTPUT(n)` | Numeric result materialization and insertion, including small scalar results. | 1 | Yes |
| `COPY(n)` | Produce and insert a copied value, excluding its later destruction; extends COPYING with a constant. | 1 | No |
| `RELEASE(c)` | Remove an entry and release its allocated buffer; `c` is diagnostic capacity, not a consensus charge input. In-place shrinkage also needs a discarded-byte charge before the original size disappears. | 1 | Yes |
| `READ(n)` | Scan/compare bytes; COMPARING, COMPARINGZERO and LENGTHCONV. | 1 | No |
| `ARITH(n)` | Add/subtract traversal with carry/borrow, including kernel setup; ARITH. | 1 | No |
| `BIT(n)` | Bitwise and shift traversal; OTHER. | 1 | No |
| `MOVE(k)` | Move `k` stack entries without copying payloads; ROLL. | 1 | No |
| `MUL(u,v)` | Limb-cell multiplication work; previously derived from ARITH in BIP441. | 2 | Yes |
| `DIVCORE(s,v)` | Quotient trials: terms in trial count `s` and `s*v`; BIP441-derived work. | 2 | Yes |
| `H256(n)` | SHA256 initialization, processing and finalization; refines HASH. | 1 | No |
| `H160(n)` | RIPEMD160 initialization, processing and finalization; refines HASH. | 1 | No |
| `H1(n)` | SHA1 initialization, processing and finalization; refines HASH. | 1 | No |
| `SIG` | Signature verification; SIGCHECK, with no duplicate hash charges. | 0 | No |
| `TWEAK` | Public-key tweak operation. | 0 | Yes |
| `SIGHASH` | Fixed signature-message construction over prepared context; variable hashing separate. | 0 | Yes |
| `OP_TX_SELECT(k)` | OP_TX selector setup plus traversal of `k` selected records/items. | 1 | Yes |
| `MACRO_DECODE(n)` | Body-byte charge on OP_MACRO declarations and OP_CALLMACRO references; fitted from a GetOp scan diagnostic. | 1 | Yes |
| `FINAL` | Once-per-script final-check remainder after applicable PREP/READ work. | 0 | Yes |

## Composition rules

- Merge `B + COPY` into copied-value production and `SELECTOR + ITEM` into `OP_TX_SELECT`.
- Measure `RELEASE` separately from `COPY`; charge each relevant buffer lifetime once. For in-place shrinkage, charge discarded logical bytes before reducing the size, then charge the retained bytes when the value is later removed. Retained capacity is diagnostic, not a consensus-visible size.
- Remove standalone `ALLOC`: required allocation and growth belong to the relevant producer or operation, including scratch storage. Never omit or charge them twice.
- Try folding `SMALL` into `OUTPUT` and ordinary `LOCK` checker overhead into `F`; confirm complete opcode coverage. Lock operands still pay applicable preparation/scanning costs.
- Retain PREP and OUTPUT constants rather than inflating F for arithmetic. A fitted slope may be zero.
- Hashes compose: HASH256 uses `H256(n) + H256(32)`; HASH160 uses `H256(n) + H160(32)`. Add F and any result work not already covered.
- MACRO_DECODE must not duplicate scanning included in F measurements; inactive regions require separate coverage checks. FINAL is per script, not per opcode. Fixed-point SCALE is not a primitive.

Measure complete defined operations, including their storage lifetimes, then check compositions through `bench_varops`. Capacity and cache state are measurement conditions, never charge inputs. Prefer simple scaling and conservative coverage over exact fits to every timing fluctuation.

[Methodology](costing-methodology.md) · [Previous source audit and measurements](results/first-five-audit-20260922/README.md)
