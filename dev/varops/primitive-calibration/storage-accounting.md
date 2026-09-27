# Frozen candidate: storage accounting

`producer-normalize-v1` uses the producer-lifetime implementation flag. The PRODUCE/NORMALIZE replacement is isolated from ordinary builds; DIVCORE repricing and removal of DISCARD, FINAL and SIGHASH charges apply to both builds. Published prices are not changed by this research checkout. A production event is a specified semantic value/result, not each allocator call. Reuse may conservatively pay production again; capacity never enters a charge.

| Path | Production/lifetime accounting | Other work / check |
|---|---|---|
| Initial witness values | PRODUCE once per item after immediate-success prescan | Empty items included; early success bypass unchanged |
| Literal/scalar push | PRODUCE(bytes); scalar uses NUMERIC_RESULT(8) | Fixed opcode cost; numeric materialization for scalar |
| DUP/OVER/PICK/TUCK families | PRODUCE once per new copy | Count conversion or truth check as applicable |
| DROP/NIP/2DROP, final cleanup | No separate release | Lifetime funded by original producer |
| ALTSTACK, SWAP/ROT/ROLL | No new production | MOVE prices ownership/header changes |
| CAT growth | PRODUCE(full result), even if allocation reused | Inputs were funded independently; growth is not free |
| SUBSTR | PRODUCE(result) once | Index PREP/READ; source/index release already funded |
| LEFT/RIGHT shrink | No new lifetime | RIGHT pays byte movement; original producer funds retained capacity |
| Numeric/bit results, comparisons, MIN/MAX | NUMERIC_RESULT(n) = PRODUCE(W(n)) + NORMALIZE(n) | PREP/kernel work separately; no second RELEASE |
| MUL | PRODUCE(full result span) + PREP(result span) + PRODUCE(scratch row) before kernel | Row/accumulation kernels exclude these allocations; only NORMALIZE at output |
| DIV/MOD | DIVCORE includes internal scratch and normalization | External result uses NUMERIC_RESULT; do not add kernel scratch again |
| Hash/key result | PRODUCE(digest/key bytes) | Hash/tweak helper writes prepared output; does not insert on stack |

The numeric output production is a conservative semantic charge even when the input allocation is reused. This is distinct from accidentally charging both an explicit RELEASE and a lifetime-inclusive PRODUCE. PREP tight-capacity growth is checked by finite source-to-result lifetimes, not an allocator-dependent extra formula. Known lifetime-fit underpredictions remain evidence to validate across machines; this ledger alone does not prove timing coverage.

Regression checks: `producer_lifetime_accounting` covers initial values, empty values, moves/drops, shrinkage and multiplication preflight; `producer_composition_boundaries` covers CAT, SUBSTR, ADD carry growth and SUB borrow shrinkage with exact and one-short budgets around byte/word/allocation boundaries. `bench_varops --verify-costs` checks independent formulas and exact budgets across generated scripts.

OP_TX/macros are postponed. Their experimental storage paths and existing prices are not finalized by this audit.
