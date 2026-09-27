# Varops costing methodology

Working method, not an accepted consensus schedule. Revised 2026-09-22 after inspecting `bench_varops_primitives.cpp`, the evaluator, and the frozen September 20 candidate. We calibrate shared work primitives, compose opcode prices from them, then challenge those prices with realistic `bench_varops` scripts. This revision defines the next calibration procedure; the existing executable does not yet implement all of it. Earlier results remain evidence, not fresh confirmation.

See [varops-primitives.md](varops-primitives.md) for each primitive's meaning, function type, production call, sampling grid and current measurement gaps.

**2026-09-26 frozen collection contract:** [producer-normalize-v1](varops-primitives.md#frozen-collection-and-fitting) supersedes the historical registry and descriptive-fit procedure below for new calibration runs. Use PRODUCE + NORMALIZE, the existing 100× underprediction objective, and `40B / T_pre` normalization (no extra 0.9 factor); SIG remains 500,000. The [storage ledger](storage-accounting.md) defines production events. Preserve prior datasets as comparisons rather than mixing model versions. New fits do not automatically overwrite implementation prices.

**Scope:** OP_TX and macro finalization, including their specialized costing, are postponed. Retain their implementation, fixtures and research; references to them in the registry and historical checklist below are research-only, not prerequisites for BIP 440. The general objective of supporting script compression remains in scope without specifying particular compression opcodes.

## Objective

Permit more expensive operations and script compression (for example, reusable bodies) without creating a slower *feasible script-evaluation workload* than the slowest known pre-v2 reference, `T_pre`, on the same machine. A workload's scripts, witnesses, and transactions must satisfy the relevant consensus size, weight, and execution limits; those limits constrain what can be repeated, but **block validation is not timed**. Freeze a pre-v2 script-workload panel and a **pinned pre-upgrade reference build**; define `T_pre` as the maximum of their repeated per-workload script-evaluation timing estimates, never the largest single run. Include any operand restoration executed by their scripts. Measure the same panel on the candidate build as a legacy-regression check, but do not let a candidate slowdown raise `T_pre`. Changing the reference build or panel requires an explicit methodology revision. `T_pre` is empirical, not proof of the absolute pre-v2 maximum.

Count every logical execution, including repeated invocations of a body stored once. The target is a true candidate/reference **script-evaluation** runtime ratio of at most 1.0 on **each** measured machine, with no averaging across machines. A reproducible slower feasible workload rejects the schedule; one noisy observation above 1.0 calls for investigation, not an immediate verdict. This narrower target does not establish a bound on full transaction or block validation. Finite tests cannot prove the bound for every script or future processor. Declare engineering headroom for genuinely new work before final pricing; document deliberately preserved parity cases separately, without assuming an arbitrary universal margin.

## Construct the price from shared work

Before fitting, describe an opcode as a sum of applicable components:

```text
opcode cost = fixed execution + setup/result work
            + copying + numeric traversal/comparison + hashing
            + any justified quadratic or collection-item work
```

Use the same coefficient for the same primitive in different opcodes. An opcode may have a separately identified fixed path or operation-specific primitive, but do not add an unexplained surcharge merely to repair its fitted curve. For each component, specify what is counted, when it is charged, and which operations use it. A zero-byte item may still incur item or allocation work; bytes alone do not always describe traversal. OP_TX therefore needs transaction-backed tests of both byte and item counts.

Declare the initial feature basis from implementation analysis before fitting: fixed, linear, or justified quadratic terms. New features require a causal explanation, a versioned model revision, and fresh confirmation, not merely a better fit. For numeric code, `W(n) = 8 ceil(n/8)` is rounded **bytes**, not a word count. Distinguish `max(W(a),W(b))`, `W(a)+W(b)`, and products by the algorithm and unequal-operand measurements. Consensus charges must be deterministic functions of specified semantics and script-visible operands, results, or transaction context; precisely specified value-dependent branches are allowed. Buffer capacity, cache hits, backend choice, and actual traversal/allocation counts are diagnostic states, **not** portable charge inputs. Keep the model simple even when those states cause timing steps. A diagnostic fit does not establish that its coefficient is the causal price of a primitive.

The published BIP schedule (v0), current local BIP schedule (v1), and research candidate must remain separate in tables and plots. No coefficient changes consensus until the complete model is validated and deliberately adopted.

### Primitive registry and predetermined formulas

A primitive is a process, not a coefficient: a fixed term and a byte term can describe one process. Keep the fewest independently measurable processes that explain the implementation. Merge identical work across opcodes; do not merge different work merely because its current timings are similar. Conversely, if fixtures cannot distinguish two coefficients, measure another independent control or retain their combined process instead of assigning arbitrary separate prices.

Use only the declared basis below. `a`, `b`, etc. are nonnegative fitted coefficients, independently named for each row unless explicitly shared. Degree means degree in the declared features: rounding a byte length with `W`, taking `max`, or counting selected items is part of the feature definition, not a freely fitted curve. A zero fitted slope does not authorize changing the declared affine model to a constant in the next run.

| Process / existing name | Predetermined formula; degree | Measurement and boundary |
| --- | --- | --- |
| Interpreter execution `F` | `a`; 0 | Slope against logical instruction count in long cheap-op scripts. Separate per-evaluation startup/finalization and known producer terms; do not assign the entire cost of a push/drop sequence to dispatch. |
| Copied-entry production `B + COPY(n)` | `a + b*n`; 1 | Time copied-value creation and insertion, excluding later destruction; `B` is the intercept, not another charge on top. |
| Buffer release `RELEASE(c)` | `a + b*c`; 1, diagnostic | Time entry removal and buffer destruction separately, including values whose logical size is small but retained capacity `c` is large. Capacity cannot be a consensus charge input; decide where its cost is amortized before adopting a schedule. |
| Rvalue insertion `ALLOC(n)` | `a + b*n`; 1 | Production insertion with tight and rounded capacities; include any growth performed by insertion. This is not a measurement of arbitrary buffer allocation. Separate byte-equality assertions from timing. |
| Numeric preparation `PREP(n)` | `a + b*W(n)`; 1 | Production ownership/conversion path under the declared entry-capacity invariant. Tight inputs check complete producer-to-consumer coverage; they are not silently discarded. |
| Numeric result `OUTPUT(n)` | `a + b*W(n)`; 1 | Materialization plus insertion, including byte compaction where performed. Do not also add `ALLOC` for the same insertion. |
| Bounded scalar result `SMALL` | `a`; 0 | Actual scalar result path across its bounded value domain. Keep separate only if it bypasses the general result path. |
| Scan / comparison `READ(s)` | `a + b*s`; 1 | Shared full-scan measurements for zero tests, equality/order comparison and normalization; specify each caller's scan span and number of calls and assess each path's fit. |
| Add/sub kernel `ARITH(s)` | `a + b*s`; 1 | Separately time prepared `AddSpans` and `SubtractSpans`, sharing one fitted function. Include carry/borrow and unequal lengths. |
| Bit traversal `BIT(s)` | `a + b*s`; 1 | Prepared bitwise/shift/reversal paths. Ensure repeated mutation does not turn the fixture into a cheaper all-zero/empty path. |
| Stack-header movement `MOVE(k)` | `a + b*k`; 1 | `Roll` over varied depths with payload bytes held separately; no payload copying. |
| Multiply row `MULROW(v)` (replaces bare `mu`) | `a + b*v`; 1 | Production `MultiplySpan`, including its carry writes. Row overhead and limb throughput are measured separately. |
| Multiplication `MUL(u,v)` | Derived, degree at most 2 | For the present schoolbook kernel, `u * (MULROW(v) + ARITH(8*(v+1)))`, with `u >= v`. Add the separately identified setup, scratch/result storage and normalization work. No independently fitted opcode coefficient. |
| Quotient estimate / correction `DIVSTEP` | `a`; 0 | Isolate bounded scalar trial work, including correction cases. Timing all of `OpDiv` is a composition check, not this primitive. |
| Division / modulo `DIVCORE(s,v)` | `a + c*s*v`; 2 | Bundled complete prepared DIV/MOD call, including normalization and scratch storage. Do not also charge its internal MUL/ARITH/storage work. Use the BIP441 operand-derived `s,v`, not measured loop counts. Compare the reduced fit against `a+b*s+c*s*v` as a diagnostic. |
| SHA-256 `H256(n)` | `a + b*n`; 1 | Production init/write/finalize, with Core and relevant libsecp paths separately labelled. Padding boundaries are samples, not fitted breakpoints. |
| RIPEMD-160 `H160(n)` | `a + b*n`; 1 | Same boundary; use each caller's legal domain, including the 520-byte direct-op limit. |
| SHA-1 `H1(n)` | `a + b*n`; 1 | Same boundary and direct-op size limit. |
| Signature allowance `SIG` | Fixed 500,000; 0 | Covers verification and fixed transaction-message preparation. Curve/challenge-hash timing remains diagnostic; no separate message-preparation primitive. |
| Public-key tweak `TWEAK` | `a`; 0 | Full fixed-size production tweak operation. |
| Lock checks `LOCK` | `a`; 0 | Real locktime/sequence checks over prepared context. |
| OP_TX planning/traversal `SELECTOR + ITEM(k)` | `a + b*k`; 1 | Joint measurement of selector and specified selected/result items, with byte/result production independently accounted. Empty-item probes alone cannot separate traversal from allocation and cleanup. |
| Decode `DECODE(n)` | `a + b*n`; 1 | Actual parser/scanner over dense opcodes and pushes. Separate once-per-script prescan from repeated execution decoding; neither may overlap with `F` unnoticed. |
| Fragment reference `REF` | `a`; 0 | Actual cursor/reference transition, excluding the body operations and separately counted scans. Current probe reports this unavailable despite the live fragment implementation. |
| Final success `FINAL` | `a`; 0 | Fixed remainder of the final check after the specified `PREP + READ` work. Retain total final-check measurements and verify the complete sum. |

This is a starting registry, not a claim that all its coefficients are identifiable or necessary. Three formerly proportional probes (`READ`, `BIT`, `MOVE`) become affine so tiny-fixture call time cannot set a universal byte/item rate. Their intercepts belong to those helper calls, not another copy of interpreter `F`. COPY and RELEASE have separate timing boundaries; neither is a pure memory-copy coefficient.

Before freezing this registry, resolve storage ownership: identify where scratch allocation, entry growth, payload release and outer-stack relocation are covered. Prefer existing complete-lifetime families when their boundaries match. Add a separate fixed/linear storage process only if existing families cannot cover the work without double counting. Likewise, measure script entry as a control; introduce a separate degree-0 entry charge only if short-script workloads demonstrate a missing cost. Do not hide either issue in every opcode's `F`.

### Compose from a source-path ledger

For each opcode, record the exact source calls, primitive multiplicities, input/result-size features, branches, charge timing and storage ownership. Derive these before looking at that opcode's timing. An independent charge calculator must agree with the meter, but that agreement alone does not establish that the ledger covers the work.

Examples to audit are `HASH160 = F + H256(n) + H160(32) + digest production`, and `ADD = F + PREP(a) + PREP(b) + ARITH(max(W(a), W(b))) + result/growth work`. Resolve the last terms from their actual producer paths rather than replacing them with an unexplained opcode surcharge. Fixed kernel overhead is allowed even for a one-byte operand; it must correspond to work actually measured.

For quadratic operations, derive counts from deterministic operand features, including padded values, fast paths, normalization growth and bounded quotient corrections. Charge a conservative size bound before superlinear work. A result length only known afterward cannot be used to justify that preflight. `DIVCORE` is calibrated as one bundled process; verify its composition with PREP, PRODUCE and NORMALIZE through complete DIV/MOD scripts.

## Measurement contract and components

Declare these boundaries, including the concrete call sites, before collection:

| Level | Timed work | Use |
| --- | --- | --- |
| Component | Prepared operands are allowed; include everything the measured operation performs. | Identify shared work and candidate coefficients. |
| Complete script | Time direct `EvalScript` plus its clean-stack/truth check (pre-v2), or `EvalTapscriptV2` plus `CheckTapscriptV2ScriptResult` (v2), including interpreter parsing, fragment prescan, metering, execution, and final-result checks. | Test composition and accept or reject the script-evaluation runtime claim. |
| Script sequence | Time the sum of the same evaluator calls for a feasible multi-script workload, sharing a budget where required. | Test cross-script state and budget effects without timing node validation. |

Prepare initial stacks, checkers, transaction context, and budgets outside these timers; exclude harness-owned fixture creation/destruction, Taproot commitment checks, transaction checks, and block plumbing. Include work performed *inside* the called evaluator, notably fragment OP_SUCCESS prescanning even though it is unmetered. Measure fixture construction and full storage lifetimes separately where needed for the memory-safety study; do not claim that script-only timings cover them.

Use `bench_varops_primitives` for direct production-helper probes and interpreter controls, and `bench_varops` for complete scripts. Prepared operands belong outside the diagnostic timer; conversion, allocation, copying, cleanup and stack/result updates performed by the measured process belong inside. Keep correctness checks and fixture comparisons outside timing, retaining only the observation barriers required to prevent optimization. Do not subtract `OP_NOP` dispatch from an opcode's price. A matched control may identify harness overhead only when ownership, iteration and cleanup match; retain both raw timings. Do not let existing varops prices determine diagnostic duration or iteration count. The finite budget remains relevant to complete-script acceptance.

Record source and binary hashes, build and crypto backend, CPU, exact fixture, operand bytes and values, vector capacity, surrounding stack, timing protocol, raw independent runs, exclusions, and same-machine `T_pre` before and after collection. Run samples serially, randomize case order, and repeat noisy or surprising cases with neighbors. Keep failed and unresolved timings visible. Invoke the evaluator directly, so script-validation caches cannot bypass it; signature fixtures must perform the intended cryptographic work. In a separate instrumented run, verify instruction and cryptographic-verification counts, initial/consumed budget, and termination reason; time the corresponding ordinary build without intrusive tracing. Hardware-cache state remains a measurement dimension.

Sample densely near zero, word/algorithm boundaries and legal endpoints, then logarithmically over larger sizes. For two operands, include equal, unequal in both orders, and one fixed while the other varies; include values that exercise carry, normalization, zero, and other relevant branches. Test ambient stack depth/bytes, capacity, hardware-cache state, and lifetime separately where they affect timing. The grid must distinguish the proposed components; otherwise a fitted decomposition is not identifiable.

For a repeatable state requiring no uncharged per-iteration work, a timing `t` gives a **diagnostic** charge requirement `40,000,000,000 × t / T_pre`. A fixture used as a hard recurring-work constraint must have a feasible script construction that recreates its relevant state; host-language resets do not suffice. Repeating a fresh allocation or preloaded operand may not fit within consensus weight and stack limits, so this projection alone neither accepts nor rejects a cost.

Do not predict a restoration loop by simply adding timings from separate one-opcode evaluator calls: that can repeat script entry/finalization and combine incompatible buffer/cache states. Sum the proposed primitive charges, then test their total against measured complete loops. Matched loops can help locate a discrepancy, but their difference is not automatically a uniquely identified primitive. Record restoration explicitly: `DUP SHA256 DROP` costs all three operations; multiplying the hash's cost by its fraction of instructions is incorrect. Also test reusable/state-preserving bodies that need less restoration.

Before final fitting, implement and declare the bounded-memory evaluator policy to be priced, including compaction, reclamation, and temporary storage. Measure finite sequences that create/duplicate large values, truncate or normalize them, retain small results under stack pressure, then consume/drop them; probe growth and shrinkage around policy thresholds. An amortized charge may cover compaction and cleanup, but its argument must include initial witness-backed state, transient peaks, and final reclamation. Untimed fixture setup cannot supply free allocation history. Set and test a separate implementation peak-memory bound; meeting the time target alone is insufficient.

## Fit, then challenge the composition

The current task is an accurate descriptive timing model. Follow the [fit rule and quality gate](varops-primitives.md#fit-rule-and-quality-gate): minimize weighted squared log ratios, `sum(w_i * ln(predicted_i/measured_i)^2)`, using only the predefined basis and nonnegative coefficients. Give size decades and path variants balanced weight. Fit median timings separately per machine; preserve raw repeatability data. There is **no** requirement to sit above every point, no safety multiplier, and no rounding in this fit.

For now, a useful fit has multiplicative RMS error at most 1.10 and at least 95% of predictions within a factor of 1.25, checked within each size decade/path rather than only globally. The linked rule specifies sparse groups, fresh checks and residual models. These are provisional model-quality thresholds, not a consensus safety guarantee. Report all discrepant points; a reproducible difference between paths may mean that the shared feature model cannot describe them accurately. Investigate before adding coefficients or changing its degree.

Fit direct processes first. For composite probes, keep independently measured components fixed and estimate only identifiable remaining terms; assess the complete predicted process. Do not log-fit negative residuals or clip them to zero and claim free work. If two costs cannot be separated, retain their combined measurement.

Only after the descriptive fits are adequate, normalize candidate rates by `40,000,000,000 / T_pre(machine)` and construct a common schedule. That later schedule must satisfy complete-workload checks on every machine, without averaging away slower machines. The method for selecting its headroom remains a separate decision; the old automatic 1.15 multiplier is not part of this fit rule. A mean/median fit alone does not bound execution time.

When producing a schedule, preserve fractional rates using `q_j = ceil(Q * theta_j)`, initially `Q = 1,000,000`; use checked accumulation and the declared opcode-level rounding, including staged precharges. Keep the unrounded fit visible. Recheck rounded charges and overflow bounds. Freeze the model, evaluator memory policy, reference panel/build and comparison protocol before fresh confirmation; previously inspected data are development evidence.

The decisive check is the **sum of costs and measured script-evaluation time of whole, feasible workloads** under the actual metered evaluator. Search for the largest evaluator runtime, not the highest isolated time/varop ratio. Include preloaded witness operands, restoration, reusable bodies, OP_MULTI, OP_TX, mixed input versions, short-operand repetition, costly state lifetimes, and low-varops work dominated by interpreter decoding, inactive regions, or fragment prescanning. For each family state its limiting resources and search sizes and mixtures under those limits; a case need not approach both weight and varops limits. Also test sequences of distinct feasible scripts in one persistent process, alongside fresh-process runs, so allocator retention is not reset away. Check whether measured components predict complete evaluator sequences; cross-opcode effects can break additivity, while a sequence total alone cannot identify which primitive to raise.

Use serial evaluation for this calibration. Parallel block scheduling and shared-budget contention are outside its runtime claim; retain separate correctness tests for shared-budget accounting.

### Confirmation decision rule

Freeze the machine/workload panel before confirmation; exploratory cases and earlier fit checks are not confirmation samples. One independent run is a fresh-process session timing the declared evaluator call or script sequence, with fixtures prepared outside its timer. For sustained-operation tests, each session instead runs the same declared sequence of *distinct* feasible scripts in a persistent process; analyze its predeclared sum of evaluator times. Interleave candidate and pinned-reference sessions in randomized order. Set the number of sessions from pilot variability **before** confirmation, with at least 30 per workload; do not stop when a desired result appears. A technical exclusion must follow a predeclared rule, not a slow time. Check session drift and correlation; if independence is untenable, the interval procedure is not valid and the comparison remains unresolved.

For each workload, `T` is the median of its independent session times. On each machine, `T_pre` is the maximum `T` over the frozen pre-v2 panel, and `R = T_candidate / T_pre` for each candidate. Form exact binomial/order-statistic lower and upper median bounds for **every** reference and candidate workload in the frozen acceptance family. With `K` such medians across all machines, allocate `0.05/(2K)` error probability to each tail; this gives at least 95% simultaneous coverage by the Bonferroni inequality. If `L` and `U` denote those bounds, use:

```text
L_pre = max(reference L); U_pre = max(reference U)
R interval = [candidate L / U_pre, candidate U / L_pre]
```

Pass a measured configuration only if every candidate interval has upper end `≤ 1`; a lower end `> 1` demonstrates failure; otherwise it is unresolved. Investigate any observed ratio above 1 even before an interval resolves. Report every interval and unresolved case; do not stop early or relabel an old holdout. Repeated confirmation campaigns for the same candidate require a predeclared error budget across attempts, rather than selecting whichever run passes. This conservative rule handles uncertainty in both timings and selection of the slowest reference, but only for the frozen finite panel under repeatable session conditions—not undiscovered scripts, machines, or implementation changes. The [order-statistic median bounds](https://vsp.pnnl.gov/help/Vsample/Test_Sub_page_for_CI_on_a_Mean.htm) use the binomial distribution; [Bonferroni's rule](https://itl.nist.gov/div898/handbook/prc/section4/prc473.htm) gives simultaneous coverage.

Separately, test **evaluator rejection paths**: budget exhaustion at operation boundaries, oversized results, late decoding or final-stack failures. Bound evaluator work and temporary memory before rejection, including allowed linear postcharge work. These tests do not redefine the successful-script `T_pre` objective and are not successful-opcode fitting samples.

Preserve raw runs and candidate revisions. If a case fails, fix the measurement or model, then obtain a *new* holdout; do not relabel the failing case as independent validation after refitting. Test at least one materially different backend or allocation path before committing to the feature basis; final validation still requires multiple machines and implementation paths. It is not complete merely because the current two-machine plots look good.

## Evidence and current status

The [September 20 candidate](results/revised-candidate-20260920/primitive-and-opcode-costing.md) and [run notes](results/revised-candidate-20260920/README.md) stay frozen. Exact formula parity demonstrates accounting agreement, not timing coverage or causal decomposition. The overview's raw fitting samples were not retained; its later fit-deviation rerun is a different dataset. Recoverable summaries cannot replace fresh raw collection.

Source review on 2026-09-22 found these concrete issues to resolve:

- `EstimateAllocation` times `Require` calls, including full output/source equality, along with insertion. That adds benchmark-only work, including a byte scan. Remeasure before interpreting `ALLOC.byte` as an insertion rate.
- `EstimateCopy` times copy **and pop/destruction**. Its slope need not be pure copying; cross-use in other producers needs a separate control and a lifetime ledger.
- `EstimateFixed` takes the maximum time/instruction over cheap scripts including empty pushes; those producers also receive `B` elsewhere. Separate entry/final costs and overlapping producer work before calling the result universal dispatch.
- `LinearRate` assigns the maximum time/unit to `ZERO`, `READ`, `BIT` and `MOVE`; a tiny fixture can embed fixed call work in every byte/item. Apply the registered affine bases instead.
- `EstimateMulDiv` measures only `MultiplySpan` for `mu`, while production multiplication also runs `AddSpans` for each row, allocates/initializes scratch and result storage, and trims the result. Current `OP_MUL` accounting has `mu*u*v` plus preparation/output, without explicit repeated `ARITH` coverage. This is a composition gap to measure, not yet a demonstrated runtime-limit failure.
- The same estimator measures complete `OpDiv` for `delta`, whereas the candidate adds `delta*steps + mu*steps*divisor_limbs`. The measured boundary overlaps the separately charged multiplication and does not isolate quotient estimation. It also samples only one-/two-/three-limb divisors.
- `EstimateItems` measures full `EvalOpTx` plus output cleanup, including the current meter and result production; the opcode formula adds `F`, `ALLOC` and other terms separately. Its selector/item fit is a bundled allowance, not isolated traversal. The non-collated visit count in its comment also differs from the executable count.
- `EstimateCall` reports static fragments unavailable, but the live evaluator implements them. `EstimateDecode` only exercises dense NOP bodies despite its broader comment. Measure actual prescan/reference paths and audit overlap with per-opcode parsing.
- `FINAL` and `SIG` use residuals after fitted allowances; a zero residual means coverage by that decomposition, not absence of work. `OUTPUT.byte = 0` similarly does not prove size-independent output for all paths.

### Ordered calibration TODO

1. [ ] **Freeze a pilot contract.** Record source/build/backend, evaluator entry/end points, capacity/cleanup policy, reference panel/build, raw artifact schema and workload limits. Confirm the reference and candidate use equivalent script-only timing boundaries. Keep all new artifacts under `dev/varops/primitive-calibration/`.
2. [ ] **Finish the primitive registry.** Resolve overlapping storage/cleanup terms and shared READ/zero-test coverage; decide which scalar/result and selector/item terms can be merged. Declare every basis and unit in a machine-readable manifest. Do not collect the full corpus until ambiguous boundaries are resolved.
3. [ ] **Complete the opcode ledger.** Map all executed paths, initially the restored opcodes and OP_TX plus their stack/hash/control dependencies. Derive full MUL/DIV/MOD compositions, normalization/correction bounds and preflight feature counts. Include final success and static fragments. Mark uncovered paths explicitly.
4. [ ] **Repair the measurement executable.** Move correctness checks outside timers; add independent controls; implement registered affine/kernel probes and the balanced log-ratio fit/quality report. Replace stale fragment probes and preserve every raw run. Make fitting replayable without rerunning measurements.
5. [ ] **Run a small identification pilot.** Start with F, copied/rvalue entry lifetimes, PREP/OUTPUT, READ and ARITH; then a hash, MUL/DIV/MOD and OP_TX. Vary each feature independently, including empty items, collated output, capacity boundaries and unequal operands. Verify batch-size and working-set stability before broad collection.
6. [ ] **Fit and assess quality.** Produce one table with primitive definition, degree, existing rate, raw fitted rate, per-decade/path relative errors and unresolved cases. Plot the declared functions and all measurements. Keep descriptive fits separate from a later rounded cost schedule.
7. [ ] **Wire a separate candidate schedule.** Generate constants/compositions from the reviewed manifest; independently verify feature counts, signature/hash work, rounding, exact-budget and one-below outcomes. Keep production defaults separate.
8. [ ] **Challenge realistic compositions with `bench_varops`.** Run restoration loops, preloaded operands, identity/state-preserving bodies, static fragments, OP_MULTI folds and transaction-backed OP_TX, including many empty results. Include short scripts/final checks, inactive regions, allocation lifetimes and rejection paths. Verify feasibility and the claimed budget/weight limits for each case.
9. [ ] **Separate measurements from projections.** Report actual evaluator time/reference time, predicted composed time and full-varops extrapolation separately. A full-budget projection becomes decisive only with a feasible way to repeat that same work/state. Fragment compression can remove a byte limit, so test the compressed construction before dismissing a projection. A passing panel does not prove every primitive is correctly identified.
10. [ ] **Resolve composition failures.** Check instrumentation, counts, omitted/double-counted work and reachable state first. Revise shared coefficients only with supporting primitive evidence. A feature change creates a new version and invalidates earlier confirmation status.
11. [ ] **Collect independent multi-machine confirmation.** Include materially different arithmetic/hash backends; fit common coefficients against every machine and freeze before fresh confirmation. Apply the decision rule above, report unresolved comparisons and test storage/rejection bounds separately.
12. [ ] **Publish the reproducible candidate.** Regenerate the costing table/plots from the manifest and raw data, document scope and remaining TODOs, then propose BIP/implementation changes for review. No historical pilot or single-machine pass is final calibration.

Next action: steps 2–4, starting with storage/timing boundaries and the missing multiply-row accumulation. Another broad timing run before these fixes would produce more data for an ambiguous decomposition.
