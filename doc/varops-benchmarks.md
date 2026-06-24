# Varops benchmarks

`bench_varops` tests BIP 440's runtime bound, including logical workloads that
could eventually be encoded more compactly. It does not propose removing the
block weight limit.

## Running

Build with `BUILD_BENCH=ON`. Run on an otherwise idle machine, with a fixed power
mode, and retain the commit, compiler/build options, CPU and operating system
alongside the CSV.

```sh
./build/bin/bench_varops --list-opcodes
./build/bin/bench_varops --epochs 1 --file varops-quick.csv
./build/bin/bench_varops --opcodes OP_DIV OP_MOD --epochs 1 --file varops-focused.csv
./build/bin/bench_varops --file varops.csv
```

One epoch is for quick exploration; the default seven stable rounds give a
better indication of timing variability.

## Reading results

- **Realistic:** execution limited by both encoded weight and the 40-billion-unit
  block varops budget.
- **Full-varops:** repeat a legal script workload in bounded batches, ignoring
  encoded weight as a limit on logical execution. Normalize the measured runtime
  to 40 billion varops. Stack and per-execution limits still apply.

The CSV retains measured work, scaling factors and individual samples. A scaled
runtime is an extrapolation, not a measurement of an actual block containing
that many encoded operations. Inspect the measured budget fraction and spread
before relying on small differences.

Compare both modes against the slowest existing-version workload on the same
machine. The 80,000-Schnorr-check timing is also reported as a stable reference;
it is not necessarily the slowest existing workload. A filtered run may omit
that workload, so use a full run for the existing-version comparison.

The corpus includes small and large operands, division normalization boundaries,
literal pushes, and maximum-depth stack operations. Timing on one machine is
calibration evidence, not a cross-platform safety conclusion.
