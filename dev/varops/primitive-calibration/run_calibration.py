#!/usr/bin/env python3
"""Measure and fit varops primitives, producing one portable JSON artifact.

Run without arguments from any directory. Intermediate CSV/HTML files are
retained under calibration-intermediate/ for inspection; the portable result is
written under data/varopsData in the research workspace, or beside this script
in other checkout layouts. No arguments or environment configuration required.
"""

import csv
import hashlib
import json
import math
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile

from plot_reduced_pilot import MODEL_ID, PRODUCER_ORDER


ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
BUILD = ROOT / "build-varops-calibration"
INTERMEDIATE = HERE / "calibration-intermediate"
REFERENCE_EPOCHS = 5
PRIMITIVE_EPOCHS = 3
SAMPLE_MS = 5
COPY_SAMPLE_MS = 30
TARGET_FRACTION = 1.0


def output_path():
    if ROOT.parent.name == "gsr" and ROOT.parent.parent.name == "core":
        data_dir = ROOT.parent.parent.parent / "data" / "varopsData"
        return data_dir / "primitive-calibration" / MODEL_ID / "varop-calibration.json"
    return HERE / "varop-calibration.json"


def run(*command):
    print("+", " ".join(map(str, command)), flush=True)
    subprocess.run(command, cwd=ROOT, check=True)


def schedule_options():
    options = ["-DGSR_PRODUCER_LIFETIME_EXPERIMENT=ON"]
    # Older runners appended this definition after clang-cl's `--`, where it
    # becomes a filename. Migrate that cache entry without erasing other flags.
    cache = BUILD / "CMakeCache.txt"
    if cache.exists():
        for line in cache.read_text(encoding="utf-8").splitlines():
            if line.startswith("APPEND_CPPFLAGS:STRING="):
                flags = line.split("=", 1)[1]
                cleaned = re.sub(r"(?<!\S)-DGSR_PRODUCER_LIFETIME_EXPERIMENT(?=\s|$)", "", flags).strip()
                if cleaned != flags:
                    options.append(f"-DAPPEND_CPPFLAGS={cleaned}")
                break
    return options


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_csv(path):
    metadata = {}
    with path.open(newline="") as source:
        lines = []
        for line in source:
            if line.startswith("#"):
                if line.startswith("# "):
                    key, separator, value = line[2:].partition(": ")
                    if separator:
                        metadata[key] = value.strip()
            elif line.strip():
                lines.append(line)
    return metadata, list(csv.DictReader(lines))


def reference_rows(path):
    metadata, rows = read_csv(path)
    eligible = [row for row in rows if row["Record_Type"] == "summary"
                and row["Domain"] == "pre-gsr-tapscript-v1"
                and row["Actual_Termination"] in {"OK", "SCRIPT_ERR_OK", "No error"}]
    if not eligible:
        raise RuntimeError("bench_varops produced no successful pre-v2 reference cases")
    worst = max(eligible, key=lambda row: float(row["Wall_Seconds"]))
    seconds = float(worst["Wall_Seconds"])
    if not math.isfinite(seconds) or seconds <= 0:
        raise RuntimeError("invalid pre-v2 reference time")
    return {
        "seconds": seconds,
        "worst_case": worst["Name"],
        "summary_cases": eligible,
        "raw_rows": [row for row in rows if row["Domain"] in
                     {"pre-gsr-tapscript-v1", "raw-schnorr"}],
        "metadata": metadata,
        "csv_sha256": sha256(path),
    }


def lifetime_checks(manifest, samples, fits, rate):
    """Report held-out lifetimes against the fitted composition; never fit them."""
    import statistics
    from collections import defaultdict

    observations = defaultdict(list)
    for sample in samples:
        observations[sample['probe']].append(float(sample['ns_per_execution']))

    def charge(family, count, span):
        fitted = fits['fits'][family]['under_penalty_100_fit']
        return rate * (fitted['a_ns'] * count + fitted['b_ns'] * span)

    checks = []
    for row in manifest:
        if not row['probe'].startswith('PRODUCER_CHECK/'):
            continue
        count, size, numeric = (int(row[k]) for k in ('items', 'bytes', 'normalize_bytes'))
        cost = charge('PRODUCE', count, size)
        if row['kind'] == 'numeric':
            span = (numeric + 7) // 8 * 8
            cost += charge('PRODUCE', 1, span) + charge('PREP', 1, span) + charge('NORMALIZE', 1, span)
        measured = statistics.median(observations[row['probe']]) * rate
        checks.append(dict(probe=row['probe'], predicted_varops=cost,
                           measured_normalized_varops=measured, ratio=measured / cost))
    return checks


def main():
    if len(sys.argv) != 1:
        raise SystemExit("run_calibration.py takes no arguments")
    output = output_path()
    print(f"Calibration output: {output}", flush=True)

    run("cmake", "-S", ROOT, "-B", BUILD, "-DCMAKE_BUILD_TYPE=Release",
        *schedule_options(), "-DWITH_USDT=OFF",
        "-DBUILD_BENCH=ON", "-DBUILD_DAEMON=OFF", "-DBUILD_CLI=OFF",
        "-DBUILD_TESTS=OFF", "-DBUILD_GUI=OFF", "-DENABLE_WALLET=OFF")
    run("cmake", "--build", BUILD, "--target", "bench_varops",
        "bench_varops_primitives", "-j", str(min(os.cpu_count() or 1, 8)))
    binary_suffix = ".exe" if os.name == "nt" else ""
    bench = BUILD / "bin" / f"bench_varops{binary_suffix}"
    primitives = BUILD / "bin" / f"bench_varops_primitives{binary_suffix}"
    run(primitives, "--self-test")

    work = INTERMEDIATE
    work.mkdir(exist_ok=True)
    reference_csv = work / "reference.csv"
    measurements_csv = work / "measurements.csv"
    composition_csv = work / "opcode-composition.csv"

    # The case filter retains every pre-v2 baseline while limiting unrelated
    # v2 timing; the sample limit does not truncate those pre-v2 baselines.
    run(bench, "--case-filter", "OP_NOP", "--sample-budget-percent", "2",
        "--exclude-experimental",
        "--epochs", str(REFERENCE_EPOCHS), "--silent", "--file", reference_csv,
        "--coverage-manifest", composition_csv)
    reference = reference_rows(reference_csv)
    run(primitives, "--reference-csv", reference_csv,
        "--calibration-candidate",
        "--epochs", str(PRIMITIVE_EPOCHS), "--sample-ms", str(SAMPLE_MS),
        "--copy-sample-ms", str(COPY_SAMPLE_MS), "--percentile", "0.5",
        "--margin", "1", "--out", measurements_csv)
    run(sys.executable, HERE / "plot_reduced_pilot.py", work,
        "--sample-ms", str(SAMPLE_MS), "--binary", primitives,
        "--producer-schedule",
        "--target-fraction", str(TARGET_FRACTION))

    fits = json.loads((work / "fits.json").read_text(encoding="utf-8"))
    measured_reference = fits["metadata"]["reference_script_seconds"]
    if not math.isclose(measured_reference, reference["seconds"], rel_tol=1e-12):
        raise RuntimeError("the fitter and reference benchmark selected different times")
    _, samples = read_csv(work / "measurements.csv.samples.csv")
    if not samples:
        raise RuntimeError("primitive benchmark produced no samples")
    # 40 billion varops over this machine's own pre-v2 reference time.
    # Retain the raw nanoseconds too so a later multi-machine fit can be
    # recomputed with a different target without rerunning the benchmark.
    target_nanoseconds = TARGET_FRACTION * reference["seconds"] * 1_000_000_000
    varops_per_ns = 40_000_000_000 / target_nanoseconds
    for sample in samples:
        nanoseconds = float(sample["ns_per_execution"])
        if not math.isfinite(nanoseconds) or nanoseconds < 0:
            raise RuntimeError("invalid primitive sample time")
        sample["fraction_of_local_target"] = nanoseconds / target_nanoseconds
        sample["normalized_varops_per_execution"] = nanoseconds * varops_per_ns

    artifact = {
        "schema": "varop-calibration-v1",
        "model_id": MODEL_ID,
        "primitive_order": PRODUCER_ORDER,
        "producer_manifest": read_csv(work / "measurements.csv.produce.csv")[1],
        "opcode_compositions": read_csv(composition_csv)[1],
        "composition_rules": {
            "NUMERIC_RESULT(n)": "PRODUCE(W(n)) + NORMALIZE(n)",
            "initial_stack": "sum(PRODUCE(length(item))); once after immediate-success prescan",
            "moves_and_drops": "no new production event; original production funds release",
            "mul": "result and scratch prepaid at full spans; only NORMALIZE at output",
            "divmod": "DIVCORE includes internal temporary storage; no extra scratch charge",
        },
        "status": "single-machine evidence and provisional local fit; not an accepted consensus schedule",
        "machine": {
            "cpu": reference["metadata"].get("CPU"),
            "architecture": reference["metadata"].get("Architecture"),
            "compiler": reference["metadata"].get("Compiler"),
            "sha256_backend": reference["metadata"].get("SHA256 Implementation"),
            "platform": fits["metadata"]["platform"],
        },
        "normalization": {
            "budget_varops": 40_000_000_000,
            "target_fraction_of_local_pre_v2_worst": TARGET_FRACTION,
            "local_pre_v2_worst_seconds": reference["seconds"],
            "varops_per_nanosecond": varops_per_ns,
        },
        "reference": reference,
        "primitive_samples": samples,
        "fitting": fits,
        "source_sha256": {
            str(path.relative_to(ROOT)): sha256(path)
            for path in (ROOT / "src/bench/bench_varops.cpp",
                         ROOT / "src/bench/bench_varops_primitives.cpp",
                         ROOT / "src/script/varops.h",
                         ROOT / "src/script/interpreter.cpp",
                         ROOT / "src/script/val64.h",
                         ROOT / "src/script/val64.cpp",
                         ROOT / "src/script/valtype_stack.h",
                         ROOT / "src/script/valtype_stack.cpp",
                         HERE / "plot_reduced_pilot.py",
                         Path(__file__).resolve())
        },
        "benchmark_binary_sha256": sha256(bench),
    }
    artifact['held_out_lifetime_checks'] = lifetime_checks(artifact['producer_manifest'], samples, fits, varops_per_ns)
    # Replace an earlier result only after every measurement and fit succeeds.
    pending = None
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=output.parent,
                                         prefix=".varop-calibration-", suffix=".json",
                                         delete=False) as destination:
            pending = Path(destination.name)
            json.dump(artifact, destination, indent=2)
            destination.write("\n")
        pending.replace(output)
    finally:
        if pending is not None:
            pending.unlink(missing_ok=True)
    print(f"Calibration saved to {output}")


if __name__ == "__main__":
    main()
