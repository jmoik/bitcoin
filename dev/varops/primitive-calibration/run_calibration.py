#!/usr/bin/env python3
"""Measure and fit varops primitives, producing one portable JSON artifact.

Run without arguments from any directory. Build files and intermediate CSV/HTML
are not calibration results; only varop-calibration.json is retained.
"""

import csv
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
BUILD = ROOT / "build-varops-calibration"
OUTPUT = HERE / "varop-calibration.json"
REFERENCE_EPOCHS = 5
PRIMITIVE_EPOCHS = 31
SAMPLE_MS = 2
COPY_SAMPLE_MS = 30
TARGET_FRACTION = 0.9


def run(*command):
    print("+", " ".join(map(str, command)), flush=True)
    subprocess.run(command, cwd=ROOT, check=True)


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


def main():
    if len(sys.argv) != 1:
        raise SystemExit("run_calibration.py takes no arguments")

    run("cmake", "-S", ROOT, "-B", BUILD, "-DCMAKE_BUILD_TYPE=Release",
        "-DBUILD_BENCH=ON", "-DBUILD_DAEMON=OFF", "-DBUILD_CLI=OFF",
        "-DBUILD_TESTS=OFF", "-DBUILD_GUI=OFF", "-DENABLE_WALLET=OFF")
    run("cmake", "--build", BUILD, "--target", "bench_varops",
        "bench_varops_primitives", "-j", str(min(os.cpu_count() or 1, 4)))
    bench = BUILD / "bin" / "bench_varops"
    primitives = BUILD / "bin" / "bench_varops_primitives"
    run(primitives, "--self-test")

    with tempfile.TemporaryDirectory(prefix="varop-calibration-") as temporary:
        work = Path(temporary)
        reference_csv = work / "reference.csv"
        measurements_csv = work / "measurements.csv"

        # The case filter retains every pre-v2 baseline while limiting unrelated
        # v2 timing; the sample limit does not truncate those pre-v2 baselines.
        run(bench, "--case-filter", "OP_NOP", "--sample-budget-percent", "2",
            "--epochs", str(REFERENCE_EPOCHS), "--silent", "--file", reference_csv)
        reference = reference_rows(reference_csv)
        run(primitives, "--reference-csv", reference_csv,
            "--epochs", str(PRIMITIVE_EPOCHS), "--sample-ms", str(SAMPLE_MS),
            "--copy-sample-ms", str(COPY_SAMPLE_MS), "--percentile", "0.5",
            "--margin", "1", "--out", measurements_csv)
        run(sys.executable, HERE / "plot_reduced_pilot.py", work,
            "--sample-ms", str(SAMPLE_MS), "--binary", primitives,
            "--target-fraction", str(TARGET_FRACTION))

        fits = json.loads((work / "fits.json").read_text())
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
        # Replace an earlier result only after every measurement and fit succeeds.
        pending = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=HERE,
                                             prefix=".varop-calibration-", suffix=".json",
                                             delete=False) as destination:
                pending = Path(destination.name)
                json.dump(artifact, destination, indent=2)
                destination.write("\n")
            pending.replace(OUTPUT)
        finally:
            if pending is not None:
                pending.unlink(missing_ok=True)
    print(f"Calibration saved to {OUTPUT}")


if __name__ == "__main__":
    main()
