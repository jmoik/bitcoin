#!/usr/bin/env python3
"""Measure varops primitives, producing one portable JSON artifact.

Run without arguments from any directory. Intermediate CSV files are retained
under calibration-intermediate/ for inspection; the portable result, with every
raw sample, is written beside this script unless --output is given. The
artifacts of several machines are fitted and combined elsewhere.

Shorter epochs and samples give a quick run for checking a machine and
estimating the full run's duration; the artifact records the settings and
each stage's wall time.
"""

import argparse
import collections
import csv
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import subprocess
import statistics
import tempfile
import threading
import time


ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
BUILD = ROOT / "build-varops-calibration"
INTERMEDIATE = HERE / "calibration-intermediate"
REFERENCE_EPOCHS = 5
PRIMITIVE_EPOCHS = 7
SAMPLE_MS = 10
COPY_SAMPLE_MS = 100
# BIP 440 measurement condition: a run is repeated if its epoch noise exceeds
# MAX_EPOCH_NOISE, up to MAX_ATTEMPTS times. Epoch noise is the median over fixtures
# of the median absolute deviation of a fixture's epochs from their median, relative
# to that median. With seven epochs, dedicated machines measure 0.3-0.5% and a Mac
# desktop with its usual background tasks 1.1-1.2%; runs disturbed by other work
# reached 1.75% with five. It is a screening threshold, not an accuracy guarantee:
# a machine loaded evenly throughout can pass it. The one-minute load average is
# recorded where the OS reports it, but is not a condition: an idle macOS desktop
# already reports 1.5-2.
MAX_EPOCH_NOISE = 0.015
MAX_ATTEMPTS = 3
LOAD_INTERVAL_SECONDS = 60
# The artifact records these sources' hashes; the benchmarks are built from them.
COMPILED_SOURCES = tuple(ROOT / path for path in (
    "src/bench/bench_varops.cpp",
    "src/bench/bench_varops_primitives.cpp",
    "src/script/varops.h",
    "src/script/interpreter.cpp",
    "src/script/val64.h",
    "src/script/val64.cpp",
    "src/script/valtype_stack.h",
    "src/script/valtype_stack.cpp",
))


def run(*command):
    print("+", " ".join(map(str, command)), flush=True)
    subprocess.run(command, cwd=ROOT, check=True)


def windows_configure_args():
    """Link the MSVC runtime statically, as Core's static Windows presets do.

    With the DLL runtime (vcpkg x64-windows) each small value's copy or fill
    costs ~50 ns more on a Ryzen 9 9950X than with the static runtime; neither
    the release build (MinGW) nor the static presets pay that.
    """
    triplet = "x64-windows-static"
    # vcpkg.json's default features (Qt, tests, wallet, ZeroMQ) are not built
    # here; installing them adds tens of minutes to a fresh build directory.
    args = [f"-DVCPKG_TARGET_TRIPLET={triplet}", "-DVCPKG_MANIFEST_NO_DEFAULT_FEATURES=ON"]
    cached = cmake_cache()
    if cached and cached.get("VCPKG_TARGET_TRIPLET", triplet) != triplet:
        # Dependencies found for the previous triplet stay cached otherwise;
        # keep the generator, compiler and toolchain the previous configuration
        # used. A Visual Studio generator otherwise falls back to MSVC, which
        # builds SHA256 without SSE4.1, AVX2 or SHA-NI.
        args.append("--fresh")
        generator = cached.get("CMAKE_GENERATOR", "")
        if generator:
            args.append(f"-G{generator}")
        if cached.get("CMAKE_GENERATOR_PLATFORM"):
            args.append(f"-A{cached['CMAKE_GENERATOR_PLATFORM']}")
        if cached.get("CMAKE_GENERATOR_TOOLSET"):
            args.append(f"-T{cached['CMAKE_GENERATOR_TOOLSET']}")
        if not generator.startswith("Visual Studio"):
            # Visual Studio generators take the compiler from the toolset.
            for key in ("CMAKE_C_COMPILER", "CMAKE_CXX_COMPILER"):
                if cached.get(key):
                    args.append(f"-D{key}={cached[key]}")
        if cached.get("CMAKE_TOOLCHAIN_FILE"):
            args.append(f"-DCMAKE_TOOLCHAIN_FILE={cached['CMAKE_TOOLCHAIN_FILE']}")
    return args


def cmake_cache():
    cache = BUILD / "CMakeCache.txt"
    if not cache.exists():
        return {}
    cached = {}
    for line in cache.read_text(encoding="utf-8", errors="replace").splitlines():
        key, separator, value = line.partition("=")
        if separator and not line.startswith(("#", "//")):
            cached[key.partition(":")[0]] = value
    return cached


def built_binary(name):
    """Return the benchmark binary this run's build produced.

    Multi-config generators (Visual Studio) write bin/Release/; a bin/ copy
    left by an earlier single-config build would otherwise be run instead.
    """
    directory = BUILD / "bin"
    if cmake_cache().get("CMAKE_CONFIGURATION_TYPES"):
        directory /= "Release"
    binary = directory / f"{name}{'.exe' if os.name == 'nt' else ''}"
    newest = max(COMPILED_SOURCES, key=lambda path: path.stat().st_mtime)
    if not binary.exists() or binary.stat().st_mtime < newest.stat().st_mtime:
        raise RuntimeError(f"{binary} is missing or older than {newest.relative_to(ROOT)}; "
                           "the build did not produce it")
    return binary


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
    # Per-round sample rows leave Domain empty; keep them by the name of their case.
    cases = {row["Name"] for row in rows if row["Record_Type"] == "summary"
             and row["Domain"] in {"pre-gsr-tapscript-v1", "raw-schnorr"}}
    return {
        "seconds": seconds,
        "worst_case": worst["Name"],
        "summary_cases": eligible,
        "raw_rows": [row for row in rows if row["Name"] in cases],
        "metadata": metadata,
        "csv_sha256": sha256(path),
    }


class LoadSampler:
    """Samples the one-minute load average during the run, where the OS reports it."""

    def __init__(self, interval):
        self.samples = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, args=(interval,), daemon=True)

    def _run(self, interval):
        while True:
            self.samples.append(os.getloadavg()[0])
            if self._stop.wait(interval):
                return

    def __enter__(self):
        if hasattr(os, "getloadavg"):
            self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join()


def epoch_noise(samples):
    """Median over fixtures of their epochs' relative median absolute deviation.

    None with fewer than three epochs. Word-rounded size aliases repeat a probe
    name within a pass; the benchmark keeps them apart by their order in it.
    """
    seen = collections.Counter()
    epochs = collections.defaultdict(list)
    for sample in samples:
        key = sample["probe"], sample["epoch"]
        epochs[sample["probe"], seen[key]].append(float(sample["ns_per_execution"]))
        seen[key] += 1
    deviations = []
    for times in epochs.values():
        middle = statistics.median(times)
        if len(times) >= 3 and middle > 0:
            deviations.append(statistics.median(abs(time - middle) for time in times) / middle)
    return statistics.median(deviations) if deviations else None


def conditions(load, noise):
    """BIP 440 measurement conditions of a run; failures are recorded and reported."""
    problems = []
    if noise is not None and noise > MAX_EPOCH_NOISE:
        problems.append(f"epoch noise {100 * noise:.2f}% exceeds {100 * MAX_EPOCH_NOISE:g}%")
    return {
        "one_minute_load": load,
        "median_one_minute_load": statistics.median(load) if load else None,
        "epoch_noise": noise,
        "limits": {"max_epoch_noise": MAX_EPOCH_NOISE},
        "problems": problems,
        "repeat_required": bool(problems),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--reference-epochs", type=int, default=REFERENCE_EPOCHS)
    parser.add_argument("--epochs", type=int, default=PRIMITIVE_EPOCHS, help="primitive epochs")
    parser.add_argument("--sample-ms", type=float, default=SAMPLE_MS)
    parser.add_argument("--copy-sample-ms", type=float, default=COPY_SAMPLE_MS)
    parser.add_argument("--output", type=Path, default=None, help="artifact path")
    parser.add_argument("--work-dir", type=Path, default=INTERMEDIATE, help="intermediate files")
    parser.add_argument("--attempts", type=int, default=MAX_ATTEMPTS,
                        help="measurements repeated while the run fails its conditions")
    args = parser.parse_args()
    if args.attempts < 1:
        parser.error("--attempts must be at least 1")
    settings = {"reference_epochs": args.reference_epochs, "primitive_epochs": args.epochs,
                "sample_ms": args.sample_ms, "copy_sample_ms": args.copy_sample_ms}
    full = settings == {"reference_epochs": REFERENCE_EPOCHS, "primitive_epochs": PRIMITIVE_EPOCHS,
                        "sample_ms": SAMPLE_MS, "copy_sample_ms": COPY_SAMPLE_MS}
    output = (args.output or HERE / "varop-calibration.json").resolve()
    print(f"Calibration output: {output}", flush=True)
    stage_seconds = {}
    started = time.monotonic()

    def stage(name):
        nonlocal started
        now = time.monotonic()
        stage_seconds[name] = now - started
        print(f"  {name}: {stage_seconds[name]:.1f} s", flush=True)
        started = now

    run("cmake", "-S", ROOT, "-B", BUILD, "-DCMAKE_BUILD_TYPE=Release",
        "-DWITH_USDT=OFF", "-DENABLE_IPC=OFF",
        "-DBUILD_BENCH=ON", "-DBUILD_DAEMON=OFF", "-DBUILD_CLI=OFF",
        "-DBUILD_TESTS=OFF", "-DBUILD_GUI=OFF", "-DENABLE_WALLET=OFF",
        *(windows_configure_args() if os.name == "nt" else []))
    # Single-config generators ignore --config and use CMAKE_BUILD_TYPE.
    run("cmake", "--build", BUILD, "--config", "Release", "--target", "bench_varops",
        "bench_varops_primitives", "-j", str(min(os.cpu_count() or 1, 8)))
    bench = built_binary("bench_varops")
    primitives = built_binary("bench_varops_primitives")
    run(primitives, "--self-test")
    stage("build")

    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    reference_csv = work / "reference.csv"
    measurements_csv = work / "measurements.csv"
    composition_csv = work / "opcode-composition.csv"

    # The case filter retains every pre-v2 baseline while limiting unrelated
    # v2 timing; the sample limit does not truncate those pre-v2 baselines.
    reference_args = ("--case-filter", "OP_NOP", "--sample-budget-percent", "2",
                      "--epochs", str(args.reference_epochs), "--silent")
    failed_attempts = []
    run_started = time.strftime("%Y%m%d-%H%M%S")
    for attempt in range(1, args.attempts + 1):
        with LoadSampler(LOAD_INTERVAL_SECONDS) as load:
            run(bench, *reference_args, "--file", reference_csv, "--coverage-manifest", composition_csv)
            reference = reference_rows(reference_csv)
            stage("reference")
            run(primitives, "--reference-csv", reference_csv,
                "--epochs", str(args.epochs), "--sample-ms", str(args.sample_ms),
                "--copy-sample-ms", str(args.copy_sample_ms), "--out", measurements_csv)
            stage("primitives")
        _, samples = read_csv(work / "measurements.csv.samples.csv")
        if not samples:
            raise RuntimeError("primitive benchmark produced no samples")
        run_conditions = conditions(load.samples, epoch_noise(samples))
        for problem in run_conditions["problems"]:
            print(f"WARNING: {problem}", flush=True)
        if not run_conditions["repeat_required"] or attempt == args.attempts:
            break
        # Keep the failed attempt's measurements beside the next one's.
        failed = work / f"failed-{run_started}-attempt-{attempt}"
        failed.mkdir()
        for path in (reference_csv, composition_csv, *work.glob("measurements.csv*")):
            path.replace(failed / path.name)
        failed_attempts.append({
            "conditions": run_conditions,
            "stage_seconds": {name: stage_seconds[name] for name in ("reference", "primitives")},
            "intermediate_dir": failed.name,
        })
        print(f"Repeating the measurements: attempt {attempt + 1} of {args.attempts}", flush=True)
    run_conditions["failed_attempts"] = failed_attempts
    if run_conditions["repeat_required"]:
        print(f"WARNING: all {args.attempts} attempts failed the measurement conditions; "
              "repeat this run before using it for pricing", flush=True)
    measurement_metadata, _ = read_csv(measurements_csv)
    measured_reference = float(measurement_metadata["Reference_Script_Evaluation_Seconds"])
    if not math.isclose(measured_reference, reference["seconds"], rel_tol=1e-12):
        raise RuntimeError("the primitive and reference benchmarks selected different times")
    # 40 billion varops over this machine's own pre-v2 reference time. The
    # multi-machine fit applies its own target to the raw nanoseconds and the
    # reference, which the artifact retains.
    target_nanoseconds = reference["seconds"] * 1_000_000_000
    varops_per_ns = 40_000_000_000 / target_nanoseconds
    for sample in samples:
        nanoseconds = float(sample["ns_per_execution"])
        if not math.isfinite(nanoseconds) or nanoseconds < 0:
            raise RuntimeError("invalid primitive sample time")
        sample["normalized_varops_per_execution"] = nanoseconds * varops_per_ns

    artifact = {
        "schema": "varop-calibration-v1",
        "model_id": measurement_metadata["Primitive_Model"],
        "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "producer_manifest": read_csv(work / "measurements.csv.produce.csv")[1],
        "opcode_compositions": read_csv(composition_csv)[1],
        "status": ("single-machine measurements" if full else
                   "quick run with shortened measurements; for checking the machine and estimating duration only"),
        "measurement_settings": settings,
        "measurement_metadata": measurement_metadata,
        "stage_seconds": stage_seconds,
        "machine": {
            "cpu": reference["metadata"].get("CPU"),
            "architecture": reference["metadata"].get("Architecture"),
            "compiler": reference["metadata"].get("Compiler"),
            "sha256_backend": reference["metadata"].get("SHA256 Implementation"),
            "platform": platform.platform(),
        },
        "normalization": {
            "budget_varops": 40_000_000_000,
            "local_pre_v2_worst_seconds": reference["seconds"],
            "varops_per_nanosecond": varops_per_ns,
        },
        "reference": reference,
        "conditions": run_conditions,
        "primitive_samples": samples,
        "source_sha256": {
            str(path.relative_to(ROOT)): sha256(path)
            for path in (*COMPILED_SOURCES, Path(__file__).resolve())
        },
        "benchmark_binary_sha256": sha256(bench),
        "primitives_binary_sha256": sha256(primitives),
    }
    # Replace an earlier result only after every measurement succeeds.
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
