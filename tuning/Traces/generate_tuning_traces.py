#!/usr/bin/env python3
"""Generate BonnMotion traces for the parameter-tuning sweeps.

This produces a small, scenario-fixed set of traces that is DISJOINT from the
test traces under ../../simulations/Traces/bonnmotion/. Used only for picking
ZRP / SA-ZRP parameter values; the test traces stay untouched so the final
evaluation isn't contaminated.

Layout:
  ./bonnmotion_tune/
    recon_n30_s30_seed{0..2}.movements
    sar_n30_s30_seed{0..2}.movements
    stress_n30_s30_seed{0..2}.movements

Files are NAMED seed{0..2} so they line up with OMNeT++'s ${repetition} index
(0..repeat-1), but the underlying BonnMotion seeds are 100..102 so the random
realisations are disjoint from the test set (which uses BonnMotion seeds 0..9).

Re-running is safe: existing files are skipped.
"""

import subprocess
import sys
from pathlib import Path

OUT = Path("bonnmotion_tune")

# Fixed midpoint of the test sweeps: 30 nodes, 30 m/s.
N = 30
S = 30

# 3 reps; BonnMotion seed = 100 + repetition_index, so randomness is disjoint
# from the test set (seeds 0..9).
REPS = list(range(3))
SEED_OFFSET = 100


def _bm(args):
    cmd = ["bm"] + args
    subprocess.run(cmd, check=True)


def run_recon(rep):
    bm_seed = SEED_OFFSET + rep
    prefix = OUT / f"recon_n{N}_s{S}_seed{rep}"
    _bm([
        "-f", str(prefix), "GaussMarkov3D",
        "-n", str(N), "-d", "600", "-i", "100",
        "-x", "3600", "-y", "1200", "-z", "50",
        "-h", str(S), "-l", "5", "-c", "4",
        "-a", "0.85",
        "-R", str(bm_seed),
    ])


def run_sar(rep):
    bm_seed = SEED_OFFSET + rep
    prefix = OUT / f"sar_n{N}_s{S}_seed{rep}"
    groups = N / 3
    _bm([
        "-f", str(prefix), "RPGM",
        "-n", str(N), "-d", "600", "-i", "100",
        "-x", "1300", "-y", "2800", "-z", "40",
        "-h", str(S), "-l", "5", "-p", "0",
        "-a", str(groups), "-s", "0.5", "-r", "70", "-c", "0",
        "-R", str(bm_seed),
    ])


def run_stress(rep):
    bm_seed = SEED_OFFSET + rep
    prefix = OUT / f"stress_n{N}_s{S}_seed{rep}"
    _bm([
        "-f", str(prefix), "RandomWaypoint",
        "-n", str(N), "-d", "600", "-i", "100",
        "-x", "1000", "-y", "1000",
        "-h", str(S), "-l", "5", "-p", "0",
        "-R", str(bm_seed),
    ])


def gunzip(path):
    gz = path.with_suffix(path.suffix + ".gz")
    if not gz.exists():
        raise FileNotFoundError(
            f"Expected {gz} after bm run, but it is missing."
        )
    subprocess.run(["gunzip", "-f", str(gz)], check=True)


def shift_coordinates(filepath, offset=150.0):
    """SAR-only: shift + clamp coords to fit constraintArea (mirrors the test
    generator). RPGM produces negative X/Y because group centres can sit at
    the edge with members orbiting in a 70m sphere."""
    with open(filepath, 'r') as f:
        lines = f.readlines()

    is_3d = False
    with open(filepath, 'w') as f:
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if line.startswith("#"):
                if line == "#3D":
                    is_3d = True
                f.write(line + "\n")
                continue

            parts = line.split()
            stride = 4 if is_3d else 3
            for i in range(0, len(parts), stride):
                if i + 1 < len(parts):
                    val_x = float(parts[i+1]) + offset
                    val_x = max(0.0, min(1500.0, val_x))
                    parts[i+1] = f"{val_x:.4f}"
                if i + 2 < len(parts):
                    val_y = float(parts[i+2]) + offset
                    val_y = max(0.0, min(3000.0, val_y))
                    parts[i+2] = f"{val_y:.4f}"
                if is_3d and i + 3 < len(parts):
                    raw_z = float(parts[i+3])
                    val_z = ((raw_z + 70.0) / 180.0) * 50.0
                    val_z = max(0.0, min(50.0, val_z))
                    parts[i+3] = f"{val_z:.4f}"
            f.write(" ".join(parts) + "\n")


def main():
    OUT.mkdir(exist_ok=True)

    scenarios = [
        ("recon",  run_recon),
        ("sar",    run_sar),
        ("stress", run_stress),
    ]

    total = 0
    generated = 0
    skipped = 0

    for scenario_name, runner in scenarios:
        for rep in REPS:
            total += 1
            out_file = OUT / f"{scenario_name}_n{N}_s{S}_seed{rep}.movements"

            if out_file.exists():
                skipped += 1
                print(f"[{total:2d}/{len(scenarios)*len(REPS)}] skip   "
                      f"{scenario_name} rep={rep} (exists)")
                continue

            runner(rep)
            gunzip(out_file)
            if scenario_name == "sar":
                shift_coordinates(out_file, 150.0)
            generated += 1
            print(f"[{total:2d}/{len(scenarios)*len(REPS)}] ok     "
                  f"{scenario_name} rep={rep} (bm seed={SEED_OFFSET+rep})")

    print()
    print(f"Done.")
    print(f"  generated : {generated}")
    print(f"  skipped   : {skipped} (already existed)")
    print(f"  total     : {total}")
    print(f"  output    : {OUT}/")


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as e:
        print(f"\nERROR: command failed: {e.cmd}", file=sys.stderr)
        sys.exit(e.returncode or 1)
