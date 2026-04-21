#!/usr/bin/env python3
"""Generate all BonnMotion traces for the FANET experiment.

Produces 150 decompressed .movements files under ./bonnmotion/:
  3 scenarios x 5 (nodes, speed) points x 10 seeds = 150 traces.

The three scenarios are:
  - recon : Gauss-Markov in a 3600 x 1200 x 200 m volume
  - sar   : Reference Point Group Mobility in a 1500 x 3000 x 50 m volume
  - stress: Random Waypoint in a 1000 x 1000 m area (2D)

Each scenario runs two 1D sweeps (over node count and over max speed) that
share the midpoint (N=30, S=30). The union is 5 unique (N, S) points, listed
explicitly in SWEEP_POINTS below so the de-duplication is visible.

Re-running the script is safe: points whose .movements file already exists
are skipped.

# NOTE: -R is BonnMotion's random seed flag. If your installed BonnMotion
# version uses a different flag name, edit the run_* functions below and
# consider removing the -R argument entirely so each invocation uses a
# fresh default seed. The output files will still be named _seed0.._seed9
# so downstream .ini files keep working.
"""

import subprocess
import sys
from pathlib import Path

OUT = Path("bonnmotion")

# 5 (nodes, speed) points per scenario -- the two sweeps share (30, 30).
SWEEP_POINTS = [(10, 30), (30, 30), (50, 30), (30, 10), (30, 50)]
SEEDS = list(range(10))


def _bm(args):
    """Invoke `bm` with the given argument list; abort on failure."""
    cmd = ["bm"] + args
    subprocess.run(cmd, check=True)


def run_recon(n, s, r):
    """Scenario 1 - Reconnaissance: Gauss-Markov, 3600 x 1200 x 50 m."""
    prefix = OUT / f"recon_n{n}_s{s}_seed{r}"
    _bm([
        "-f", str(prefix), "GaussMarkov3D",
        "-n", str(n), "-d", "600", "-i", "100",
        "-x", "3400", "-y", "1000", "-z", "30",
        "-h", str(s), "-l", "5", "-c", "4",
        "-a", "0.85",
        "-R", str(r),
    ])


def run_sar(n, s, r):
    """Scenario 2 - SAR: Reference Point Group Mobility, 1500 x 3000 x 50 m."""
    prefix = OUT / f"sar_n{n}_s{s}_seed{r}"
    groups = n / 3 
    _bm([
        "-f", str(prefix), "RPGM",
        "-n", str(n), "-d", "600", "-i", "100",
        "-x", "1300", "-y", "2800", "-z", "40",
        "-h", str(s), "-l", "5", "-p", "0",
        "-a", str(groups), "-s", "0.5", "-r", "70", "-c", "0",
        "-R", str(r),
    ])


def run_stress(n, s, r):
    """Scenario 3 - Stress: Random Waypoint, 1000 x 1000 m (2D)."""
    prefix = OUT / f"stress_n{n}_s{s}_seed{r}"
    _bm([
        "-f", str(prefix), "RandomWaypoint",
        "-n", str(n), "-d", "600", "-i", "100",
        "-x", "1000", "-y", "1000",
        "-h", str(s), "-l", "5", "-p", "0",
        "-R", str(r),
    ])


def gunzip(path):
    """Decompress <path>.gz in place and remove the .gz file.

    `path` is the expected decompressed file (a Path). The compressed file
    is at path.with_suffix(path.suffix + '.gz').
    """
    gz = path.with_suffix(path.suffix + ".gz")
    if not gz.exists():
        raise FileNotFoundError(
            f"Expected {gz} after bm run, but it is missing. "
            f"Check BonnMotion output naming."
        )
    # -f to overwrite any stale decompressed file left by a prior partial run.
    subprocess.run(["gunzip", "-f", str(gz)], check=True)


def shift_coordinates(filepath, offset=150.0):
    """Shift all node coordinates in .movements file by an offset to eliminate negative values."""
    with open(filepath, 'r') as f:
        lines = f.readlines()

    is_3d = False
    with open(filepath, 'w') as f:
        for idx, line in enumerate(lines):
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
            
            # The structure of each line is: time1 x1 y1 [z1] time2 x2 y2 [z2] ...
            # We iterate in chunks of 'stride' to safely skip timestamps.
            for i in range(0, len(parts), stride):
                # parts[i] is the timestamp (e.g. 0.0), so we DO NOT shift it.
                
                # Shift and Clamp X coordinate
                if i + 1 < len(parts):
                    val_x = float(parts[i+1]) + offset
                    val_x = max(0.0, min(1500.0, val_x))
                    parts[i+1] = f"{val_x:.4f}"
                    
                # Shift and Clamp Y coordinate
                if i + 2 < len(parts):
                    val_y = float(parts[i+2]) + offset
                    val_y = max(0.0, min(3000.0, val_y))
                    parts[i+2] = f"{val_y:.4f}"
                    
                # Compress/Scale Z coordinate instead of clamping to prevent dragging
                if is_3d and i + 3 < len(parts):
                    # BonnMotion Z can range from roughly -70 to 110 because the nodes
                    # deploy in a 70m radius sphere around a group center. 
                    # Instead of hard-clamping which flattens them to the floor, 
                    # we linearly map the ~180m raw span into the 0m - 50m boundary.
                    raw_z = float(parts[i+3])
                    val_z = ((raw_z + 70.0) / 180.0) * 50.0
                    val_z = max(0.0, min(50.0, val_z))  # Safety fallback
                    parts[i+3] = f"{val_z:.4f}"
                    
            f.write(" ".join(parts) + "\n")


def main():
    OUT.mkdir(exist_ok=True)

    scenarios = [
        ("recon", run_recon),
        ("sar", run_sar),
        ("stress", run_stress),
    ]

    total = 0
    generated = 0
    skipped = 0

    for scenario_name, runner in scenarios:
        for n, s in SWEEP_POINTS:
            for r in SEEDS:
                total += 1
                out_file = OUT / f"{scenario_name}_n{n}_s{s}_seed{r}.movements"

                if out_file.exists():
                    skipped += 1
                    print(
                        f"[{total:3d}/150] skip   {scenario_name} "
                        f"n={n} s={s} seed={r} (exists)"
                    )
                    continue

                runner(n, s, r)
                gunzip(out_file)
                if scenario_name == 'sar':
                    shift_coordinates(out_file, 150.0)
                generated += 1
                print(
                    f"[{total:3d}/150] ok     {scenario_name} "
                    f"n={n} s={s} seed={r}"
                )

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
