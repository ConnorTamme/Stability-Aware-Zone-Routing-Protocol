#!/usr/bin/env python3
"""
Extract per-run + aggregated metrics from a FANET experiment's
results_scalars.csv (output of opp_scavetool x results/*.sca).

Per run we compute:
  pdr               packet delivery ratio (sink rcvd / sum of UAV app[0] sent)
  mean_delay_s      mean end-to-end delay at the sink (from histogram row)
  delay_stddev_s    stddev of end-to-end delay -- jitter proxy
  overhead_ratio    routing control bytes / payload bytes delivered
  rd_per_s          route discoveries initiated per second (NaN for OLSR)

True RFC-3550 jitter (mean abs of consecutive delay differences) needs the
per-packet endToEndDelay vector, which the killed export did not produce.
The stddev proxy is the practical fall-back; see the README section on
re-exporting that one vector.

Usage:
  python extract_metrics.py FanetRecon
  python extract_metrics.py FanetRecon --active-seconds 400
  python extract_metrics.py FanetRecon --no-plots

The plot stage produces five PNGs in <experiment>/figs/, one per metric. Each
shows the NodeSweep on the left and the SpeedSweep on the right, grouped bars
by protocol with sample-stddev error bars across the 10 repetitions.

NOTE: this script assumes the FanetRecon/FanetSar topology where the single
sink is `<network>.groundStation.app[0]`. FanetStress fans into uav[5..9]; to
support it, generalize SINK_APP0 / SINK_APP1 / UAV_APP_RE per network name.
"""
import argparse
import csv
import math
import re
import sys
from collections import defaultdict
from pathlib import Path

# Module-path matchers. Network name is captured so the same code works for
# FanetRecon and FanetSar (their network classes differ but the topology
# shape -- one sink at groundStation.app[0] -- is the same).
UAV_APP_RE  = re.compile(r"^Fanet\w+Network\.uav\[\d+\]\.app\[(\d+)\]$")
SINK_APP0_RE = re.compile(r"^Fanet\w+Network\.groundStation\.app\[0\]$")
SINK_APP1_RE = re.compile(r"^Fanet\w+Network\.groundStation\.app\[1\]$")


def is_uav_app(module: str, idx: int) -> bool:
    m = UAV_APP_RE.match(module)
    return bool(m) and int(m.group(1)) == idx


def is_sink_app0(module: str) -> bool:
    return bool(SINK_APP0_RE.match(module))


def is_sink_app1(module: str) -> bool:
    return bool(SINK_APP1_RE.match(module))


def parse_config(cfg: str):
    # e.g. Recon_NodeSweep_Aodv, Recon_SpeedSweep_Zrp_k1, Recon_NodeSweep_StabilityZrp
    parts = cfg.split("_", 2)
    sweep = parts[1] if len(parts) > 1 else "?"
    proto = parts[2] if len(parts) > 2 else "?"
    axis  = "numNodes" if sweep.startswith("Node") else "maxSpeed"
    return proto, axis


def fnum(s):
    if s is None or s == "":
        return float("nan")
    try:
        return float(s)
    except ValueError:
        return float("nan")


def mean_std(values):
    vs = [v for v in values if isinstance(v, (int, float)) and not math.isnan(v)]
    if not vs:
        return float("nan"), float("nan")
    m = sum(vs) / len(vs)
    if len(vs) == 1:
        return m, 0.0
    var = sum((v - m) ** 2 for v in vs) / (len(vs) - 1)  # sample stddev
    return m, math.sqrt(var)


# ---------------------------------------------------------------------------
# Plotting
# ---------------------------------------------------------------------------
PROTO_ORDER = ["StabilityZrp", "Zrp_k1", "Zrp_k2", "Zrp_k3", "Aodv", "Olsr"]
PROTO_COLORS = {
    "StabilityZrp": "#d62728",   # red -- the proposed protocol, made to stand out
    "Zrp_k1":       "#9ecae1",
    "Zrp_k2":       "#4292c6",
    "Zrp_k3":       "#08519c",
    "Aodv":         "#2ca02c",
    "Olsr":         "#9467bd",
}
AXIS_LABELS = {
    "numNodes": "Number of UAVs",
    "maxSpeed": "Max speed (m/s)",
}
METRICS = [
    # (key, ylabel, title, fmt, fixed_ylim)
    #   fmt: "percent" | "seconds" | "bytes" | "rate" | "linear"
    #   fixed_ylim: hard ylim (lo, hi) for semantically-bounded metrics, or None
    ("pdr",            "Packet delivery ratio",                 "Packet Delivery Ratio",        "percent", (0.0, 1.0)),
    ("mean_delay_s",   "Mean end-to-end delay",                 "End-to-End Delay",             "seconds", None),
    ("delay_stddev_s", "Stddev of end-to-end delay (jitter)",   "Jitter (stddev of delay)",     "seconds", None),
    ("overhead_ratio", "Routing overhead (control / payload)",  "Routing Overhead (ratio)",     "percent", None),
    ("control_bytes",  "Total routing control bytes",           "Routing Overhead (raw bytes)", "bytes",   None),
    ("rd_per_s",       "Route discoveries per second",          "Route Discovery Rate",         "rate",    None),
]


def _apply_y_formatter(ax, fmt):
    from matplotlib.ticker import PercentFormatter, FuncFormatter
    if fmt == "percent":
        ax.yaxis.set_major_formatter(PercentFormatter(xmax=1.0, decimals=0))
    elif fmt == "seconds":
        ax.yaxis.set_major_formatter(FuncFormatter(
            lambda v, _: "0" if v == 0 else f"{v:.2g} s"))
    elif fmt == "bytes":
        def _b(v, _):
            av = abs(v)
            if av >= 1e6:  return f"{v/1e6:.1f} MB"
            if av >= 1e3:  return f"{v/1e3:.0f} KB"
            return f"{int(v)} B" if v == int(v) else f"{v:.0f} B"
        ax.yaxis.set_major_formatter(FuncFormatter(_b))
    elif fmt == "rate":
        ax.yaxis.set_major_formatter(FuncFormatter(
            lambda v, _: "0" if v == 0 else f"{v:.2g}/s"))


def plot_metric_box(per_run, metric_key, ylabel, title, fmt, out_png,
                    fixed_ylim=None, ymax_pct=99):
    """Box + strip plot. One subplot per sweep axis, x-axis = sweep value,
    one box per (sweep_value, protocol) with the 10 reps overlaid as dots.

    Y-axis is in real units (formatted by `fmt`). For metrics with a natural
    bounded range (PDR), `fixed_ylim` pins the axis. For unbounded metrics,
    the upper limit is clipped at `ymax_pct`th percentile across all values
    so a single far-out outlier doesn't squash the rest of the data flat.
    Outliers above the clip are dropped from view; a footer tells the reader
    how many were hidden so the chart isn't lying about the data.
    """
    try:
        import numpy as np
        import pandas as pd
        import seaborn as sns
        import matplotlib.pyplot as plt
    except ImportError as e:
        print(f"missing plotting dep ({e}); pip install pandas seaborn matplotlib",
              file=sys.stderr)
        return

    valid = [r for r in per_run
             if r[metric_key] is not None
             and isinstance(r[metric_key], (int, float))
             and math.isfinite(r[metric_key])]
    if not valid:
        print(f"no valid values for {metric_key}; skipping", file=sys.stderr)
        return

    df = pd.DataFrame(valid)
    present = [p for p in PROTO_ORDER if p in set(df["protocol"])]
    df["protocol"] = pd.Categorical(df["protocol"], categories=present, ordered=True)
    palette = {p: PROTO_COLORS.get(p, "gray") for p in present}

    vals = df[metric_key].astype(float).to_numpy()
    if fixed_ylim is not None:
        ylim_bot, ylim_top = fixed_ylim
        n_clipped = int((vals > ylim_top).sum() + (vals < ylim_bot).sum())
    else:
        ylim_bot = 0.0 if vals.min() >= 0 else float(vals.min()) * 1.05
        # clip upper at ymax_pct percentile, but only if there's actually a long tail
        p99 = float(np.percentile(vals, ymax_pct))
        if vals.max() > p99 * 1.5:
            ylim_top = p99 * 1.08
        else:
            ylim_top = float(vals.max()) * 1.05
        n_clipped = int((vals > ylim_top).sum())

    fig, axes = plt.subplots(1, 2, figsize=(13.5, 5.6), sharey=True, squeeze=False)
    axes = axes[0]
    fig.suptitle(title, fontsize=14, y=1.0)

    for ax, axis_name in zip(axes, ("numNodes", "maxSpeed")):
        sub = df[df["sweep_axis"] == axis_name]
        if sub.empty:
            ax.set_visible(False)
            continue

        sns.boxplot(data=sub, x="sweep_value", y=metric_key, hue="protocol",
                    palette=palette, ax=ax,
                    showfliers=False, whis=(0, 100),
                    linewidth=0.9, width=0.72)
        sns.stripplot(data=sub, x="sweep_value", y=metric_key, hue="protocol",
                      dodge=True, palette=palette, ax=ax,
                      size=2.8, alpha=0.75, jitter=0.16,
                      legend=False, edgecolor="black", linewidth=0.25)

        ax.set_xlabel(AXIS_LABELS.get(axis_name, axis_name))
        ax.set_ylabel(ylabel if axis_name == "numNodes" else "")
        ax.set_title(f"{axis_name} sweep")
        ax.grid(axis="y", linestyle="--", alpha=0.45)
        ax.set_axisbelow(True)
        ax.set_ylim(ylim_bot, ylim_top)
        _apply_y_formatter(ax, fmt)

    # Single legend on first subplot, dropped from second
    for i, ax in enumerate(axes):
        leg = ax.get_legend()
        if leg is None:
            continue
        if i == 0:
            ax.legend(title="Protocol", loc="best", fontsize=9, ncol=2,
                      framealpha=0.92)
        else:
            leg.remove()

    if n_clipped > 0:
        max_val = float(vals.max())
        msg = (f"y-axis clipped at {ylim_top:.3g}; {n_clipped} of {len(vals)} reps "
               f"exceed this (max observed: {max_val:.3g}).")
        fig.text(0.5, -0.012, msg, ha="center", fontsize=8, color="dimgray")

    plt.tight_layout()
    fig.savefig(out_png, dpi=150, bbox_inches="tight")
    plt.close(fig)


def make_plots(per_run, fig_dir):
    try:
        import matplotlib  # noqa: F401
    except ImportError:
        print("matplotlib not installed -- skipping plots "
              "(install with: pip install matplotlib numpy)", file=sys.stderr)
        return
    fig_dir.mkdir(exist_ok=True)
    for key, ylabel, title, fmt, fixed_ylim in METRICS:
        out = fig_dir / f"{key}.png"
        plot_metric_box(per_run, key, ylabel, title, fmt, out, fixed_ylim=fixed_ylim)
        print(f"wrote {out}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("experiment", help="experiment dir, e.g. FanetRecon")
    ap.add_argument("--active-seconds", type=float, default=400.0,
                    help="sim-time-limit minus warmup-period (default 400)")
    ap.add_argument("--csv", default="results_scalars.csv",
                    help="scalars CSV name (default results_scalars.csv)")
    ap.add_argument("--no-plots", action="store_true",
                    help="skip the plotting step")
    args = ap.parse_args()

    here   = Path(__file__).resolve().parent
    exp    = here / args.experiment
    src    = exp / args.csv
    if not src.is_file():
        sys.exit(f"not found: {src}")

    runs   = {}                                # run_id -> meta dict
    acc    = defaultdict(lambda: {
        "sent": 0.0, "rcvd": 0.0,
        "ctrl_bytes": 0.0, "rcvd_bytes": 0.0,
        "rd_count": 0.0,
        "delay_count": float("nan"),
        "delay_mean":  float("nan"),
        "delay_stddev": float("nan"),
    })

    print(f"reading {src} ...", file=sys.stderr)
    with src.open(newline="", encoding="utf-8") as f:
        rdr = csv.DictReader(f)
        for n, row in enumerate(rdr, 1):
            if n % 1_000_000 == 0:
                print(f"  {n:,} rows", file=sys.stderr)
            run = row["run"]
            t   = row["type"]
            if t == "runattr":
                meta = runs.setdefault(run, {})
                an, av = row["attrname"], row["attrvalue"]
                if an in ("configname", "repetition"):
                    meta[an] = av
            elif t == "itervar":
                meta = runs.setdefault(run, {})
                meta[row["attrname"]] = row["attrvalue"]
            elif t == "scalar":
                mod, name = row["module"], row["name"]
                v = fnum(row["value"])
                if math.isnan(v):
                    continue
                a = acc[run]
                if name == "packetSent:count" and is_uav_app(mod, 0):
                    a["sent"] += v
                elif is_sink_app0(mod):
                    if name == "packetReceived:count":
                        a["rcvd"] += v
                    elif name == "packetReceived:sum(packetBytes)":
                        a["rcvd_bytes"] += v
                elif name == "controlPacketSent:sum(packetBytes)" and (
                        is_uav_app(mod, 1) or is_sink_app1(mod)):
                    a["ctrl_bytes"] += v
                elif name == "routeDiscoveryStarted:count" and (
                        is_uav_app(mod, 1) or is_sink_app1(mod)):
                    a["rd_count"] += v
            elif t == "histogram":
                if is_sink_app0(row["module"]) and row["name"] == "endToEndDelay:histogram":
                    a = acc[run]
                    a["delay_count"]  = fnum(row["count"])
                    a["delay_mean"]   = fnum(row["mean"])
                    a["delay_stddev"] = fnum(row["stddev"])

    # build per-run rows
    per_run = []
    for run, meta in runs.items():
        cfg   = meta.get("configname", "?")
        proto, axis = parse_config(cfg)
        rep   = int(meta.get("repetition", -1))
        sval  = meta.get(axis, "")
        try:
            sval_n = int(sval)
        except ValueError:
            sval_n = -1
        a = acc[run]
        sent, rcvd = a["sent"], a["rcvd"]
        pdr        = (rcvd / sent) if sent > 0 else float("nan")
        overhead   = (a["ctrl_bytes"] / a["rcvd_bytes"]) if a["rcvd_bytes"] > 0 else float("nan")
        rd_rate    = float("nan") if proto == "Olsr" else (a["rd_count"] / args.active_seconds)
        per_run.append({
            "run": run,
            "config": cfg,
            "protocol": proto,
            "sweep_axis": axis,
            "sweep_value": sval_n,
            "repetition": rep,
            "packets_sent": int(sent),
            "packets_rcvd": int(rcvd),
            "pdr": pdr,
            "mean_delay_s":   a["delay_mean"],
            "delay_stddev_s": a["delay_stddev"],
            "control_bytes":  int(a["ctrl_bytes"]),
            "data_bytes_rcvd": int(a["rcvd_bytes"]),
            "overhead_ratio": overhead,
            "rd_started_total": int(a["rd_count"]),
            "rd_per_s": rd_rate,
        })

    per_run.sort(key=lambda d: (d["protocol"], d["sweep_axis"], d["sweep_value"], d["repetition"]))
    out_rows = exp / "metrics_per_run.csv"
    with out_rows.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(per_run[0].keys()))
        w.writeheader(); w.writerows(per_run)

    # aggregate across repetitions
    groups = defaultdict(list)
    for d in per_run:
        groups[(d["protocol"], d["sweep_axis"], d["sweep_value"])].append(d)
    summary = []
    for (proto, axis, sv), drs in groups.items():
        row = {"protocol": proto, "sweep_axis": axis, "sweep_value": sv,
               "n_reps": len(drs)}
        for k in ("pdr", "mean_delay_s", "delay_stddev_s", "overhead_ratio", "rd_per_s"):
            m, s = mean_std([d[k] for d in drs])
            row[f"{k}_mean"] = m
            row[f"{k}_std"]  = s
        summary.append(row)
    summary.sort(key=lambda d: (d["sweep_axis"], d["sweep_value"], d["protocol"]))
    out_sum = exp / "metrics_summary.csv"
    with out_sum.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(summary[0].keys()))
        w.writeheader(); w.writerows(summary)

    print(f"wrote {out_rows}  ({len(per_run)} runs)", file=sys.stderr)
    print(f"wrote {out_sum}  ({len(summary)} groups)", file=sys.stderr)

    if not args.no_plots:
        make_plots(per_run, exp / "figs")


if __name__ == "__main__":
    main()
