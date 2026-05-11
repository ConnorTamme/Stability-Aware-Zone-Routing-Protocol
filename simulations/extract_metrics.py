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


def pool_delay_stats(sinks):
    """Pool per-sink endToEndDelay stats into (count, mean, stddev, min, max).
    `sinks` is {module_fqn: {count, mean, stddev, min, max}}. FanetRecon/Sar
    have a single sink so this collapses; FanetStress would have 5 if this
    script were taught to recognize that topology.

    mean is count-weighted; stddev pooled (sample-style, n_i >> 1). min/max
    span sinks. They're absent for old runs that recorded the default histogram
    only -- in that case both stay NaN.
    """
    valid = []
    for s in sinks.values():
        c = s.get("count", float("nan"))
        if math.isnan(c) or c == 0:
            continue
        valid.append((c, s.get("mean", float("nan")),
                      s.get("stddev", float("nan")),
                      s.get("min", float("nan")),
                      s.get("max", float("nan"))))
    if not valid:
        return (float("nan"),) * 5
    total_n = sum(c for c, _, _, _, _ in valid)
    pooled_mean = sum(c * m for c, m, _, _, _ in valid) / total_n
    pooled_var = 0.0
    for c, m, sd, _, _ in valid:
        if math.isnan(sd):
            sd = 0.0
        pooled_var += (c - 1) * sd * sd + c * (m - pooled_mean) ** 2
    pooled_var /= max(total_n - 1, 1)
    pooled_std = math.sqrt(max(pooled_var, 0.0))
    mins = [mn for _, _, _, mn, _ in valid if not math.isnan(mn)]
    maxs = [mx for _, _, _, _, mx in valid if not math.isnan(mx)]
    return (
        total_n,
        pooled_mean,
        pooled_std,
        min(mins) if mins else float("nan"),
        max(maxs) if maxs else float("nan"),
    )


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
    # Per-discovery quality metrics, emitted by ZRP / SA-ZRP at the IERP query
    # source. AODV/OLSR don't emit these so those bars stay empty.
    ("route_length_mean",         "Mean route length (hops)",          "Average Route Length",          "linear",  None),
    ("route_discovery_time_mean", "Mean route discovery time (s)",     "Average Route Discovery Time",  "seconds", None),
]

# Per-run packet drop accounting -- mirror of the same table in tuning/extract_metrics.py.
# INET emits these as scalars from various modules (radio/MAC/IP/queue) on every
# node; we aggregate count across all modules for each run, since the question
# is "where in the network are packets being dropped", not "by which node".
#
# Layout: (signal_name, short_key, layer_tag, human_label).
# layer_tag groups failures into families:
#   phy  = radio collision / SNR
#   mac  = MAC contention / retry / queue full / no carrier
#   ip   = IP routing layer (ARP, route lookup, TTL, forwarding)
#   app  = above-IP / protocol-internal (lifetime expired in IERP queue, etc.)
#   misc = bookkeeping (duplicates) -- noisy but kept for completeness
#
# Deliberately omitted: packetDrop:count (parent signal, double-counts the
# specific reasons), packetDropOther / packetDropUndefined / packetDropNotAddressedToUs
# (catch-all noise that's huge in a broadcast network and not actionable).
DROP_COUNTERS = [
    ("packetDropIncorrectlyReceived",     "phy_incorrectly_received",  "phy",  "PHY incorrectly received (collision/SNR)"),
    ("packetDropRetryLimitReached",       "mac_retry_limit",           "mac",  "MAC retry limit (no link-layer ACK)"),
    ("packetDropQueueOverflow",           "queue_overflow",            "mac",  "Queue overflow"),
    ("packetDropNoCarrier",               "no_carrier",                "mac",  "No carrier"),
    ("packetDropNoRouteFound",            "no_route_found",            "ip",   "IP no route found"),
    ("packetDropAddressResolutionFailed", "arp_failed",                "ip",   "ARP failed (next hop gone)"),
    ("packetDropHopLimitReached",         "hop_limit_reached",         "ip",   "Hop limit reached (TTL=0)"),
    ("packetDropForwardingDisabled",      "forwarding_disabled",       "ip",   "Forwarding disabled"),
    ("packetDropInterfaceDown",           "interface_down",            "ip",   "Interface down"),
    ("packetDropLifetimeExpired",         "lifetime_expired",          "app",  "Lifetime expired (aged out of queue)"),
    ("packetDropDuplicateDetected",       "duplicate_detected",        "misc", "Duplicate detected"),
]
DROP_LAYER_COLOR = {
    "phy":  "#d62728",   # red
    "mac":  "#ff7f0e",   # orange
    "ip":   "#1f77b4",   # blue
    "app":  "#2ca02c",   # green
    "misc": "#7f7f7f",   # grey
}

# Per-type control packet attribution. Each ZRP/SA-ZRP routing module emits
# one of these signals per send (the @signal[pktSent*] declarations in
# Zrp.ned / SaZrp.ned). The @statistic record= clause is
# `count, stats(packetBytes)`, so opp_scavetool produces one "statistic" row
# per (module, type) carrying count + sum + mean + stddev + min + max.
# AODV/OLSR don't emit these (only the aggregate controlPacketSent), so for
# those protocols every per-type field stays NaN/0.
#
# (signal_short, csv_key, human_label, color)
PKT_TYPES = [
    ("NDP",       "ndp",        "NDP_Hello",         "#1f77b4"),  # blue
    ("IARP",      "iarp",       "IARP link state",   "#2ca02c"),  # green
    ("IERPQuery", "ierp_query", "IERP query (RREQ)", "#d62728"),  # red
    ("IERPReply", "ierp_reply", "IERP reply (RREP)", "#9467bd"),  # purple
    ("BRP",       "brp",        "BRP bordercast",    "#ff7f0e"),  # orange
]
# Map from pktSent<short> -> csv_key, used to dispatch the stats(packetBytes)
# statistic row into the right per-type bucket.
PKT_SHORT_TO_KEY = {f"pktSent{short}": key for (short, key, _, _) in PKT_TYPES}


def pool_size_stats(per_module):
    """Pool per-module size stats for one packet type into a single dict
    {count, sum_bytes, mean, stddev, min, max}.

    Identical math to pool_delay_stats but consumes/produces the per-type
    layout used by PKT_TYPES. count and sum_bytes sum across modules; mean is
    count-weighted, stddev pooled (sample-style, n_i >> 1), min/max span
    modules.
    """
    valid = [(s.get("count", 0), s.get("mean", float("nan")),
              s.get("stddev", float("nan")), s.get("min", float("nan")),
              s.get("max", float("nan")))
             for s in per_module.values() if s.get("count", 0) > 0]
    total_count = sum(s.get("count", 0) for s in per_module.values())
    total_bytes = sum(s.get("sum_bytes", 0) for s in per_module.values())
    if not valid:
        return {"count": int(total_count), "sum_bytes": int(total_bytes),
                "mean": float("nan"), "stddev": float("nan"),
                "min": float("nan"), "max": float("nan")}
    pooled_mean = sum(c * m for c, m, _, _, _ in valid) / sum(c for c, _, _, _, _ in valid)
    pooled_var = 0.0
    for c, m, sd, _, _ in valid:
        if math.isnan(sd):
            sd = 0.0
        pooled_var += (c - 1) * sd * sd + c * (m - pooled_mean) ** 2
    pooled_var /= max(total_count - 1, 1)
    pooled_std = math.sqrt(max(pooled_var, 0.0))
    mins = [mn for _, _, _, mn, _ in valid if not math.isnan(mn)]
    maxs = [mx for _, _, _, _, mx in valid if not math.isnan(mx)]
    return {
        "count":     int(total_count),
        "sum_bytes": int(total_bytes),
        "mean":      pooled_mean,
        "stddev":    pooled_std,
        "min":       min(mins) if mins else float("nan"),
        "max":       max(maxs) if maxs else float("nan"),
    }


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


def plot_drops_breakdown(per_run, out_png):
    """Stacked horizontal bars: where packets are being dropped, network-wide.
    Two panels (numNodes sweep, maxSpeed sweep). Within each panel, one bar
    per (sweep_value, protocol). Bar segments are coloured by drop reason,
    grouped by failure layer (PHY -> MAC -> IP -> app -> misc), so the eye
    can pick out 'is this a channel problem or a routing problem' at a glance.

    Bar value is the mean drop count across the 10 reps."""
    try:
        import numpy as np
        import matplotlib.pyplot as plt
    except ImportError as e:
        print(f"missing plotting dep ({e}); pip install matplotlib numpy",
              file=sys.stderr)
        return

    if not per_run:
        return

    # (axis, sweep_value, protocol) -> {key: mean drop count}
    agg = defaultdict(lambda: {key: [] for (_, key, _, _) in DROP_COUNTERS})
    for r in per_run:
        bucket = agg[(r["sweep_axis"], r["sweep_value"], r["protocol"])]
        for (_sig, key, _layer, _label) in DROP_COUNTERS:
            bucket[key].append(r[f"drop_{key}"])
    for k in agg:
        for key in agg[k]:
            vals = [v for v in agg[k][key]
                    if not (isinstance(v, float) and math.isnan(v))]
            agg[k][key] = (sum(vals) / len(vals)) if vals else 0.0

    axes_to_plot = ["numNodes", "maxSpeed"]
    fig, axes = plt.subplots(1, 2, figsize=(16, 8), squeeze=False)
    axes = axes[0]
    fig.suptitle("Packet drops, attributed by layer and reason "
                 "(mean across reps)", fontsize=13)

    legend_seen = set()
    for ax, axis_name in zip(axes, axes_to_plot):
        # Bars in the order: smallest sweep value -> largest, and within each
        # sweep value, the canonical PROTO_ORDER. Visually this lines up
        # protocols at the same density / mobility for easy compare.
        bars_meta = []
        sweep_vals = sorted({k[1] for k in agg if k[0] == axis_name})
        for sv in sweep_vals:
            for proto in PROTO_ORDER:
                drops = agg.get((axis_name, sv, proto))
                if drops is None:
                    continue
                bars_meta.append((sv, proto, drops))

        if not bars_meta:
            ax.set_visible(False)
            continue

        labels = [f"{sv}  {proto}" for (sv, proto, _) in bars_meta]
        y = np.arange(len(bars_meta))

        left = np.zeros(len(bars_meta))
        for (_sig, key, layer, label) in DROP_COUNTERS:
            seg = np.array([b[2][key] for b in bars_meta], dtype=float)
            if seg.sum() == 0:
                continue
            color = DROP_LAYER_COLOR[layer]
            legend_label = f"[{layer}] {label}" if label not in legend_seen else None
            ax.barh(y, seg, left=left, color=color, edgecolor="white",
                    linewidth=0.4, label=legend_label)
            legend_seen.add(label)
            left += seg

        ax.set_yticks(y)
        ax.set_yticklabels(labels, fontsize=8)
        ax.invert_yaxis()
        ax.set_xlabel("Mean dropped packets per run (all modules)")
        ax.set_title(f"{AXIS_LABELS.get(axis_name, axis_name)} sweep", fontsize=11)
        ax.grid(axis="x", linestyle="--", alpha=0.45)
        ax.set_axisbelow(True)
        # Visually separate sweep-value groups with thin horizontal lines.
        if len(sweep_vals) > 1:
            group_size = len(bars_meta) // len(sweep_vals)
            for i in range(1, len(sweep_vals)):
                ax.axhline(i * group_size - 0.5, color="black",
                           linewidth=0.5, alpha=0.35)

    # Single legend for both panels.
    handles, labels = [], []
    for ax in axes:
        h, l = ax.get_legend_handles_labels()
        for hi, li in zip(h, l):
            if li and li not in labels:
                handles.append(hi); labels.append(li)
    if handles:
        fig.legend(handles, labels, loc="lower center", ncol=3,
                   fontsize=8, framealpha=0.92,
                   bbox_to_anchor=(0.5, -0.02))

    plt.tight_layout(rect=(0, 0.05, 1, 0.96))
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

    drops_out = fig_dir / "drops_breakdown.png"
    plot_drops_breakdown(per_run, drops_out)
    print(f"wrote {drops_out}", file=sys.stderr)


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

    # Pre-compute the set of drop scalar names we care about so the inner
    # loop can dispatch with one dict lookup per row instead of a startswith.
    DROP_NAME_TO_KEY = {f"{sig}:count": key
                        for (sig, key, _layer, _label) in DROP_COUNTERS}

    # endToEndDelay scalar names produced when the recording mode override in
    # the ini swaps the default histogram for count/mean/stddev/min/max scalars.
    # Old runs (still on default histogram-only mode) populate delay_sinks via
    # the histogram branch below -- they just won't have min/max.
    DELAY_SCALAR_FIELDS = {
        "endToEndDelay:count":  "count",
        "endToEndDelay:mean":   "mean",
        "endToEndDelay:stddev": "stddev",
        "endToEndDelay:min":    "min",
        "endToEndDelay:max":    "max",
    }

    def _new_acc():
        a = {
            "sent": 0.0, "rcvd": 0.0,
            "ctrl_bytes": 0.0, "rcvd_bytes": 0.0,
            "rd_count": 0.0,
            # Per-sink endToEndDelay stats: module FQN -> {count, mean, stddev,
            # min, max}. Pooled across sinks at run finalization.
            "delay_sinks": {},
            # Per-(packet type, routing module) size stats: pkt_key ->
            # module_fqn -> {count, sum_bytes, mean, stddev, min, max}. Pooled
            # across all routing modules in the run at finalization to give a
            # single network-wide breakdown. ZRP/SA-ZRP populate this; AODV/OLSR
            # don't emit per-type signals so it stays empty for them.
            "pkt_per_type_module": {key: {} for (_, key, _, _) in PKT_TYPES},
            # Sum + count across all routing modules in this run, of the
            # per-discovery routeLength and routeDiscoveryTime emissions. The
            # network-wide averages are sum/count -- correct because each
            # emission carries equal weight (one successful discovery).
            "route_len_count": 0.0,  "route_len_sum":  0.0,
            "route_disc_count": 0.0, "route_disc_sum": 0.0,
        }
        for (_sig, key, _layer, _label) in DROP_COUNTERS:
            a[f"drop_{key}"] = 0.0
        return a

    runs   = {}                                # run_id -> meta dict
    acc    = defaultdict(_new_acc)

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
                # Drop counters fire from MAC / radio / IPv4 modules, none of
                # which the app/role matchers below recognize. Aggregate them
                # across every module in the run -- we want network-wide drop
                # attribution, not per-node.
                drop_key = DROP_NAME_TO_KEY.get(name)
                if drop_key is not None:
                    acc[run][f"drop_{drop_key}"] += v
                    continue
                a = acc[run]
                if name == "packetSent:count" and is_uav_app(mod, 0):
                    a["sent"] += v
                elif is_sink_app0(mod):
                    if name == "packetReceived:count":
                        a["rcvd"] += v
                    elif name == "packetReceived:sum(packetBytes)":
                        a["rcvd_bytes"] += v
                    else:
                        field = DELAY_SCALAR_FIELDS.get(name)
                        if field is not None:
                            sink = a["delay_sinks"].setdefault(mod, {})
                            sink[field] = v
                elif name == "controlPacketSent:sum(packetBytes)" and (
                        is_uav_app(mod, 1) or is_sink_app1(mod)):
                    a["ctrl_bytes"] += v
                elif name == "routeDiscoveryStarted:count" and (
                        is_uav_app(mod, 1) or is_sink_app1(mod)):
                    a["rd_count"] += v
                elif (is_uav_app(mod, 1) or is_sink_app1(mod)):
                    # Per-discovery route quality metrics. count and sum let us
                    # compute the network-wide mean as sum/count without
                    # weighting (each emission = one completed discovery).
                    if name == "routeLength:count":
                        a["route_len_count"] += v
                    elif name == "routeLength:sum":
                        a["route_len_sum"] += v
                    elif name == "routeDiscoveryTime:count":
                        a["route_disc_count"] += v
                    elif name == "routeDiscoveryTime:sum":
                        a["route_disc_sum"] += v
            elif t in ("histogram", "statistic"):
                # endToEndDelay: old runs recorded a histogram, new runs record
                # a stats object (after the appendBins crash fix). Both rows
                # carry count/mean/stddev; only stats carries min/max. Per-type
                # packet sizes (pktSent*:stats(packetBytes)) also land here.
                mod, name = row["module"], row["name"]
                if is_sink_app0(mod) and name in ("endToEndDelay:histogram",
                                                  "endToEndDelay:stats"):
                    new_count = fnum(row["count"])
                    if math.isnan(new_count) or new_count == 0:
                        continue
                    sink = acc[run]["delay_sinks"].setdefault(mod, {})
                    sink["count"]  = new_count
                    sink["mean"]   = fnum(row["mean"])
                    sink["stddev"] = fnum(row["stddev"])
                    if "min" in row and "max" in row:
                        sink["min"] = fnum(row["min"])
                        sink["max"] = fnum(row["max"])
                elif (is_uav_app(mod, 1) or is_sink_app1(mod)) and \
                        name.endswith(":stats(packetBytes)"):
                    # Per-type packet size stats: row name like
                    # "pktSentNDP:stats(packetBytes)". Map back to pkt_key.
                    short = name.split(":")[0]
                    pkt_key = PKT_SHORT_TO_KEY.get(short)
                    if pkt_key is not None:
                        mod_stats = acc[run]["pkt_per_type_module"][pkt_key].setdefault(mod, {})
                        mod_stats["count"]     = fnum(row["count"])
                        mod_stats["sum_bytes"] = fnum(row.get("sum", float("nan")))
                        mod_stats["mean"]      = fnum(row["mean"])
                        mod_stats["stddev"]    = fnum(row["stddev"])
                        if "min" in row and "max" in row:
                            mod_stats["min"] = fnum(row["min"])
                            mod_stats["max"] = fnum(row["max"])

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
        delay_count, delay_mean, delay_std, delay_min, delay_max = pool_delay_stats(a["delay_sinks"])
        # Network-wide averages of routeLength (hops) and routeDiscoveryTime
        # (seconds). count is total successful discoveries across all routing
        # modules in this run; mean is sum/count. Both stay NaN for AODV/OLSR
        # which don't emit these signals, and for ZRP/SA-ZRP runs in which no
        # discovery completed.
        rl_count, rl_sum = a["route_len_count"], a["route_len_sum"]
        rd_dur_count, rd_dur_sum = a["route_disc_count"], a["route_disc_sum"]
        route_len_mean      = (rl_sum / rl_count)        if rl_count > 0     else float("nan")
        route_disc_time_mean = (rd_dur_sum / rd_dur_count) if rd_dur_count > 0 else float("nan")
        row = {
            "run": run,
            "config": cfg,
            "protocol": proto,
            "sweep_axis": axis,
            "sweep_value": sval_n,
            "repetition": rep,
            "packets_sent": int(sent),
            "packets_rcvd": int(rcvd),
            "pdr": pdr,
            "mean_delay_s":   delay_mean,
            "delay_stddev_s": delay_std,
            "min_delay_s":    delay_min,
            "max_delay_s":    delay_max,
            "control_bytes":  int(a["ctrl_bytes"]),
            "data_bytes_rcvd": int(a["rcvd_bytes"]),
            "overhead_ratio": overhead,
            "rd_started_total": int(a["rd_count"]),
            "rd_per_s": rd_rate,
            "route_length_count":         int(rl_count),
            "route_length_mean":          route_len_mean,
            "route_discovery_time_count": int(rd_dur_count),
            "route_discovery_time_mean":  route_disc_time_mean,
        }
        drop_total = 0
        for (_sig, key, _layer, _label) in DROP_COUNTERS:
            n = int(a[f"drop_{key}"])
            row[f"drop_{key}"] = n
            drop_total += n
        row["drop_total"] = drop_total
        # Per-type packet attribution: count + total bytes + size distribution
        # for each ZRP/SA-ZRP control packet type. Sum of pkt_*_count across
        # all five types should equal controlPacketSent count (sanity check);
        # sum of pkt_*_bytes should equal control_bytes.
        for (_short, key, _label, _color) in PKT_TYPES:
            stats = pool_size_stats(a["pkt_per_type_module"][key])
            row[f"pkt_{key}_count"]       = stats["count"]
            row[f"pkt_{key}_bytes"]       = stats["sum_bytes"]
            row[f"pkt_{key}_mean_size"]   = stats["mean"]
            row[f"pkt_{key}_min_size"]    = stats["min"]
            row[f"pkt_{key}_max_size"]    = stats["max"]
            row[f"pkt_{key}_stddev_size"] = stats["stddev"]
        per_run.append(row)

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
        for k in ("pdr", "mean_delay_s", "delay_stddev_s",
                  "min_delay_s", "max_delay_s",
                  "overhead_ratio", "rd_per_s",
                  "route_length_mean", "route_discovery_time_mean"):
            m, s = mean_std([d[k] for d in drs])
            row[f"{k}_mean"] = m
            row[f"{k}_std"]  = s
        for (_sig, key, _layer, _label) in DROP_COUNTERS:
            m, s = mean_std([d[f"drop_{key}"] for d in drs])
            row[f"drop_{key}_mean"] = m
            row[f"drop_{key}_std"]  = s
        m, s = mean_std([d["drop_total"] for d in drs])
        row["drop_total_mean"] = m
        row["drop_total_std"]  = s
        # Per-type packet stats: aggregate count/bytes/size distribution across
        # the n repetitions of this (protocol, axis, value) cell.
        for (_short, key, _label, _color) in PKT_TYPES:
            for field in ("count", "bytes", "mean_size",
                          "min_size", "max_size", "stddev_size"):
                m, s = mean_std([d[f"pkt_{key}_{field}"] for d in drs])
                row[f"pkt_{key}_{field}_mean"] = m
                row[f"pkt_{key}_{field}_std"]  = s
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
