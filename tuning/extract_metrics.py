#!/usr/bin/env python3
"""
Extract per-run + aggregated metrics from a TUNING experiment's
results_scalars.csv (output of opp_scavetool x results/*.sca).

This is the tuning counterpart to ../simulations/extract_metrics.py. Same
metrics, but the sweep axis is the protocol parameter being tuned (e.g.
NDP_helloInterval, stabilityThreshold) instead of numNodes/maxSpeed.

Per run we compute:
  pdr               packet delivery ratio
  mean_delay_s      mean end-to-end delay at the sink (from histogram row)
  delay_stddev_s    stddev of end-to-end delay (jitter proxy)
  control_bytes     raw routing control bytes
  overhead_ratio    routing control bytes / payload bytes delivered
  rd_per_s          route discoveries initiated per second (NaN for non-reactive)

Topology-aware: FanetRecon / FanetSar funnel into groundStation.app[0]; FanetStress
fans into uav[5..9].app[0] from sources uav[0..4].app[0], with routing apps at
uav[0..9].app[1] and uav[10..].app[0]. The right module set is selected by the
runattr `network` value.

Plot output: one PNG per swept parameter under <experiment>/figs/, with one
subplot per metric. Each subplot puts param value on the x-axis and overlays
the protocols (ZRP, SA-ZRP) so you can read off the effect of the parameter
across both at a glance.

Usage:
  python extract_metrics.py FanetRecon
  python extract_metrics.py FanetRecon --active-seconds 200
  python extract_metrics.py FanetRecon --no-plots
"""
import argparse
import csv
import math
import re
import sys
from collections import defaultdict
from pathlib import Path

# ---------------------------------------------------------------------------
# Topology-specific module matchers
# ---------------------------------------------------------------------------
# Recon / Sar: single sink at groundStation, UAV traffic at uav[*].app[0],
# routing at uav[*].app[1] + groundStation.app[1].
GS_SINK_RE      = re.compile(r"^Fanet\w+Network\.groundStation\.app\[0\]$")
GS_ROUTING_RE   = re.compile(r"^Fanet\w+Network\.groundStation\.app\[1\]$")
UAV_APP_RE      = re.compile(r"^Fanet\w+Network\.uav\[(\d+)\]\.app\[(\d+)\]$")


def stress_uav_role(idx):
    """For FanetStress: uav[0..4]=source, uav[5..9]=sink, uav[10..]=forwarder.
    Returns one of 'source', 'sink', 'forwarder'."""
    if idx <= 4:
        return "source"
    if idx <= 9:
        return "sink"
    return "forwarder"


def classify_module(network, module):
    """Return a tag describing what role this module plays in the metrics
    pipeline, or None if irrelevant. Tags consumed by the accumulator below.
    """
    # OMNeT++ writes the FQN ("sa_zrp.simulations.FanetSar.FanetSarNetwork")
    # into the `network` runattr; we only care about the leaf class name.
    network = network.rsplit(".", 1)[-1]
    if network in ("FanetReconNetwork", "FanetSarNetwork"):
        if GS_SINK_RE.match(module):
            return "sink_traffic"
        if GS_ROUTING_RE.match(module):
            return "routing"
        m = UAV_APP_RE.match(module)
        if not m:
            return None
        app_idx = int(m.group(2))
        if app_idx == 0:
            return "uav_traffic_source"  # all UAVs are senders
        if app_idx == 1:
            return "routing"
        return None

    if network == "FanetStressNetwork":
        m = UAV_APP_RE.match(module)
        if not m:
            return None
        uav_idx = int(m.group(1))
        app_idx = int(m.group(2))
        role = stress_uav_role(uav_idx)
        if role == "source" and app_idx == 0:
            return "uav_traffic_source"
        if role == "sink" and app_idx == 0:
            return "sink_traffic"
        # Routing app sits at app[1] for pairs (uav[0..9]) and app[0] for
        # forwarders (uav[10..]) -- see ../simulations/FanetStress/omnetpp.ini.
        if role in ("source", "sink") and app_idx == 1:
            return "routing"
        if role == "forwarder" and app_idx == 0:
            return "routing"
        return None

    return None


# ---------------------------------------------------------------------------
# Config name parsing
# ---------------------------------------------------------------------------
# e.g. Recon_TuneNDPHello_Zrp, Sar_TuneStability_StabilityZrp
CONFIG_RE = re.compile(r"^(?P<scen>\w+?)_Tune(?P<param>\w+?)_(?P<proto>\w+)$")

# Short config-name token -> (full ini parameter name, human-readable label)
PARAM_INFO = {
    "ZoneRadius":        ("zoneRadius",          "Zone radius"),
    "NDPHello":          ("NDP_helloInterval",   "NDP hello interval (s)"),
    "IARPUpdate":        ("IARP_updateInterval", "IARP update interval (s)"),
    "IARPEventDelay":    ("IARP_eventDelay",     "IARP event delay (ms)"),
    "LinkLifetime":      ("linkStateLifetime",   "Link state lifetime (s)"),
    "Stability":         ("stabilityThreshold",  "Stability threshold (tau)"),
    "DecayBeta":         ("decayBeta",           "Decay beta"),
    "EmaAlpha":          ("emaAlpha",            "EMA alpha"),
    "DistanceExponent":  ("distanceExponent",    "Distance exponent p"),
}

# Joint (2D) sweeps: param_short -> (x-axis (full,label), series (full,label)).
# Each row will additionally carry a "series_value" for the second iter var, and
# the plot draws one line per series_value (instead of per protocol).
JOINT_PARAM_INFO = {
    "StabDecay": (
        ("stabilityThreshold", "Stability threshold (tau)"),
        ("decayBeta",          "Decay beta"),
    ),
}

# Per-run packet drop accounting. INET emits these as scalars from various
# modules (radio/MAC/IP/queue) on every node, so we aggregate the count across
# *all* modules for each run -- the question we want to answer is "where are
# packets being dropped network-wide", not "which node dropped them".
#
# Layout: (signal_name, short_key, layer_tag, human_label).
# layer_tag is used by the breakdown plot to colour by failure family:
#   phy = radio collisions / SNR
#   mac = MAC contention / retry / queue full
#   ip  = IP routing layer (ARP, route lookup, TTL, forwarding)
#   app = above-IP / protocol-internal (lifetime expired in IERP queue, etc.)
#   misc = uninteresting bookkeeping drops (duplicates, not addressed to us)
#
# We deliberately omit packetDrop:count (the parent signal -- always shadows
# one of the specific reasons below, would double count) and packetDropOther
# / packetDropUndefined / packetDropNotAddressedToUs (catch-all noise that's
# huge in a broadcast network and not actionable).
DROP_COUNTERS = [
    # PHY: radio rx pipeline rejected the frame (collision, low SNR, BER)
    ("packetDropIncorrectlyReceived",   "phy_incorrectly_received",  "phy", "PHY incorrectly received (collision/SNR)"),
    # MAC: 802.11 retransmits exhausted -- next-hop ACK never came back
    ("packetDropRetryLimitReached",     "mac_retry_limit",           "mac", "MAC retry limit (no link-layer ACK)"),
    # MAC queue full when something tried to enqueue
    ("packetDropQueueOverflow",         "queue_overflow",            "mac", "Queue overflow"),
    # MAC: medium not available before deadline
    ("packetDropNoCarrier",             "no_carrier",                "mac", "No carrier"),
    # IP: routing table had no entry for the destination
    ("packetDropNoRouteFound",          "no_route_found",            "ip",  "IP no route found"),
    # IP: ARP timed out for the next hop -- next-hop physically unreachable
    ("packetDropAddressResolutionFailed", "arp_failed",              "ip",  "ARP failed (next hop gone)"),
    # IP: TTL hit zero (forwarding loop, or chosen path too long)
    ("packetDropHopLimitReached",       "hop_limit_reached",         "ip",  "Hop limit reached (TTL=0)"),
    # IP: forwarding administratively disabled on this node
    ("packetDropForwardingDisabled",    "forwarding_disabled",       "ip",  "Forwarding disabled"),
    # IP: interface down
    ("packetDropInterfaceDown",         "interface_down",            "ip",  "Interface down"),
    # App / above-IP: packet sat in a queue past its lifetime (e.g. SA-ZRP
    # delayedPackets, or an ARP holding queue exceeding the retry budget)
    ("packetDropLifetimeExpired",       "lifetime_expired",          "app", "Lifetime expired (aged out of queue)"),
    # IP duplicate detection (broadcast deduplication etc.)
    ("packetDropDuplicateDetected",     "duplicate_detected",        "misc", "Duplicate detected"),
]
DROP_LAYER_COLOR = {
    "phy":  "#d62728",   # red
    "mac":  "#ff7f0e",   # orange
    "ip":   "#1f77b4",   # blue
    "app":  "#2ca02c",   # green
    "misc": "#7f7f7f",   # grey
}

# Per-type control packet attribution. Each ZRP/SA-ZRP routing module emits one
# of these signals per send (the @signal[pktSent*] declarations in Zrp.ned /
# SaZrp.ned). The @statistic record= clause produces six scalars per type per
# module; we aggregate across modules at run finalization. AODV/OLSR don't
# emit these (they only emit the aggregate controlPacketSent), so for those
# protocols every per-type field stays NaN/0.
#
# (signal_short, csv_key, human_label, color)
PKT_TYPES = [
    ("NDP",       "ndp",        "NDP_Hello",         "#1f77b4"),  # blue
    ("IARP",      "iarp",       "IARP link state",   "#2ca02c"),  # green
    ("IERPQuery", "ierp_query", "IERP query (RREQ)", "#d62728"),  # red
    ("IERPReply", "ierp_reply", "IERP reply (RREP)", "#9467bd"),  # purple
    ("BRP",       "brp",        "BRP bordercast",    "#ff7f0e"),  # orange
]
# Map from .csv 'name' column -> (csv_key, field). Field is one of:
#   count, sum_bytes, mean, min, max, stddev.
PKT_SCALAR_FIELDS = {}
for (_short, _key, _label, _color) in PKT_TYPES:
    sig = f"pktSent{_short}"
    PKT_SCALAR_FIELDS[f"{sig}:count"]               = (_key, "count")
    PKT_SCALAR_FIELDS[f"{sig}:sum(packetBytes)"]    = (_key, "sum_bytes")
    PKT_SCALAR_FIELDS[f"{sig}:mean(packetBytes)"]   = (_key, "mean")
    PKT_SCALAR_FIELDS[f"{sig}:min(packetBytes)"]    = (_key, "min")
    PKT_SCALAR_FIELDS[f"{sig}:max(packetBytes)"]    = (_key, "max")
    PKT_SCALAR_FIELDS[f"{sig}:stddev(packetBytes)"] = (_key, "stddev")


def parse_config(cfg):
    """Returns (proto, param_short, param_full, param_label, joint_info).
    joint_info is None for OFAT sweeps; for joint sweeps it's
    ((x_full, x_label), (series_full, series_label))."""
    m = CONFIG_RE.match(cfg)
    if not m:
        return None, None, None, None, None
    proto = m.group("proto")
    param_short = m.group("param")
    joint = JOINT_PARAM_INFO.get(param_short)
    if joint is not None:
        # Use the x-axis var as the "primary" param so existing per-run rows
        # still record a sensible param_full/param_value pair.
        (x_full, x_label), _ = joint
        return proto, param_short, x_full, x_label, joint
    info = PARAM_INFO.get(param_short)
    if info is None:
        return proto, param_short, param_short, param_short, None
    param_full, param_label = info
    return proto, param_short, param_full, param_label, None


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
    var = sum((v - m) ** 2 for v in vs) / (len(vs) - 1)
    return m, math.sqrt(var)


def pool_size_stats(per_module):
    """Pool per-module size stats for one packet type into a single dict
    {count, sum_bytes, mean, stddev, min, max}.

    Identical math to pool_delay_stats but consumes/produces the per-type
    layout used by PKT_TYPES. count and sum_bytes sum across modules; mean is
    count-weighted, stddev pooled (sample-style, n_i >> 1), min/max span
    modules. Used by both per-run finalization (aggregating across all routing
    nodes in one run) and the per-type breakdown plot.
    """
    valid = [(s.get("count", 0), s.get("mean", float("nan")),
              s.get("stddev", float("nan")), s.get("min", float("nan")),
              s.get("max", float("nan")))
             for s in per_module.values() if s.get("count", 0) > 0]
    def _nz(x):
        return 0 if x is None or (isinstance(x, float) and math.isnan(x)) else x
    total_count = sum(_nz(s.get("count", 0)) for s in per_module.values())
    total_bytes = sum(_nz(s.get("sum_bytes", 0)) for s in per_module.values())
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


def pool_delay_stats(sinks):
    """Pool per-sink endToEndDelay stats into a single (count, mean, stddev,
    min, max) tuple. `sinks` is {module_fqn: {count, mean, stddev, min, max}}.
    FanetStress has 5 sinks; FanetRecon/Sar collapse to a single entry.

    mean is count-weighted. stddev uses pooled-variance (sample-style, assumes
    n_i >> 1, which holds at our packet rates). min/max are taken across sinks
    -- they're absent for old runs that recorded the default histogram only,
    in which case both end up NaN.
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
PROTO_ORDER  = ["Zrp", "StabilityZrp"]
PROTO_LABEL  = {"Zrp": "ZRP", "StabilityZrp": "SA-ZRP"}
PROTO_COLOR  = {"Zrp": "#1f77b4", "StabilityZrp": "#d62728"}
PROTO_MARKER = {"Zrp": "o",        "StabilityZrp": "s"}

METRICS = [
    # (key, ylabel, fmt)
    ("pdr",                       "Packet delivery ratio",                "percent"),
    ("mean_delay_s",              "Mean end-to-end delay",                "seconds"),
    ("delay_stddev_s",            "Delay stddev (jitter proxy)",          "seconds"),
    ("overhead_ratio",            "Routing overhead (control / payload)", "ratio"),
    ("control_bytes",             "Routing control bytes",                "bytes"),
    ("rd_per_s",                  "Route discoveries / s (1st attempt)",  "rate"),
    ("rd_retries_per_s",          "Discovery retransmits / s",            "rate"),
    ("rd_retries_per_discovery",  "Avg retransmits per discovery",        "ratio"),
    ("route_length_mean",         "Mean route length (hops)",             "linear"),
    ("route_discovery_time_mean", "Mean route discovery time",            "seconds"),
]
# 10 metrics -> 2x5 grid.
METRICS_GRID = (2, 5)


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


def plot_param(per_run, param_short, param_full, param_label, out_png):
    """One PNG per swept parameter -- 2x3 grid, one subplot per metric, each
    overlaying the protocols (line = mean, error bars = sample stddev across
    repetitions)."""
    try:
        import numpy as np
        import matplotlib.pyplot as plt
    except ImportError as e:
        print(f"missing plotting dep ({e}); pip install matplotlib numpy",
              file=sys.stderr)
        return

    rows = [r for r in per_run if r["param_short"] == param_short]
    if not rows:
        return

    # Group by (protocol, param_value) -> list of metric dicts
    groups = defaultdict(list)
    for r in rows:
        groups[(r["protocol"], r["param_value"])].append(r)

    protos = [p for p in PROTO_ORDER if any(r["protocol"] == p for r in rows)]
    param_vals = sorted({r["param_value"] for r in rows})

    fig, axes = plt.subplots(*METRICS_GRID, figsize=(20, 9))
    fig.suptitle(f"Parameter sweep: {param_label}", fontsize=14)

    for ax, (key, ylabel, fmt) in zip(axes.flat, METRICS):
        for proto in protos:
            xs, means, stds = [], [], []
            for v in param_vals:
                vals = [r[key] for r in groups.get((proto, v), [])
                        if isinstance(r[key], (int, float)) and not math.isnan(r[key])]
                if not vals:
                    continue
                m, s = mean_std(vals)
                xs.append(v); means.append(m); stds.append(s)
            if xs:
                # Clamp lower error bar to >= 0 -- with n=3 reps the
                # across-rep stddev frequently exceeds tiny means (delay
                # especially), and an unclamped symmetric error bar would
                # render as negative delay/PDR/overhead which is impossible.
                lower = [min(s, m) for m, s in zip(means, stds)]
                upper = list(stds)
                ax.errorbar(xs, means, yerr=[lower, upper],
                            label=PROTO_LABEL[proto],
                            color=PROTO_COLOR[proto],
                            marker=PROTO_MARKER[proto],
                            markersize=6, linewidth=1.6, capsize=3)

        ax.set_xlabel(param_label)
        ax.set_ylabel(ylabel)
        ax.grid(True, linestyle="--", alpha=0.45)
        ax.set_axisbelow(True)
        _apply_y_formatter(ax, fmt)
        if key == "pdr":
            ax.set_ylim(0, 1.05)
        if len(param_vals) > 1:
            ax.set_xticks(param_vals)
        ax.legend(loc="best", fontsize=9, framealpha=0.92)

    plt.tight_layout()
    fig.savefig(out_png, dpi=150, bbox_inches="tight")
    plt.close(fig)


def plot_joint(per_run, param_short, x_label, series_label, out_png):
    """Joint (2D) sweep plot: x-axis is the primary param, one line per
    distinct series_value (the second iter var). Same 2x3 metric grid as
    plot_param. SA-ZRP only -- joint sweeps don't include ZRP."""
    try:
        import matplotlib.pyplot as plt
    except ImportError as e:
        print(f"missing plotting dep ({e}); pip install matplotlib numpy",
              file=sys.stderr)
        return

    rows = [r for r in per_run if r["param_short"] == param_short]
    if not rows:
        return

    # Group by (series_value, x_value) -> list of metric dicts (one per rep).
    groups = defaultdict(list)
    for r in rows:
        groups[(r["series_value"], r["param_value"])].append(r)

    series_vals = sorted({r["series_value"] for r in rows
                          if not math.isnan(r["series_value"])})
    x_vals = sorted({r["param_value"] for r in rows
                     if not math.isnan(r["param_value"])})

    # Color cycle across series values; line/marker style is uniform so the
    # series axis reads cleanly even on grayscale prints.
    cmap_colors = ["#1f77b4", "#d62728", "#2ca02c", "#9467bd",
                   "#ff7f0e", "#17becf", "#8c564b", "#7f7f7f"]

    fig, axes = plt.subplots(*METRICS_GRID, figsize=(20, 9))
    fig.suptitle(f"Joint sweep: {x_label}  vs  {series_label}", fontsize=14)

    for ax, (key, ylabel, fmt) in zip(axes.flat, METRICS):
        for i, sv in enumerate(series_vals):
            xs, means, stds = [], [], []
            for v in x_vals:
                vals = [r[key] for r in groups.get((sv, v), [])
                        if isinstance(r[key], (int, float)) and not math.isnan(r[key])]
                if not vals:
                    continue
                m, s = mean_std(vals)
                xs.append(v); means.append(m); stds.append(s)
            if xs:
                # Clamp lower error bar to >= 0 so std-across-3-reps doesn't
                # render as physically impossible negative delay/PDR/etc.
                lower = [min(s, m) for m, s in zip(means, stds)]
                upper = list(stds)
                ax.errorbar(xs, means, yerr=[lower, upper],
                            label=f"{series_label.split(' ')[0]}={sv:g}",
                            color=cmap_colors[i % len(cmap_colors)],
                            marker="o", markersize=5, linewidth=1.4, capsize=3)

        ax.set_xlabel(x_label)
        ax.set_ylabel(ylabel)
        ax.grid(True, linestyle="--", alpha=0.45)
        ax.set_axisbelow(True)
        _apply_y_formatter(ax, fmt)
        if key == "pdr":
            ax.set_ylim(0, 1.05)
        if len(x_vals) > 1:
            ax.set_xticks(x_vals)
        ax.legend(loc="best", fontsize=8, framealpha=0.92)

    plt.tight_layout()
    fig.savefig(out_png, dpi=150, bbox_inches="tight")
    plt.close(fig)


def plot_drops_breakdown(per_run, out_png):
    """Stacked horizontal bars showing where packets are dropped network-wide.
    One bar per (param_short, protocol, param_value); segments coloured by
    drop reason, grouped by failure layer (PHY -> MAC -> IP -> app -> misc).
    Bar values are mean count across repetitions.

    The point of this plot is to answer 'is the limiting factor channel
    saturation, routing-table misses, or something else' at a glance, across
    every parameter setting we swept."""
    try:
        import numpy as np
        import matplotlib.pyplot as plt
    except ImportError as e:
        print(f"missing plotting dep ({e}); pip install matplotlib numpy",
              file=sys.stderr)
        return

    rows = [r for r in per_run]
    if not rows:
        return

    # Sort: sweep param, then protocol (Zrp before SA-ZRP so the eye can compare),
    # then ascending param value. For joint sweeps, also break out by series_value.
    def _bar_key(r):
        return (r["param_short"], r["protocol"], r["param_value"], r["series_value"])

    # Aggregate replicates: (sweep, proto, pval, sval) -> mean drops per reason.
    agg = defaultdict(lambda: {key: [] for (_, key, _, _) in DROP_COUNTERS})
    for r in rows:
        bucket = agg[_bar_key(r)]
        for (_sig, key, _layer, _label) in DROP_COUNTERS:
            bucket[key].append(r[f"drop_{key}"])
    # Replace value-lists with means.
    for k in agg:
        for key in agg[k]:
            vals = [v for v in agg[k][key] if not (isinstance(v, float) and math.isnan(v))]
            agg[k][key] = (sum(vals) / len(vals)) if vals else 0.0

    # Group bars by sweep and produce one figure per sweep so the bar count
    # per fig stays sane.
    by_sweep = defaultdict(list)
    for key, drops in agg.items():
        sweep, proto, pval, sval = key
        by_sweep[sweep].append((proto, pval, sval, drops))

    sweeps = sorted(by_sweep)
    if not sweeps:
        return
    n_sweeps = len(sweeps)
    fig, axes = plt.subplots(n_sweeps, 1, figsize=(13, 1.6 + 0.6 * sum(
        len(by_sweep[s]) for s in sweeps)), squeeze=False)
    axes = axes[:, 0]

    for ax, sweep in zip(axes, sweeps):
        bars = sorted(by_sweep[sweep],
                      key=lambda b: (b[0], b[1], b[2]))
        labels = []
        for proto, pval, sval, _ in bars:
            label = f"{proto}  pval={pval:g}"
            if not math.isnan(sval):
                label += f"  sval={sval:g}"
            labels.append(label)
        y = np.arange(len(bars))

        # Stack segments left-to-right grouped by layer family.
        left = np.zeros(len(bars))
        plotted_layers = set()
        for (_sig, key, layer, label) in DROP_COUNTERS:
            seg = np.array([b[3][key] for b in bars], dtype=float)
            if seg.sum() == 0:
                continue
            color = DROP_LAYER_COLOR[layer]
            # First time we see a layer, use the human label; subsequent reasons
            # in the same layer get the same colour but distinct legend entries.
            ax.barh(y, seg, left=left, color=color, edgecolor="white",
                    linewidth=0.5, label=f"[{layer}] {label}")
            left += seg
            plotted_layers.add(layer)

        ax.set_yticks(y)
        ax.set_yticklabels(labels, fontsize=8)
        ax.invert_yaxis()
        ax.set_xlabel("Mean dropped packets per run (across all modules)")
        ax.set_title(f"sweep: {sweep}", fontsize=11)
        ax.grid(axis="x", linestyle="--", alpha=0.45)
        ax.set_axisbelow(True)
        if plotted_layers:
            ax.legend(loc="lower right", fontsize=7, ncol=2, framealpha=0.92)

    plt.tight_layout()
    fig.savefig(out_png, dpi=150, bbox_inches="tight")
    plt.close(fig)


def plot_pkt_type_breakdown(per_run, out_png, mode="bytes"):
    """Stacked horizontal bars showing the per-type control-packet breakdown.
    One bar per (param_short, protocol, param_value, series_value); segments
    coloured by packet type from PKT_TYPES. Bar lengths are means across reps.

    mode="bytes": x-axis = total wire bytes per type (overhead breakdown).
    mode="count": x-axis = number of packets per type (chattiness breakdown).

    Only ZRP/SA-ZRP rows participate -- AODV/OLSR don't emit per-type signals
    so they'd render as empty bars.
    """
    try:
        import numpy as np
        import matplotlib.pyplot as plt
    except ImportError as e:
        print(f"missing plotting dep ({e}); pip install matplotlib numpy",
              file=sys.stderr)
        return

    field = "bytes" if mode == "bytes" else "count"
    rows = [r for r in per_run if any(r[f"pkt_{k}_{field}"] for (_, k, _, _) in PKT_TYPES)]
    if not rows:
        return

    def _bar_key(r):
        return (r["param_short"], r["protocol"], r["param_value"], r["series_value"])

    agg = defaultdict(lambda: {key: [] for (_, key, _, _) in PKT_TYPES})
    for r in rows:
        bucket = agg[_bar_key(r)]
        for (_short, key, _label, _color) in PKT_TYPES:
            bucket[key].append(r[f"pkt_{key}_{field}"])
    for k in agg:
        for key in agg[k]:
            vals = [v for v in agg[k][key]
                    if not (isinstance(v, float) and math.isnan(v))]
            agg[k][key] = (sum(vals) / len(vals)) if vals else 0.0

    by_sweep = defaultdict(list)
    for key, types in agg.items():
        sweep, proto, pval, sval = key
        by_sweep[sweep].append((proto, pval, sval, types))

    sweeps = sorted(by_sweep)
    if not sweeps:
        return
    n_sweeps = len(sweeps)
    fig, axes = plt.subplots(n_sweeps, 1, figsize=(13, 1.6 + 0.6 * sum(
        len(by_sweep[s]) for s in sweeps)), squeeze=False)
    axes = axes[:, 0]

    for ax, sweep in zip(axes, sweeps):
        bars = sorted(by_sweep[sweep], key=lambda b: (b[0], b[1], b[2]))
        labels = []
        for proto, pval, sval, _ in bars:
            label = f"{proto}  pval={pval:g}"
            if not math.isnan(sval):
                label += f"  sval={sval:g}"
            labels.append(label)
        y = np.arange(len(bars))

        left = np.zeros(len(bars))
        for (_short, key, label, color) in PKT_TYPES:
            seg = np.array([b[3][key] for b in bars], dtype=float)
            if seg.sum() == 0:
                continue
            ax.barh(y, seg, left=left, color=color, edgecolor="white",
                    linewidth=0.5, label=label)
            left += seg

        ax.set_yticks(y)
        ax.set_yticklabels(labels, fontsize=8)
        ax.invert_yaxis()
        if mode == "bytes":
            ax.set_xlabel("Mean control bytes per run, by packet type")
            from matplotlib.ticker import FuncFormatter
            def _b(v, _):
                av = abs(v)
                if av >= 1e6: return f"{v/1e6:.1f} MB"
                if av >= 1e3: return f"{v/1e3:.0f} KB"
                return f"{int(v)} B"
            ax.xaxis.set_major_formatter(FuncFormatter(_b))
        else:
            ax.set_xlabel("Mean control packets per run, by type")
        ax.set_title(f"sweep: {sweep}", fontsize=11)
        ax.grid(axis="x", linestyle="--", alpha=0.45)
        ax.set_axisbelow(True)
        ax.legend(loc="lower right", fontsize=8, ncol=2, framealpha=0.92)

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
    # Group rows by parameter so each PNG covers one sweep cleanly.
    by_param = defaultdict(list)
    for r in per_run:
        by_param[r["param_short"]].append(r)

    for param_short in sorted(by_param):
        sample = by_param[param_short][0]
        out = fig_dir / f"{param_short}.png"
        if param_short in JOINT_PARAM_INFO:
            plot_joint(per_run, param_short, sample["param_label"],
                       sample["series_label"], out)
        else:
            plot_param(per_run, param_short, sample["param_full"],
                       sample["param_label"], out)
        print(f"wrote {out}", file=sys.stderr)

    # Cross-sweep drop attribution.
    drops_out = fig_dir / "drops_breakdown.png"
    plot_drops_breakdown(per_run, drops_out)
    print(f"wrote {drops_out}", file=sys.stderr)

    # Cross-sweep per-type packet attribution. Two views: bytes (overhead) and
    # count (chattiness). They tell different stories -- e.g. NDP is high-count
    # but low-bytes, IARP can be the reverse when neighbourhoods are dense.
    pkt_bytes_out = fig_dir / "pkt_types_bytes.png"
    plot_pkt_type_breakdown(per_run, pkt_bytes_out, mode="bytes")
    print(f"wrote {pkt_bytes_out}", file=sys.stderr)
    pkt_count_out = fig_dir / "pkt_types_count.png"
    plot_pkt_type_breakdown(per_run, pkt_count_out, mode="count")
    print(f"wrote {pkt_count_out}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("experiment", help="experiment dir, e.g. FanetRecon")
    ap.add_argument("--active-seconds", type=float, default=200.0,
                    help="sim-time-limit minus warmup-period (default 200)")
    ap.add_argument("--csv", default="results_scalars.csv",
                    help="scalars CSV name (default results_scalars.csv)")
    ap.add_argument("--no-plots", action="store_true",
                    help="skip the plotting step")
    args = ap.parse_args()

    here = Path(__file__).resolve().parent
    exp  = here / args.experiment
    src  = exp / args.csv
    if not src.is_file():
        sys.exit(f"not found: {src}")

    # Pre-compute the set of drop scalar names we care about, so the inner
    # loop can dispatch with one dict lookup per row instead of N startswith()s.
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
            "rd_retry_count": 0.0,
            # Per-sink endToEndDelay stats: module FQN -> {count, mean, stddev,
            # min, max}. Pooled across sinks at run finalization. FanetStress
            # has 5 sinks (uav[5..9]); FanetRecon/Sar collapse to a single
            # groundStation entry.
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

    runs = {}  # run_id -> meta dict
    acc  = defaultdict(_new_acc)

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
                if an in ("configname", "repetition", "network"):
                    meta[an] = av
            elif t == "itervar":
                meta = runs.setdefault(run, {})
                meta[row["attrname"]] = row["attrvalue"]
            elif t == "scalar":
                name = row["name"]
                v = fnum(row["value"])
                if math.isnan(v):
                    continue
                # Drop counters fire from MAC / radio / IPv4 modules that
                # classify_module() doesn't tag (it only knows app/routing
                # modules), so handle them here BEFORE the role gate. We
                # aggregate across all modules in the run -- the question is
                # network-wide drop attribution, not per-node.
                drop_key = DROP_NAME_TO_KEY.get(name)
                if drop_key is not None:
                    acc[run][f"drop_{drop_key}"] += v
                    continue
                # Need network from runattrs to classify modules; the row
                # ordering puts runattrs before scalars in scavetool output,
                # so this lookup is safe.
                meta = runs.get(run, {})
                network = meta.get("network", "")
                tag = classify_module(network, row["module"])
                if tag is None:
                    continue
                a = acc[run]
                if tag == "uav_traffic_source" and name == "packetSent:count":
                    a["sent"] += v
                elif tag == "sink_traffic":
                    if name == "packetReceived:count":
                        a["rcvd"] += v
                    elif name == "packetReceived:sum(packetBytes)":
                        a["rcvd_bytes"] += v
                    else:
                        field = DELAY_SCALAR_FIELDS.get(name)
                        if field is not None:
                            sink = a["delay_sinks"].setdefault(row["module"], {})
                            sink[field] = v
                elif tag == "routing":
                    if name == "controlPacketSent:sum(packetBytes)":
                        a["ctrl_bytes"] += v
                    elif name == "routeDiscoveryStarted:count":
                        a["rd_count"] += v
                    elif name == "routeDiscoveryRetried:count":
                        # Only ZRP and SA-ZRP record this; AODV/OLSR scalars
                        # never carry it, which is the desired asymmetry.
                        a["rd_retry_count"] += v
                    elif name == "routeLength:count":
                        a["route_len_count"] += v
                    elif name == "routeLength:sum":
                        a["route_len_sum"] += v
                    elif name == "routeDiscoveryTime:count":
                        a["route_disc_count"] += v
                    elif name == "routeDiscoveryTime:sum":
                        a["route_disc_sum"] += v
                    else:
                        info = PKT_SCALAR_FIELDS.get(name)
                        if info is not None:
                            pkt_key, field = info
                            mod_stats = a["pkt_per_type_module"][pkt_key].setdefault(row["module"], {})
                            mod_stats[field] = v
            elif t in ("histogram", "statistic"):
                # Backward compat path: pre-fix runs still record endToEndDelay
                # as a histogram. New runs record it as `stats` object.
                # Pull count/mean/stddev from the histogram/statistic row
                # into the same per-sink dict the scalar branch populates.
                # min/max stay NaN for old histogram runs, but are pulled for stats.
                meta = runs.get(run, {})
                network = meta.get("network", "")
                tag = classify_module(network, row["module"])
                if tag == "sink_traffic" and row["name"] in ("endToEndDelay:histogram", "endToEndDelay:stats"):
                    new_count = fnum(row["count"])
                    if math.isnan(new_count) or new_count == 0:
                        continue
                    sink = acc[run]["delay_sinks"].setdefault(row["module"], {})
                    sink["count"]  = new_count
                    sink["mean"]   = fnum(row["mean"])
                    sink["stddev"] = fnum(row["stddev"])
                    if "min" in row and "max" in row:
                        sink["min"] = fnum(row["min"])
                        sink["max"] = fnum(row["max"])
                elif tag == "routing" and row["name"].endswith(":stats(packetBytes)"):
                    k = row["name"].split(":")[0]
                    # Map from pktSentNDP to ndp via PKT_SCALAR_FIELDS
                    info = PKT_SCALAR_FIELDS.get(k + ":count")
                    if info is not None:
                        pkt_key, _ = info
                        mod_stats = acc[run]["pkt_per_type_module"][pkt_key].setdefault(row["module"], {})
                        mod_stats["count"]     = fnum(row["count"])
                        mod_stats["sum_bytes"] = fnum(row.get("sum", float("nan")))
                        mod_stats["mean"]      = fnum(row["mean"])
                        mod_stats["stddev"]    = fnum(row["stddev"])
                        if "min" in row and "max" in row:
                            mod_stats["min"] = fnum(row["min"])
                            mod_stats["max"] = fnum(row["max"])

    # Build per-run rows.
    per_run = []
    for run, meta in runs.items():
        cfg = meta.get("configname", "?")
        proto, param_short, param_full, param_label, joint = parse_config(cfg)
        if proto is None:
            continue  # not a Tune* config (Base configs leak in via repeat=3 noop)
        rep = int(meta.get("repetition", -1))
        # The iter var name matches param_full, set in the .ini.
        pval_raw = meta.get(param_full, "")
        try:
            pval = float(pval_raw)
        except (TypeError, ValueError):
            pval = float("nan")

        # For joint sweeps, also pull the second iter var (the "series" axis).
        series_full = ""
        series_label = ""
        sval = float("nan")
        if joint is not None:
            (_, _), (series_full, series_label) = joint
            sval_raw = meta.get(series_full, "")
            try:
                sval = float(sval_raw)
            except (TypeError, ValueError):
                sval = float("nan")

        a = acc[run]
        sent, rcvd = a["sent"], a["rcvd"]
        pdr      = (rcvd / sent) if sent > 0 else float("nan")
        overhead = (a["ctrl_bytes"] / a["rcvd_bytes"]) if a["rcvd_bytes"] > 0 else float("nan")
        delay_count, delay_mean, delay_std, delay_min, delay_max = pool_delay_stats(a["delay_sinks"])
        # rd_per_s is NaN for OLSR in the test pipeline; not relevant here
        # (we only sweep ZRP / SA-ZRP), but harmless to keep the same shape.
        rd_rate       = a["rd_count"] / args.active_seconds
        rd_retry_rate = a["rd_retry_count"] / args.active_seconds
        # retries-per-discovery: how many retransmits the average new discovery
        # incurs before either succeeding or hitting ierpMaxRetries. If routes
        # exist this should be near zero -- nonzero values mean queries/replies
        # are getting lost or the stability filter is rejecting valid paths.
        rd_retries_per_discovery = (a["rd_retry_count"] / a["rd_count"]) if a["rd_count"] > 0 else float("nan")
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
            "param_short":  param_short,
            "param_full":   param_full,
            "param_label":  param_label,
            "param_value":  pval,
            "series_full":  series_full,
            "series_label": series_label,
            "series_value": sval,
            "repetition":   rep,
            "packets_sent": int(sent),
            "packets_rcvd": int(rcvd),
            "pdr":            pdr,
            "mean_delay_s":   delay_mean,
            "delay_stddev_s": delay_std,
            "min_delay_s":    delay_min,
            "max_delay_s":    delay_max,
            "control_bytes":  int(a["ctrl_bytes"]),
            "data_bytes_rcvd": int(a["rcvd_bytes"]),
            "overhead_ratio": overhead,
            "rd_started_total": int(a["rd_count"]),
            "rd_per_s": rd_rate,
            "rd_retries_total": int(a["rd_retry_count"]),
            "rd_retries_per_s": rd_retry_rate,
            "rd_retries_per_discovery": rd_retries_per_discovery,
            "route_length_count":         int(rl_count),
            "route_length_mean":          route_len_mean,
            "route_discovery_time_count": int(rd_dur_count),
            "route_discovery_time_mean":  route_disc_time_mean,
        }
        # Drop counters: total counts per reason, plus a grand total. Stored
        # as ints because that's the natural unit.
        drop_total = 0
        for (_sig, key, _layer, _label) in DROP_COUNTERS:
            n = int(a[f"drop_{key}"])
            row[f"drop_{key}"] = n
            drop_total += n
        row["drop_total"] = drop_total
        # Per-type packet attribution: for each ZRP/SA-ZRP control packet type,
        # write count + total bytes + size distribution stats. Sum of
        # pkt_*_count across all five types should equal the controlPacketSent
        # count (sanity check); sum of pkt_*_bytes should equal control_bytes.
        for (_short, key, _label, _color) in PKT_TYPES:
            stats = pool_size_stats(a["pkt_per_type_module"][key])
            row[f"pkt_{key}_count"]      = stats["count"]
            row[f"pkt_{key}_bytes"]      = stats["sum_bytes"]
            row[f"pkt_{key}_mean_size"]  = stats["mean"]
            row[f"pkt_{key}_min_size"]   = stats["min"]
            row[f"pkt_{key}_max_size"]   = stats["max"]
            row[f"pkt_{key}_stddev_size"] = stats["stddev"]
        per_run.append(row)

    if not per_run:
        sys.exit(f"no Tune* runs found in {src}")

    per_run.sort(key=lambda d: (d["param_short"], d["protocol"],
                                d["param_value"], d["series_value"], d["repetition"]))
    out_rows = exp / "metrics_per_run.csv"
    with out_rows.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(per_run[0].keys()))
        w.writeheader(); w.writerows(per_run)

    # Aggregate across repetitions. For joint sweeps, series_value participates
    # in the grouping so each (tau, beta) cell gets its own summary row.
    groups = defaultdict(list)
    for d in per_run:
        groups[(d["param_short"], d["param_full"], d["protocol"],
                d["param_value"], d["series_value"])].append(d)
    summary = []
    for (param_short, param_full, proto, pv, sv), drs in groups.items():
        row = {"param_short": param_short, "param_full": param_full,
               "protocol": proto, "param_value": pv,
               "series_full": drs[0]["series_full"], "series_value": sv,
               "n_reps": len(drs)}
        for k in ("pdr", "mean_delay_s", "delay_stddev_s",
                  "min_delay_s", "max_delay_s",
                  "overhead_ratio", "control_bytes", "rd_per_s",
                  "rd_retries_per_s", "rd_retries_per_discovery",
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
        # Per-type packet stats: aggregate count/bytes/mean-size/min/max/stddev
        # across the n repetitions of this (param, protocol) cell. Useful for
        # the breakdown plot and for direct CSV inspection.
        for (_short, key, _label, _color) in PKT_TYPES:
            for field in ("count", "bytes", "mean_size",
                          "min_size", "max_size", "stddev_size"):
                m, s = mean_std([d[f"pkt_{key}_{field}"] for d in drs])
                row[f"pkt_{key}_{field}_mean"] = m
                row[f"pkt_{key}_{field}_std"]  = s
        summary.append(row)
    summary.sort(key=lambda d: (d["param_short"], d["protocol"],
                                d["param_value"], d["series_value"]))
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
