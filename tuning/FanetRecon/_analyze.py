import csv
from collections import defaultdict
import statistics as st


def fnum(s):
    try:
        return float(s)
    except Exception:
        return None


def aggregate(want):
    groups = defaultdict(list)
    with open("metrics_summary.csv") as f:
        r = csv.DictReader(f)
        for row in r:
            if row["param_short"] not in want:
                continue
            key = (row["param_short"], row["protocol"], float(row["param_value"]))
            groups[key].append(row)
    return groups


cols = [
    "pdr_mean",
    "overhead_ratio_mean",
    "control_bytes_mean",
    "rd_per_s_mean",
    "rd_retries_per_s_mean",
    "rd_retries_per_discovery_mean",
    "mean_delay_s_mean",
    "pkt_ndp_count_mean",
    "pkt_iarp_count_mean",
    "pkt_ierp_reply_count_mean",
    "pkt_brp_count_mean",
    "drop_no_route_found_mean",
]


def show(want, label):
    print("=" * 80)
    print(label)
    print("=" * 80)
    groups = aggregate(want)
    for key in sorted(groups.keys()):
        rows = groups[key]
        agg = {}
        for c in cols:
            vals = [fnum(r[c]) for r in rows if fnum(r[c]) is not None]
            agg[c] = st.mean(vals) if vals else float("nan")
        n = len(rows)
        print(
            f"{key[0]:15s} {key[1]:13s} val={key[2]:>7}  n={n:2}  "
            f"pdr={agg['pdr_mean']:.3f}  "
            f"oh={agg['overhead_ratio_mean']:.3f}  "
            f"ctrlKB={agg['control_bytes_mean']/1024:7.0f}  "
            f"rd/s={agg['rd_per_s_mean']:.3f}  "
            f"retr/disc={agg['rd_retries_per_discovery_mean']:.2f}  "
            f"delay_ms={agg['mean_delay_s_mean']*1000:5.1f}  "
            f"NDP={agg['pkt_ndp_count_mean']:5.0f}  "
            f"IARP={agg['pkt_iarp_count_mean']:6.0f}  "
            f"IERPrep={agg['pkt_ierp_reply_count_mean']:5.0f}  "
            f"BRP={agg['pkt_brp_count_mean']:5.0f}  "
            f"noRoute={agg['drop_no_route_found_mean']:6.0f}"
        )


show(["IARPEventDelay"], "IARP event delay sweep")
show(["IARPUpdate"], "IARP update interval sweep")
show(["NDPHello"], "NDP hello interval sweep")
show(["LinkLifetime"], "Link state lifetime sweep")
show(["DecayBeta"], "Decay beta sweep (SA-ZRP only)")
show(["Stability"], "Stability threshold tau sweep (SA-ZRP only)")
show(["EmaAlpha"], "EMA alpha sweep")
show(["DistanceExponent"], "Distance exponent p sweep")
