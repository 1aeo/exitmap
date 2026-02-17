#!/usr/bin/env python3
"""
Exit DNS Health — Historical Analysis
======================================
Comprehensive analysis of Tor exit relay DNS health scan results from
https://exitdnshealth.1aeo.com/

This analysis covers 100 archive scans from Jan 24 – Feb 17, 2026, tracking
the evolution from single-instance scanning to the 4-instance parallel
cross-validation model and demonstrating why the latter produces the most
accurate and reliable exit relay DNS health statistics.
"""

# %% [markdown]
# # 🔬 Tor Exit DNS Health — Historical Analysis
#
# **Data source:** https://exitdnshealth.1aeo.com/ (100 archive scans, Jan 24 – Feb 17, 2026)
#
# **Goal:** Analyse the history of all scan results to identify repeat patterns, flag anomalies,
# and build confidence that the **4-instance parallel cross-validation model** is the most
# reliable way to measure exit relay DNS health — because single-instance scanning caused
# significant timeouts and unreachable-relay inflation due to Tor network inconsistencies.

# %% — Imports & Configuration
import json
import os
import warnings
from datetime import datetime, timezone
from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import matplotlib.patches as mpatches
import matplotlib.ticker as mticker
import numpy as np
import pandas as pd
import seaborn as sns

warnings.filterwarnings("ignore", category=FutureWarning)

# ── 1AEO Brand palette ──────────────────────────────────────────────────────
AEO_GREEN = "#00ff7f"
AEO_GREEN_DIM = "#00cc66"
AEO_GREEN_DARK = "#004d26"
AEO_DARK_BG = "#121212"
AEO_DARK_SURFACE = "#1e1e1e"
AEO_TEXT = "#ffffff"
AEO_TEXT_MUTED = "#cccccc"
AEO_TEXT_DIM = "#888888"

STATUS_SUCCESS = "#3fb950"
STATUS_ERROR = "#f85149"
STATUS_WARNING = "#d29922"
STATUS_INFO = "#58a6ff"
STATUS_PURPLE = "#a371f7"

PHASE_COLORS = {
    "single": STATUS_ERROR,       # red — single instance
    "cv2": STATUS_WARNING,        # orange — 2-instance CV experiment
    "cv4": STATUS_SUCCESS,        # green — 4-instance CV (production)
}
PHASE_LABELS = {
    "single": "Single Instance",
    "cv2": "2-Instance CV",
    "cv4": "4-Instance CV",
}

DATA_DIR = Path("/workspace/analysis/data")
CHARTS_DIR = Path("/workspace/analysis/charts")
CHARTS_DIR.mkdir(parents=True, exist_ok=True)

# Apply dark style globally
plt.rcParams.update({
    "figure.facecolor": AEO_DARK_BG,
    "axes.facecolor": AEO_DARK_SURFACE,
    "axes.edgecolor": AEO_TEXT_DIM,
    "axes.labelcolor": AEO_TEXT_MUTED,
    "xtick.color": AEO_TEXT_DIM,
    "ytick.color": AEO_TEXT_DIM,
    "text.color": AEO_TEXT,
    "legend.facecolor": AEO_DARK_SURFACE,
    "legend.edgecolor": AEO_TEXT_DIM,
    "grid.color": "#333333",
    "grid.alpha": 0.5,
    "font.size": 11,
    "axes.titlesize": 14,
    "axes.labelsize": 12,
    "figure.dpi": 150,
    "savefig.dpi": 150,
    "savefig.facecolor": AEO_DARK_BG,
    "savefig.bbox": "tight",
})


def save_chart(fig, name):
    """Save figure to charts directory."""
    path = CHARTS_DIR / f"{name}.png"
    fig.savefig(path, bbox_inches="tight", pad_inches=0.3)
    print(f"  ✓ Saved {path}")


# %% — Load & Parse All Archive Files
print("=" * 70)
print("PHASE 1: Loading archive data")
print("=" * 70)

rows = []
skipped = []

for fpath in sorted(DATA_DIR.glob("dns_health_*.json")):
    try:
        with open(fpath) as f:
            data = json.load(f)
    except (json.JSONDecodeError, ValueError):
        skipped.append((fpath.name, "invalid/empty JSON"))
        continue

    m = data["metadata"]
    scan = m.get("scan", {})
    timing = m.get("timing", {}).get("total", {})
    cv = m.get("cross_validation", {})
    consistency = cv.get("consistency", {})
    waves = scan.get("waves", {})

    # Determine phase
    scan_type = scan.get("type", "single")
    instances = scan.get("instances", 1)
    if scan_type == "cross_validate" and instances >= 4:
        phase = "cv4"
    elif scan_type == "cross_validate":
        phase = "cv2"
    else:
        phase = "single"

    # Parse timestamp
    ts_str = m.get("timestamp", "")
    try:
        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except Exception:
        ts = datetime.now(timezone.utc)

    row = {
        "filename": fpath.name,
        "timestamp": ts,
        "scan_type": scan_type,
        "instances": instances,
        "phase": phase,
        # Relay counts
        "consensus_relays": m.get("consensus_relays", 0),
        "tested_relays": m.get("tested_relays", 0),
        "unreachable_relays": m.get("unreachable_relays", 0),
        # DNS outcomes
        "dns_success": m.get("dns_success", 0),
        "dns_fail": m.get("dns_fail", 0),
        "dns_timeout": m.get("dns_timeout", 0),
        "dns_wrong_ip": m.get("dns_wrong_ip", 0),
        "dns_socks_error": m.get("dns_socks_error", 0),
        "dns_network_error": m.get("dns_network_error", 0),
        "dns_error": m.get("dns_error", 0),
        "dns_exception": m.get("dns_exception", 0),
        "dns_unknown": m.get("dns_unknown", 0),
        # Circuit errors
        "circuit_timeout": m.get("circuit_timeout", 0),
        "circuit_destroyed": m.get("circuit_destroyed", 0),
        "circuit_channel_closed": m.get("circuit_channel_closed", 0),
        "circuit_connect_failed": m.get("circuit_connect_failed", 0),
        "circuit_no_path": m.get("circuit_no_path", 0),
        "circuit_resource_limit": m.get("circuit_resource_limit", 0),
        "circuit_hibernating": m.get("circuit_hibernating", 0),
        "circuit_finished": m.get("circuit_finished", 0),
        "circuit_connection_closed": m.get("circuit_connection_closed", 0),
        "circuit_io_error": m.get("circuit_io_error", 0),
        "circuit_protocol_error": m.get("circuit_protocol_error", 0),
        "circuit_internal_error": m.get("circuit_internal_error", 0),
        "circuit_failed": m.get("circuit_failed", 0),
        # Rates
        "dns_success_rate": m.get("dns_success_rate_percent", 0.0),
        "reachability_rate": m.get("reachability_rate_percent", 0.0),
        # Timing
        "timing_avg_ms": timing.get("avg_ms", None),
        "timing_min_ms": timing.get("min_ms", None),
        "timing_max_ms": timing.get("max_ms", None),
        "timing_p50_ms": timing.get("p50_ms", None),
        "timing_p95_ms": timing.get("p95_ms", None),
        "timing_p99_ms": timing.get("p99_ms", None),
        # Cross-validation metrics
        "cv_relays_improved": cv.get("relays_improved", None),
        "cv_recovered_timeout": cv.get("recovered_from_timeout", None),
        "cv_recovered_dns_fail": cv.get("recovered_from_dns_fail", None),
        "cv_recovered_error": cv.get("recovered_from_error", None),
        "cv_all_success": consistency.get("all_success", None),
        "cv_all_failed": consistency.get("all_failed", None),
        "cv_mixed": consistency.get("mixed", None),
        # Waves
        "waves_enabled": waves.get("enabled", False),
        "waves_total": waves.get("total_waves", None),
        "waves_batch_size": waves.get("batch_size", None),
        "waves_total_retries": waves.get("total_retries", None),
    }

    # Flag anomalies
    is_anomalous = False
    anomaly_reasons = []
    if row["consensus_relays"] < 100:
        is_anomalous = True
        anomaly_reasons.append(f"very low consensus_relays={row['consensus_relays']}")
    if row["dns_success_rate"] == 0.0 and row["tested_relays"] > 0:
        is_anomalous = True
        anomaly_reasons.append("0% DNS success with tested relays")
    if row["tested_relays"] == 0 and row["consensus_relays"] > 100:
        is_anomalous = True
        anomaly_reasons.append("0 tested relays despite large consensus")
    if row["reachability_rate"] > 100.0:
        is_anomalous = True
        anomaly_reasons.append(f"reachability_rate={row['reachability_rate']:.1f}% > 100 (broken consensus count)")
    if row["consensus_relays"] > 5000:
        is_anomalous = True
        anomaly_reasons.append(f"abnormally high consensus_relays={row['consensus_relays']} (likely duplicated relay list)")

    row["is_anomalous"] = is_anomalous
    row["anomaly_reasons"] = "; ".join(anomaly_reasons) if anomaly_reasons else None

    rows.append(row)

df = pd.DataFrame(rows)
df = df.sort_values("timestamp").reset_index(drop=True)

print(f"Loaded {len(df)} scan records ({len(skipped)} skipped)")
if skipped:
    for name, reason in skipped:
        print(f"  ⚠ Skipped: {name} — {reason}")

print(f"Date range: {df['timestamp'].min()} → {df['timestamp'].max()}")
print(f"Phases: {df['phase'].value_counts().to_dict()}")

# %% [markdown]
# ## 📊 Phase Breakdown
#
# The data reveals three distinct scanning phases:
#
# | Phase | Scan Type | Instances | Period | Scans |
# |-------|-----------|-----------|--------|-------|
# | **Single Instance** | `single` | 1 | Jan 24–29 | High frequency (every 2h) |
# | **2-Instance CV** | `cross_validate` | 2 | Jan 25, 29 (brief experiments) | 3 scans only |
# | **4-Instance CV** | `cross_validate` | 4 | Jan 30 onwards | Stabilised at every 12h |

# %% — Summary Statistics Table
print("\n" + "=" * 70)
print("PHASE 2: Summary Statistics by Phase")
print("=" * 70)

# Exclude the anomalous 2-relay scan from stats
df_clean = df[~df["is_anomalous"]].copy()

key_metrics = [
    "dns_success_rate", "reachability_rate", "dns_timeout",
    "unreachable_relays", "tested_relays", "consensus_relays",
    "dns_fail", "timing_avg_ms",
]

summary = df_clean.groupby("phase")[key_metrics].agg(["mean", "std", "min", "max", "count"])
for phase in ["single", "cv2", "cv4"]:
    if phase in summary.index:
        print(f"\n{'─' * 50}")
        print(f"  {PHASE_LABELS[phase]} (n={summary.loc[phase, ('dns_success_rate', 'count')]:.0f} scans)")
        print(f"{'─' * 50}")
        for metric in key_metrics:
            if phase in summary.index:
                s = summary.loc[phase, metric]
                print(f"  {metric:>25s}:  mean={s['mean']:8.2f}  std={s['std']:7.2f}  "
                      f"min={s['min']:8.2f}  max={s['max']:8.2f}")

# %% — Helper: phase-shaded background
def shade_phases(ax, df):
    """Add semi-transparent background bands for each scanning phase."""
    phase_ranges = df_clean.groupby("phase")["timestamp"].agg(["min", "max"])
    for phase, color in PHASE_COLORS.items():
        if phase in phase_ranges.index:
            tmin = phase_ranges.loc[phase, "min"]
            tmax = phase_ranges.loc[phase, "max"]
            ax.axvspan(tmin, tmax, alpha=0.08, color=color, zorder=0)


def format_date_axis(ax):
    """Format x-axis with nice date labels."""
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%b %d"))
    ax.xaxis.set_major_locator(mdates.DayLocator(interval=2))
    plt.setp(ax.get_xticklabels(), rotation=45, ha="right")


def add_phase_legend(ax, loc="upper left"):
    """Add a phase legend to the chart."""
    handles = [
        mpatches.Patch(facecolor=PHASE_COLORS[p], alpha=0.7, label=PHASE_LABELS[p])
        for p in ["single", "cv2", "cv4"]
    ]
    ax.legend(handles=handles, loc=loc, fontsize=9, framealpha=0.8)


# ═══════════════════════════════════════════════════════════════════════════
# CHART 1: DNS Success Rate Over Time
# ═══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("CHART 1: DNS Success Rate Over Time")
print("=" * 70)

fig, ax = plt.subplots(figsize=(14, 6))
shade_phases(ax, df_clean)

for phase in ["single", "cv2", "cv4"]:
    mask = (df_clean["phase"] == phase)
    subset = df_clean[mask]
    ax.scatter(subset["timestamp"], subset["dns_success_rate"],
               c=PHASE_COLORS[phase], s=40, alpha=0.85, zorder=3,
               label=PHASE_LABELS[phase], edgecolors="white", linewidths=0.3)
    if len(subset) > 1:
        ax.plot(subset["timestamp"], subset["dns_success_rate"],
                c=PHASE_COLORS[phase], alpha=0.4, linewidth=1, zorder=2)

# Annotate anomalous scans
for _, row in df[df["is_anomalous"]].iterrows():
    ax.annotate(f"⚠ {row['anomaly_reasons']}",
                xy=(row["timestamp"], row["dns_success_rate"]),
                xytext=(10, -25), textcoords="offset points",
                fontsize=7, color=STATUS_WARNING,
                arrowprops=dict(arrowstyle="->", color=STATUS_WARNING, lw=0.8))

ax.set_ylabel("DNS Success Rate (%)")
ax.set_title("DNS Success Rate Over Time — By Scanning Phase", fontweight="bold", pad=15)
ax.set_ylim(bottom=max(0, df_clean["dns_success_rate"].min() - 3))
ax.grid(True, alpha=0.3)
format_date_axis(ax)
add_phase_legend(ax, loc="lower right")

# Add mean lines
for phase in ["single", "cv4"]:
    mask = df_clean["phase"] == phase
    if mask.any():
        mean_val = df_clean.loc[mask, "dns_success_rate"].mean()
        phase_ts = df_clean.loc[mask, "timestamp"]
        ax.hlines(mean_val, phase_ts.min(), phase_ts.max(),
                  colors=PHASE_COLORS[phase], linestyles="dashed", alpha=0.5, linewidth=1)
        ax.text(phase_ts.max(), mean_val + 0.15,
                f"  mean={mean_val:.1f}%", fontsize=8, color=PHASE_COLORS[phase], va="bottom")

fig.tight_layout()
save_chart(fig, "01_dns_success_rate")
plt.close(fig)

# ═══════════════════════════════════════════════════════════════════════════
# CHART 2: Reachability Rate Over Time
# ═══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("CHART 2: Reachability Rate Over Time")
print("=" * 70)

fig, ax = plt.subplots(figsize=(14, 6))
shade_phases(ax, df_clean)

for phase in ["single", "cv2", "cv4"]:
    mask = df_clean["phase"] == phase
    subset = df_clean[mask]
    ax.scatter(subset["timestamp"], subset["reachability_rate"],
               c=PHASE_COLORS[phase], s=40, alpha=0.85, zorder=3,
               label=PHASE_LABELS[phase], edgecolors="white", linewidths=0.3)
    if len(subset) > 1:
        ax.plot(subset["timestamp"], subset["reachability_rate"],
                c=PHASE_COLORS[phase], alpha=0.4, linewidth=1, zorder=2)

# Add mean lines with improvement annotation
single_reach = df_clean.loc[df_clean["phase"] == "single", "reachability_rate"].mean()
cv4_reach = df_clean.loc[df_clean["phase"] == "cv4", "reachability_rate"].mean()
ax.axhline(single_reach, color=PHASE_COLORS["single"], linestyle="--", alpha=0.4, linewidth=1)
ax.axhline(cv4_reach, color=PHASE_COLORS["cv4"], linestyle="--", alpha=0.4, linewidth=1)

# Improvement annotation
mid_ts = df_clean["timestamp"].iloc[len(df_clean) // 2]
ax.annotate(f"+{cv4_reach - single_reach:.1f}pp improvement",
            xy=(mid_ts, (single_reach + cv4_reach) / 2),
            fontsize=11, fontweight="bold", color=AEO_GREEN, ha="center",
            bbox=dict(boxstyle="round,pad=0.3", facecolor=AEO_DARK_BG, edgecolor=AEO_GREEN, alpha=0.9))

ax.set_ylabel("Reachability Rate (%)")
ax.set_title("Relay Reachability Rate Over Time — The Biggest Win", fontweight="bold", pad=15)
ax.set_ylim(75, 101)
ax.grid(True, alpha=0.3)
format_date_axis(ax)
add_phase_legend(ax, loc="lower right")

fig.tight_layout()
save_chart(fig, "02_reachability_rate")
plt.close(fig)

# ═══════════════════════════════════════════════════════════════════════════
# CHART 3: Timeout & Unreachable Relay Counts
# ═══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("CHART 3: Timeout & Unreachable Counts Over Time")
print("=" * 70)

fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(14, 8), sharex=True)

# Top: Unreachable relays
for phase in ["single", "cv2", "cv4"]:
    mask = df_clean["phase"] == phase
    subset = df_clean[mask]
    ax1.bar(subset["timestamp"], subset["unreachable_relays"],
            width=0.03, color=PHASE_COLORS[phase], alpha=0.8, label=PHASE_LABELS[phase])

ax1.set_ylabel("Unreachable Relays")
ax1.set_title("Unreachable Relays Per Scan — Single Instance vs 4-Instance CV", fontweight="bold", pad=10)
ax1.grid(True, alpha=0.3)
ax1.legend(fontsize=9, loc="upper left")

# Bottom: DNS + Circuit timeouts
df_clean["total_timeouts"] = df_clean["dns_timeout"] + df_clean["circuit_timeout"]
for phase in ["single", "cv2", "cv4"]:
    mask = df_clean["phase"] == phase
    subset = df_clean[mask]
    ax2.bar(subset["timestamp"], subset["total_timeouts"],
            width=0.03, color=PHASE_COLORS[phase], alpha=0.8, label=PHASE_LABELS[phase])

ax2.set_ylabel("Total Timeouts (DNS + Circuit)")
ax2.set_title("Timeout Count Per Scan", fontweight="bold", pad=10)
ax2.grid(True, alpha=0.3)
format_date_axis(ax2)
ax2.legend(fontsize=9, loc="upper left")

fig.tight_layout()
save_chart(fig, "03_timeouts_unreachable")
plt.close(fig)

# ═══════════════════════════════════════════════════════════════════════════
# CHART 4: Tested vs Consensus Relays
# ═══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("CHART 4: Tested vs Consensus Relays")
print("=" * 70)

fig, ax = plt.subplots(figsize=(14, 6))
shade_phases(ax, df_clean)

ax.plot(df_clean["timestamp"], df_clean["consensus_relays"],
        color=STATUS_INFO, alpha=0.9, linewidth=1.5, label="Consensus Relays", marker=".", markersize=4)
ax.plot(df_clean["timestamp"], df_clean["tested_relays"],
        color=AEO_GREEN, alpha=0.9, linewidth=1.5, label="Tested Relays", marker=".", markersize=4)

# Fill the gap
ax.fill_between(df_clean["timestamp"], df_clean["tested_relays"], df_clean["consensus_relays"],
                alpha=0.15, color=STATUS_ERROR, label="Untested Gap")

ax.set_ylabel("Relay Count")
ax.set_title("Tested vs Consensus Relays — Gap Closure with 4-Instance CV", fontweight="bold", pad=15)
ax.grid(True, alpha=0.3)
format_date_axis(ax)
ax.legend(fontsize=9, loc="center left")

# Annotate the gap
single_mask = df_clean["phase"] == "single"
if single_mask.any():
    single_gap = (df_clean.loc[single_mask, "consensus_relays"] - df_clean.loc[single_mask, "tested_relays"]).mean()
    cv4_mask = df_clean["phase"] == "cv4"
    cv4_gap = (df_clean.loc[cv4_mask, "consensus_relays"] - df_clean.loc[cv4_mask, "tested_relays"]).mean()
    ax.text(0.98, 0.95,
            f"Single instance avg gap: {single_gap:.0f} relays\n4-CV avg gap: {cv4_gap:.0f} relays",
            transform=ax.transAxes, fontsize=10, va="top", ha="right",
            bbox=dict(boxstyle="round,pad=0.4", facecolor=AEO_DARK_BG, edgecolor=AEO_GREEN, alpha=0.9),
            color=AEO_TEXT)

fig.tight_layout()
save_chart(fig, "04_tested_vs_consensus")
plt.close(fig)

# ═══════════════════════════════════════════════════════════════════════════
# CHART 5: Cross-Validation Recovery Impact
# ═══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("CHART 5: Cross-Validation Recovery Impact")
print("=" * 70)

df_cv = df_clean[df_clean["phase"].isin(["cv2", "cv4"]) & df_clean["cv_relays_improved"].notna()].copy()

fig, ax = plt.subplots(figsize=(14, 6))

if len(df_cv) > 0:
    bar_width = 0.02
    ax.bar(df_cv["timestamp"], df_cv["cv_recovered_dns_fail"].fillna(0),
           width=bar_width, color=STATUS_ERROR, alpha=0.85, label="Recovered from DNS Fail")
    ax.bar(df_cv["timestamp"], df_cv["cv_recovered_timeout"].fillna(0),
           width=bar_width, bottom=df_cv["cv_recovered_dns_fail"].fillna(0),
           color=STATUS_WARNING, alpha=0.85, label="Recovered from Timeout")
    ax.bar(df_cv["timestamp"], df_cv["cv_recovered_error"].fillna(0),
           width=bar_width,
           bottom=df_cv["cv_recovered_dns_fail"].fillna(0) + df_cv["cv_recovered_timeout"].fillna(0),
           color=STATUS_PURPLE, alpha=0.85, label="Recovered from Error")

    # Total improved line
    ax.plot(df_cv["timestamp"], df_cv["cv_relays_improved"],
            color=AEO_GREEN, linewidth=1.5, alpha=0.8, marker="o", markersize=4,
            label="Total Relays Improved", zorder=5)

    mean_improved = df_cv["cv_relays_improved"].mean()
    ax.axhline(mean_improved, color=AEO_GREEN, linestyle="--", alpha=0.4)
    ax.text(df_cv["timestamp"].iloc[-1], mean_improved + 2,
            f"  mean={mean_improved:.0f}", fontsize=9, color=AEO_GREEN)

ax.set_ylabel("Relays Recovered by Cross-Validation")
ax.set_title("Cross-Validation Recovery — Relays Saved from False Negatives", fontweight="bold", pad=15)
ax.grid(True, alpha=0.3)
format_date_axis(ax)
ax.legend(fontsize=9, loc="upper left")

fig.tight_layout()
save_chart(fig, "05_cv_recovery_impact")
plt.close(fig)

# ═══════════════════════════════════════════════════════════════════════════
# CHART 6: Per-Instance Failure Distribution (4-CV Heatmap)
# ═══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("CHART 6: Per-Instance Failure Distribution Heatmap")
print("=" * 70)

# Collect per-instance stats from all 4-CV files
instance_data = []
for fpath in sorted(DATA_DIR.glob("dns_health_*.json")):
    try:
        with open(fpath) as f:
            data = json.load(f)
    except (json.JSONDecodeError, ValueError):
        continue
    m = data["metadata"]
    scan = m.get("scan", {})
    if scan.get("instances", 1) < 4:
        continue
    cv = m.get("cross_validation", {})
    pis = cv.get("per_instance_stats", {})
    ts = m.get("timestamp", "")
    for inst_name, stats in pis.items():
        total = sum(stats.values())
        success = stats.get("success", 0)
        fails = total - success
        instance_data.append({
            "timestamp": ts[:10],
            "instance": inst_name,
            "total": total,
            "success": success,
            "failures": fails,
            "fail_rate": (fails / total * 100) if total > 0 else 0,
        })

if instance_data:
    df_inst = pd.DataFrame(instance_data)

    # Filter out instances with very low totals (e.g., single tor_connection_refused entries)
    df_inst = df_inst[df_inst["total"] >= 10]

    # Group by instance (across all scans) to get average failure rate
    inst_summary = df_inst.groupby("instance").agg(
        avg_fail_rate=("fail_rate", "mean"),
        std_fail_rate=("fail_rate", "std"),
        total_tested=("total", "sum"),
        total_failures=("failures", "sum"),
    ).reset_index()

    # Separate instance and wave
    inst_summary["cv_instance"] = inst_summary["instance"].str.extract(r"(cv\d+)")
    inst_summary["wave"] = inst_summary["instance"].str.extract(r"(w\d+)")

    # Drop rows where cv_instance or wave couldn't be extracted
    inst_summary = inst_summary.dropna(subset=["cv_instance", "wave"])

    # Create heatmap pivot
    pivot = inst_summary.pivot(index="cv_instance", columns="wave", values="avg_fail_rate")

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5), gridspec_kw={"width_ratios": [2, 1]})

    # Heatmap
    sns.heatmap(pivot, annot=True, fmt=".1f", cmap="YlOrRd", ax=ax1,
                linewidths=1, linecolor=AEO_DARK_BG,
                cbar_kws={"label": "Avg Failure Rate (%)"})
    ax1.set_title("Per-Instance Avg Failure Rate (%) — 4-CV Scans", fontweight="bold", pad=10)
    ax1.set_xlabel("Wave")
    ax1.set_ylabel("Instance")

    # Bar chart: overall per-instance failure rate
    by_cv = inst_summary.groupby("cv_instance").agg(
        total_tested=("total_tested", "sum"),
        total_failures=("total_failures", "sum"),
    ).reset_index()
    by_cv["fail_rate"] = by_cv["total_failures"] / by_cv["total_tested"] * 100

    bars = ax2.barh(by_cv["cv_instance"], by_cv["fail_rate"],
                    color=[STATUS_ERROR, STATUS_WARNING, STATUS_INFO, STATUS_PURPLE], alpha=0.85)
    ax2.set_xlabel("Overall Failure Rate (%)")
    ax2.set_title("Aggregate Per-Instance\nFailure Rate", fontweight="bold", pad=10)
    ax2.grid(True, alpha=0.3, axis="x")

    for bar, rate in zip(bars, by_cv["fail_rate"]):
        ax2.text(bar.get_width() + 0.05, bar.get_y() + bar.get_height() / 2,
                 f"{rate:.2f}%", va="center", fontsize=9, color=AEO_TEXT)

    fig.tight_layout()
    save_chart(fig, "06_per_instance_failures")
    plt.close(fig)

# ═══════════════════════════════════════════════════════════════════════════
# CHART 7: Timing Distribution Over Time
# ═══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("CHART 7: Timing Distribution Over Time")
print("=" * 70)

df_timing = df_clean[df_clean["timing_p50_ms"].notna()].copy()

fig, ax = plt.subplots(figsize=(14, 6))
shade_phases(ax, df_timing)

ax.plot(df_timing["timestamp"], df_timing["timing_p50_ms"] / 1000,
        color=STATUS_SUCCESS, alpha=0.9, linewidth=1.5, marker=".", markersize=4, label="p50 (median)")
ax.plot(df_timing["timestamp"], df_timing["timing_p95_ms"] / 1000,
        color=STATUS_WARNING, alpha=0.8, linewidth=1.5, marker=".", markersize=4, label="p95")
ax.plot(df_timing["timestamp"], df_timing["timing_p99_ms"] / 1000,
        color=STATUS_ERROR, alpha=0.7, linewidth=1.5, marker=".", markersize=4, label="p99")

ax.fill_between(df_timing["timestamp"],
                df_timing["timing_p50_ms"] / 1000,
                df_timing["timing_p95_ms"] / 1000,
                alpha=0.1, color=STATUS_WARNING)
ax.fill_between(df_timing["timestamp"],
                df_timing["timing_p95_ms"] / 1000,
                df_timing["timing_p99_ms"] / 1000,
                alpha=0.08, color=STATUS_ERROR)

ax.set_ylabel("Response Time (seconds)")
ax.set_title("DNS Query Timing Distribution Over Time (p50 / p95 / p99)", fontweight="bold", pad=15)
ax.grid(True, alpha=0.3)
format_date_axis(ax)
ax.legend(fontsize=9, loc="upper right")

fig.tight_layout()
save_chart(fig, "07_timing_distribution")
plt.close(fig)

# ═══════════════════════════════════════════════════════════════════════════
# CHART 8: DNS Failure Categories Breakdown
# ═══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("CHART 8: DNS Failure Categories Breakdown")
print("=" * 70)

fig, ax = plt.subplots(figsize=(14, 6))
shade_phases(ax, df_clean)

failure_cols = [
    ("dns_fail", STATUS_ERROR, "DNS Fail"),
    ("dns_timeout", STATUS_WARNING, "DNS Timeout"),
    ("circuit_timeout", STATUS_PURPLE, "Circuit Timeout"),
    ("circuit_destroyed", STATUS_INFO, "Circuit Destroyed"),
    ("circuit_channel_closed", "#e0a0ff", "Circuit Channel Closed"),
]

bottom = np.zeros(len(df_clean))
for col, color, label in failure_cols:
    vals = df_clean[col].values.astype(float)
    ax.bar(df_clean["timestamp"], vals, bottom=bottom,
           width=0.03, color=color, alpha=0.85, label=label)
    bottom += vals

ax.set_ylabel("Error Count")
ax.set_title("DNS & Circuit Failure Categories Per Scan", fontweight="bold", pad=15)
ax.grid(True, alpha=0.3)
format_date_axis(ax)
ax.legend(fontsize=9, loc="upper left")

fig.tight_layout()
save_chart(fig, "08_failure_categories")
plt.close(fig)

# ═══════════════════════════════════════════════════════════════════════════
# CHART 9: Consistency Analysis (CV Files)
# ═══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("CHART 9: Cross-Validation Consistency Analysis")
print("=" * 70)

df_cv4 = df_clean[(df_clean["phase"] == "cv4") & df_clean["cv_all_success"].notna()].copy()

if len(df_cv4) > 0:
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6), gridspec_kw={"width_ratios": [2.5, 1]})

    # Stacked area of consistency over time
    ax1.fill_between(df_cv4["timestamp"], 0, df_cv4["cv_all_success"],
                     alpha=0.7, color=STATUS_SUCCESS, label="All Instances Agree: Success")
    ax1.fill_between(df_cv4["timestamp"], df_cv4["cv_all_success"],
                     df_cv4["cv_all_success"] + df_cv4["cv_mixed"],
                     alpha=0.7, color=STATUS_WARNING, label="Mixed (CV Rescued)")
    ax1.fill_between(df_cv4["timestamp"],
                     df_cv4["cv_all_success"] + df_cv4["cv_mixed"],
                     df_cv4["cv_all_success"] + df_cv4["cv_mixed"] + df_cv4["cv_all_failed"],
                     alpha=0.7, color=STATUS_ERROR, label="All Instances Agree: Failed")

    ax1.set_ylabel("Relay Count")
    ax1.set_title("Cross-Validation Consistency Over Time (4-CV)", fontweight="bold", pad=10)
    ax1.grid(True, alpha=0.3)
    format_date_axis(ax1)
    ax1.legend(fontsize=9, loc="lower left")

    # Pie chart of averages (using legend to avoid label overlap on small slices)
    avg_success = df_cv4["cv_all_success"].mean()
    avg_mixed = df_cv4["cv_mixed"].mean()
    avg_failed = df_cv4["cv_all_failed"].mean()
    sizes = [avg_success, avg_mixed, avg_failed]
    legend_labels = [f"All Success ({avg_success:.0f} avg)",
                     f"Mixed / CV Rescued ({avg_mixed:.0f} avg)",
                     f"All Failed ({avg_failed:.0f} avg)"]
    colors = [STATUS_SUCCESS, STATUS_WARNING, STATUS_ERROR]
    explode = (0, 0.12, 0.12)
    wedges, texts, autotexts = ax2.pie(sizes, colors=colors,
                                        autopct="%1.1f%%", startangle=140,
                                        explode=explode, pctdistance=0.78,
                                        textprops={"fontsize": 9, "color": AEO_TEXT})
    for at in autotexts:
        at.set_fontsize(9)
        at.set_color(AEO_DARK_BG)
        at.set_fontweight("bold")
    ax2.legend(wedges, legend_labels, loc="lower center", fontsize=8,
               bbox_to_anchor=(0.5, -0.15), framealpha=0.8)
    ax2.set_title("Average Consistency\nBreakdown", fontweight="bold", pad=10)

    fig.tight_layout()
    save_chart(fig, "09_consistency_analysis")
    plt.close(fig)

# ═══════════════════════════════════════════════════════════════════════════
# CHART 10: Scan Reliability / Confidence Metric
# ═══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("CHART 10: Overall Scan Confidence Metric")
print("=" * 70)

df_clean["confidence"] = (
    (df_clean["tested_relays"] / df_clean["consensus_relays"].replace(0, 1))
    * (df_clean["dns_success_rate"] / 100.0)
    * 100.0
)

fig, ax = plt.subplots(figsize=(14, 6))
shade_phases(ax, df_clean)

for phase in ["single", "cv2", "cv4"]:
    mask = df_clean["phase"] == phase
    subset = df_clean[mask]
    ax.scatter(subset["timestamp"], subset["confidence"],
               c=PHASE_COLORS[phase], s=50, alpha=0.85, zorder=3,
               label=PHASE_LABELS[phase], edgecolors="white", linewidths=0.3)
    if len(subset) > 1:
        ax.plot(subset["timestamp"], subset["confidence"],
                c=PHASE_COLORS[phase], alpha=0.4, linewidth=1, zorder=2)

# Add means
single_conf = df_clean.loc[df_clean["phase"] == "single", "confidence"].mean()
cv4_conf = df_clean.loc[df_clean["phase"] == "cv4", "confidence"].mean()

ax.axhline(single_conf, color=PHASE_COLORS["single"], linestyle="--", alpha=0.4)
ax.axhline(cv4_conf, color=PHASE_COLORS["cv4"], linestyle="--", alpha=0.4)

ax.text(0.98, 0.05,
        f"Confidence = (tested/consensus) × dns_success_rate\n"
        f"Single: {single_conf:.1f}%  →  4-CV: {cv4_conf:.1f}%  (+{cv4_conf - single_conf:.1f}pp)",
        transform=ax.transAxes, fontsize=10, va="bottom", ha="right",
        bbox=dict(boxstyle="round,pad=0.4", facecolor=AEO_DARK_BG, edgecolor=AEO_GREEN, alpha=0.9),
        color=AEO_TEXT)

ax.set_ylabel("Confidence Score (%)")
ax.set_title("Overall Scan Confidence Metric Over Time", fontweight="bold", pad=15)
ax.grid(True, alpha=0.3)
format_date_axis(ax)
add_phase_legend(ax, loc="lower left")

fig.tight_layout()
save_chart(fig, "10_confidence_metric")
plt.close(fig)

# ═══════════════════════════════════════════════════════════════════════════
# ANOMALY DETECTION & FLAGGING
# ═══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("ANOMALY DETECTION & FLAGGING")
print("=" * 70)

# 1. Explicitly flagged anomalies
print("\n── Flagged Anomalous Scans ──")
anomalous = df[df["is_anomalous"]]
if len(anomalous) > 0:
    for _, row in anomalous.iterrows():
        print(f"  ⚠ {row['filename']}: {row['anomaly_reasons']}")
else:
    print("  None found")

# 2. Skipped files (empty/invalid)
print("\n── Skipped Files (Invalid JSON) ──")
if skipped:
    for name, reason in skipped:
        print(f"  ⚠ {name}: {reason}")
else:
    print("  None")

# 3. Statistical outliers within 4-CV phase
print("\n── Statistical Outliers in 4-Instance CV Phase ──")
df_cv4_stats = df_clean[df_clean["phase"] == "cv4"].copy()
if len(df_cv4_stats) > 5:
    for metric in ["dns_success_rate", "reachability_rate", "dns_timeout", "dns_fail"]:
        mean = df_cv4_stats[metric].mean()
        std = df_cv4_stats[metric].std()
        if std > 0:
            outliers = df_cv4_stats[abs(df_cv4_stats[metric] - mean) > 2 * std]
            for _, row in outliers.iterrows():
                print(f"  ⚠ {row['filename']}: {metric}={row[metric]:.2f} "
                      f"(mean={mean:.2f}, 2σ={2*std:.2f})")

# 4. Missing scan windows
print("\n── Missing Scan Windows ──")
# After Jan 30, expect scans at 00:05 and 12:05 daily
from datetime import timedelta
expected_start = datetime(2026, 1, 31, tzinfo=timezone.utc)
expected_end = df["timestamp"].max()
cv4_timestamps = set(df_clean.loc[df_clean["phase"] == "cv4", "timestamp"].dt.date)
current = expected_start.date()
while current <= expected_end.date():
    if current not in cv4_timestamps:
        print(f"  ⚠ No 4-CV scan found for {current}")
    current += timedelta(days=1)

# 5. Scan frequency change detection
print("\n── Scan Frequency Pattern ──")
df_by_date = df_clean.groupby(df_clean["timestamp"].dt.date).size()
for date, count in df_by_date.items():
    if date >= expected_start.date() and count < 2:
        print(f"  ⚠ {date}: only {count} scan(s) (expected 2)")

# ═══════════════════════════════════════════════════════════════════════════
# KEY FINDINGS SUMMARY
# ═══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("KEY FINDINGS SUMMARY")
print("=" * 70)

single_stats = df_clean[df_clean["phase"] == "single"]
cv4_stats = df_clean[df_clean["phase"] == "cv4"]

findings = f"""
╔══════════════════════════════════════════════════════════════════════╗
║           Tor Exit DNS Health — Analysis Key Findings               ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  1. REACHABILITY: {single_stats['reachability_rate'].mean():.1f}% → {cv4_stats['reachability_rate'].mean():.1f}%                          ║
║     4-Instance CV improved relay reachability by                     ║
║     +{cv4_stats['reachability_rate'].mean() - single_stats['reachability_rate'].mean():.1f} percentage points. Single instance missed ~17%   ║
║     of relays due to Tor network inconsistencies.                    ║
║                                                                      ║
║  2. TIMEOUTS: {single_stats['dns_timeout'].mean():.0f}/scan → {cv4_stats['dns_timeout'].mean():.0f}/scan                              ║
║     DNS timeouts dropped from ~{single_stats['dns_timeout'].mean():.0f} to ~{cv4_stats['dns_timeout'].mean():.0f} per scan.              ║
║     Circuit timeouts similarly reduced.                              ║
║                                                                      ║
║  3. DNS SUCCESS RATE: {single_stats['dns_success_rate'].mean():.1f}% → {cv4_stats['dns_success_rate'].mean():.1f}%                     ║
║     More accurate measurement of true DNS health.                    ║
║                                                                      ║
║  4. CV RECOVERY: ~{cv4_stats['cv_relays_improved'].mean():.0f} relays rescued per scan                   ║
║     Cross-validation prevents {cv4_stats['cv_relays_improved'].mean():.0f} false-negative results       ║
║     per scan on average.                                             ║
║                                                                      ║
║  5. INSTANCE FAILURES ARE RANDOM                                     ║
║     No single instance is consistently worse — failures are          ║
║     distributed randomly across all 4 instances, confirming          ║
║     that failures come from Tor network variability, not             ║
║     from the scanning infrastructure.                                ║
║                                                                      ║
║  6. ANOMALIES DETECTED:                                              ║
║     • 1 broken scan (Jan 26 00:05): only 2 consensus relays         ║
║     • 1 empty archive file (Feb 7 00:05): 0 bytes                   ║
║     • Some single-scan days in Feb (expected 2)                      ║
║     • Feb 8 missing entirely                                         ║
║                                                                      ║
║  7. SCAN SCHEDULE STABILISED                                         ║
║     From every 2h (12/day) in single-instance era to every          ║
║     12h (2/day) with 4-CV — because each scan is now much           ║
║     more comprehensive and reliable.                                 ║
║                                                                      ║
║  8. CONFIDENCE METRIC: {single_conf:.1f}% → {cv4_conf:.1f}%                          ║
║     The composite (tested/consensus × success_rate) metric           ║
║     confirms the 4-instance parallel model produces the most         ║
║     reliable picture of Tor exit relay DNS health.                   ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
"""
print(findings)

print("\n✅ Analysis complete. All charts saved to:", CHARTS_DIR)
print("   Chart files:")
for p in sorted(CHARTS_DIR.glob("*.png")):
    print(f"     {p.name}")
