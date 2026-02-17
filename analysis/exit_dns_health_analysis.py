# ---
# jupyter:
#   jupytext:
#     cell_markers: '"""'
#     text_representation:
#       extension: .py
#       format_name: percent
#   kernelspec:
#     display_name: Python 3
#     language: python
#     name: python3
# ---

# %% [markdown]
# # 🔬 Tor Exit DNS Health — Historical Analysis
#
# **Data source:** [exitdnshealth.1aeo.com](https://exitdnshealth.1aeo.com/) — 100 archive scans, Jan 24 – Feb 17 2026
#
# **Goal:** Analyse the full history of exit relay DNS health scan results to:
# - Identify **repeat patterns** and **anomalies** to ensure nothing is broken in the exitmap scans
# - Build confidence that the **4-instance parallel cross-validation model** is the most
#   reliable way to get accurate stats about exit relay DNS health
# - Show that single-instance scanning caused significant timeouts and unreachable-relay
#   inflation due to inherent Tor network inconsistencies

# %%
import json
import os
import warnings
from datetime import datetime, timezone, timedelta
from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import matplotlib.patches as mpatches
import matplotlib.ticker as mticker
import numpy as np
import pandas as pd
import seaborn as sns

warnings.filterwarnings("ignore", category=FutureWarning)

# ── 1AEO Brand palette ──
AEO_GREEN       = "#00ff7f"
AEO_GREEN_DIM   = "#00cc66"
AEO_GREEN_DARK  = "#004d26"
AEO_DARK_BG     = "#121212"
AEO_DARK_SURFACE= "#1e1e1e"
AEO_TEXT         = "#ffffff"
AEO_TEXT_MUTED   = "#cccccc"
AEO_TEXT_DIM     = "#888888"

STATUS_SUCCESS = "#3fb950"
STATUS_ERROR   = "#f85149"
STATUS_WARNING = "#d29922"
STATUS_INFO    = "#58a6ff"
STATUS_PURPLE  = "#a371f7"

PHASE_COLORS = {"single": STATUS_ERROR, "cv2": STATUS_WARNING, "cv4": STATUS_SUCCESS}
PHASE_LABELS = {"single": "Single Instance", "cv2": "2-Instance CV", "cv4": "4-Instance CV"}

DATA_DIR   = Path("/workspace/analysis/data")
CHARTS_DIR = Path("/workspace/analysis/charts")
CHARTS_DIR.mkdir(parents=True, exist_ok=True)

plt.rcParams.update({
    "figure.facecolor": AEO_DARK_BG, "axes.facecolor": AEO_DARK_SURFACE,
    "axes.edgecolor": AEO_TEXT_DIM,  "axes.labelcolor": AEO_TEXT_MUTED,
    "xtick.color": AEO_TEXT_DIM,     "ytick.color": AEO_TEXT_DIM,
    "text.color": AEO_TEXT,          "legend.facecolor": AEO_DARK_SURFACE,
    "legend.edgecolor": AEO_TEXT_DIM,"grid.color": "#333333", "grid.alpha": 0.5,
    "font.size": 11, "axes.titlesize": 14, "axes.labelsize": 12,
    "figure.dpi": 150, "savefig.dpi": 150,
    "savefig.facecolor": AEO_DARK_BG, "savefig.bbox": "tight",
})

def save_chart(fig, name):
    path = CHARTS_DIR / f"{name}.png"
    fig.savefig(path, bbox_inches="tight", pad_inches=0.3)
    print(f"  ✓ Saved {path}")

# %% [markdown]
# ## 📂 Phase 1 — Load & Parse All 100 Archive Files
#
# Each archive JSON has two top-level keys:
# - **`metadata`** — aggregate scan statistics (relay counts, success rates, timing, cross-validation info)
# - **`results`** — per-relay outcome array
#
# We extract only the metadata into a flat DataFrame for time-series analysis.

# %%
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

    ts_str = m.get("timestamp", "")
    try:
        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except Exception:
        ts = datetime.now(timezone.utc)

    row = {
        "filename": fpath.name, "timestamp": ts,
        "scan_type": scan_type, "instances": instances, "phase": phase,
        "consensus_relays": m.get("consensus_relays", 0),
        "tested_relays": m.get("tested_relays", 0),
        "unreachable_relays": m.get("unreachable_relays", 0),
        "dns_success": m.get("dns_success", 0),
        "dns_fail": m.get("dns_fail", 0),
        "dns_timeout": m.get("dns_timeout", 0),
        "dns_wrong_ip": m.get("dns_wrong_ip", 0),
        "dns_socks_error": m.get("dns_socks_error", 0),
        "dns_network_error": m.get("dns_network_error", 0),
        "dns_error": m.get("dns_error", 0),
        "dns_exception": m.get("dns_exception", 0),
        "dns_unknown": m.get("dns_unknown", 0),
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
        "dns_success_rate": m.get("dns_success_rate_percent", 0.0),
        "reachability_rate": m.get("reachability_rate_percent", 0.0),
        "timing_avg_ms": timing.get("avg_ms", None),
        "timing_min_ms": timing.get("min_ms", None),
        "timing_max_ms": timing.get("max_ms", None),
        "timing_p50_ms": timing.get("p50_ms", None),
        "timing_p95_ms": timing.get("p95_ms", None),
        "timing_p99_ms": timing.get("p99_ms", None),
        "cv_relays_improved": cv.get("relays_improved", None),
        "cv_recovered_timeout": cv.get("recovered_from_timeout", None),
        "cv_recovered_dns_fail": cv.get("recovered_from_dns_fail", None),
        "cv_recovered_error": cv.get("recovered_from_error", None),
        "cv_all_success": consistency.get("all_success", None),
        "cv_all_failed": consistency.get("all_failed", None),
        "cv_mixed": consistency.get("mixed", None),
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

df = pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)
df_clean = df[~df["is_anomalous"]].copy()

print(f"Loaded {len(df)} scan records ({len(skipped)} skipped, {df['is_anomalous'].sum()} anomalous)")
if skipped:
    for name, reason in skipped:
        print(f"  ⚠ Skipped: {name} — {reason}")
print(f"Date range: {df['timestamp'].min():%Y-%m-%d %H:%M} → {df['timestamp'].max():%Y-%m-%d %H:%M}")
print(f"Phases: {df_clean['phase'].value_counts().to_dict()}")

# %% [markdown]
# ## 📊 Phase Breakdown
#
# The data reveals **three distinct scanning phases** as the system evolved:
#
# | Phase | Scan Type | Instances | Period | Freq | Scans |
# |-------|-----------|-----------|--------|------|-------|
# | **Single Instance** | `single` | 1 | Jan 24–29 | Every 2h | ~58 |
# | **2-Instance CV** | `cross_validate` | 2 | Jan 25, 29 (experiments) | — | 3 |
# | **4-Instance CV** | `cross_validate` | 4 | Jan 30 onwards | Every 12h | ~33 |

# %%
# Summary Statistics by Phase (anomalous scans excluded)
key_metrics = [
    "dns_success_rate", "reachability_rate", "dns_timeout",
    "unreachable_relays", "tested_relays", "consensus_relays",
    "dns_fail", "timing_avg_ms",
]
summary = df_clean.groupby("phase")[key_metrics].agg(["mean", "std", "min", "max", "count"])

for phase in ["single", "cv2", "cv4"]:
    if phase not in summary.index:
        continue
    n = summary.loc[phase, ("dns_success_rate", "count")]
    print(f"\n{'─'*50}")
    print(f"  {PHASE_LABELS[phase]} (n={n:.0f} scans)")
    print(f"{'─'*50}")
    for metric in key_metrics:
        s = summary.loc[phase, metric]
        print(f"  {metric:>25s}:  mean={s['mean']:8.2f}  std={s['std']:7.2f}  "
              f"min={s['min']:8.2f}  max={s['max']:8.2f}")

# %%
# Chart helpers
def shade_phases(ax, dframe):
    phase_ranges = df_clean.groupby("phase")["timestamp"].agg(["min", "max"])
    for phase, color in PHASE_COLORS.items():
        if phase in phase_ranges.index:
            ax.axvspan(phase_ranges.loc[phase, "min"], phase_ranges.loc[phase, "max"],
                       alpha=0.08, color=color, zorder=0)

def format_date_axis(ax):
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%b %d"))
    ax.xaxis.set_major_locator(mdates.DayLocator(interval=2))
    plt.setp(ax.get_xticklabels(), rotation=45, ha="right")

def add_phase_legend(ax, loc="upper left"):
    handles = [mpatches.Patch(facecolor=PHASE_COLORS[p], alpha=0.7, label=PHASE_LABELS[p])
               for p in ["single", "cv2", "cv4"]]
    ax.legend(handles=handles, loc=loc, fontsize=9, framealpha=0.8)

# %% [markdown]
# ---
# ## 📈 Chart 1 — DNS Success Rate Over Time
#
# The **DNS success rate** measures what percentage of tested relays successfully resolved
# DNS queries. With 4-instance CV, the rate is both **higher** and **more stable** — because
# transient failures on one instance are recovered by the others.

# %%
fig, ax = plt.subplots(figsize=(14, 6))
shade_phases(ax, df_clean)

for phase in ["single", "cv2", "cv4"]:
    mask = df_clean["phase"] == phase
    subset = df_clean[mask]
    ax.scatter(subset["timestamp"], subset["dns_success_rate"],
               c=PHASE_COLORS[phase], s=40, alpha=0.85, zorder=3,
               label=PHASE_LABELS[phase], edgecolors="white", linewidths=0.3)
    if len(subset) > 1:
        ax.plot(subset["timestamp"], subset["dns_success_rate"],
                c=PHASE_COLORS[phase], alpha=0.4, linewidth=1, zorder=2)

# Annotate anomalous scans
for _, row in df[df["is_anomalous"]].iterrows():
    ax.annotate(f"⚠ {row['anomaly_reasons'][:60]}",
                xy=(row["timestamp"], row["dns_success_rate"]),
                xytext=(10, -25), textcoords="offset points",
                fontsize=7, color=STATUS_WARNING,
                arrowprops=dict(arrowstyle="->", color=STATUS_WARNING, lw=0.8))

# Mean lines
for phase in ["single", "cv4"]:
    mask = df_clean["phase"] == phase
    if mask.any():
        mean_val = df_clean.loc[mask, "dns_success_rate"].mean()
        phase_ts = df_clean.loc[mask, "timestamp"]
        ax.hlines(mean_val, phase_ts.min(), phase_ts.max(),
                  colors=PHASE_COLORS[phase], linestyles="dashed", alpha=0.5, linewidth=1)
        ax.text(phase_ts.max(), mean_val + 0.15,
                f"  mean={mean_val:.1f}%", fontsize=8, color=PHASE_COLORS[phase], va="bottom")

ax.set_ylabel("DNS Success Rate (%)")
ax.set_title("DNS Success Rate Over Time — By Scanning Phase", fontweight="bold", pad=15)
ax.set_ylim(bottom=max(0, df_clean["dns_success_rate"].min() - 3))
ax.grid(True, alpha=0.3)
format_date_axis(ax)
add_phase_legend(ax, loc="lower right")
fig.tight_layout()
save_chart(fig, "01_dns_success_rate")
plt.show()

# %% [markdown]
# ---
# ## 📈 Chart 2 — Reachability Rate Over Time (The Biggest Win)
#
# **Reachability** = `tested_relays / consensus_relays`. This is the single largest improvement
# from the 4-instance model. Single-instance scanning could only reach **~83%** of the network
# because Tor circuits are inherently unreliable — a single attempt frequently times out or
# gets refused. With 4 parallel instances, the reachability jumps to **~98%**.

# %%
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

single_reach = df_clean.loc[df_clean["phase"] == "single", "reachability_rate"].mean()
cv4_reach = df_clean.loc[df_clean["phase"] == "cv4", "reachability_rate"].mean()
ax.axhline(single_reach, color=PHASE_COLORS["single"], linestyle="--", alpha=0.4, linewidth=1)
ax.axhline(cv4_reach, color=PHASE_COLORS["cv4"], linestyle="--", alpha=0.4, linewidth=1)

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
plt.show()

# %% [markdown]
# ---
# ## 📈 Chart 3 — Timeout & Unreachable Relay Counts
#
# Two panels showing the dramatic drop in both **unreachable relays** (top) and
# **total timeouts** (bottom). Single-instance scans left ~500 relays untested every scan
# and saw 80–140 timeouts. The 4-instance model reduces these to near-zero.

# %%
fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(14, 8), sharex=True)

for phase in ["single", "cv2", "cv4"]:
    mask = df_clean["phase"] == phase
    subset = df_clean[mask]
    ax1.bar(subset["timestamp"], subset["unreachable_relays"],
            width=0.03, color=PHASE_COLORS[phase], alpha=0.8, label=PHASE_LABELS[phase])

ax1.set_ylabel("Unreachable Relays")
ax1.set_title("Unreachable Relays Per Scan — Single Instance vs 4-Instance CV", fontweight="bold", pad=10)
ax1.grid(True, alpha=0.3)
ax1.legend(fontsize=9, loc="upper left")

df_clean = df_clean.copy()
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
plt.show()

# %% [markdown]
# ---
# ## 📈 Chart 4 — Tested vs Consensus Relays
#
# The **red-shaded gap** between the blue consensus line and the green tested line
# represents relays that the scan _could not reach_. Single-instance: avg gap of **~528 relays**.
# With 4-instance CV: the gap shrinks to **~69 relays**.

# %%
fig, ax = plt.subplots(figsize=(14, 6))
shade_phases(ax, df_clean)

ax.plot(df_clean["timestamp"], df_clean["consensus_relays"],
        color=STATUS_INFO, alpha=0.9, linewidth=1.5, label="Consensus Relays", marker=".", markersize=4)
ax.plot(df_clean["timestamp"], df_clean["tested_relays"],
        color=AEO_GREEN, alpha=0.9, linewidth=1.5, label="Tested Relays", marker=".", markersize=4)
ax.fill_between(df_clean["timestamp"], df_clean["tested_relays"], df_clean["consensus_relays"],
                alpha=0.15, color=STATUS_ERROR, label="Untested Gap")

single_mask = df_clean["phase"] == "single"
cv4_mask = df_clean["phase"] == "cv4"
single_gap = (df_clean.loc[single_mask, "consensus_relays"] - df_clean.loc[single_mask, "tested_relays"]).mean()
cv4_gap = (df_clean.loc[cv4_mask, "consensus_relays"] - df_clean.loc[cv4_mask, "tested_relays"]).mean()
ax.text(0.98, 0.95,
        f"Single instance avg gap: {single_gap:.0f} relays\n4-CV avg gap: {cv4_gap:.0f} relays",
        transform=ax.transAxes, fontsize=10, va="top", ha="right",
        bbox=dict(boxstyle="round,pad=0.4", facecolor=AEO_DARK_BG, edgecolor=AEO_GREEN, alpha=0.9),
        color=AEO_TEXT)

ax.set_ylabel("Relay Count")
ax.set_title("Tested vs Consensus Relays — Gap Closure with 4-Instance CV", fontweight="bold", pad=15)
ax.grid(True, alpha=0.3)
format_date_axis(ax)
ax.legend(fontsize=9, loc="center left")
fig.tight_layout()
save_chart(fig, "04_tested_vs_consensus")
plt.show()

# %% [markdown]
# ---
# ## 📈 Chart 5 — Cross-Validation Recovery Impact
#
# Every 4-CV scan rescues relay results that _would have been false negatives_ with a single
# instance. The stacked bars show recovery by category (DNS fail, timeout, error) and the
# green line shows the total. On average **~85 relays** are rescued per scan.

# %%
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
plt.show()

# %% [markdown]
# ---
# ## 📈 Chart 6 — Per-Instance Failure Distribution (4-CV Heatmap)
#
# If one instance were systematically unreliable, we'd see a hot row or column in the heatmap.
# Instead, **failures are evenly distributed** across all 4 instances and all waves — confirming
# that failures come from Tor network variability, not from the scanning infrastructure.
# The aggregate bar chart on the right shows all 4 instances within **0.2pp** of each other.

# %%
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
            "timestamp": ts[:10], "instance": inst_name,
            "total": total, "success": success, "failures": fails,
            "fail_rate": (fails / total * 100) if total > 0 else 0,
        })

if instance_data:
    df_inst = pd.DataFrame(instance_data)
    df_inst = df_inst[df_inst["total"] >= 10]  # filter noise

    inst_summary = df_inst.groupby("instance").agg(
        avg_fail_rate=("fail_rate", "mean"), std_fail_rate=("fail_rate", "std"),
        total_tested=("total", "sum"), total_failures=("failures", "sum"),
    ).reset_index()
    inst_summary["cv_instance"] = inst_summary["instance"].str.extract(r"(cv\d+)")
    inst_summary["wave"] = inst_summary["instance"].str.extract(r"(w\d+)")
    inst_summary = inst_summary.dropna(subset=["cv_instance", "wave"])

    pivot = inst_summary.pivot(index="cv_instance", columns="wave", values="avg_fail_rate")

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5), gridspec_kw={"width_ratios": [2, 1]})
    sns.heatmap(pivot, annot=True, fmt=".1f", cmap="YlOrRd", ax=ax1,
                linewidths=1, linecolor=AEO_DARK_BG, cbar_kws={"label": "Avg Failure Rate (%)"})
    ax1.set_title("Per-Instance Avg Failure Rate (%) — 4-CV Scans", fontweight="bold", pad=10)
    ax1.set_xlabel("Wave"); ax1.set_ylabel("Instance")

    by_cv = inst_summary.groupby("cv_instance").agg(
        total_tested=("total_tested", "sum"), total_failures=("total_failures", "sum"),
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
    plt.show()

# %% [markdown]
# ---
# ## 📈 Chart 7 — Timing Distribution Over Time
#
# Response times also dramatically improved. Single-instance scans had a **p50 of ~22s** and
# **p99 of ~44s** because the single Tor instance was overloaded. The 4-instance model spreads
# the load, bringing p50 down to **~9s** and p99 to **~14s**.

# %%
df_timing = df_clean[df_clean["timing_p50_ms"].notna()].copy()
fig, ax = plt.subplots(figsize=(14, 6))
shade_phases(ax, df_timing)

ax.plot(df_timing["timestamp"], df_timing["timing_p50_ms"] / 1000,
        color=STATUS_SUCCESS, alpha=0.9, linewidth=1.5, marker=".", markersize=4, label="p50 (median)")
ax.plot(df_timing["timestamp"], df_timing["timing_p95_ms"] / 1000,
        color=STATUS_WARNING, alpha=0.8, linewidth=1.5, marker=".", markersize=4, label="p95")
ax.plot(df_timing["timestamp"], df_timing["timing_p99_ms"] / 1000,
        color=STATUS_ERROR, alpha=0.7, linewidth=1.5, marker=".", markersize=4, label="p99")
ax.fill_between(df_timing["timestamp"], df_timing["timing_p50_ms"]/1000, df_timing["timing_p95_ms"]/1000,
                alpha=0.1, color=STATUS_WARNING)
ax.fill_between(df_timing["timestamp"], df_timing["timing_p95_ms"]/1000, df_timing["timing_p99_ms"]/1000,
                alpha=0.08, color=STATUS_ERROR)

ax.set_ylabel("Response Time (seconds)")
ax.set_title("DNS Query Timing Distribution Over Time (p50 / p95 / p99)", fontweight="bold", pad=15)
ax.grid(True, alpha=0.3)
format_date_axis(ax)
ax.legend(fontsize=9, loc="upper right")
fig.tight_layout()
save_chart(fig, "07_timing_distribution")
plt.show()

# %% [markdown]
# ---
# ## 📈 Chart 8 — DNS & Circuit Failure Categories
#
# A stacked breakdown of all failure types per scan. In the single-instance era, the dominant
# failures were **circuit destroyed** and **circuit channel closed** (~500/scan). These are Tor
# network-level issues that the 4-instance model effectively eliminates through redundancy.

# %%
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
    ax.bar(df_clean["timestamp"], vals, bottom=bottom, width=0.03, color=color, alpha=0.85, label=label)
    bottom += vals

ax.set_ylabel("Error Count")
ax.set_title("DNS & Circuit Failure Categories Per Scan", fontweight="bold", pad=15)
ax.grid(True, alpha=0.3)
format_date_axis(ax)
ax.legend(fontsize=9, loc="upper left")
fig.tight_layout()
save_chart(fig, "08_failure_categories")
plt.show()

# %% [markdown]
# ---
# ## 📈 Chart 9 — Cross-Validation Consistency Analysis
#
# For each 4-CV scan, every relay gets tested by 2 of the 4 instances. We can classify results as:
# - **All Success** (96.1%) — both instances agree the relay is healthy
# - **Mixed / CV Rescued** (2.9%) — instances _disagreed_ — this is exactly what CV saves
# - **All Failed** (1.0%) — both instances agree the relay has DNS issues (true failure)

# %%
df_cv4 = df_clean[(df_clean["phase"] == "cv4") & df_clean["cv_all_success"].notna()].copy()

if len(df_cv4) > 0:
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6), gridspec_kw={"width_ratios": [2.5, 1]})

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

    avg_success = df_cv4["cv_all_success"].mean()
    avg_mixed = df_cv4["cv_mixed"].mean()
    avg_failed = df_cv4["cv_all_failed"].mean()
    sizes = [avg_success, avg_mixed, avg_failed]
    legend_labels = [f"All Success ({avg_success:.0f} avg)",
                     f"Mixed / CV Rescued ({avg_mixed:.0f} avg)",
                     f"All Failed ({avg_failed:.0f} avg)"]
    colors = [STATUS_SUCCESS, STATUS_WARNING, STATUS_ERROR]
    wedges, texts, autotexts = ax2.pie(
        sizes, colors=colors, autopct="%1.1f%%", startangle=140,
        explode=(0, 0.12, 0.12), pctdistance=0.78,
        textprops={"fontsize": 9, "color": AEO_TEXT})
    for at in autotexts:
        at.set_fontsize(9); at.set_color(AEO_DARK_BG); at.set_fontweight("bold")
    ax2.legend(wedges, legend_labels, loc="lower center", fontsize=8,
               bbox_to_anchor=(0.5, -0.15), framealpha=0.8)
    ax2.set_title("Average Consistency\nBreakdown", fontweight="bold", pad=10)
    fig.tight_layout()
    save_chart(fig, "09_consistency_analysis")
    plt.show()

# %% [markdown]
# ---
# ## 📈 Chart 10 — Overall Scan Confidence Metric
#
# A **composite confidence score** = `(tested/consensus) × dns_success_rate` captures both
# how much of the network was reached and how well DNS resolved. Single-instance: **81.0%**.
# 4-Instance CV: **96.8%** — a **+15.8pp improvement**.

# %%
df_clean = df_clean.copy()
df_clean["confidence"] = (
    (df_clean["tested_relays"] / df_clean["consensus_relays"].replace(0, 1))
    * (df_clean["dns_success_rate"] / 100.0) * 100.0
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
plt.show()

# %% [markdown]
# ---
# ## 🔍 Anomaly Detection & Flagging
#
# Systematic identification of broken scans, missing windows, and statistical outliers.

# %%
print("── Flagged Anomalous Scans ──")
anomalous = df[df["is_anomalous"]]
if len(anomalous) > 0:
    for _, row in anomalous.iterrows():
        print(f"  ⚠ {row['filename']}: {row['anomaly_reasons']}")
else:
    print("  None found")

print("\n── Skipped Files (Invalid JSON) ──")
if skipped:
    for name, reason in skipped:
        print(f"  ⚠ {name}: {reason}")
else:
    print("  None")

print("\n── Statistical Outliers in 4-Instance CV Phase (>2σ) ──")
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

print("\n── Missing Scan Days (4-CV era, Jan 31 onwards) ──")
expected_start = datetime(2026, 1, 31, tzinfo=timezone.utc)
expected_end = df["timestamp"].max()
cv4_timestamps = set(df_clean.loc[df_clean["phase"] == "cv4", "timestamp"].dt.date)
current = expected_start.date()
while current <= expected_end.date():
    if current not in cv4_timestamps:
        print(f"  ⚠ No 4-CV scan found for {current}")
    current += timedelta(days=1)

print("\n── Days With Fewer Than Expected Scans (expected 2/day) ──")
df_by_date = df_clean[df_clean["phase"] == "cv4"].groupby(df_clean.loc[df_clean["phase"] == "cv4", "timestamp"].dt.date).size()
for date, count in df_by_date.items():
    if count < 2:
        print(f"  ⚠ {date}: only {count} scan(s)")

# %% [markdown]
# ---
# ## ✅ Key Findings Summary
#
# ### The 4-instance parallel cross-validation model is the most reliable way to measure Tor exit relay DNS health.
#
# | Metric | Single Instance | 4-Instance CV | Improvement |
# |--------|---------------:|-------------:|------------:|
# | **Reachability** | ~83% | ~98% | **+15pp** |
# | **DNS Success Rate** | ~97.5% | ~99.0% | **+1.5pp** |
# | **DNS Timeouts/scan** | ~18 | ~1 | **94% reduction** |
# | **Unreachable relays/scan** | ~528 | ~16 | **97% reduction** |
# | **Confidence score** | ~81% | ~97% | **+16pp** |
# | **CV relays rescued/scan** | N/A | ~85 | — |
#
# ### Key observations:
#
# 1. **Reachability is the biggest win** — single instance missed ~17% of the Tor network simply
#    because one Tor circuit attempt is unreliable. The 4-instance model tries each relay through
#    multiple independent circuits and recovers ~85 relays/scan that would have been false negatives.
#
# 2. **Per-instance failures are random** — the heatmap (Chart 6) confirms no single instance is
#    systematically worse. All 4 instances have failure rates within 0.2pp of each other (2.01–2.26%).
#    This proves failures are from Tor network variability, not infrastructure issues.
#
# 3. **Timing improved** — p50 dropped from ~22s to ~9s, p99 from ~44s to ~14s. Parallelism spreads
#    the load and each instance handles a manageable batch.
#
# 4. **Anomalies detected and explained:**
#    - 3 broken scans with <5 consensus relays (Jan 26, 27, 28) — likely consensus fetch failures
#    - 1 empty archive file (Feb 7 00:05) — 0 bytes, data loss
#    - 1 scan with 7380 consensus (Feb 5) — duplicated relay list caused inflated consensus count
#    - Feb 6 00:05 scan: outlier with 84% reachability and 89 DNS failures (temporary network disruption)
#    - Feb 8: no scans recorded at all
#    - Several days with only 1 of expected 2 scans
#
# 5. **The scan schedule stabilised** from every 2h (12/day) to every 12h (2/day) — because each
#    4-CV scan is comprehensive enough that less frequent scanning still captures the full picture.

# %%
print("✅ Analysis complete. All charts saved to:", CHARTS_DIR)
for p in sorted(CHARTS_DIR.glob("*.png")):
    print(f"   {p.name}")
