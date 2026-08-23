#!/usr/bin/env python3
from pathlib import Path
import os
os.environ.setdefault("MPLCONFIGDIR", "/tmp/feupsu-matplotlib")
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.colors import Normalize
from matplotlib.cm import ScalarMappable

BASE = Path(__file__).resolve().parent
raw_df = pd.read_csv(BASE / "corrected_hw_summary.csv")

# Aggregate repeated measurements before plotting.  OptLength and the derived
# parameters are deterministic for a given case; timing and serialized request
# size are retained as mean/std so that instability is visible in the plots.
keys = [
    "OriginalBitlength", "ServerSet", "PolyModulusDegree", "Mu",
    "EffectiveBitlength", "HammingWeight", "OptLength",
    "plain_modulus_bits",
]
df = (
    raw_df.groupby(keys, as_index=False)
    .agg(
        time_server_per_mu1_ms=("time_server_per_mu1_ms", "mean"),
        time_server_per_mu1_std_ms=("time_server_per_mu1_ms", "std"),
        time_server_scaled_ms=("time_server_scaled_ms", "mean"),
        time_server_scaled_std_ms=("time_server_scaled_ms", "std"),
        comm_request=("comm_request", "mean"),
        comm_request_std=("comm_request", "std"),
        runs=("run", "count"),
    )
    .fillna({
        "time_server_per_mu1_std_ms": 0,
        "time_server_scaled_std_ms": 0,
        "comm_request_std": 0,
    })
)
df.to_csv(BASE / "corrected_hw_averages.csv", index=False)

for (original, server_set), group in df.groupby(["OriginalBitlength", "ServerSet"]):
    group = group.sort_values("HammingWeight")
    fig, left = plt.subplots(figsize=(8, 4.8))
    right = left.twinx()
    left.plot(group.HammingWeight, group.time_server_per_mu1_ms, "o-", color="tab:blue",
              label="server time (mu=1)")
    left.fill_between(
        group.HammingWeight,
        group.time_server_per_mu1_ms - group.time_server_per_mu1_std_ms,
        group.time_server_per_mu1_ms + group.time_server_per_mu1_std_ms,
        color="tab:blue", alpha=0.15,
    )
    right.plot(group.HammingWeight, group.comm_request / (1024 * 1024), "s-", color="tab:orange",
               label="request communication")
    left.set_xlabel("Hamming weight")
    left.set_ylabel("Server time per mu=1 (ms)", color="tab:blue")
    right.set_ylabel("Request communication (MiB)", color="tab:orange")
    title = f"Original element length={original}"
    if server_set:
        title += f", server_set={server_set}"
    left.set_title(title)
    left.grid(alpha=0.25)
    fig.tight_layout()
    suffix = f"server_{server_set}" if server_set else "base"
    fig.savefig(BASE / f"corrected_{original}_hw_{suffix}.png", dpi=220)
    plt.close(fig)

# Reproduce the Runtime-vs-Communication visualization used in replot.ipynb.
plt.rcParams.update({
    "font.family": "CMR10",
    "font.size": 18,
    "axes.labelsize": 18,
    "xtick.labelsize": 14,
    "ytick.labelsize": 14,
})
cmap = plt.get_cmap("plasma")

group32 = df[df.OriginalBitlength == 32].sort_values("HammingWeight")
fig, ax = plt.subplots(figsize=(7.2, 5.6))
comm = group32.comm_request / (1024 * 1024)
runtime = group32.time_server_per_mu1_ms
hw = group32.HammingWeight
ax.plot(comm, runtime, color="0.7", linewidth=2.5, zorder=1)
scatter = ax.scatter(comm, runtime, c=hw, cmap=cmap, s=110, zorder=2)
ax.errorbar(
    comm, runtime,
    xerr=group32.comm_request_std / (1024 * 1024),
    yerr=group32.time_server_per_mu1_std_ms,
    fmt="none", ecolor="0.45", elinewidth=1.2, capsize=3, alpha=0.75,
    zorder=0,
)
ax.set_xlabel("Communication Cost (MiB)")
ax.set_ylabel("Runtime (ms)")
ax.set_title("32-bit elements")
ax.grid(alpha=0.3)
cbar = fig.colorbar(scatter, ax=ax)
cbar.set_label("Hamming weight")
fig.tight_layout()
fig.savefig(BASE / "corrected_32_runtime_communication.png", dpi=300, bbox_inches="tight")
plt.close(fig)

data128 = df[df.OriginalBitlength == 128]


def plot_128(output: str, *, min_hw: int | None = None, log_scale: bool = False) -> None:
    plotted = data128 if min_hw is None else data128[data128.HammingWeight >= min_hw]
    groups = list(plotted.groupby("ServerSet"))
    norm = Normalize(vmin=plotted.HammingWeight.min(), vmax=plotted.HammingWeight.max())
    fig, axes = plt.subplots(2, 2, figsize=(14, 10.5))
    for ax, (server_set, group) in zip(axes.flat, groups):
        group = group.sort_values("HammingWeight")
        comm = group.comm_request / (1024 * 1024)
        # Plot the server time actually measured by the benchmark.  The
        # corrected hw experiment runs the existing mu=1 benchmark path, so no
        # multiplication by the target mu is applied here.
        runtime = group.time_server_per_mu1_ms
        hw = group.HammingWeight
        ax.plot(comm, runtime, color="0.7", linewidth=2.2, zorder=1)
        ax.scatter(comm, runtime, c=hw, cmap=cmap, norm=norm, s=80, zorder=2)
        ax.errorbar(
            comm, runtime,
            xerr=group.comm_request_std / (1024 * 1024),
            yerr=group.time_server_per_mu1_std_ms,
            fmt="none", ecolor="0.45", elinewidth=1.0, capsize=2, alpha=0.7,
            zorder=0,
        )
        if log_scale:
            ax.set_xscale("log")
            ax.set_yscale("log")
        exponent = int(round(float(__import__("math").log2(server_set))))
        ax.set_title(rf"Server set size = $2^{{{exponent}}}$")
        ax.set_xlabel("Communication Cost (MiB)")
        ax.set_ylabel(r"Measured Server Runtime at $\mu=1$ (ms)")
        ax.grid(alpha=0.3)

    title = "128-bit elements"
    if min_hw is not None:
        title += rf" ($hw \geq {min_hw}$)"
    fig.suptitle(title, fontsize=22)
    fig.colorbar(ScalarMappable(norm=norm, cmap=cmap), ax=axes, label="Hamming weight",
                 fraction=0.025, pad=0.03)
    fig.subplots_adjust(left=0.08, right=0.9, bottom=0.07, top=0.91, wspace=0.28, hspace=0.3)
    fig.savefig(BASE / output, dpi=300, bbox_inches="tight")
    plt.close(fig)


def plot_128_combined(output: str, *, min_hw: int) -> None:
    """Put all server-set curves in one linear-axis comparison plot."""
    plotted = data128[data128.HammingWeight >= min_hw]
    norm = Normalize(vmin=plotted.HammingWeight.min(), vmax=plotted.HammingWeight.max())
    # Use exactly the same canvas size as the 32-bit companion figure so that
    # both figures have the same apparent font size when placed side by side.
    fig, ax = plt.subplots(figsize=(7.2, 5.6))
    markers = ["o", "s", "^", "D"]
    for marker, (server_set, group) in zip(markers, plotted.groupby("ServerSet")):
        group = group.sort_values("HammingWeight")
        comm = group.comm_request / (1024 * 1024)
        runtime = group.time_server_per_mu1_ms
        exponent = int(round(float(__import__("math").log2(server_set))))
        label = rf"Server set $2^{{{exponent}}}$"
        ax.plot(
            comm, runtime, color="0.7", linewidth=1.25, zorder=1,
        )
        ax.scatter(
            comm, runtime, c=group.HammingWeight, cmap=cmap, norm=norm,
            marker=marker, s=42, label=label, zorder=2,
        )
        ax.errorbar(
            comm, runtime,
            xerr=group.comm_request_std / (1024 * 1024),
            yerr=group.time_server_per_mu1_std_ms,
            fmt="none", ecolor="0.45", elinewidth=0.65, capsize=1.5,
            alpha=0.5, zorder=1,
        )

    # Keep the title typography identical to the 32-bit companion figure.
    ax.set_title("128-bit elements")
    ax.set_xlabel("Communication Cost (MiB)")
    ax.set_ylabel("Runtime (ms)")
    ax.grid(alpha=0.3)
    ax.legend(fontsize=14)
    cbar = fig.colorbar(ScalarMappable(norm=norm, cmap=cmap), ax=ax)
    cbar.set_label("Hamming weight")
    tick_min = int(plotted.HammingWeight.min())
    tick_max = int(plotted.HammingWeight.max())
    cbar.set_ticks(range(tick_min, tick_max + 1, 2))
    fig.tight_layout()
    fig.savefig(BASE / output, dpi=300, bbox_inches="tight")
    plt.close(fig)


# The combined linear plot focuses on the useful trade-off region.  hw=8 and
# smaller points are omitted here; the log-scale companion retains them.
plot_128_combined("corrected_128_runtime_communication.png", min_hw=9)
# The log-scale companion retains every valid hamming weight, including the
# low-hw outliers, so no experimental result is lost from the visualization.
plot_128("corrected_128_runtime_communication_log.png", log_scale=True)

print(f"aggregated {len(raw_df)} measurements into {len(df)} cases")
print(f"averages: {BASE / 'corrected_hw_averages.csv'}")
