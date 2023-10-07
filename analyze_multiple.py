# ---
# jupyter:
#   jupytext:
#     formats: ipynb,py:percent
#     text_representation:
#       extension: .py
#       format_name: percent
#       format_version: '1.3'
#       jupytext_version: 1.14.5
#   kernelspec:
#     display_name: incast-analysis-venv
#     language: python
#     name: incast-analysis-venv
# ---

# %% editable=true slideshow={"slide_type": ""}
# %matplotlib widget

import multiprocessing
import os
from os import path
import pickle

import numpy as np
from matplotlib import pyplot as plt

import analysis

PARALLEL = True

COLORS_FRIENDLY_HEX = [
    "#d73027",  # red
    "#fc8d59",  # orange
    "#a68f51",  # gold
    "#91bfdb",  # light blue
    "#4575b4",  # dark blue
    "grey",
]


# %% editable=true slideshow={"slide_type": ""}
def load_one(exp_dir):
    if not path.exists(exp_dir):
        return None

    data_flp = path.join(exp_dir, "data.pickle")
    if path.exists(data_flp):
        print(f"Loading from file: {exp_dir}...")
        with open(data_flp, "rb") as fil:
            try:
                data = pickle.load(fil)
                print(f"Succeeded loading from file: {data_flp}")
                return data
            except:
                print(f"Warning: Failed loading from file: {data_flp}")

    # Select experiments with 10 Gbps links, discard those with 2000 flows.
    # data = analysis.get_all_metrics_for_exp(exp_dir, filt=lambda c: c["smallLinkBandwidthMbps"] == 10000 and c["numBurstSenders"] != 2000)
    try:
        data = analysis.get_all_metrics_for_exp(exp_dir)
    except:
        print(f"Error during: {exp_dir}")
        raise

    with open(data_flp, "wb") as fil:
        pickle.dump(data, fil)
    return data


def load_all(sweep_dir, filt=None):
    exp_dirs = [
        path.join(sweep_dir, dirn)
        for dirn in os.listdir(sweep_dir)
        if dirn != "graphs" and dirn != "tmpfs"
    ]
    exp_dirs = [
        exp_dir
        for exp_dir in exp_dirs
        if filt is None or filt(analysis.get_config_json(exp_dir))
    ]

    print(f"Loading {len(exp_dirs)} experiments...")
    if PARALLEL:
        with multiprocessing.Pool(processes=20) as pool:
            exp_to_data = dict(zip(exp_dirs, pool.map(load_one, exp_dirs)))
    else:
        exp_to_data = {
            exp_dir: analysis.get_all_metrics_for_exp(exp_dir) for exp_dir in exp_dirs
        }

    exp_to_data = {exp: data for exp, data in exp_to_data.items() if data is not None}

    print(f"Loaded {len(exp_to_data)} experiments.")
    return exp_to_data


# %% editable=true slideshow={"slide_type": ""}
SWEEP_DIR = "/data_ssd/ccanel/incast/sweep/background-senders"
EXP_TO_DATA = load_all(
    SWEEP_DIR,
    # filt=lambda c: c["rwndStrategy"] == "static" and c["numBurstSenders"] < 1000,
)


# %%
STATIC_EXP_TO_DATA = {
    exp: data
    for exp, data in EXP_TO_DATA.items()
    if data["config"]["rwndStrategy"] == "static"
}
NONE_EXP_TO_DATA = {
    exp: data
    for exp, data in EXP_TO_DATA.items()
    if data["config"]["rwndStrategy"] == "none"
}


# %% editable=true slideshow={"slide_type": ""}
def graph_avg_queue_depth(exp_to_data, sweep_dir, key, key_modifier, xlabel):
    graph_dir = path.join(sweep_dir, "graphs")
    if not path.isdir(graph_dir):
        os.makedirs(graph_dir)

    connss = sorted(
        list({data["config"]["numBurstSenders"] for data in exp_to_data.values()})
    )
    # rwnds = sorted(
    #     list({data["config"]["staticRwndBytes"] for data in exp_to_data.values()})
    # )

    def get_x(data):
        return key_modifier(data["config"][key])

    def get_y(data):
        return np.mean([t[0] for t in data["incast_q_avg_depth_by_burst"][1:]])

    plt.close()
    fig, axes = analysis.get_axes(width=7)
    ax = axes[0]

    for i, conns in enumerate(connss):
        print(conns)
        points = [
            (get_x(data), get_y(data))
            for exp, data in exp_to_data.items()
            if data["config"]["numBurstSenders"] == conns
        ]
        points = sorted(points)
        xs, ys = zip(*points)
        print(xs)
        print(ys)
        ax.plot(
            xs,
            ys,
            COLORS_FRIENDLY_HEX[i],
            label=conns,
            linewidth=analysis.LINESIZE,
            alpha=0.7,
        )

    ax.set_xlabel(xlabel, fontsize=analysis.FONTSIZE)
    ax.set_ylabel("average queue length\n(packets)", fontsize=analysis.FONTSIZE)
    ax.set_xlim(left=0)
    ax.set_ylim(bottom=0)
    ax.tick_params(axis="x", labelsize=analysis.FONTSIZE)
    ax.tick_params(axis="y", labelsize=analysis.FONTSIZE)
    ax.legend(
        fontsize=analysis.FONTSIZE,
        bbox_to_anchor=(1.02, 0.5),
        loc="center left",
        title="Flows",
        title_fontsize=analysis.FONTSIZE,
    )

    plt.tight_layout()
    analysis.show(fig)
    analysis.save(graph_dir, suffix="incast_queue")


# def graph_avg_tput(exp_to_data, sweep_dir, key, key_modifier, xlabel):
#     graph_dir = path.join(sweep_dir, "graphs")
#     if not path.isdir(graph_dir):
#         os.makedirs(graph_dir)

#     def get_x(data):
#         return key_modifier(data["config"][key])

#     def get_y(data):
#         return [x / 1e9 for x in data["avg_tput_by_burst_bps"][1:]]

#     points = [(get_x(data), get_y(data)) for exp, data in exp_to_data.items()]
#     points = sorted(points)
#     xs, ys = zip(*points)

#     fig, axes = analysis.get_axes(width=6)
#     ax = axes[0]

#     ax.plot(xs, ys, "o-", alpha=0.8)

#     ax.set_xlabel(xlabel, fontsize=analysis.FONTSIZE)
#     ax.set_ylabel("throughput (Gbps)", fontsize=analysis.FONTSIZE)
#     ax.set_xlim(left=0)
#     ax.set_ylim(bottom=0, top=next(iter(exp_to_data.values()))["config"]["smallLinkBandwidthMbps"] / 1e3 * 1.1)
#     ax.tick_params(axis='x', labelsize=analysis.FONTSIZE)
#     ax.tick_params(axis='y', labelsize=analysis.FONTSIZE)

#     plt.tight_layout()
#     analysis.show(fig)
#     analysis.save(graph_dir, suffix="incast_queue")

graph_avg_queue_depth(
    STATIC_EXP_TO_DATA,
    SWEEP_DIR,
    key="staticRwndBytes",
    key_modifier=lambda x: x / 1e3,
    xlabel="RWND clamp (KB)",
)


# %%
# graph_avg_queue_depth(none_sweep_exp_to_data, none_sweep_dir, key="numBurstSenders", key_modifier=lambda x: x, xlabel="number of flows")
# graph_avg_tput(none_sweep_exp_to_data, none_sweep_dir, key="numBurstSenders", key_modifier=lambda x: x, xlabel="number of flows")

# %%

# graph_avg_tput(static_exp_to_data, sweep_dir, key="staticRwndBytes", key_modifier=lambda x: x / 1e3, xlabel="RWND clamp (KB)")

# %% editable=true slideshow={"slide_type": ""}
# Graph queue over time for various RWND thresholds.


def graph_queue(exp_to_data, sweep_dir):
    graph_dir = path.join(sweep_dir, "graphs")
    if not path.isdir(graph_dir):
        os.makedirs(graph_dir)

    fig, axes = analysis.get_axes(width=12)
    ax = axes[0]

    # Plot a line for each marking threshold.
    max_x = 0
    max_y = 0
    for i, data in enumerate(
        reversed(
            sorted(exp_to_data.values(), key=lambda p: p["config"]["staticRwndBytes"])
        )
    ):
        xs, avg_ys, _, _, _, _, _ = data["incast_queue_across_bursts"]
        xs = np.array(xs) - xs[0]
        xs = xs * 1e3
        # ax.plot(xs, ys, COLORS_FRIENDLY_HEX[i], drawstyle="steps-post", label=f"RWND: {round(data['config']['staticRwndBytes'] / 1024)} KB", linewidth=analysis.LINESIZE, alpha=0.7)
        ax.plot(
            xs,
            avg_ys,
            drawstyle="steps-post",
            label=round(data["config"]["staticRwndBytes"] / 1024),
            linewidth=analysis.LINESIZE,
            alpha=0.7,
        )
        max_x = max(max_x, xs[-1])
        max_y = max(max_y, *avg_ys)

    # Draw a line at the marking threshold
    marking_threshold_packets = next(iter(exp_to_data.values()))["config"][
        "smallQueueMinThresholdPackets"
    ]
    ax.plot(
        [0, max_x],
        [marking_threshold_packets] * 2,
        label="ECN threshold",
        color="orange",
        linestyle="dashed",
        linewidth=analysis.LINESIZE,
        alpha=1,
    )
    # # Draw a line at the queue capacity
    # capacity_packets = next(iter(exp_to_data.values()))["config"]["smallQueueSizePackets"]
    # ax.plot(
    #     [0, max_x],
    #     [capacity_packets] * 2,
    #     label="Queue capacity",
    #     color="red",
    #     linestyle="dotted",
    #     linewidth=analysis.LINESIZE,
    #     alpha=0.8,
    # )

    ax.set_xlabel("time (ms)", fontsize=analysis.FONTSIZE)
    ax.set_ylabel("queue length (packets)", fontsize=analysis.FONTSIZE)
    # ax.set_xlim(left=0)
    # ax.set_ylim(bottom=0, top=capacity_packets * 1.1)
    ax.set_ylim(bottom=-1, top=max_y * 1.1)
    ax.tick_params(axis="x", labelsize=analysis.FONTSIZE)
    ax.tick_params(axis="y", labelsize=analysis.FONTSIZE)
    ax.legend(
        fontsize=analysis.FONTSIZE,
        bbox_to_anchor=(1.02, 0.5),
        loc="center left",
        title="RWND clamp (KB)",
        title_fontsize=analysis.FONTSIZE,
        ncols=2,
    )

    plt.tight_layout()
    analysis.show(fig)
    analysis.save(graph_dir, suffix="incast_queue")


for CONNS in [50, 100, 150, 200, 500]:
    # for CONNS in [150]:
    print(CONNS)
    graph_queue(
        {
            exp: data
            for exp, data in STATIC_EXP_TO_DATA.items()
            if data["config"]["numBurstSenders"] == CONNS
            and data["config"]["staticRwndBytes"] < 11000
        },
        SWEEP_DIR,
    )


# %%
# Graph FCT distribution for various RWND thresholds


def graph_fct(exp_to_data, sweep_dir):
    graph_dir = path.join(sweep_dir, "graphs")
    if not path.isdir(graph_dir):
        os.makedirs(graph_dir)

    fig, axes = analysis.get_axes(width=6)

    num_bursts = next(iter(exp_to_data.values()))["config"]["numBursts"] - 1
    for i, data in enumerate(
        reversed(
            sorted(exp_to_data.values(), key=lambda p: p["config"]["staticRwndBytes"])
        )
    ):
        durations = []
        for burst_idx in range(1, num_bursts):
            times = [
                flow_times_by_burst[burst_idx]
                for flow_times_by_burst in data[
                    "sender_to_flow_times_by_burst"
                ].values()
            ]
            durations.extend([(end - start) * 1e3 for start, _, end, _ in times])

        count, bins_count = np.histogram(durations, bins=len(durations))
        # axes[0].plot(bins_count[1:], np.cumsum(count / sum(count)), COLORS_FRIENDLY_HEX[i], label=round(data['config']['staticRwndBytes'] / 1024), linewidth=analysis.LINESIZE, alpha=0.7)
        axes[0].plot(
            bins_count[1:],
            np.cumsum(count / sum(count)),
            label=round(data["config"]["staticRwndBytes"] / 1024),
            linewidth=analysis.LINESIZE,
            alpha=0.7,
        )

    # axes[0].set_title(f"CDF of flow duration: Burst {burst_idx + 1} of {num_bursts}", fontsize=FONTSIZE)
    axes[0].set_xlabel("flow duration (ms)", fontsize=analysis.FONTSIZE)
    axes[0].set_ylabel("CDF", fontsize=analysis.FONTSIZE)
    axes[0].tick_params(axis="x", labelsize=analysis.FONTSIZE)
    axes[0].tick_params(axis="y", labelsize=analysis.FONTSIZE)
    axes[0].set_xlim(left=0)
    axes[0].set_ylim(bottom=0, top=1.01)
    axes[0].legend(
        fontsize=analysis.FONTSIZE,
        bbox_to_anchor=(1.02, 0.5),
        loc="center left",
        title="RWND clamp (KB)",
        title_fontsize=analysis.FONTSIZE,
        ncols=2,
    )

    analysis.show(fig)
    analysis.save(graph_dir, suffix="flow_duration_cdf")


for CONNS in [50, 100, 150, 200, 500]:
    print(CONNS)
    # graph_fct(static_exp_to_data_filtered, sweep_dir)
    graph_fct(
        {
            exp: data
            for exp, data in STATIC_EXP_TO_DATA.items()
            if data["config"]["numBurstSenders"] == CONNS
            and data["config"]["staticRwndBytes"] < 11000
        },
        SWEEP_DIR,
    )


# %% editable=true slideshow={"slide_type": ""}
# Graph p95 CWND over time for various RWND thresholds


def graph_p95_bytes_in_flight(exp_to_data, sweep_dir):
    graph_dir = path.join(sweep_dir, "graphs")
    if not path.isdir(graph_dir):
        os.makedirs(graph_dir)

    fig, axes = analysis.get_axes()
    ax = axes[0]

    # Plot a line for each marking threshold.
    max_x = 0
    max_y = 0
    for i, data in enumerate(
        reversed(
            sorted(exp_to_data.values(), key=lambda p: p["config"]["staticRwndBytes"])
        )
    ):
        # Last element in the tuple is the total cwnd
        xs, _, _, _, _, percentiles, _ = data["cwnd_metrics_across_bursts"]
        xs = np.array(xs) - xs[0]
        xs = xs * 1e3
        # Extract p95
        ys = percentiles[4]
        # ax.plot(xs, ys, COLORS_FRIENDLY_HEX[i], label=round(data['config']['staticRwndBytes'] / 1024), linewidth=analysis.LINESIZE, alpha=0.7)
        ax.plot(
            xs,
            ys,
            label=round(data["config"]["staticRwndBytes"] / 1024),
            linewidth=analysis.LINESIZE,
            alpha=0.7,
        )
        max_x = max(max_x, xs[-1])
        max_y = max(max_y, *ys)

    ax.set_xlabel("time (ms)", fontsize=analysis.FONTSIZE)
    ax.set_ylabel("per-flow in-flight data\n(p95, bytes)", fontsize=analysis.FONTSIZE)
    # ax.set_xlim(left=0)
    ax.set_ylim(bottom=-1, top=max_y * 1.1)
    ax.tick_params(axis="x", labelsize=analysis.FONTSIZE)
    ax.tick_params(axis="y", labelsize=analysis.FONTSIZE)
    ax.legend(
        fontsize=analysis.FONTSIZE,
        bbox_to_anchor=(1.02, 0.5),
        loc="center left",
        title="RWND clamp (KB)",
        title_fontsize=analysis.FONTSIZE,
        ncols=2,
    )

    plt.tight_layout()
    analysis.show(fig)
    analysis.save(graph_dir, suffix="p95_bytes_in_flight")


for CONNS in [50, 100, 150, 200, 500]:
    print(CONNS)
    # graph_p95_bytes_in_flight({exp: data for exp, data in static_exp_to_data.items() if data["config"]["numBurstSenders"] == CONNS and data["config"]["staticRwndBytes"] < 11000 and (data["config"]["staticRwndBytes"] / 1024) % 2 == 0}, sweep_dir)
    graph_p95_bytes_in_flight(
        {
            exp: data
            for exp, data in STATIC_EXP_TO_DATA.items()
            if data["config"]["numBurstSenders"] == CONNS
            and data["config"]["staticRwndBytes"] < 11000
        },
        SWEEP_DIR,
    )


# %%
# Graph total CWND over time for various RWND thresholds


def graph_total_cwnd(exp_to_data, sweep_dir):
    graph_dir = path.join(sweep_dir, "graphs")
    if not path.isdir(graph_dir):
        os.makedirs(graph_dir)

    fig, axes = analysis.get_axes()
    ax = axes[0]

    # Plot a line for each marking threshold.
    max_x = 0
    max_y = 0
    for i, data in enumerate(
        reversed(
            sorted(exp_to_data.values(), key=lambda p: p["config"]["staticRwndBytes"])
        )
    ):
        bdp_bytes = (
            data["config"]["smallLinkBandwidthMbps"]
            * 1e6
            / 8
            * 6
            * data["config"]["delayPerLinkUs"]
            / 1e6
        )
        # print(bdp_bytes)
        # Last element in the tuple is the total cwnd
        xs, _, _, _, _, _, ys = data["cwnd_metrics_across_bursts"]
        # print(ys[-10:])
        xs = np.array(xs) - xs[0]
        xs = xs * 1e3
        ys = ys / bdp_bytes
        # ax.plot(xs, ys, COLORS_FRIENDLY_HEX[i], label=round(data['config']['staticRwndBytes'] / 1024), linewidth=analysis.LINESIZE, alpha=0.7)
        ax.plot(
            xs,
            ys,
            label=round(data["config"]["staticRwndBytes"] / 1024),
            linewidth=analysis.LINESIZE,
            alpha=0.7,
        )
        max_x = max(max_x, xs[-1])
        max_y = max(max_y, *ys)

    # # Draw a line at the BDP
    # marking_threshold_packets = next(iter(exp_to_data.values()))["config"]["smallQueueMinThresholdPackets"]
    # ax.plot(
    #     [0, max_x],
    #     [marking_threshold_packets] * 2,
    #     label="ECN threshold",
    #     color="orange",
    #     linestyle="dashed",
    #     linewidth=analysis.LINESIZE,
    #     alpha=1,
    # )

    ax.set_xlabel("time (ms)", fontsize=analysis.FONTSIZE)
    ax.set_ylabel("total in-flight data\n(x BDP)", fontsize=analysis.FONTSIZE)
    # ax.set_xlim(left=0)
    ax.set_ylim(bottom=-1, top=max_y * 1.1)
    ax.tick_params(axis="x", labelsize=analysis.FONTSIZE)
    ax.tick_params(axis="y", labelsize=analysis.FONTSIZE)
    ax.legend(
        fontsize=analysis.FONTSIZE,
        bbox_to_anchor=(1.02, 0.5),
        loc="center left",
        title="RWND clamp (KB)",
        title_fontsize=analysis.FONTSIZE,
        ncols=2,
    )

    plt.tight_layout()
    analysis.show(fig)
    analysis.save(graph_dir, suffix="total_in_flight_data")


# for exp, data in static_exp_to_data.items():
#     print(exp)

# d = static_exp_to_data["/data_hdd/ccanel/incast/incast_sweep_static/background-senders/15ms-100-0-11-TcpDctcp-10000mbps-2000000B-10icwnd-0offset-static-rwnd8192B-20tokens-4g-80ecn-1_0da"]
# print(len(d["cwnd_metrics_across_bursts"]))
# print(d["cwnd_metrics_across_bursts"][-7][1000:1010])


for CONNS in [50, 100, 150, 200, 500]:
    print(CONNS)
    # graph_total_cwnd({exp: data for exp, data in static_exp_to_data.items() if data["config"]["numBurstSenders"] == CONNS and data["config"]["staticRwndBytes"] < 11000 and (data["config"]["staticRwndBytes"] / 1024) % 2 == 0}, sweep_dir)
    graph_total_cwnd(
        {
            exp: data
            for exp, data in STATIC_EXP_TO_DATA.items()
            if data["config"]["numBurstSenders"] == CONNS
            and data["config"]["staticRwndBytes"] < 11000
        },
        SWEEP_DIR,
    )

# %%
# delack_sweep_dir = "/data_hdd/incast/out/delack_sweep_2ms"
# delack_sweep_exp_to_data = load_sweep(delack_sweep_dir)

# %%
# def graph_delack_sweep(exp_to_data, sweep_dir):
#     graph_dir = path.join(sweep_dir, "graphs")
#     if not path.isdir(graph_dir):
#         os.makedirs(graph_dir)

#     def get_x(data):
#         return data["config"]["delAckCount"]

#     def get_y(data):
#         return np.mean([end - start for start, end in data["burst_times"][1:]])

#     points = [(get_x(data), get_y(data)) for exp, data in exp_to_data.items()]
#     points = sorted(points)
#     xs, ys = zip(*points)
#     ys = [y * 1e3 for y in ys]

#     fig, axes = analysis.get_axes(width=5)
#     ax = axes[0]

#     ax.plot(xs, ys, "o-", alpha=0.8)

#     ax.set_title(f"Average burst duration vs. DelAckCount")
#     ax.set_xlabel("DelAckCount")
#     ax.set_ylabel("Burst duration (ms)")
#     ax.set_xlim(left=0)
#     ax.set_ylim(bottom=0)

#     plt.tight_layout()
#     analysis.show(fig)
#     analysis.save(graph_dir, suffix="duration")


# def graph_delack_sweep_cdf(exp_to_data, sweep_dir):
#     graph_dir = path.join(sweep_dir, "graphs")
#     if not path.isdir(graph_dir):
#         os.makedirs(graph_dir)

#     label_to_durations = {
#         data["config"]["delAckCount"]: [
#             (end - start) * 1e3 for start, end in data["burst_times"]
#         ]
#         for exp, data in exp_to_data.items()
#     }

#     fig, axes = analysis.get_axes(width=5)
#     ax = axes[0]

#     for label, durations in sorted(label_to_durations.items()):
#         plt.plot(
#             np.sort(durations),
#             np.arange(1, len(durations) + 1) / float(len(durations)),
#             drawstyle="steps-post",
#             label=label,
#             alpha=0.8,
#         )

#     ideal_ms = list(set(data["ideal_sec"] * 1e3 for data in exp_to_data.values()))
#     assert len(ideal_ms) == 1
#     ideal_ms = ideal_ms[0]
#     # plt.axvline(ideal_ms, color="b", linestyle="dashed", label="Ideal")

#     ax.set_title(f"Burst duration CDF for various DelAckCount")
#     ax.set_xlabel("Burst duration (ms)")
#     ax.set_ylabel("CDF")
#     ax.set_xlim(left=0)
#     ax.set_ylim(bottom=0, top=1.01)
#     # ax.legend()

#     plt.tight_layout()
#     analysis.show(fig)
#     analysis.save(graph_dir, suffix="duration_cdf")

# %%
# graph_delack_sweep(delack_sweep_exp_to_data, delack_sweep_dir)
# graph_delack_sweep_cdf(delack_sweep_exp_to_data, delack_sweep_dir)

# %% [markdown]
# Interesting things to plot:
# - RTT CDF: Randomly sample 1000 RTTs from each configuration, whenever there is actually traffic flowing
# - Average non-empty queue depth: Average depth of the incast queue whenever it's not 0 or 1.

# %% editable=true slideshow={"slide_type": ""}
# Randomly sample 1000 points
# Plot CDF
