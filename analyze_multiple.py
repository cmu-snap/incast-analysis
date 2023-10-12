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

import math
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
CONNSS = [50, 100, 150, 200, 500]
DUR_MS = "15ms"


# %% editable=true slideshow={"slide_type": ""}
def load_one(exp_dir):
    if not path.exists(exp_dir):
        return None

    data_flp = path.join(exp_dir, "data.pickle")
    if path.exists(data_flp):
        # if False:
        print(f"Loading from file: {exp_dir}...")
        with open(data_flp, "rb") as fil:
            try:
                data = pickle.load(fil)
                print(f"Succeeded loading from file: {data_flp}")
                return data
            except:
                print(f"Warning: Failed loading from file: {data_flp}")

    try:
        data = analysis.get_all_metrics_for_exp(exp_dir, interp_delta=1e5)
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
        exp_to_data = {exp_dir: load_one(exp_dir) for exp_dir in exp_dirs}

    exp_to_data = {exp: data for exp, data in exp_to_data.items() if data is not None}

    print(f"Loaded {len(exp_to_data)} experiments.")
    return exp_to_data


# %% editable=true slideshow={"slide_type": ""}
SWEEP_DIR = "/data_ssd/ccanel/incast/sweep/background-senders"
GRAPH_DIR = path.join(SWEEP_DIR, "graphs")
if not path.isdir(GRAPH_DIR):
    os.makedirs(GRAPH_DIR)

EXP_TO_DATA = load_all(
    SWEEP_DIR,
    filt=lambda c: (
        DUR_MS in c["outputDirectory"]
        and c["numBurstSenders"] <= 1000
        and c["smallLinkBandwidthMbps"] == 10000
        and c["smallQueueMinThresholdPackets"] == 65
        and (
            (
                c["rwndStrategy"] == "none"
                and c["numBurstSenders"] in [100, 150, 200, 500, 1000]
            )
            or (c["rwndStrategy"] == "static" and c["numBurstSenders"] == 100)
        )
    ),
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

    # Plot a line for each number of flows.
    for i, conns in enumerate(connss):
        print(conns)
        points = [
            (get_x(data), get_y(data))
            for exp, data in exp_to_data.items()
            if data["config"]["numBurstSenders"] == conns
        ]
        points = sorted(points)
        xs, ys = zip(*points)
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
    analysis.save(graph_dir, suffix=f"incast_queue_{DUR_MS}")


def graph_avg_tput(exp_to_data, sweep_dir, key, key_modifier, xlabel):
    graph_dir = path.join(sweep_dir, "graphs")
    if not path.isdir(graph_dir):
        os.makedirs(graph_dir)

    def get_x(data):
        return key_modifier(data["config"][key])

    def get_y(data):
        return [x / 1e9 for x in data["avg_tput_by_burst_bps"][1:]]

    points = [(get_x(data), get_y(data)) for exp, data in exp_to_data.items()]
    points = sorted(points)
    xs, ys = zip(*points)

    fig, axes = analysis.get_axes(width=6)
    ax = axes[0]

    ax.plot(xs, ys, "o-", alpha=0.8)

    ax.set_xlabel(xlabel, fontsize=analysis.FONTSIZE)
    ax.set_ylabel("throughput (Gbps)", fontsize=analysis.FONTSIZE)
    ax.set_xlim(left=0)
    ax.set_ylim(
        bottom=0,
        top=next(iter(exp_to_data.values()))["config"]["smallLinkBandwidthMbps"]
        / 1e3
        * 1.1,
    )
    ax.tick_params(axis="x", labelsize=analysis.FONTSIZE)
    ax.tick_params(axis="y", labelsize=analysis.FONTSIZE)

    plt.tight_layout()
    analysis.show(fig)
    analysis.save(graph_dir, suffix="incast_queue")


# graph_avg_queue_depth(
#     STATIC_EXP_TO_DATA,
#     SWEEP_DIR,
#     key="staticRwndBytes",
#     key_modifier=lambda x: x / 1e3,
#     xlabel="RWND clamp (KB)",
# )

# graph_avg_tput(
#     STATIC_EXP_TO_DATA,
#     SWEEP_DIR,
#     key="staticRwndBytes",
#     key_modifier=lambda x: x / 1e3,
#     xlabel="RWND clamp (KB)",
# )


# %% editable=true slideshow={"slide_type": ""}
# Graph queue over time for various RWND thresholds.
def graph_queue(
    lines,
    marking_threshold_packets,
    capacity_packets,
    graph_dir,
    legend_title=None,
    prefix=None,
    suffix=None,
    ncols=3,
):
    fig, axes = analysis.get_axes()
    ax = axes[0]

    # Plot a line for each RWND clamp.
    max_x = 0
    max_y = 0
    for xs, ys, label in lines:
        xs = xs - xs[0]
        xs = xs * 1e3
        ax.plot(
            xs,
            ys,
            drawstyle="steps-post",
            label=label,
            linewidth=analysis.LINESIZE,
            alpha=0.7,
        )
        max_x = max(max_x, xs[-1])
        max_y = max(max_y, *avg_ys)

    # Draw a line at the marking threshold
    ax.plot(
        [0, max_x],
        [marking_threshold_packets] * 2,
        label="ECN\nthreshold" if DUR_MS == "2ms" else "ECN threshold",
        color="orange",
        linestyle="dashed",
        linewidth=analysis.LINESIZE,
        alpha=1,
    )
    # Draw a line at the queue capacity
    if max_y > capacity_packets / 2:
        # Draw a line at the queue capacity
        ax.plot(
            [0, max_x],
            [capacity_packets] * 2,
            label="queue capacity",
            color="red",
            linestyle="dotted",
            linewidth=analysis.LINESIZE,
            alpha=0.8,
        )
        max_y = capacity_packets
    elif len(lines) == 1:
        max_y = capacity_packets / 2

    ax.set_xlabel("time (ms)", fontsize=analysis.FONTSIZE)
    ax.set_ylabel(
        "packets" if len(lines) == 1 else "queue length\n(packets)",
        fontsize=analysis.FONTSIZE,
    )
    ax.tick_params(axis="x", labelsize=analysis.FONTSIZE)
    ax.tick_params(axis="y", labelsize=analysis.FONTSIZE)
    ax.set_xlim(left=-0.01 * max_x, right=1.01 * max_x)
    ax.set_ylim(bottom=-0.01 * max_y, top=1.1 * max_y)
    if DUR_MS == "2ms":
        ax.legend(
            fontsize=analysis.FONTSIZE,
            ncols=ncols,
            **(
                {}
                if legend_title is None
                else {"title": legend_title, "title_fontsize": analysis.FONTSIZE}
            ),
            bbox_to_anchor=(1.02, 0.5),
            loc="center left",
        )
    else:
        ax.legend(
            fontsize=analysis.FONTSIZE,
            loc="center right" if max_y > capacity_packets / 2 else "upper right",
            ncols=ncols,
            **(
                {}
                if legend_title is None
                else {"title": legend_title, "title_fontsize": analysis.FONTSIZE}
            ),
        )

    plt.tight_layout()
    analysis.show(fig)
    analysis.save(graph_dir, prefix, suffix)


for CONNS in [100]:
    print(CONNS)

    datas = [
        data
        for data in EXP_TO_DATA.values()
        if data["config"]["numBurstSenders"] == CONNS
    ]

    # Add a line for No RWND tuning
    none = [data for data in datas if data["config"]["rwndStrategy"] == "none"]
    assert len(none) == 1

    # Add a line for each RWND clamp.
    max_x = 0
    max_y = 0
    lines = []
    for i, data in enumerate(
        list(
            reversed(
                sorted(
                    (
                        data
                        for data in datas
                        if (
                            data["config"]["rwndStrategy"] == "static"
                            and data["config"]["staticRwndBytes"] < 11000
                        )
                    ),
                    key=lambda p: p["config"]["staticRwndBytes"],
                )
            )
        )
        + none
    ):
        if (
            DUR_MS != "2ms"
            and data["config"]["rwndStrategy"] == "static"
            and round(data["config"]["staticRwndBytes"] / 1024) % 2 == 1
        ):
            continue
        xs, avg_ys, _, _, _, _, _ = data["incast_queue_across_bursts"]
        xs = np.asarray(xs)
        lines.append(
            (
                xs,
                avg_ys,
                "None"
                if data["config"]["rwndStrategy"] == "none"
                else round(data["config"]["staticRwndBytes"] / 1024),
            )
        )

    marking_threshold_packets = datas[0]["config"]["smallQueueMinThresholdPackets"]
    capacity_packets = datas[0]["config"]["smallQueueSizePackets"]

    graph_queue(
        lines,
        marking_threshold_packets,
        capacity_packets,
        GRAPH_DIR,
        legend_title="RWND clamp (KB)",
        prefix=f"staticRwnd_{DUR_MS}_{none[0]['config']['numBurstSenders']}flows",
        suffix=f"incast_queue",
        ncols=2 if DUR_MS == "2ms" else 3,
    )


# Plot a none case for each number of connections
if DUR_MS != "2ms":
    for CONNS in [50, 100, 150, 500, 1000]:
        print(CONNS)

        datas = [
            data
            for data in EXP_TO_DATA.values()
            if data["config"]["numBurstSenders"] == CONNS
        ]
        # Add a line for No RWND tuning
        none = [data for data in datas if data["config"]["rwndStrategy"] == "none"]
        assert len(none) == 1
        none = none[0]

        xs, avg_ys, _, _, _, _, _ = none["incast_queue_across_bursts"]
        xs = np.asarray(xs)
        lines = [(xs, avg_ys, "queue depth")]

        marking_threshold_packets = datas[0]["config"]["smallQueueMinThresholdPackets"]
        capacity_packets = datas[0]["config"]["smallQueueSizePackets"]

        graph_queue(
            lines,
            marking_threshold_packets,
            capacity_packets,
            GRAPH_DIR,
            prefix=f"noRwnd_{DUR_MS}_{none['config']['numBurstSenders']}flows",
            suffix=f"incast_queue",
            ncols=2,
        )


if DUR_MS == "2ms":
    datas = [
        data
        for data in EXP_TO_DATA.values()
        if data["config"]["rwndStrategy"] == "none"
    ]

    lines = []
    for data in sorted(datas, key=lambda d: d["config"]["numBurstSenders"]):
        xs, avg_ys, _, _, _, _, _ = data["incast_queue_across_bursts"]
        xs = np.asarray(xs)
        lines.append((xs, avg_ys, data["config"]["numBurstSenders"]))

    marking_threshold_packets = datas[0]["config"]["smallQueueMinThresholdPackets"]
    capacity_packets = datas[0]["config"]["smallQueueSizePackets"]

    graph_queue(
        lines,
        marking_threshold_packets,
        capacity_packets,
        GRAPH_DIR,
        prefix=f"noRwnd_{DUR_MS}_allFlowCounts",
        suffix=f"incast_queue",
        ncols=1,
        legend_title="Flow count",
    )


# %%
# Graph FCT distribution for various RWND thresholds
def graph_fct(lines, graph_dir, legend_title=None, prefix=None, suffix=None, ncols=3):
    fig, axes = analysis.get_axes(width=6)  #  if len(lines) > 1 else 3)
    ax = axes[0]

    max_x = 0
    for fcts, label in lines:
        max_x = max(max_x, *fcts)
        count, bins_count = np.histogram(fcts, bins=len(fcts))
        ax.plot(
            bins_count[1:],
            np.cumsum(count / sum(count)),
            label=label,
            linewidth=analysis.LINESIZE,
            alpha=0.7,
        )

    ax.set_xlabel("flow duration (ms)", fontsize=analysis.FONTSIZE)
    ax.set_ylabel("CDF", fontsize=analysis.FONTSIZE)
    ax.tick_params(axis="x", labelsize=analysis.FONTSIZE)
    ax.tick_params(axis="y", labelsize=analysis.FONTSIZE)
    ax.set_xlim(left=-0.01 * max_x, right=1.01 * max_x)
    ax.set_ylim(bottom=-0.01, top=1.01)
    if len(lines) > 1:
        ax.legend(
            fontsize=analysis.FONTSIZE,
            # bbox_to_anchor=(1.02, 0.5),
            # loc="center left",
            loc="upper left",
            ncols=ncols,
            title="RWND clamp (KB)",
            title_fontsize=analysis.FONTSIZE,
        )

    analysis.show(fig)
    analysis.save(graph_dir, prefix, suffix)


for CONNS in [100]:
    print(CONNS)

    datas = [
        data
        for data in EXP_TO_DATA.values()
        if data["config"]["numBurstSenders"] == CONNS
    ]
    # Add a line for No RWND tuning
    none = [data for data in datas if data["config"]["rwndStrategy"] == "none"]
    assert len(none) == 1

    # Add a line for each RWND clamp.
    max_x = 0
    max_y = 0
    lines = []
    for i, data in enumerate(
        list(
            reversed(
                sorted(
                    (
                        data
                        for data in datas
                        if (
                            data["config"]["rwndStrategy"] == "static"
                            and data["config"]["staticRwndBytes"] < 11000
                        )
                    ),
                    key=lambda p: p["config"]["staticRwndBytes"],
                )
            )
        )
        + none
    ):
        if (
            data["config"]["rwndStrategy"] == "static"
            and round(data["config"]["staticRwndBytes"] / 1024) % 2 == 1
        ):
            continue

        fcts = []
        for burst_idx in range(1, data["config"]["numBursts"]):
            times = [
                flow_times_by_burst[burst_idx]
                for flow_times_by_burst in data[
                    "sender_to_flow_times_by_burst"
                ].values()
            ]
            fcts.extend([(end - start) * 1e3 for start, _, end, _ in times])
        lines.append(
            (
                fcts,
                "None"
                if data["config"]["rwndStrategy"] == "none"
                else round(data["config"]["staticRwndBytes"] / 1024),
            )
        )

    graph_fct(
        lines,
        GRAPH_DIR,
        legend_title="RWND clamp (KB)",
        prefix=f"staticRwnd_{DUR_MS}_{none[0]['config']['numBurstSenders']}flows",
        suffix=f"fct",
    )


# Plot a none case for each number of connections
for CONNS in [100]:
    print(CONNS)

    none = [
        data
        for data in EXP_TO_DATA.values()
        if (
            data["config"]["numBurstSenders"] == CONNS
            and data["config"]["rwndStrategy"] == "none"
        )
    ]
    assert len(none) == 1
    none = none[0]

    fcts = []
    for burst_idx in range(1, none["config"]["numBursts"]):
        times = [
            flow_times_by_burst[burst_idx]
            for flow_times_by_burst in none["sender_to_flow_times_by_burst"].values()
        ]
        fcts.extend([(end - start) * 1e3 for start, _, end, _ in times])
    print("min:", min(fcts), "max:", max(fcts))
    lines = [(fcts, None)]

    graph_fct(
        lines,
        GRAPH_DIR,
        legend_title=None,
        prefix=f"noRwnd_{DUR_MS}_{none['config']['numBurstSenders']}flows",
        suffix=f"fct",
    )


# %% editable=true slideshow={"slide_type": ""}
# Graph p95 CWND over time for various RWND thresholds
def graph_p95_bytes_in_flight(exp_to_data, sweep_dir):
    graph_dir = path.join(sweep_dir, "graphs")
    if not path.isdir(graph_dir):
        os.makedirs(graph_dir)

    fig, axes = analysis.get_axes()
    ax = axes[0]

    # Plot a line for No RWND tuning
    none = [
        data
        for data in exp_to_data.values()
        if data["config"]["rwndStrategy"] == "none"
    ]
    assert len(none) == 1

    # Plot a line for each RWND clamp.
    max_x = 0
    max_y = 0
    for i, data in enumerate(
        list(
            reversed(
                sorted(
                    (
                        data
                        for data in exp_to_data.values()
                        if data["config"]["rwndStrategy"] == "static"
                        and data["config"]["staticRwndBytes"] < 11000
                    ),
                    key=lambda p: p["config"]["staticRwndBytes"],
                )
            )
        )
        + none
    ):
        if (
            data["config"]["rwndStrategy"] == "static"
            and round(data["config"]["staticRwndBytes"] / 1024) % 2 == 1
        ):
            continue

        # Last element in the tuple is the total cwnd
        xs, _, _, _, _, percentiles, _ = data["cwnd_metrics_across_bursts"]
        xs = np.asarray(xs) - xs[0]
        xs = xs * 1e3
        # Extract p95
        ys = percentiles[4]
        ys = ys / 1e3
        xs = xs[: len(ys)]
        ys = ys[: len(xs)]
        # print(len(xs), len(ys))
        # ax.plot(xs, ys, COLORS_FRIENDLY_HEX[i], label=round(data['config']['staticRwndBytes'] / 1024), linewidth=analysis.LINESIZE, alpha=0.7)
        ax.plot(
            xs,
            ys,
            label="None"
            if data["config"]["rwndStrategy"] == "none"
            else round(data["config"]["staticRwndBytes"] / 1024),
            linewidth=analysis.LINESIZE,
            alpha=0.7,
        )
        max_x = max(max_x, xs[-1])
        max_y = max(max_y, *ys)

    ax.set_xlabel("time (ms)", fontsize=analysis.FONTSIZE)
    ax.set_ylabel("per-flow in-flight data\n(p95, KB)", fontsize=analysis.FONTSIZE)
    ax.set_xlim(left=-0.01 * max_x, right=1.01 * max_x)
    ax.set_ylim(bottom=-0.01 * max_y, top=1.1 * max_y)
    ax.tick_params(axis="x", labelsize=analysis.FONTSIZE)
    ax.tick_params(axis="y", labelsize=analysis.FONTSIZE)
    ax.legend(
        fontsize=analysis.FONTSIZE,
        # bbox_to_anchor=(1.02, 0.5),
        # loc="center left",
        loc="upper center",
        title="RWND clamp (KB)",
        title_fontsize=analysis.FONTSIZE,
        ncols=3,
    )

    plt.tight_layout()
    analysis.show(fig)
    analysis.save(
        graph_dir,
        suffix=f"staticRwnd_p95_bytes_in_flight_{DUR_MS}_{none[0]['config']['numBurstSenders']}flows",
    )


for CONNS in [100]:
    print(CONNS)
    graph_p95_bytes_in_flight(
        {
            exp: data
            for exp, data in EXP_TO_DATA.items()
            if data["config"]["numBurstSenders"] == CONNS
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

    # Plot a line for No RWND tuning
    none = [
        data
        for data in exp_to_data.values()
        if data["config"]["rwndStrategy"] == "none"
    ]
    assert len(none) == 1

    # Plot a line for each RWND clamp.
    max_x = 0
    max_y = 0
    for i, data in enumerate(
        list(
            reversed(
                sorted(
                    (
                        data
                        for data in exp_to_data.values()
                        if data["config"]["rwndStrategy"] == "static"
                        and data["config"]["staticRwndBytes"] < 11000
                    ),
                    key=lambda p: p["config"]["staticRwndBytes"],
                )
            )
        )
        + none
    ):
        if (
            data["config"]["rwndStrategy"] == "static"
            and round(data["config"]["staticRwndBytes"] / 1024) % 2 == 1
        ):
            continue

        bdp_bytes = (
            data["config"]["smallLinkBandwidthMbps"]
            * 1e6
            / 8
            * 6
            * data["config"]["delayPerLinkUs"]
            / 1e6
        )
        print(bdp_bytes)
        # Last element in the tuple is the total cwnd
        xs, _, _, _, _, _, total_ys = data["cwnd_metrics_across_bursts"]
        print(total_ys[:10])
        xs = np.array(xs) - xs[0]
        xs = xs * 1e3
        total_ys = total_ys / bdp_bytes
        # ax.plot(xs, ys, COLORS_FRIENDLY_HEX[i], label=round(data['config']['staticRwndBytes'] / 1024), linewidth=analysis.LINESIZE, alpha=0.7)
        ax.plot(
            xs,
            total_ys,
            label="None"
            if data["config"]["rwndStrategy"] == "none"
            else round(data["config"]["staticRwndBytes"] / 1024),
            linewidth=analysis.LINESIZE,
            alpha=0.7,
        )
        max_x = max(max_x, xs[-1])
        max_y = max(max_y, *total_ys)

    # # Draw a line at the BDP
    # marking_threshold_packets = next(iter(exp_to_data.values()))["config"]["smallQueueMinThresholdPackets"]
    # ax.plot(
    #     [0, max_x],
    #     [marking_threshold_packets] * 2,
    #     label="ECN thresh",
    #     color="orange",
    #     linestyle="dashed",
    #     linewidth=analysis.LINESIZE,
    #     alpha=1,
    # )

    ax.set_xlabel("time (ms)", fontsize=analysis.FONTSIZE)
    ax.set_ylabel("total in-flight data\n(x BDP)", fontsize=analysis.FONTSIZE)
    ax.set_xlim(left=-0.01 * max_x, right=1.01 * max_x)
    ax.set_ylim(bottom=-0.01 * max_y, top=1.1 * max_y)
    ax.tick_params(axis="x", labelsize=analysis.FONTSIZE)
    ax.tick_params(axis="y", labelsize=analysis.FONTSIZE)
    ax.legend(
        fontsize=analysis.FONTSIZE,
        # bbox_to_anchor=(1.02, 0.5),
        # loc="center left",
        loc="upper right",
        title="RWND clamp (KB)",
        title_fontsize=analysis.FONTSIZE,
        ncols=3,
    )

    plt.tight_layout()
    analysis.show(fig)
    analysis.save(
        graph_dir,
        suffix=f"staticRwnd_total_in_flight_data_{DUR_MS}_{none[0]['config']['numBurstSenders']}flows",
    )


for CONNS in [100]:
    print(CONNS)
    graph_total_cwnd(
        {
            exp: data
            for exp, data in EXP_TO_DATA.items()
            if data["config"]["numBurstSenders"] == CONNS
        },
        SWEEP_DIR,
    )


# %%
# Graph all flows in flight data over time for a specific RWND clamp
def graph_sender_inflight(exp_to_data, sweep_dir, clamp):
    graph_dir = path.join(sweep_dir, "graphs")
    if not path.isdir(graph_dir):
        os.makedirs(graph_dir)

    fig, axes = analysis.get_axes()
    ax = axes[0]

    options = [
        data
        for data in exp_to_data.values()
        if data["config"]["rwndStrategy"] == "static"
        and data["config"]["staticRwndBytes"] == clamp
    ]
    assert len(options) == 1
    data = options[0]

    print(data["config"]["outputDirectory"])

    max_x = 0
    max_y = 0
    for sender, bursts in data["sender_to_cwnds_by_burst"].items():
        burst = bursts[-1]
        xs, ys = zip(*burst)
        xs = np.array(xs) - xs[0]
        xs = xs * 1e3
        ax.plot(
            xs,
            ys,
            linewidth=analysis.LINESIZE,
            alpha=0.7,
        )
        max_x = max(max_x, xs[-1])
        max_y = max(max_y, *ys)

    ax.set_xlabel("time (ms)", fontsize=analysis.FONTSIZE)
    ax.set_ylabel("in-flight data (bytes)", fontsize=analysis.FONTSIZE)
    # ax.set_xlim(left=0)
    ax.set_ylim(bottom=-1, top=max_y * 1.1)
    ax.tick_params(axis="x", labelsize=analysis.FONTSIZE)
    ax.tick_params(axis="y", labelsize=analysis.FONTSIZE)

    plt.tight_layout()
    analysis.show(fig)
    analysis.save(
        graph_dir,
        suffix=f"in_flight_data_{DUR_MS}_{data['config']['numBurstSenders']}flows_{clamp}KB",
    )


# for CONNS in CONNSS:
#     print(CONNS)
#     graph_sender_inflight(
#         {
#             exp: data
#             for exp, data in EXP_TO_DATA.items()
#             if data["config"]["numBurstSenders"] == CONNS
#         },
#         SWEEP_DIR,
#         2048
#     )

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
#     ax = ax

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
#     ax = ax

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

# %%
if False:
    del EXP_TO_DATA
    EXP_TO_DATA_2MS = load_all(
        SWEEP_DIR,
        filt=lambda c: "2ms" in c["outputDirectory"] and c["numBurstSenders"] < 1000,
    )
    STATIC_EXP_TO_DATA_2MS = {
        exp: data
        for exp, data in EXP_TO_DATA.items()
        if data["config"]["rwndStrategy"] == "static"
    }

    for CONNS in CONNS:
        # for CONNS in [150]:
        print(CONNS)
        graph_queue(
            {
                exp: data
                for exp, data in STATIC_EXP_TO_DATA_2MS.items()
                if data["config"]["numBurstSenders"] == CONNS
                and data["config"]["staticRwndBytes"] < 11000
            },
            SWEEP_DIR,
        )

    for CONNS in CONNS:
        print(CONNS)
        # graph_fct(static_exp_to_data_filtered, sweep_dir)
        graph_fct(
            {
                exp: data
                for exp, data in STATIC_EXP_TO_DATA_2MS.items()
                if data["config"]["numBurstSenders"] == CONNS
                and data["config"]["staticRwndBytes"] < 11000
            },
            SWEEP_DIR,
        )

    for CONNS in CONNS:
        print(CONNS)
        # graph_p95_bytes_in_flight({exp: data for exp, data in static_exp_to_data.items() if data["config"]["numBurstSenders"] == CONNS and data["config"]["staticRwndBytes"] < 11000 and (data["config"]["staticRwndBytes"] / 1024) % 2 == 0}, sweep_dir)
        graph_p95_bytes_in_flight(
            {
                exp: data
                for exp, data in STATIC_EXP_TO_DATA_2MS.items()
                if data["config"]["numBurstSenders"] == CONNS
                and data["config"]["staticRwndBytes"] < 11000
            },
            SWEEP_DIR,
        )

    for CONNS in CONNS:
        print(CONNS)
        # graph_total_cwnd({exp: data for exp, data in static_exp_to_data.items() if data["config"]["numBurstSenders"] == CONNS and data["config"]["staticRwndBytes"] < 11000 and (data["config"]["staticRwndBytes"] / 1024) % 2 == 0}, sweep_dir)
        graph_total_cwnd(
            {
                exp: data
                for exp, data in STATIC_EXP_TO_DATA_2MS.items()
                if data["config"]["numBurstSenders"] == CONNS
                and data["config"]["staticRwndBytes"] < 11000
            },
            SWEEP_DIR,
        )
