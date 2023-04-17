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

# %%
# %matplotlib widget

import collections
import json
import math
import os
from os import path

import numpy as np
from matplotlib import pyplot as plt

# %%
OUT_DIR = "/data_hdd/incast/out/15ms-100-3-TcpDctcp-10icwnd-0offset-none-rwnd1000000B-20tokens-3g"
OUT_DIR_GRAPHS = path.join(OUT_DIR, "graphs")
if not path.isdir(OUT_DIR_GRAPHS):
    os.makedirs(OUT_DIR_GRAPHS)

# %%
# TODO: Add burstiness analysis from receiver pcap, flow level


def filter_samples(samples, start, end):
    return [sample for sample in samples if start <= sample[0] <= end]


def separate_samples_into_bursts(
    samples,
    burst_times,
    flow_times=None,
    filter_on_flow_times=False,
    bookend=True,
    earliest_sec=None,
):
    num_bursts = len(burst_times)
    bursts = []

    if filter_on_flow_times:
        assert flow_times is not None
    else:
        assert flow_times is None
        flow_times = [(None, None, None, None)] * num_bursts

    for burst_idx, (
        (burst_start, burst_end),
        (flow_start, _, flow_end, _),
    ) in enumerate(zip(burst_times, flow_times)):
        burst = []
        for sample in samples:
            if burst_start <= sample[0] <= burst_end and (
                not filter_on_flow_times or flow_start <= sample[0] <= flow_end
            ):
                # This sample is part of the current burst.
                burst.append(sample)

        # Insert a sample at precisely the start and end time for this burst, if possible.
        if bookend:
            start, end = (
                (flow_start, flow_end)
                if filter_on_flow_times
                else (burst_start, burst_end)
            )
            if burst_idx > 0:
                # Make sure that the burst has a sample at the start time
                # Two case: Either we have no samples for this burst, so we take
                # the last value from the previous burst, or we do have samples for
                # this burst but not at the start time, so we also take the last
                # value from the previous burst. In both cases, make sure there is
                # a previous burst.
                if (not burst and bursts[-1]) or (
                    burst and burst[0][0] != start and bursts[-1]
                ):
                    burst.insert(0, (start, *bursts[-1][-1][1:]))
            # Every burst should now have at least one sample: start.
            # Note: This will fail if we have no data for the first burst.

            if burst:
                # Make sure that the burst has a sample at the end time
                if burst[-1][0] != end:
                    burst.append((end, *burst[-1][1:]))
                # Every burst should now have at least two samples: start and end
                assert len(burst) >= 2, (burst, start, end)

        bursts.append(burst)
    # Make sure we have the expected number of bursts
    assert len(bursts) == num_bursts
    return bursts


# %%
def parse_times_line(line):
    # Format: <start time seconds> <end time seconds>
    parts = line.strip().split(" ")
    assert len(parts) == 2
    return [float(sec) for sec in parts]


def parse_burst_times(out_dir):
    with open(path.join(out_dir, "logs", "burst_times.log"), "r") as fil:
        return [parse_times_line(line) for line in fil if line.strip()[0] != "#"]


def parse_config_json(out_dir):
    with open(path.join(out_dir, "config.json"), "r") as fil:
        return json.load(fil)


BURST_TIMES = parse_burst_times(OUT_DIR)
# BURST_TIMES = [(start, (start + 0.03) if (end - start) > 0.03 else end) for start, end in BURST_TIMES]

CONFIG = parse_config_json(OUT_DIR)

ideal_sec = CONFIG["bytesPerSender"] * CONFIG["numSenders"] / (
    CONFIG["smallLinkBandwidthMbps"] * 1e6 / 8
) + (6 * CONFIG["delayPerLinkUs"] / 1e6)
print(
    "Burst times:",
    f"Ideal: {ideal_sec * 1e3:.4f} ms",
    *[
        f"{burst_idx + 1}: [{start} -> {end}] - {(end - start) * 1e3:.4f} ms - {(end - start) / ideal_sec * 100:.2f} %"
        for burst_idx, (start, end) in enumerate(BURST_TIMES)
    ],
    sep="\n",
)

MARKING_THRESHOLD = CONFIG["smallQueueMinThresholdPackets"]
QUEUE_CAPACITY = CONFIG["smallQueueSizePackets"]


# %%
def parse_queue_line(line):
    # Format: <timestamp seconds> <num packets> <backlog time microseconds>
    parts = line.strip().split(" ")
    assert len(parts) == 2
    time_sec, packets = parts
    time_sec = float(time_sec)
    packets = int(packets)
    # backlog_us = float(backlog_us)
    return time_sec, packets  # , backlog_us


def parse_mark_line(line):
    # Format <timestamp seconds>
    parts = line.strip().split(" ")
    assert len(parts) == 1
    return (float(parts[0]), None)


def parse_drop_line(line):
    # Format: <timestamp seconds> <drop type>
    parts = line.strip().split(" ")
    assert len(parts) == 2
    time_sec, drop_type = parts
    time_sec = float(time_sec)
    drop_type = int(drop_type)
    return time_sec, drop_type


def graph_queue(
    out_dir, queue_name, burst_times, marking_threshold_packets, capacity_packets
):
    queue_prefix = (
        "incast_queue"
        if queue_name == "Incast Queue"
        else ("uplink_queue" if queue_name == "Uplink Queue" else None)
    )
    assert queue_prefix is not None
    depth_flp = path.join(out_dir, f"{queue_prefix}_depth.log")
    mark_flp = path.join(out_dir, f"{queue_prefix}_mark.log")
    drop_flp = path.join(out_dir, f"{queue_prefix}_drop.log")

    depth_samples = []
    with open(depth_flp, "r") as fil:
        depth_samples = [
            parse_queue_line(line) for line in fil if line.strip()[0] != "#"
        ]
    burst_depths = separate_samples_into_bursts(depth_samples, burst_times)

    mark_samples = []
    with open(mark_flp, "r") as fil:
        mark_samples = [parse_mark_line(line) for line in fil if line.strip()[0] != "#"]
    burst_marks = separate_samples_into_bursts(mark_samples, burst_times, bookend=False)

    drop_samples = []
    with open(drop_flp, "r") as fil:
        drop_samples = [parse_drop_line(line) for line in fil if line.strip()[0] != "#"]
    burst_drops = separate_samples_into_bursts(drop_samples, burst_times, bookend=False)

    num_bursts = len(burst_depths)
    with plt.ioff():
        fig, axes = plt.subplots(
            figsize=(10, 3 * num_bursts), nrows=num_bursts, ncols=1
        )
    if num_bursts == 1:
        axes = [axes]
    else:
        axes = axes.flatten()

    for burst_idx, (ax, burst) in enumerate(zip(axes, burst_depths)):
        # Plot marks and drops on a second y axis

        # If there are marks, plot them...
        if burst_idx < len(burst_marks) and burst_marks[burst_idx]:
            mark_xs, _ = zip(*burst_marks[burst_idx])
            mark_ys = [marking_threshold_packets] * len(mark_xs)
            ax.plot(mark_xs, mark_ys, "x", color="orange", label="ECN marks", alpha=0.8)

        # If there are drops, plot them...
        if burst_idx < len(burst_drops) and burst_drops[burst_idx]:
            drop_xs, _ = zip(*burst_drops[burst_idx])
            drop_ys = [capacity_packets] * len(drop_xs)
            ax.plot(drop_xs, drop_ys, "x", color="red", label="Drops", alpha=0.8)

        # Plot depth
        xs, ys = zip(*burst)
        blue = "tab:blue"
        ax.plot(xs, ys, drawstyle="steps-post", color=blue, alpha=0.8)

        # Draw a line at the marking threshold
        ax.plot(
            [xs[0], xs[-1]],
            [marking_threshold_packets] * 2,
            label="Marking threshold",
            color="orange",
            linestyle="dashed",
            alpha=0.8,
        )
        # Draw a line at the queue capacity
        ax.plot(
            [xs[0], xs[-1]],
            [capacity_packets] * 2,
            label="Queue capacity",
            color="red",
            linestyle="dotted",
            alpha=0.8,
        )

        ax.set_title(f"{queue_name} Length: Burst {burst_idx + 1} of {num_bursts}")
        ax.set_xlabel("time (seconds)")
        ax.set_ylabel("queue length (packets)")
        # ax.tick_params(axis='y', labelcolor=blue)
        ax.set_ylim(bottom=0)
        ax.legend()

    plt.tight_layout()
    # Change the toolbar position
    fig.canvas.toolbar_position = "left"
    # If true then scrolling while the mouse is over the canvas will not move the entire notebook
    fig.canvas.capture_scroll = True
    fig.show()

    out_flp = path.join(
        OUT_DIR_GRAPHS,
        path.basename(OUT_DIR) + "_" + "_".join(queue_name.split(" ")).lower(),
    )
    plt.savefig(out_flp + ".pdf")
    plt.savefig(out_flp + ".png", dpi=300)

    return burst_depths, burst_marks, burst_drops


INCAST_Q_DEPTHS_BY_BURST, _, _ = graph_queue(
    path.join(OUT_DIR, "logs"),
    "Incast Queue",
    BURST_TIMES,
    MARKING_THRESHOLD,
    QUEUE_CAPACITY,
)


# %%
def calculate_time_at_or_above_threshold_helper(depths, thresh, start_sec, end_sec):
    # Identify crossover points and above regions points by filtering burst_samples.
    above_regions = []
    last_depth = None
    last_cross_up = None
    for x, depth in depths:
        if depth < thresh:
            if last_cross_up is not None:
                above_regions.append((last_cross_up, x))
                last_cross_up = None
        elif depth >= thresh:
            if last_depth is None or last_depth < thresh:
                last_cross_up = x
        last_depth = depth
    if last_cross_up is not None:
        above_regions.append((last_cross_up, end_sec))

    above_sec = sum(
        region_end_sec - region_start_sec
        for region_start_sec, region_end_sec in above_regions
    )
    total_sec = end_sec - start_sec
    return above_sec, total_sec, above_sec / total_sec * 100


def calculate_time_at_or_above_threshold(burst_depths, burst_times, thresh, label):
    num_bursts = len(burst_times)
    for burst_idx, (depths, (start_sec, end_sec)) in enumerate(
        zip(burst_depths, burst_times)
    ):
        above_sec, total_sec, perc = calculate_time_above_threshold_helper(
            depths, thresh, start_sec, end_sec
        )
        print(
            f"Burst {burst_idx + 1} of {num_bursts} - Time above {label}: {above_sec * 1e3:.2f} ms ({perc:.2f}%)"
        )


calculate_time_at_or_above_threshold(
    INCAST_Q_DEPTHS_BY_BURST, BURST_TIMES, MARKING_THRESHOLD, "marking threshold"
)

# %%
calculate_time_at_or_above_threshold(INCAST_Q_DEPTHS_BY_BURST, BURST_TIMES, 1, "empty")

# %%
calculate_time_at_or_above_threshold(
    INCAST_Q_DEPTHS_BY_BURST, BURST_TIMES, QUEUE_CAPACITY * 0.9, "90% capacity"
)

# %%
_, _, _ = graph_queue(
    path.join(OUT_DIR, "logs"),
    "Uplink Queue",
    BURST_TIMES,
    MARKING_THRESHOLD,
    QUEUE_CAPACITY,
)


# %%
def parse_flow_times(flow_times_json):
    return [
        {
            times["id"]: (times["start"], times["firstPacket"], times["end"], ip)
            for ip, times in flows.items()
        }
        for burst, flows in sorted(flow_times_json.items(), key=lambda p: int(p[0]))
    ]


def graph_active_connections(log_dir, burst_times):
    with open(path.join(log_dir, "flow_times.json"), "r") as fil:
        flow_times = json.load(fil)
    flow_times = parse_flow_times(flow_times)

    num_bursts = len(burst_times)
    with plt.ioff():
        fig, axes = plt.subplots(
            figsize=(10, 3 * num_bursts), nrows=num_bursts, ncols=1
        )
    if num_bursts == 1:
        axes = [axes]
    else:
        axes = axes.flatten()

    for burst_idx, ax in enumerate(axes):
        times = flow_times[burst_idx].values()
        starts, _, ends, _ = zip(*times)
        serialized = [(start, 1) for start in starts] + [(end, -1) for end in ends]
        serialized = sorted(serialized, key=lambda p: p[0])
        # earliest_time = serialized[0][0]
        # serialized = [(x - earliest_time, y) for x, y in serialized]
        active = [serialized[0]]
        for time, action in serialized[1:]:
            active.append((time, active[-1][1] + action))
        xs, ys = zip(*active)

        ax.plot(xs, ys, drawstyle="steps-post", alpha=0.8)

        ax.set_title(
            f"Active connections over time: Burst {burst_idx + 1} of {num_bursts}"
        )
        ax.set_xlabel("time (seconds)")
        ax.set_ylabel("active connections")
        ax.set_ylim(bottom=0)

    plt.tight_layout()
    # Change the toolbar position
    fig.canvas.toolbar_position = "left"
    # If true then scrolling while the mouse is over the canvas will not move the entire notebook
    fig.canvas.capture_scroll = True
    fig.show()

    out_flp = path.join(
        OUT_DIR_GRAPHS, path.basename(OUT_DIR) + "_" + "active_connections"
    )
    plt.savefig(out_flp + ".pdf")
    plt.savefig(out_flp + ".png", dpi=300)

    return flow_times


FLOW_TIMES = graph_active_connections(path.join(OUT_DIR, "logs"), BURST_TIMES)


# %%
def graph_cdf_of_flow_duration(flow_times, burst_times):
    num_bursts = len(burst_times)
    with plt.ioff():
        fig, axes = plt.subplots(figsize=(5, 3 * num_bursts), nrows=num_bursts, ncols=1)
    if num_bursts == 1:
        axes = [axes]
    else:
        axes = axes.flatten()

    for burst_idx, ax in enumerate(axes):
        times = flow_times[burst_idx].values()
        durations = [end - start for start, _, end, _ in times]

        count, bins_count = np.histogram(durations, bins=len(durations))
        ax.plot(bins_count[1:], np.cumsum(count / sum(count)), alpha=0.8)

        ax.set_title(f"CDF of flow duration: Burst {burst_idx + 1} of {num_bursts}")
        ax.set_xlabel("duration (seconds)")
        ax.set_ylabel("CDF")
        ax.set_xlim(left=0)
        ax.set_ylim(bottom=0, top=1)

    plt.tight_layout()
    # Change the toolbar position
    fig.canvas.toolbar_position = "left"
    # If true then scrolling while the mouse is over the canvas will not move the entire notebook
    fig.canvas.capture_scroll = True
    fig.show()

    out_flp = path.join(
        OUT_DIR_GRAPHS, path.basename(OUT_DIR) + "_" + "flow_duration_cdf"
    )
    plt.savefig(out_flp + ".pdf")
    plt.savefig(out_flp + ".png", dpi=300)


graph_cdf_of_flow_duration(FLOW_TIMES, BURST_TIMES)


# %%
def parse_cwnd_line(line):
    parts = line.strip().split(" ")
    assert len(parts) == 2
    time_sec, cwnd_bytes = parts
    time_sec = float(time_sec)
    cwnd_bytes = int(cwnd_bytes)
    return time_sec, cwnd_bytes


def parse_cwnds(flp):
    with open(flp, "r") as fil:
        return [parse_cwnd_line(line) for line in fil if line.strip()[0] != "#"]


def parse_sender(flp):
    return int(path.basename(flp).split("_")[0][6:])


def graph_sender_cwnd(out_dir, burst_times, flow_times):
    cwnd_flps = [
        path.join(out_dir, fln)
        for fln in os.listdir(out_dir)
        if fln.startswith("sender") and fln.endswith("_cwnd.log")
    ]

    sender_to_cwnds_by_burst = {
        parse_sender(flp): separate_samples_into_bursts(
            # Read all CWND samples for this sender
            parse_cwnds(flp),
            burst_times,
            # Look up the start and end time for this sender
            [burst_flow_times[parse_sender(flp)] for burst_flow_times in flow_times],
            filter_on_flow_times=True,
            earliest_sec=False,
            bookend=True,
        )
        for flp in cwnd_flps
    }

    num_bursts = len(burst_times)
    with plt.ioff():
        fig, axes = plt.subplots(
            figsize=(10, 3 * num_bursts), nrows=num_bursts, ncols=1
        )
    if num_bursts == 1:
        axes = [axes]
    else:
        axes = axes.flatten()

    for burst_idx, ax in enumerate(axes):
        ax.set_title(
            f"CWND of active connections: Burst {burst_idx + 1} of {num_bursts}"
        )
        ax.set_xlabel("time (seconds)")
        ax.set_ylabel("CWND (bytes)")

        for sender, bursts in sender_to_cwnds_by_burst.items():
            if not bursts[burst_idx]:
                continue
            xs, ys = zip(*bursts[burst_idx])
            ax.plot(xs, ys, label=sender, drawstyle="steps-post", alpha=0.8)

        ax.set_ylim(bottom=0)

    plt.tight_layout()
    # Change the toolbar position
    fig.canvas.toolbar_position = "left"
    # If true then scrolling while the mouse is over the canvas will not move the entire notebook
    fig.canvas.capture_scroll = True
    fig.show()

    out_flp = path.join(OUT_DIR_GRAPHS, path.basename(OUT_DIR) + "_" + "cwnd")
    plt.savefig(out_flp + ".pdf")
    plt.savefig(out_flp + ".png", dpi=300)

    return sender_to_cwnds_by_burst


SENDER_TO_CWNDS_BY_BURST = graph_sender_cwnd(
    path.join(OUT_DIR, "logs"), BURST_TIMES, FLOW_TIMES
)


# %%
# Inspired by https://stackoverflow.com/questions/10058227/calculating-mean-of-arrays-with-different-lengths
def tolerant_metrics(xs, arrays, interp_delta, percentiles):
    # Map x value to index. Used to quickly determine where each array starts
    # relative to the overall xs.
    xs_map = {
        round(x, int(math.log(interp_delta, 10))): idx for idx, x in enumerate(xs)
    }

    # Create 2d array to fit the largest array
    combined_2d = np.ma.empty((len(xs), len(arrays)))
    combined_2d.mask = True

    for idx, array in enumerate(arrays):
        # Look up this array's start position
        start_idx = xs_map[round(array[0][0], int(math.log(interp_delta, 10)))]
        combined_2d[start_idx : start_idx + len(array), idx] = list(zip(*array))[1]

    return (
        combined_2d.mean(axis=-1),
        combined_2d.std(axis=-1),
        combined_2d.min(axis=-1),
        combined_2d.max(axis=-1),
        np.nanpercentile(
            np.ma.filled(np.ma.masked_where(combined_2d < 0, combined_2d), np.nan),
            percentiles,
            axis=-1,
        ),
        combined_2d.sum(axis=-1),
    )


def step_interp(old_xs, old_ys, new_xs):
    # Lengths must be nonzero and agree.
    assert len(old_xs) > 0
    assert len(old_ys) > 0
    assert len(new_xs) > 0
    assert len(old_xs) == len(old_ys)
    # xs must be strictly non-decreasing.
    assert (np.diff(old_xs) >= 0).all(), np.diff(old_xs)
    assert (np.diff(new_xs) >= 0).all()
    # This is strictly interpolation, not extrapolation.
    assert new_xs[0] >= old_xs[0]
    assert new_xs[-1] <= old_xs[-1]

    new_ys = np.empty(len(new_xs))
    # Points to the next value in xs and ys that is past the current x we are interpolating.
    old_idx = 0
    for new_idx, new_x in enumerate(new_xs):
        # Move old_idx forward until it is at a position where the next element
        # in old_xs is strictly greater than new_x.
        #
        # old_idx will never grow larger than len(old_xs) - 2
        while old_idx < len(old_xs) - 2 and new_x >= old_xs[old_idx + 1]:
            old_idx += 1

        # If old_idx is immediately before the last element in old_xs, then
        # check manually if we need to advance old_idx to the last element in
        # old_xs.
        if old_idx == len(old_xs) - 2:
            if new_x >= old_xs[len(old_xs) - 1]:
                old_idx += 1

        new_ys[new_idx] = old_ys[old_idx]

    assert len(new_xs) == len(new_ys)
    return new_ys


def interpolate_flows_for_burst(
    sender_to_cwnds_by_burst, sender_to_cwnds_by_burst_interp, burst_idx, interp_delta
):
    # Interpolate each flow at uniform intervals.
    for sender, bursts in sender_to_cwnds_by_burst.items():
        if bursts[burst_idx]:
            start_x = bursts[burst_idx][0][0]
            end_x = bursts[burst_idx][-1][0]
            new_xs = np.array(
                [
                    x / interp_delta
                    for x in range(
                        math.ceil(start_x * interp_delta),
                        math.floor(end_x * interp_delta) + 1,
                    )
                ]
            )
            assert len(bursts[burst_idx]) > 0
            # print("interp_delta", interp_delta)
            # print("start_x", start_x)
            # print("end_x", end_x)
            # print(
            #     "math.ceil(start_x * interp_delta)", math.ceil(start_x * interp_delta)
            # )
            # print(
            #     "math.floor(end_x * interp_delta) + 1",
            #     math.floor(end_x * interp_delta) + 1,
            # )
            assert len(new_xs) > 0
            new_ys = step_interp(*zip(*bursts[burst_idx]), new_xs)
        else:
            new_xs = np.array([])
            new_ys = np.array([])
        sender_to_cwnds_by_burst_interp[sender].append(list(zip(new_xs, new_ys)))


def calculate_aggregate_metrics(valid, interp_delta, percentiles):
    # Determine the overall x-axis range for this burst, across all valid senders.
    start_x = min(samples[0][0] for samples in valid)
    end_x = max(samples[-1][0] for samples in valid)
    xs = np.array(
        [
            x / interp_delta
            for x in range(
                math.floor(start_x * interp_delta), math.ceil(end_x * interp_delta) + 1
            )
        ]
    )

    # Calculate and verify metrics.
    avg_ys, stdev_ys, min_ys, max_ys, percentiles_ys, sum_ys = tolerant_metrics(
        xs, valid, interp_delta, percentiles
    )
    assert len(xs) == len(avg_ys)
    assert len(xs) == len(stdev_ys)
    assert len(xs) == len(min_ys)
    assert len(xs) == len(max_ys)
    assert len(xs) == percentiles_ys.shape[1]
    assert len(xs) == len(sum_ys)

    return xs, avg_ys, stdev_ys, min_ys, max_ys, percentiles_ys, sum_ys


def graph_aggregate_cwnd_per_burst_helper(
    ax,
    sender_to_cwnds_by_burst,
    sender_to_cwnds_by_burst_interp,
    burst_idx,
    burst_times,
    interp_delta,
    percentiles,
):
    interpolate_flows_for_burst(
        sender_to_cwnds_by_burst,
        sender_to_cwnds_by_burst_interp,
        burst_idx,
        interp_delta,
    )

    # Throw away senders that do not have any samples for this burst.
    valid = [
        bursts[burst_idx]
        for bursts in sender_to_cwnds_by_burst_interp.values()
        if bursts[burst_idx]
    ]
    print(
        f"Burst {burst_idx} has "
        f"{len(valid)}/{len(sender_to_cwnds_by_burst_interp)} "
        "senders with at least one CWND sample."
    )

    (
        xs,
        avg_ys,
        stdev_ys,
        min_ys,
        max_ys,
        percentiles_ys,
        _,
    ) = calculate_aggregate_metrics(valid, interp_delta, percentiles)

    # Left graph
    ax[0].fill_between(xs, min_ys, max_ys, alpha=0.25, label="min/max")
    ax[0].fill_between(
        xs, avg_ys - stdev_ys, avg_ys + stdev_ys, alpha=0.5, label="avg +/- stdev"
    )
    ax[0].plot(xs, avg_ys, label="avg", alpha=0.8)
    ax[0].set_title(
        f"CWND of active connections: Burst {burst_idx + 1} of {len(burst_times)}"
    )
    ax[0].set_xlabel("time (seconds)")
    ax[0].set_ylabel("CWND (bytes)")
    ax[0].set_ylim(bottom=0)
    ax[0].legend()

    # Right graph
    ax[1].plot(xs, avg_ys, label="avg", alpha=0.8)
    for idx in range(1, percentiles_ys.shape[0]):
        ax[1].fill_between(
            xs,
            percentiles_ys[idx - 1],
            percentiles_ys[idx],
            alpha=0.5,
            label=f"p{percentiles[idx]}",
        )
    ax[1].set_title(
        f"CWND of active connections: Burst {burst_idx + 1} of {len(burst_times)}"
    )
    ax[1].set_xlabel("time (seconds)")
    ax[1].set_ylabel("CWND (bytes)")
    ax[1].set_ylim(bottom=0)
    ax[1].legend()


def graph_aggregate_cwnd_per_burst(
    sender_to_cwnds_by_burst, burst_times, interp_delta, percentiles
):
    num_bursts = len(burst_times)
    with plt.ioff():
        fig, axes = plt.subplots(
            figsize=(13, 3 * num_bursts), nrows=num_bursts, ncols=2
        )
    if num_bursts == 1:
        axes = [axes]

    # Calculate aggregate metrics, graph them, and store interpolated flows in
    # this dict.
    sender_to_cwnds_by_burst_interp = collections.defaultdict(list)
    for burst_idx, ax in enumerate(axes):
        graph_aggregate_cwnd_per_burst_helper(
            ax,
            sender_to_cwnds_by_burst,
            sender_to_cwnds_by_burst_interp,
            burst_idx,
            burst_times,
            interp_delta,
            percentiles,
        )

    for sender, bursts_interp in sender_to_cwnds_by_burst_interp.items():
        assert len(bursts_interp) == num_bursts

    plt.tight_layout()
    # Change the toolbar position
    fig.canvas.toolbar_position = "left"
    # If true then scrolling while the mouse is over the canvas will not move the entire notebook
    fig.canvas.capture_scroll = True
    fig.show()

    out_flp = path.join(OUT_DIR_GRAPHS, path.basename(OUT_DIR) + "_" + "cwnd_analysis")
    plt.savefig(out_flp + ".pdf")
    plt.savefig(out_flp + ".png", dpi=300)

    return sender_to_cwnds_by_burst_interp


INTERP_DELTA = 1e5
PERCENTILES = [0, 25, 50, 75, 95, 100]
SENDER_TO_CWNDS_BY_BURST_INTERP = graph_aggregate_cwnd_per_burst(
    SENDER_TO_CWNDS_BY_BURST, BURST_TIMES, INTERP_DELTA, PERCENTILES
)


# %%
def calculate_average_queue_depth(burst_depths, interp_delta, bandwidth_bps):
    num_bursts = len(burst_depths)
    for burst_idx, depths in enumerate(burst_depths):
        old_xs, old_ys = zip(*depths)
        start_x = old_xs[0]
        end_x = old_xs[-1]
        new_xs = np.array(
            [
                x / interp_delta
                for x in range(
                    math.ceil(start_x * interp_delta),
                    math.floor(end_x * interp_delta) + 1,
                )
            ]
        )
        new_ys = step_interp(old_xs, old_ys, new_xs)
        avg_q_packets = new_ys.mean()
        avg_q_bytes = avg_q_packets * BYTES_PER_PACKET
        avg_q_us = avg_q_bytes / (bandwidth_bps / 8) * 1e6
        print(
            f"Burst {burst_idx + 1} of {num_bursts} - Average queue depth: {avg_q_packets:.2f} packets, {avg_q_bytes:.2f} bytes, {avg_q_us:.2f} us"
        )


BYTES_PER_PACKET = 1500
BANDWIDTH_BITSPS = CONFIG["smallLinkBandwidthMbps"] * 1e6
calculate_average_queue_depth(
    INCAST_Q_DEPTHS_BY_BURST,
    INTERP_DELTA,
    BANDWIDTH_BITSPS,
)


# %%
def graph_estimated_queue_ingress_rate(burst_depths, bandwidth_bps, interp_delta):
    num_bursts = len(burst_depths)
    with plt.ioff():
        fig, axes = plt.subplots(
            figsize=(10, 3 * num_bursts), nrows=num_bursts, ncols=1
        )
    if num_bursts == 1:
        axes = [axes]
    else:
        axes = axes.flatten()

    for burst_idx, (ax, depths) in enumerate(zip(axes, burst_depths)):
        old_xs, old_ys = zip(*depths)
        start_x = old_xs[0]
        end_x = old_xs[-1]
        new_xs = np.array(
            [
                x / interp_delta
                for x in range(
                    math.ceil(start_x * interp_delta),
                    math.floor(end_x * interp_delta) + 1,
                )
            ]
        )
        new_ys = step_interp(old_xs, old_ys, new_xs)
        new_ys *= 8 * 1500

        ax.set_title(
            f"Estimated queue ingress rate: Burst {burst_idx + 1} of {num_bursts}"
        )
        ax.set_xlabel("time (seconds)")
        ax.set_ylabel("ingress rate (Gbps)")

        dydxs = np.gradient(new_ys, new_xs)

        # print(bandwidth_bps)
        dydxs = np.array(
            [
                dydx if y == 0 else (dydx + bandwidth_bps)
                for dydx, y in zip(dydxs, new_ys)
            ]
        )
        dydxs /= 1e9

        ax.plot(new_xs, dydxs, alpha=0.8)
        ax.set_ylim(bottom=min(0, min(dydxs) * 1.1))

    plt.tight_layout()
    # Change the toolbar position
    fig.canvas.toolbar_position = "left"
    # If true then scrolling while the mouse is over the canvas will not move the entire notebook
    fig.canvas.capture_scroll = True
    fig.show()

    out_flp = path.join(
        OUT_DIR_GRAPHS, path.basename(OUT_DIR) + "_" + "queue_ingress_rate"
    )
    plt.savefig(out_flp + ".pdf")
    plt.savefig(out_flp + ".png", dpi=300)


graph_estimated_queue_ingress_rate(
    INCAST_Q_DEPTHS_BY_BURST, BANDWIDTH_BITSPS, interp_delta=1e5
)


# %%
def graph_aggregate_cwnd_across_bursts(
    sender_to_cwnds_by_burst_interp, num_bursts, interp_delta, percentiles
):
    # We always ignore the first burst, since it is different than the others
    # due to slow start.
    if num_bursts == 1:
        print(
            "No results because we ignore the frst burst, but there is only one burst."
        )
        return

    # Flatten all senders and bursts.
    flattened_flows = []
    # Throw away the first burst, because it always looks different.
    for burst_idx in range(1, num_bursts):
        # Find the earliest start time for a flow in this burst.
        start_x = min(
            bursts[burst_idx][0][0]
            for bursts in sender_to_cwnds_by_burst_interp.values()
        )
        for bursts in sender_to_cwnds_by_burst_interp.values():
            # Throw away bursts with no samples.
            if bursts[burst_idx]:
                flattened_flows.append(
                    [
                        # Make all bursts start at time 0.
                        (sample[0] - start_x, *sample[1:])
                        for sample in bursts[burst_idx]
                    ]
                )

    (
        xs,
        avg_ys,
        stdev_ys,
        min_ys,
        max_ys,
        percentiles_ys,
        _,
    ) = calculate_aggregate_metrics(flattened_flows, interp_delta, percentiles)

    with plt.ioff():
        fig, axes = plt.subplots(figsize=(13, 3), nrows=1, ncols=2)

    # Left graph
    axes[0].fill_between(xs, min_ys, max_ys, alpha=0.25, label="min/max")
    axes[0].fill_between(
        xs, avg_ys - stdev_ys, avg_ys + stdev_ys, alpha=0.5, label="avg +/- stdev"
    )
    axes[0].plot(xs, avg_ys, label="avg", alpha=0.8)
    axes[0].set_title("CWND of active connections across all bursts")
    axes[0].set_xlabel("time (seconds)")
    axes[0].set_ylabel("CWND (bytes)")
    axes[0].set_ylim(bottom=0)
    axes[0].legend()

    # Right graph
    axes[1].plot(xs, avg_ys, label="avg", alpha=0.8)
    for idx in range(1, percentiles_ys.shape[0]):
        axes[1].fill_between(
            xs,
            percentiles_ys[idx - 1],
            percentiles_ys[idx],
            alpha=0.5,
            label=f"p{percentiles[idx]}",
        )
    axes[1].set_title("CWND of active connections across all bursts")
    axes[1].set_xlabel("time (seconds)")
    axes[1].set_ylabel("CWND (bytes)")
    axes[1].set_ylim(bottom=0)
    axes[1].legend()

    plt.tight_layout()
    # Change the toolbar position
    fig.canvas.toolbar_position = "left"
    # If true then scrolling while the mouse is over the canvas will not move the entire notebook
    fig.canvas.capture_scroll = True
    fig.show()

    out_flp = path.join(
        OUT_DIR_GRAPHS, path.basename(OUT_DIR) + "_" + "combined_cwnd_analysis"
    )
    plt.savefig(out_flp + ".pdf")
    plt.savefig(out_flp + ".png", dpi=300)


graph_aggregate_cwnd_across_bursts(
    SENDER_TO_CWNDS_BY_BURST_INTERP, len(BURST_TIMES), INTERP_DELTA, PERCENTILES
)


# %%
def graph_total_cwnd(
    sender_to_cwnds_by_burst_interp, burst_times, bdp_bytes, interp_delta
):
    num_bursts = len(burst_times)
    with plt.ioff():
        fig, axes = plt.subplots(
            figsize=(13, 3 * num_bursts), nrows=num_bursts, ncols=2
        )
    if num_bursts == 1:
        axes = [axes]

    for burst_idx, ax in enumerate(axes):
        valid = [
            bursts[burst_idx]
            for bursts in sender_to_cwnds_by_burst_interp.values()
            if bursts[burst_idx]
        ]
        xs, _, _, _, _, _, sum_ys = calculate_aggregate_metrics(
            valid, interp_delta, percentiles=[]
        )

        ax[0].plot(
            xs, sum_ys / 1e3, label="Total CWND of active connections", alpha=0.8
        )

        # Draw a line at the BDP
        bdp_kbytes = bdp_bytes / 1e3
        ax[0].plot(
            [xs[0], xs[-1]],
            [bdp_kbytes, bdp_kbytes],
            label="BDP",
            color="orange",
            linestyle="dashed",
            alpha=0.8,
        )

        ax[0].set_title(f"Total CWND in bytes: Burst {burst_idx + 1} of {num_bursts}")
        ax[0].set_xlabel("time (seconds)")
        ax[0].set_ylabel("kilobytes")
        ax[0].set_ylim(bottom=0)
        ax[0].legend()

        ax[1].plot(
            xs,
            [y / bdp_bytes for y in sum_ys],
            label="Total CWND as a multiple of BDP",
            alpha=0.8,
        )
        ax[1].set_title(
            f"Total CWND in multiples of BDP: Burst {burst_idx + 1} of {num_bursts}"
        )
        ax[1].set_xlabel("time (seconds)")
        ax[1].set_ylabel("multiples of the BDP")
        ax[1].set_ylim(bottom=0)

    plt.tight_layout()
    # Change the toolbar position
    fig.canvas.toolbar_position = "left"
    # If true then scrolling while the mouse is over the canvas will not move the entire notebook
    fig.canvas.capture_scroll = True
    fig.show()

    out_flp = path.join(OUT_DIR_GRAPHS, path.basename(OUT_DIR) + "_" + "total_cwnd")
    plt.savefig(out_flp + ".pdf")
    plt.savefig(out_flp + ".png", dpi=300)


BDP_BYTES = (
    CONFIG["smallLinkBandwidthMbps"] * 1e6 / 8 * 6 * CONFIG["delayPerLinkUs"] / 1e6
)
graph_total_cwnd(SENDER_TO_CWNDS_BY_BURST_INTERP, BURST_TIMES, BDP_BYTES, INTERP_DELTA)


# %%
def graph_cwnd_change_cdf(sender_to_cwnds_by_burst, burst_times):
    num_bursts = len(burst_times)
    with plt.ioff():
        fig, axes = plt.subplots(figsize=(5, 3 * num_bursts), nrows=num_bursts, ncols=1)
    if num_bursts == 1:
        axes = [axes]
    else:
        axes = axes.flatten()

    for burst_idx, ax in enumerate(axes):
        cwnd_down = []
        cwnd_up = []
        for sender_cwnds in sender_to_cwnds_by_burst.values():
            if len(sender_cwnds[burst_idx]) < 2:
                continue
            _, sender_cwnds_burst = zip(*sender_cwnds[burst_idx])
            # Compute percent difference
            cwnd_changes = np.diff(sender_cwnds_burst) / sender_cwnds_burst[:-1] * 100
            # Filter based on whether increase or decrease
            cwnd_down.extend(abs(x) for x in cwnd_changes if x < 0)
            cwnd_up.extend(x for x in cwnd_changes if x > 0)

        # Plot CWND decreases
        count, bins_count = np.histogram(cwnd_down, bins=len(cwnd_down))
        ax.plot(
            bins_count[1:],
            np.cumsum(count / sum(count)),
            alpha=0.8,
            label="CWND decrease",
            color="red",
        )

        # Plot CWND increases
        count, bins_count = np.histogram(cwnd_up, bins=len(cwnd_up))
        ax.plot(
            bins_count[1:],
            np.cumsum(count / sum(count)),
            alpha=0.8,
            linestyle="dashed",
            label="CWND increase",
            color="green",
        )

        ax.set_title(f"CDF of CWND change (%): Burst {burst_idx + 1} of {num_bursts}")
        ax.set_xlabel("CWND change (%)")
        ax.set_ylabel("CDF")
        ax.set_xlim(left=0) 
        ax.set_ylim(bottom=0, top=1)
        ax.legend()

    plt.tight_layout()
    # Change the toolbar position
    fig.canvas.toolbar_position = "left"
    # If true then scrolling while the mouse is over the canvas will not move the entire notebook
    fig.canvas.capture_scroll = True
    fig.show()

    out_flp = path.join(
        OUT_DIR_GRAPHS, path.basename(OUT_DIR) + "_" + "cwnd_change_cdf"
    )
    plt.savefig(out_flp + ".pdf")
    plt.savefig(out_flp + ".png", dpi=300)


graph_cwnd_change_cdf(SENDER_TO_CWNDS_BY_BURST, BURST_TIMES)
