import logging
import json
import os.path
import statistics
import hashlib
import math
from typing import Dict, List
from collections import defaultdict

import matplotlib.pyplot as plt
import numpy as np
from jsonpath_ng.ext import parse

logging.getLogger("matplotlib").setLevel(logging.WARNING)
logging.getLogger('PIL').setLevel(logging.WARNING)

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.DEBUG,
    format=f"%(asctime)s %(module)s: %(message)s",
)


POWMOD_NS = 7397852


def total_powmod_escrow(n):
    return 4 * (n ** 2) + 18 * n


def total_powmod_verify(n):
    return 4 * (n ** 2) + 13 * n


def total_powmod_escrow_and_verify(n, m):
    return total_powmod_escrow(n) + (m-1) * total_powmod_verify(n)


def total_powmod_proof_wikstroem(n):
    return 7 * n + 5


def total_powmod_verify_wikstroem(n):
    return 9 * n + 15


def total_powmod_wikstroem(n, m):
    return total_powmod_proof_wikstroem(n) + (m-1) * total_powmod_verify_wikstroem(n)


def total_dkg(m):
    t = np.ceil(m / 2 - 1)
    return m**2 * t + m**2 + m * t + 5 * m + 2 * t + 2


def confidence_interval(std: float, n: int, level: int) -> float:
    if level == 90:
        z = 1.645
    elif level == 95:
        z = 1.96
    elif level == 98:
        z = 2.33
    elif level == 99:
        z = 2.58
    else:
        raise RuntimeError("Unknown level for confidence interval")

    return z * (std / math.sqrt(n))


def get_figsize(columnwidth, wf=0.5, hf=(5. ** 0.5 - 1.0) / 2.0, ):
    # Source: https://stackoverflow.com/a/31527287
    """Parameters:
      - wf [float]:  width fraction in columnwidth units
      - hf [float]:  height fraction in columnwidth units.
                     Set by default to golden ratio.
      - columnwidth [float]: width of the column in latex. Get this from LaTeX
                             using \showthe\columnwidth
    Returns:  [fig_width,fig_height]: that should be given to matplotlib
    """
    fig_width_pt = columnwidth * wf
    inches_per_pt = 1.0 / 72.27  # Convert pt to inch
    fig_width = fig_width_pt * inches_per_pt  # width in inches
    fig_height = fig_width * hf  # height in inches
    return [fig_width, fig_height]


def get_config_key_for_match(match, key: str, _expr_cache={}) -> int:
    if key not in _expr_cache:
        _expr_cache[key] = parse(f"`this`.`parent`.`parent`.`parent`.{key}")
    expr = _expr_cache.get(key)
    return expr.find(match)[0].value


def get_duration_data(
    file: str, peer_type: str, config_constr: str, x_axis: str, peer_id: str, measurement: str
) -> Dict[int, List[float]]:
    h = hashlib.sha256()
    h.update(f"{file}{peer_type}{config_constr}{x_axis}{peer_id}{measurement}".encode())
    config_hash = h.hexdigest()
    config_cache = os.path.join("plot_cache", f"{config_hash}.json")
    if os.path.isfile(config_cache):
        logger.warning(f"Loading duration data from cache ...")
        with open(config_cache, mode="r") as fp:
            out = json.load(fp)
            out = {int(k): v for (k, v) in out.items()}
        return out

    expr = parse(f"$[?{config_constr}].{peer_type}['{peer_id}'].{measurement}")

    with open(file, mode="r") as fp:
        data = json.load(fp)

    out = defaultdict(list)
    for match in expr.find(data):
        out[get_config_key_for_match(match, x_axis)].append(
            sum(val["duration"] for val in match.value)
        )
    out = dict(out)

    with open(config_cache, mode="w") as fp:
        json.dump(out, fp)

    return out


def get_mean_xy_from_duration_data(data, scaling):
    x = sorted(data.keys())
    y = [statistics.mean(data[i]) * scaling for i in x]
    return x, y


def get_mean_xy_err_from_duration_data(data, scaling):
    x = sorted(data.keys())
    y = [statistics.mean(data[i]) * scaling for i in x]
    std = [statistics.stdev(data[i]) * scaling for i in x]
    err = [
        confidence_interval(std, len(data[x[0]]), 99) for std in std
    ]
    return x, y, err


def plot_line_graph(x, y, labels, fmts, xlabel, ylabel, title, path, errors=None):
    if not errors:
        errors = [[None] for _ in x]

    plt.style.use(['science'])
    fig, ax = plt.subplots(figsize=get_figsize(427.43153, wf=1.0, hf=0.5))

    ax.set(
        xlabel=xlabel,
        ylabel=ylabel,
        title=title
    )

    prev_color = None
    for x_values, y_values, label, fmt, error in zip(x, y, labels, fmts, errors):
        use_prev_color = fmt.find("__prev__") >= 0
        if use_prev_color:
            fmt = fmt.replace("__prev__", "")
        if not any(error):
            lines = plt.plot(x_values, y_values, fmt, label=label)
        else:
            lines = plt.errorbar(x_values, y_values, fmt=fmt, label=label, yerr=error, ecolor="black", capsize=1.0, barsabove=True)
        if use_prev_color:
            lines[0].set_color(prev_color)
        prev_color = lines[0].get_color()

    legend = plt.legend(frameon=True, fancybox=False, shadow=False)
    legend.get_frame().set_linewidth(0.5)
    legend.get_frame().set_edgecolor("black")

    fig.tight_layout()

    plt.savefig(path)
    plt.show()


def plot_grouped_bar_chart(labels, group1, group2, glabel1, glabel2, xlabel, ylabel, title, path):
    plt.style.use(['science'])
    fig, ax = plt.subplots(figsize=get_figsize(427.43153, wf=0.6, hf=1.0))

    x = np.arange(len(labels))  # the label locations
    width = 0.25  # the width of the bars

    rects1 = ax.bar(x - width / 2, group1, width, label=glabel1)
    rects2 = ax.bar(x + width / 2, group2, width, label=glabel2)

    ax.set(
        xlabel=xlabel,
        ylabel=ylabel,
        title=title,
    )
    ax.set_xticks(x, labels=labels)
    ax.set_ylim(top=ax.get_ylim()[1] + 1)

    legend = plt.legend(frameon=True, fancybox=False, shadow=False, loc="upper left")
    legend.get_frame().set_linewidth(0.5)
    legend.get_frame().set_edgecolor("black")

    ax.bar_label(rects1, padding=1.5, fmt="%.2f")
    ax.bar_label(rects2, padding=1.5, fmt="%.2f")

    fig.tight_layout()

    plt.savefig(path)
    plt.show()


def gen_plot_escrow_user_scaling_to_250(path):
    data_escrow = get_duration_data(
        "eval_data/scaling_users.json",
        "peer",
        "mixpeers=3 & consortiumpeers=2 & users <= 250",
        "users",
        "0",
        "escrow_commitment",
    )
    data_verify = get_duration_data(
        "eval_data/scaling_users.json",
        "peer",
        "mixpeers=3 & consortiumpeers=2 & users <= 250",
        "users",
        "0",
        "verify_escrowed_commitment",
    )
    x_escrow, y_escrow, err_escrow = get_mean_xy_err_from_duration_data(data_escrow, 1 / 1_000_000 / 1000 / 60)
    x_verify, y_verify, err_verify = get_mean_xy_err_from_duration_data(data_verify, 1 / 1_000_000 / 1000 / 60)
    y_total = [e + v for e, v in zip(y_escrow, y_verify)]
    err_total = [a + b for a, b in zip(err_escrow, err_verify)]

    plot_line_graph(
        [x_escrow, x_verify, x_escrow],
        [y_escrow, y_verify, y_total],
        ["Construction", "Verification (total)", "Total runtime"],
        ["", "", ""],
        "Users", "Duration (in minutes)",
        "Permutation Escrow", path,
        errors=[err_escrow, err_verify, err_total]
    )


def gen_plot_escrow_user_scaling_with_extrapolate(path):
    x = [[]]
    y = [[]]
    labels = ["Measurements"]
    fmts = ["k+"]
    for i in [3, 5, 7]:
        data_escrow = get_duration_data(
            "eval_data/scaling_users.json",
            "peer",
            f"mixpeers={i} & consortiumpeers=2",
            "users",
            "0",
            "escrow_commitment",
        )
        data_verify = get_duration_data(
            "eval_data/scaling_users.json",
            "peer",
            f"mixpeers={i} & consortiumpeers=2",
            "users",
            "0",
            "verify_escrowed_commitment",
        )
        x_escrow, y_escrow = get_mean_xy_from_duration_data(data_escrow, 1 / 1_000_000 / 1000 / 60 / 60)
        x_verify, y_verify = get_mean_xy_from_duration_data(data_verify, 1 / 1_000_000 / 1000 / 60 / 60)
        y_total = [e + v for e, v in zip(y_escrow, y_verify)]

        n = np.arange(10, 500, 1)
        m = i
        f = total_powmod_escrow_and_verify(n, m)
        # convert to hours
        f = f * (POWMOD_NS / 1_000_000) / 1000 / 60 / 60

        x = x + [n, x_escrow]
        y = y + [f, y_total]
        labels = labels + [
            f"{i} peers",
            ""
        ]
        fmts = fmts + ["", "__prev__+"]

    plot_line_graph(
        x,
        y,
        labels,
        fmts,
        "Users", "Duration (in hours)",
        "Permutation Escrow", path
    )


def gen_plot_dkg_peer_scaling(path):
    data = get_duration_data(
        "eval_data/dkg2.json",
        "consortium",
        "mixpeers=3",
        "consortiumpeers",
        "0",
        "dkg_perform",
    )
    x, y, err = get_mean_xy_err_from_duration_data(data, 1 / 1_000_000 / 1000 / 60)

    m = np.arange(3, 47, 1)
    f = total_dkg(m)
    # convert to minutes
    f = f * (POWMOD_NS / 1_000_000) / 1000 / 60

    plot_line_graph(
        [x, m],
        [y, f],
        ["Runtime", "Estimated runtime"],
        ["", ""],
        "Peers", "Duration (in minutes)",
        "DKG", path,
        errors=[err, [None for _ in m]]
    )


def gen_plot_pos_user_scaling(path):
    data_pos = get_duration_data(
        "eval_data/scaling_users.json",
        "peer",
        "mixpeers=3 & consortiumpeers=2",
        "users",
        "0",
        "proof_of_shuffle",
    )
    data_verify = get_duration_data(
        "eval_data/scaling_users.json",
        "peer",
        "mixpeers=3 & consortiumpeers=2",
        "users",
        "0",
        "verify_proof_of_shuffle",
    )
    x_pos, y_pos, err_pos = get_mean_xy_err_from_duration_data(data_pos, 1 / 1_000_000 / 1000)
    x_verify, y_verify, err_verify = get_mean_xy_err_from_duration_data(data_verify, 1 / 1_000_000 / 1000)
    y_total = [proof + verify for proof, verify in zip(y_pos, y_verify)]
    err_total = [a + b for a, b in zip(err_pos, err_verify)]

    plot_line_graph(
        [x_pos, x_verify, x_pos],
        [y_pos, y_verify, y_total],
        ["Construction", "Verification", "Total runtime"],
        ["", "", ""],
        "Users", "Duration (in seconds)",
        "Proof of Shuffle", path,
        errors=[err_pos, err_verify, err_total]
    )


def gen_plot_escrow_mixpeer_scaling(path):
    data_escrow = get_duration_data(
        "eval_data/scaling_mixpeers.json",
        "peer",
        "consortiumpeers=2",
        "mixpeers",
        "0",
        "escrow_commitment",
    )
    data_verify = get_duration_data(
        "eval_data/scaling_mixpeers.json",
        "peer",
        "consortiumpeers=2",
        "mixpeers",
        "0",
        "verify_escrowed_commitment",
    )
    x_escrow, y_escrow, err_escrow = get_mean_xy_err_from_duration_data(data_escrow, 1 / 1_000_000 / 1000 / 60)
    x_verify, y_verify, err_verify = get_mean_xy_err_from_duration_data(data_verify, 1 / 1_000_000 / 1000 / 60)
    y_total = [e + v for e, v in zip(y_escrow, y_verify)]
    n = 10
    m = np.arange(3, 47, 1)
    f = total_powmod_escrow_and_verify(n, m)
    # convert to minutes
    f = f * (POWMOD_NS / 1_000_000) / 1000 / 60

    plot_line_graph(
        [x_escrow, x_verify, x_escrow, m],
        [y_escrow, y_verify, y_total, f],
        ["Construction", "Verification (total)", "Total runtime", "Estimated runtime"],
        ["", "", "", ""],
        "Mix Peers", "Duration (in minutes)",
        "Permutation Escrow", path,
        errors=[err_escrow, err_verify, [a + b for a, b in zip(err_escrow, err_verify)], [None for _ in m]],
    )


def gen_plot_pos_mixpeer_scaling(path):
    data_proof = get_duration_data(
        "eval_data/scaling_mixpeers.json",
        "peer",
        "consortiumpeers=2",
        "mixpeers",
        "0",
        "proof_of_shuffle",
    )
    data_verify = get_duration_data(
        "eval_data/scaling_mixpeers.json",
        "peer",
        "consortiumpeers=2",
        "mixpeers",
        "0",
        "verify_proof_of_shuffle",
    )
    x_proof, y_proof, err_proof = get_mean_xy_err_from_duration_data(data_proof, 1 / 1_000_000 / 1000)
    x_verify, y_verify, err_verify = get_mean_xy_err_from_duration_data(data_verify, 1 / 1_000_000 / 1000)
    y_total = [e + v for e, v in zip(y_proof, y_verify)]
    n = 10
    m = np.arange(3, 47, 1)
    f = total_powmod_wikstroem(n, m)
    # convert to seconds
    f = f * (POWMOD_NS / 1_000_000) / 1000

    plot_line_graph(
        [x_proof, x_verify, x_proof, m],
        [y_proof, y_verify, y_total, f],
        ["Construction", "Verification (total)", "Total runtime", "Estimated runtime"],
        ["", "", "", ""],
        "Mix Peers", "Duration (in seconds)",
        "Proof of Shuffle", path,
        errors=[err_proof, err_verify, [a + b for a, b in zip(err_proof, err_verify)], [0 for _ in m]],
    )


def gen_bar_chart_deanon_scaling_users(path):
    data_full_recovery = get_duration_data(
        "eval_data/deanon_users.json",
        "consortium",
        "consortiumpeers=47 & mixpeers=3 & recovery=0",
        "users",
        "0",
        "recover",
    )
    data_single_recovery = get_duration_data(
        "eval_data/deanon_users.json",
        "consortium",
        "consortiumpeers=47 & mixpeers=3 & recovery=1",
        "users",
        "0",
        "recover_single",
    )

    x_full, y_full = get_mean_xy_from_duration_data(data_full_recovery, 1 / 1_000_000 / 1000 / 60)
    x_single, y_single = get_mean_xy_from_duration_data(data_single_recovery, 1 / 1_000_000 / 1000 / 60)

    plot_grouped_bar_chart(
        x_full,
        y_full, y_single,
        "Full Recovery", "Single Recovery",
        "Users", "Duration (in minutes)",
        "Identity Recovery", path
    )


def gen_bar_chart_inverse_perm_scaling_users(path):
    data_proof = get_duration_data(
        "eval_data/deanon_users.json",
        "peer",
        "consortiumpeers=47 & mixpeers=3 & recovery=1",
        "users",
        "0",
        "proof_of_inverse_permutation_commitment",
    )
    data_verify = get_duration_data(
        "eval_data/deanon_users.json",
        "peer",
        "consortiumpeers=47 & mixpeers=3 & recovery=1",
        "users",
        "0",
        "verify_inverse_permutation_commitment_proof",
    )

    x_proof, y_proof = get_mean_xy_from_duration_data(data_proof, 1 / 1_000_000 / 1000)
    x_verify, y_verify = get_mean_xy_from_duration_data(data_verify, 1 / 1_000_000 / 1000)

    plot_grouped_bar_chart(
        x_proof,
        y_proof, y_verify,
        "Proof", "Verification",
        "Users", "Duration (in seconds)",
        "Proof of Inv. Permutation Commitment", path
    )


def main() -> None:
    thesis_path = "../2021-ma-loebbert/thesis/figures/plots"
    gen_plot_escrow_user_scaling_with_extrapolate(os.path.join(thesis_path, "escrow.svg"))
    gen_plot_escrow_user_scaling_to_250(os.path.join(thesis_path, "escrow_250.svg"))
    gen_plot_pos_user_scaling(os.path.join(thesis_path, "pos.svg"))

    gen_plot_escrow_mixpeer_scaling(os.path.join(thesis_path, "escrow_peer.svg"))
    gen_plot_pos_mixpeer_scaling(os.path.join(thesis_path, "pos_peer.svg"))
    gen_plot_dkg_peer_scaling(os.path.join(thesis_path, "dkg.svg"))

    gen_bar_chart_deanon_scaling_users(os.path.join(thesis_path, "deanon.svg"))
    gen_bar_chart_inverse_perm_scaling_users(os.path.join(thesis_path, "inverseperm.svg"))


if __name__ == "__main__":
    main()
