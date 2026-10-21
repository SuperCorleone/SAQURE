import re
import os
from typing import Dict, List, Optional
import glob
import numpy as np

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import Rectangle, Patch
from matplotlib.ticker import AutoMinorLocator, MultipleLocator, FormatStrFormatter
from matplotlib.lines import Line2D

import argparse

RESULTS_BASE = "SAQURE-simulator/results"
PLOTS_DIR = "experiments/plots"
# The RQ1-RQ3 figures report the Adaptation Gain (G):
# G = (C_cur - C_new) / C_cur * 100, the share of the current configuration's long-term cost
# that the option an approach chose removes. C_new is the SAQURE-DTMC price of the chosen option
# and C_cur is the current configuration's price on that DTMC (same scenario and phase),
# so higher is better and a negative bar is a choice worse than not adapting.
GAIN_PLOTS_DIR = f"{PLOTS_DIR}/adaptation_gain"
GAIN_LABEL = 'Adaptation Gain (%)'
# (RECT_YMIN, RECT_YLIM, major tick step) of the gain axis.
GAIN_AXIS_RQ1 = (-3, 35, 10)
GAIN_AXIS_RQ23 = (-6, 24, 4)
# RQ2/RQ3 figures are 1.2:1 (width:height), height 6.7in.
RQ23_FIGSIZE = (6.7 * 1.2, 6.7)
# Spacing (%) of the background grid on the RQ2/RQ3 figures.
GAIN_GRID_RQ23 = 0.5
# Opacity of that grid; darker than the RQ1 grid (0.15) so that close bars can be compared.
GAIN_GRID_ALPHA_RQ23 = 0.3
# Spacing (%) of the fine background grid on the RQ1 gain figure.
GAIN_GRID_RQ1 = 1
GAIN_ROWS = []  # (figure, group, arm, C_cur, C_new, G) for adaptation_gain_values.csv

# run_experiments.sh writes the RAMSES arm to rq1_logs/<S>/RAMSES, while the plot configs
# below key it as "QoS". Without this the RAMSES series is silently missing from every RQ1 plot.
LOG_DIR_BY_KEY = {"QoS": "RAMSES"}

# ═══════════════════════════════════════════════════════════════
# Utility functions (unchanged from create_plots.py)
# ═══════════════════════════════════════════════════════════════

def extract_log_fields(log_content: str) -> Dict[str, str]:
    """
    Extract the required fields from the log content
    """
    best_option = None
    best_option_cost_values = None
    extract_time = None

    # 1. extract best_option
    best_option_match = re.search(
        r'Best option:.*?Change.*?from.*?to\s+([\w-]+?)-service',
        log_content
    )

    no_better_found = False
    if best_option_match:
        best_option = best_option_match.group(1) + "-service"
    else:
        no_better_match = re.search(r'No better option found', log_content)
        if no_better_match:
            no_better_found = True
            current_graph_match = re.search(
                r'"currentImplementationId":"([\w-]+?)-service"',
                log_content
            )
            if current_graph_match:
                service_base = current_graph_match.group(1)
                base_name = re.sub(r'-\d+$', '', service_base)
                best_option = f"{base_name}-1-service"

    # 2. extract best_option_cost_values
    cost_match = re.search(r'Best cost value:\s*([\d.]+)', log_content)
    if cost_match:
        best_option_cost_values = cost_match.group(1)
    elif no_better_found:
        first_cost_match = re.search(r'Cost Value:\s*([\d.]+)', log_content)
        if first_cost_match:
            best_option_cost_values = first_cost_match.group(1)

    # 3. extract extract_time
    time_match = re.search(
        r'Runtime decision time:\s*([\d.]+)ms',
        log_content
    )
    if time_match:
        extract_time = time_match.group(1)

    return {
        'best_option': best_option,
        'best_option_cost_values': best_option_cost_values,
        'extract_time': extract_time
    }

def extract_log_fields_RQ1_longcul(log_content: str) -> Dict[str, str]:
    best_option = None
    best_option_cost_values = None
    extract_time = None

    best_option_match = re.search(
        r'Key with min value:\s+([\w-]+?)-service',
        log_content
    )

    no_better_found = False
    if best_option_match:
        best_option = best_option_match.group(1) + "-service"
    else:
        print("error: extract_log_fields_RQ1_longcul: no best option found")
        return {}

    cost_match = re.search(r'Min value:\s*([\d.]+)', log_content)
    if cost_match:
        best_option_cost_values = cost_match.group(1)
    else:
        print("error: extract_log_fields_RQ1_longcul: no best option found")
        return {}

    time_match = re.search(
        r'Time to extract best option by Radapt without DTMC:\s*([\d.]+)ms',
        log_content
    )
    if time_match:
        extract_time = time_match.group(1)

    return {
        'best_option': best_option,
        'best_option_cost_values': best_option_cost_values,
        'extract_time': extract_time
    }

def calculate_statistics(data):
    """Calculate statistical indicators"""
    if len(data) == 0:
        return {}

    data = np.array(data)
    min_val = np.min(data)
    max_val = np.max(data)
    mean_val = np.mean(data)
    q1 = np.percentile(data, 25)
    q2 = np.percentile(data, 50)
    q3 = np.percentile(data, 75)

    return {
        'min': min_val,
        'max': max_val,
        'mean': mean_val,
        'q1': q1,
        'q2': q2,
        'q3': q3,
    }

def read_log_files(folder_path):
    """Read all .log files in the folder"""
    txt_files = []
    file_paths = glob.glob(os.path.join(folder_path, "*.log"))

    for file_path in file_paths:
        filename = os.path.basename(file_path)
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
            txt_files.append({
                'filename': filename,
                'content': content
            })

    return txt_files

def calculate_statistics_for_folder(folder_path, spacial_case):
    """Calculate statistics for all log files in the folder"""
    times = []
    logs_dic = read_log_files(folder_path)
    best_cost = 0.0
    best_option = ""
    for log in logs_dic:
        if spacial_case:
            result = extract_log_fields_RQ1_longcul(log['content'])
        else:
            result = extract_log_fields(log['content'])
        best_option = result['best_option']
        best_cost = float(result['best_option_cost_values'])

        if result['extract_time']:
            times.append(float(result['extract_time']))

    if times:
        time_stats = calculate_statistics(times)
        return time_stats, best_cost, best_option
    else:
        return {}

def extract_cost_from_SAQURE(folder_path: str, target_service: str) -> float | None:
    """
    Extract the Cost Value corresponding to target_service from the log.
    """
    logs_dic = read_log_files(folder_path)

    lines = []
    if isinstance(logs_dic, dict):
        lines = [str(v) for v in logs_dic.values()]
    elif isinstance(logs_dic, list):
        for log_entry in logs_dic:
            if isinstance(log_entry, dict):
                lines.extend(str(v) for v in log_entry.values())
            else:
                lines.append(str(log_entry))
    else:
        lines = [str(logs_dic)]

    lines = "\n".join(lines).splitlines()

    # Stage 1: Find "from ... to target_service"
    for i, line in enumerate(lines):
        match = re.search(r'from\s+.*?\s+to\s+([\w-]+)', line)
        if match and match.group(1) == target_service:
            for next_line in lines[i+1:]:
                cost_match = re.search(r'Cost Value:\s*([\d.eE+-]+)', next_line)
                if cost_match:
                    return float(cost_match.group(1))

    # Stage 2: Find Cost Value after "Current graph:"
    for i, line in enumerate(lines):
        if "Current graph:" in line:
            for next_line in lines[i+1:]:
                cost_match = re.search(r'Cost Value:\s*([\d.eE+-]+)', next_line)
                if cost_match:
                    return float(cost_match.group(1))

    print("error in extract_cost_from_SAQURE func: wrong service")
    return None

def extract_eadsa_time(log_content: str) -> Optional[float]:
    """
    Extract EADSA implementation time from log
    """
    m = re.search(r'Time to implement EADSA for [\w_]+:\s*([\d.]+)ms', log_content)
    return float(m.group(1)) if m else None

def calculate_eadsa_statistics_for_folder(folder_path):
    """Read all log files in the folder and calculate statistics for EADSA time"""
    logs_dic = read_log_files(folder_path)
    times = []

    for log in logs_dic:
        t = extract_eadsa_time(log['content'])
        if t is not None:
            times.append(t)

    if times:
        return calculate_statistics(times)
    return {}


# ═══════════════════════════════════════════════════════════════
# Shared color/style definitions
# ═══════════════════════════════════════════════════════════════

COLORS = {
    'red': (163/255, 81/255, 57/255),
    'dark pink': (202/255, 162/255, 173/255),
    'dark orange': (234/255, 177/255, 112/255),
    'dark purple': (182/255, 175/255, 197/255),
    'dark cyan-blue': (182/255, 207/255, 212/255),
    'cyan-blue': (225/255, 241/255, 246/255),
    'purple': (230/255, 226/255, 245/255),
    'orange': (244/255, 224/255, 155/255),
    'pink': (246/255, 223/255, 224/255),
    'pink_red': (221/255, 185/255, 172/255),
}

# RQ2 uses slightly different orange shades
COLORS_RQ2 = {
    **COLORS,
    'dark orange': (238/255, 197/255, 160/255),
    'orange': (249/255, 235/255, 221/255),
}


# ═══════════════════════════════════════════════════════════════
# Plot: RQ1 (dual-axis: cost bar + time boxplot)
# ═══════════════════════════════════════════════════════════════

def plot_rq1(time_stats_all, cost_values_all, experiment_name, save_path, gain_axis=GAIN_AXIS_RQ1):
    """
    Plot all sub-scenarios of RQ1 in one figure (Adaptation Gain bars + decision-time boxplots).
    cost_values_all holds the Adaptation Gain (%) of each arm's chosen option.
    """
    FIG_SIZE = (12, 6)
    BAR_WIDTH = 0.08
    BOX_WIDTH = 0.08
    GROUP_SPACING = 0.15
    X_BLOCK_WIDTH = 0.1
    TREND_LING_LINEWIDTH = 1.0
    IQR_LINEWIDTH = 0.8
    HATCH_LINE_WIDTH = 0.5

    POINTSIZE = 2
    Y_MARGIN_RATIO = 1.02
    # Retuned for the 4-state DTMC: decision time is 2.2-4.7 s (was 45-60 s).
    Y_MAX_MARGIN = 5000
    Y_MIN_MARGIN = -8000
    RECT_YMIN, RECT_YLIM = gain_axis[0], gain_axis[1]
    DOT_HLINE_DENSITY = 1

    FONT_SIZE_TICK = 24
    TICK_LABEL_SIZE = 18
    FONT_SIZE_LEGEND = 15
    FONT_SIZE_LEGEND_TITLE = 18

    colors = COLORS

    baseline_colors = {
        'AQUA': colors['cyan-blue'],
        'QoS': colors['purple'],
        'SAQURE_seq': colors['orange'],
        'SAQURE_para': colors['pink_red'],
    }
    edge_colors = {
        'AQUA': colors['dark cyan-blue'],
        'QoS': colors['dark purple'],
        'SAQURE_seq': colors['dark orange'],
        'SAQURE_para': colors['red'],
    }
    hatch_patterns = {
        'AQUA': '///',
        'QoS': '\\\\\\',
        'SAQURE_seq': '---',
        'SAQURE_para': '',
    }
    line_styles = {
        'AQUA': '-',
        'QoS': (0, (10, 5)),
        'SAQURE_seq': '-.',
        'SAQURE_para': ':',
    }
    marker_styles = {
        'AQUA': 'o',
        'QoS': 's',
        'SAQURE_seq': '^',
        'SAQURE_para': 'D',
    }
    mapping = {
        'QoS': 'RAMSES',
        'SAQURE_seq': 'SAQURE$^{-}_{para}$',
        'SAQURE_para': 'SAQURE'
    }

    # Data preparation
    sub_scenarios = list(time_stats_all.keys())
    baselines = list(time_stats_all[sub_scenarios[0]].keys())

    x_positions = {}
    x_ticks = []
    current_pos = 0
    for i, sub_scenario in enumerate(sub_scenarios):
        scenario_positions = []
        for j, baseline in enumerate(baselines):
            pos = current_pos + j * (BAR_WIDTH + 0.02)
            scenario_positions.append(pos)
        x_positions[sub_scenario] = scenario_positions
        x_ticks.append(np.mean(scenario_positions))
        current_pos = max(scenario_positions) + GROUP_SPACING

    fig, ax1 = plt.subplots(figsize=FIG_SIZE)
    ax2 = ax1.twinx()

    # Cost bar chart
    bars = []
    bar_labels = []
    for sub_scenario in sub_scenarios:
        for j, baseline in enumerate(baselines):
            if baseline in cost_values_all[sub_scenario]:
                x_pos = x_positions[sub_scenario][j]
                bar = ax1.bar(
                    x_pos, cost_values_all[sub_scenario][baseline],
                    width=BAR_WIDTH, color=baseline_colors[baseline],
                    edgecolor=edge_colors[baseline],
                    hatch=hatch_patterns[baseline],
                    hatch_linewidth=HATCH_LINE_WIDTH,
                    zorder=2, label=baseline if sub_scenario == sub_scenarios[0] else ""
                )
                if sub_scenario == sub_scenarios[0]:
                    bars.append(bar)
                    bar_labels.append(mapping.get(baseline, baseline))

    # Time boxplot
    all_time_values = []
    for sub_scenario in sub_scenarios:
        for baseline in baselines:
            if baseline in time_stats_all[sub_scenario]:
                stats = time_stats_all[sub_scenario][baseline]
                all_time_values.extend([stats['min'], stats['max'], stats['q1'], stats['q3'], stats['mean']])

    ax2.set_ylim(Y_MIN_MARGIN, Y_MAX_MARGIN)

    baseline_mean_positions = {baseline: [] for baseline in baselines}
    for sub_scenario in sub_scenarios:
        for j, baseline in enumerate(baselines):
            if baseline in time_stats_all[sub_scenario]:
                stats = time_stats_all[sub_scenario][baseline]
                x_pos = x_positions[sub_scenario][j]
                baseline_mean_positions[baseline].append((x_pos, stats['mean']))

                rect = Rectangle(
                    (x_pos - BOX_WIDTH / 2, stats['q1']),
                    BOX_WIDTH, stats['q3'] - stats['q1'],
                    facecolor=baseline_colors[baseline], edgecolor=edge_colors[baseline],
                    linewidth=IQR_LINEWIDTH, hatch=hatch_patterns[baseline],
                    hatch_linewidth=HATCH_LINE_WIDTH, zorder=4
                )
                ax2.add_patch(rect)
                ax2.vlines(x_pos, stats['min'], stats['q1'], colors=edge_colors[baseline], linewidth=1, zorder=2)
                ax2.vlines(x_pos, stats['q3'], stats['max'], colors=edge_colors[baseline], linewidth=1, zorder=2)
                ax2.plot(x_pos, stats['mean'], marker=marker_styles[baseline],
                         color=edge_colors[baseline], markersize=POINTSIZE+5, zorder=6,
                         markeredgecolor='black', markeredgewidth=0.5)
                ax2.hlines(stats['mean'], x_pos - BOX_WIDTH / 2, x_pos + BOX_WIDTH / 2,
                           colors=edge_colors[baseline], linewidth=1.2, zorder=5)

    # Mean trend lines
    mean_trend_lines = []
    for baseline in baselines:
        if baseline_mean_positions[baseline]:
            positions = sorted(baseline_mean_positions[baseline], key=lambda x: x[0])
            x_coords = [pos[0] for pos in positions]
            y_coords = [pos[1] for pos in positions]
            line, = ax2.plot(x_coords, y_coords, color=edge_colors[baseline],
                             linestyle=line_styles[baseline], linewidth=TREND_LING_LINEWIDTH,
                             marker=marker_styles[baseline], markersize=0, zorder=3,
                             markeredgecolor='black', markeredgewidth=0.5,
                             label=f'{mapping.get(baseline, baseline)}')
            mean_trend_lines.append(line)

    # Axis settings
    plt.rcParams['text.usetex'] = True
    ax1.set_xticks(x_ticks)
    num_opts_comments = {'1': '3 options', '2': '3 options', '3': '4 options', '4': '4 options', '5': '4 options'}
    x_tick_labels = []
    for ss in sub_scenarios:
        main_part = ss[0:-1]
        num = ss[-1]
        if num_opts_comments:
            x_tick_label = f'{main_part}$_{num}$' + f' ({num_opts_comments.get(num)})'
        else:
            x_tick_label = f'{main_part}$_{num}$'
        x_tick_labels.append(x_tick_label)

    ax1.set_xticklabels(x_tick_labels)
    ax1.set_ylabel(GAIN_LABEL, fontsize=FONT_SIZE_TICK)
    ax2.set_ylabel('Runtime Decision Time (ms)', fontsize=FONT_SIZE_TICK)
    ax1.set_ylim(RECT_YMIN, RECT_YLIM)
    ax1.axhline(0, color='black', linewidth=0.8, zorder=3)

    ax1.tick_params(axis='x', labelsize=TICK_LABEL_SIZE)
    ax1.tick_params(axis='y', labelsize=TICK_LABEL_SIZE)
    ax2.tick_params(axis='y', labelsize=TICK_LABEL_SIZE)

    ax2.ticklabel_format(style='sci', axis='y', scilimits=(0, 0))
    ax2.locator_params(axis='y', nbins=10)
    ax1.yaxis.set_major_locator(MultipleLocator(gain_axis[2]))
    ax1.yaxis.set_minor_locator(AutoMinorLocator())

    ax1.set_xlim(-X_BLOCK_WIDTH, current_pos - GROUP_SPACING + X_BLOCK_WIDTH)

    # Grid lines
    # Fine background grid over the whole axis, including the negative band.
    for y in np.arange(np.ceil(RECT_YMIN / GAIN_GRID_RQ1) * GAIN_GRID_RQ1, RECT_YLIM, GAIN_GRID_RQ1):
        ax1.axhline(y=y, color='gray', linestyle='--', linewidth=0.75, alpha=0.15, zorder=0)
    ax1.set_axisbelow(True)

    fig.tight_layout()
    plt.savefig(save_path, dpi=200)
    plt.show()


# ═══════════════════════════════════════════════════════════════
# Plot: RQ2 / RQ3 (dual-axis: cost bar + time boxplot, T1/T2)
# ═══════════════════════════════════════════════════════════════

def plot_rq2_rq3(time_stats_all, cost_values_all, config, save_path):
    """
    Plot RQ2 or RQ3 sub-scenario (dual-axis: Adaptation Gain bar + time boxplot).
    cost_values_all holds the Adaptation Gain (%) of each arm's chosen option.
    config = [Y_MIN_MARGIN_RATIO, Y_MARGIN_RATIO, RECT_YMIN, RECT_YLIM,
              DOT_HLINE_DENSITY, y_settick]
    """
    FIG_SIZE = RQ23_FIGSIZE
    BAR_WIDTH = 0.1
    BOX_WIDTH = 0.1
    GROUP_SPACING = 0.16
    X_BLOCK_WIDTH = 0.07
    IQR_LINEWIDTH = 0.8
    HATCH_LINE_WIDTH = 0.5

    POINTSIZE = 2
    Y_MIN_MARGIN_RATIO = config[0]
    Y_MARGIN_RATIO = config[1]
    RECT_YMIN = config[2]
    RECT_YLIM = config[3]
    DOT_HLINE_DENSITY = config[4]
    Y_SETTICK = config[5]

    FONT_SIZE_TICK = 25
    TICK_LABEL_SIZE = 22
    FONT_SIZE_LEGEND = 15
    FONT_SIZE_LEGEND_TITLE = 18

    colors = COLORS_RQ2

    baseline_colors = {
        'AQUA': colors['cyan-blue'],
        'SAQURE_nodyPa': colors['orange'],
        'SAQURE': colors['pink_red']
    }
    edge_colors = {
        'AQUA': colors['dark cyan-blue'],
        'SAQURE_nodyPa': colors['dark orange'],
        'SAQURE': colors['red']
    }
    hatch_patterns = {
        'AQUA': '///',
        'SAQURE_nodyPa': '\\\\\\',
        'SAQURE': '',
    }
    marker_styles = {
        'AQUA': 'o',
        'SAQURE_nodyPa': 's',
        'SAQURE': 'D',
    }
    mapping = {
        'AQUA': 'AQUA',
        'SAQURE_nodyPa': 'SAQURE$^{-}_{dyPa}$',
        'SAQURE': 'SAQURE'
    }

    # Data preparation
    sub_scenarios = list(time_stats_all.keys())
    baselines = list(time_stats_all[sub_scenarios[0]].keys())

    x_positions = {}
    x_ticks = []
    current_pos = 0
    for i, sub_scenario in enumerate(sub_scenarios):
        scenario_positions = []
        for j, baseline in enumerate(baselines):
            pos = current_pos + j * (BAR_WIDTH + 0.02)
            scenario_positions.append(pos)
        x_positions[sub_scenario] = scenario_positions
        x_ticks.append(np.mean(scenario_positions))
        current_pos = max(scenario_positions) + GROUP_SPACING

    # Keep tick/offset-text rendering identical for every sub-scenario: usetex
    # must be fixed BEFORE the axes (and their tick Text objects and
    # ScalarFormatter) are created, otherwise only the first figure produced by
    # the process is rendered without TeX (S1 vs S2/S3 mismatch).
    plt.rcParams['text.usetex'] = False

    fig, ax1 = plt.subplots(figsize=FIG_SIZE)
    ax2 = ax1.twinx()

    # Cost bar chart
    bars = []
    bar_labels = []
    for sub_scenario in sub_scenarios:
        for j, baseline in enumerate(baselines):
            if baseline in cost_values_all[sub_scenario]:
                x_pos = x_positions[sub_scenario][j]
                bar = ax1.bar(x_pos, cost_values_all[sub_scenario][baseline],
                              width=BAR_WIDTH, color=baseline_colors[baseline],
                              edgecolor=edge_colors[baseline],
                              hatch=hatch_patterns[baseline],
                              hatch_linewidth=HATCH_LINE_WIDTH,
                              zorder=2, label=baseline if sub_scenario == sub_scenarios[0] else "")
                if sub_scenario == sub_scenarios[0]:
                    bars.append(bar)
                    bar_labels.append(mapping.get(baseline, baseline))

    # Time boxplot
    all_time_values = []
    for sub_scenario in sub_scenarios:
        for baseline in baselines:
            if baseline in time_stats_all[sub_scenario]:
                stats = time_stats_all[sub_scenario][baseline]
                all_time_values.extend([stats['min'], stats['max'], stats['q1'], stats['q3'], stats['mean']])

    if all_time_values:
        y_min = min(all_time_values)
        y_max = max(all_time_values)
        ax2.set_ylim(y_min * Y_MIN_MARGIN_RATIO, y_max * Y_MARGIN_RATIO)

    baseline_mean_positions = {baseline: [] for baseline in baselines}
    for sub_scenario in sub_scenarios:
        for j, baseline in enumerate(baselines):
            if baseline in time_stats_all[sub_scenario]:
                stats = time_stats_all[sub_scenario][baseline]
                x_pos = x_positions[sub_scenario][j]
                baseline_mean_positions[baseline].append((x_pos, stats['mean']))

                rect = Rectangle(
                    (x_pos - BOX_WIDTH / 2, stats['q1']),
                    BOX_WIDTH, stats['q3'] - stats['q1'],
                    facecolor=baseline_colors[baseline], edgecolor=edge_colors[baseline],
                    linewidth=IQR_LINEWIDTH, hatch=hatch_patterns[baseline],
                    hatch_linewidth=HATCH_LINE_WIDTH, zorder=4
                )
                ax2.add_patch(rect)
                ax2.vlines(x_pos, stats['min'], stats['q1'], colors=edge_colors[baseline], linewidth=1, zorder=2)
                ax2.vlines(x_pos, stats['q3'], stats['max'], colors=edge_colors[baseline], linewidth=1, zorder=2)
                ax2.plot(x_pos, stats['mean'], marker=marker_styles[baseline],
                         color=edge_colors[baseline],
                         markersize=POINTSIZE+5 if marker_styles[baseline] else POINTSIZE,
                         zorder=6,
                         markeredgecolor='black' if marker_styles[baseline] else None,
                         markeredgewidth=0.5 if marker_styles[baseline] else 0)
                ax2.hlines(stats['mean'], x_pos - BOX_WIDTH / 2, x_pos + BOX_WIDTH / 2,
                           colors=edge_colors[baseline], linewidth=1.2, zorder=5)

    # Axis settings
    plt.rcParams['text.usetex'] = True
    ax1.set_xticks(x_ticks)
    x_tick_labels = []
    for ss in sub_scenarios:
        main_part = ss[0:-1]
        num = ss[-1]
        x_tick_label = f'{main_part}$_{num}$'
        x_tick_labels.append(x_tick_label)
    ax1.set_xticklabels(x_tick_labels)
    ax1.set_ylabel(GAIN_LABEL, fontsize=FONT_SIZE_TICK)
    ax2.set_ylabel('Runtime Decision Time (ms)', fontsize=FONT_SIZE_TICK)
    ax1.set_ylim(RECT_YMIN, RECT_YLIM)
    ax1.axhline(0, color='black', linewidth=0.8, zorder=3)

    ax1.yaxis.set_major_locator(MultipleLocator(Y_SETTICK))
    ax2.ticklabel_format(style='sci', axis='y', scilimits=(0, 0))

    ax1.tick_params(axis='both', which='major', labelsize=TICK_LABEL_SIZE)
    ax2.tick_params(axis='y', which='major', labelsize=TICK_LABEL_SIZE)

    ax1.set_xlim(-X_BLOCK_WIDTH, current_pos - GROUP_SPACING + X_BLOCK_WIDTH)

    # Grid lines
    grid_start = np.ceil(RECT_YMIN / DOT_HLINE_DENSITY - 1e-9) * DOT_HLINE_DENSITY
    for y in np.arange(grid_start, RECT_YLIM, DOT_HLINE_DENSITY):
        ax1.axhline(y=y, color='gray', linestyle='--', linewidth=0.75,
                    alpha=GAIN_GRID_ALPHA_RQ23, zorder=0)
    ax1.set_axisbelow(True)

    fig.tight_layout()
    plt.savefig(save_path, dpi=200)
    plt.show()

# ═══════════════════════════════════════════════════════════════
# Data loading + main
# ═══════════════════════════════════════════════════════════════

def ensure_plots_dir():
    os.makedirs(PLOTS_DIR, exist_ok=True)
    os.makedirs(GAIN_PLOTS_DIR, exist_ok=True)


def current_config_cost(folder):
    """Long-term cost of the current configuration: the first PRISM result after 'Current graph:'."""
    for path in sorted(glob.glob(os.path.join(folder, '*.log'))):
        lines = open(path, errors='replace').read().splitlines()
        for i, line in enumerate(lines):
            if 'Current graph:' in line:
                for nxt in lines[i + 1:]:
                    m = re.search(r'Cost Value:\s*([\d.eE+-]+)', nxt)
                    if m:
                        return float(m.group(1))
    return None


def to_gain(figure, group, costs, current):
    """Adaptation Gain (%) of each arm's chosen option against the current configuration."""
    gains = {}
    for arm, cost in costs.items():
        gains[arm] = 100.0 * (current - cost) / current
        GAIN_ROWS.append((figure, group, arm, current, cost, gains[arm]))
        print(f"    G {figure} {group} {arm}: {gains[arm]:.2f}% (C_cur {current:.4f}, C_new {cost:.4f})")
    return gains


def run_gain():
    """RQ1-RQ3 Adaptation Gain figures, plus the values behind them."""
    os.makedirs(GAIN_PLOTS_DIR, exist_ok=True)
    GAIN_ROWS.clear()
    run_rq1()
    run_rq2()
    run_rq3()
    with open(f'{GAIN_PLOTS_DIR}/adaptation_gain_values.csv', 'w') as out:
        out.write('figure,group,arm,C_cur,C_new,G_percent\n')
        for row in GAIN_ROWS:
            out.write('%s,%s,%s,%.6f,%.6f,%.2f\n' % row)
    print(f"Adaptation Gain figures and values written to {GAIN_PLOTS_DIR}/")


def run_rq1():
    """Load data and plot RQ1"""
    experiments_RQ1 = {
        'RQ1': {
            'S1': ['QoS', 'AQUA', 'SAQURE_seq', 'SAQURE_para'],
            'S2': ['QoS', 'AQUA', 'SAQURE_seq', 'SAQURE_para'],
            'S3': ['QoS', 'AQUA', 'SAQURE_seq', 'SAQURE_para'],
            'S4': ['QoS', 'AQUA', 'SAQURE_seq', 'SAQURE_para'],
            'S5': ['QoS', 'AQUA', 'SAQURE_seq', 'SAQURE_para'],
        }
    }

    for experiment, sub_scenarios in experiments_RQ1.items():
        print(f"=== {experiment} ===")
        time_stats_all = {}
        cost_values_all = {}

        for sub_scenario, baselines in sub_scenarios.items():
            print(f"=== Sub-scenario: {sub_scenario} ===")
            time_stats_all[sub_scenario] = {}
            cost_values_all[sub_scenario] = {}

            folder_path_SAQURE = f"{RESULTS_BASE}/rq1_logs/{sub_scenario}/SAQURE_para"
            if os.path.exists(folder_path_SAQURE):
                time_SAQURE, cost_SAQURE, option_SAQURE = calculate_statistics_for_folder(folder_path_SAQURE, False)
                print('option_SAQURE:: ' + option_SAQURE)
            else:
                print(f"Folder does not exist: {folder_path_SAQURE}")
                continue

            for baseline_name in baselines:
                print(f"=== Baseline: {baseline_name} ===")
                folder_path = f"{RESULTS_BASE}/rq1_logs/{sub_scenario}/{LOG_DIR_BY_KEY.get(baseline_name, baseline_name)}"

                if os.path.exists(folder_path):
                    if "SAQURE-longcul" in baseline_name:
                        statistics, best_cost, best_option = calculate_statistics_for_folder(folder_path, True)
                    else:
                        statistics, best_cost, best_option = calculate_statistics_for_folder(folder_path, False)
                    if statistics:
                        time_stats_all[sub_scenario][baseline_name] = statistics
                        if best_option == option_SAQURE:
                            cost_values_all[sub_scenario][baseline_name] = cost_SAQURE
                            print(f'cost_SAQURE_{sub_scenario}_{baseline_name}: {cost_SAQURE}\n best_option: {best_option}')
                        else:
                            cost_values_all[sub_scenario][baseline_name] = extract_cost_from_SAQURE(folder_path_SAQURE, best_option)
                            print(f'cost_SAQURE_{sub_scenario}_{baseline_name}: {extract_cost_from_SAQURE(folder_path_SAQURE, best_option)}\n best_option: {best_option}')
                    else:
                        print(f"Warning: {baseline_name} has no valid data")
                else:
                    print(f"Folder does not exist: {folder_path}")

        if time_stats_all and cost_values_all:
            gains = {sub: to_gain('RQ1', sub, costs, current_config_cost(f"{RESULTS_BASE}/rq1_logs/{sub}/SAQURE_para"))
                     for sub, costs in cost_values_all.items()}
            plot_rq1(time_stats_all, gains, experiment, f'{GAIN_PLOTS_DIR}/RQ1_TeaStore_gain.png',
                     gain_axis=GAIN_AXIS_RQ1)
        else:
            print(f"== {experiment} has no valid data, skipping plot ==")


def run_rq2():
    """Load data and plot RQ2 (AQUA vs SAQURE, with T1/T2)"""
    experiments_RQ2 = {
        'S1': {"T1": ['AQUA', 'SAQURE'], "T2": ['AQUA', 'SAQURE']},
        'S2': {"T1": ['AQUA', 'SAQURE'], "T2": ['AQUA', 'SAQURE']},
        'S3': {"T1": ['AQUA', 'SAQURE'], "T2": ['AQUA', 'SAQURE']},
    }

    # [Y_MIN_MARGIN_RATIO, Y_MARGIN_RATIO] of the decision-time axis.
    configs = {
        'S1': [0.0, 1.02],
        'S2': [0.0, 1.02],
        'S3': [0.0, 1.02],
    }

    for item, times in experiments_RQ2.items():
        print(f"=== RQ2 {item} ===")
        time_stats_all = {}
        cost_values_all = {}
        cfg = configs[item]

        folder_path_SAQURE_T1 = f"{RESULTS_BASE}/rq2_logs/{item}/T1/SAQURE"
        if os.path.exists(folder_path_SAQURE_T1):
            time_SAQURE_T1, cost_SAQURE_T1, option_SAQURE_T1 = calculate_statistics_for_folder(folder_path_SAQURE_T1, False)
            print('option_SAQURE_T1: ' + option_SAQURE_T1)
        else:
            print(f"Folder does not exist: {folder_path_SAQURE_T1}")
            continue

        for time_phase, baselines in times.items():
            print(f"=== Sub-scenario: {time_phase} ===")
            time_stats_all[time_phase] = {}
            cost_values_all[time_phase] = {}

            folder_path_SAQURE = f"{RESULTS_BASE}/rq2_logs/{item}/{time_phase}/SAQURE"
            if os.path.exists(folder_path_SAQURE):
                time_SAQURE, cost_SAQURE, option_SAQURE = calculate_statistics_for_folder(folder_path_SAQURE, False)
                print('option_SAQURE:: ' + option_SAQURE)
            else:
                print(f"Folder does not exist: {folder_path_SAQURE}")
                continue

            for baseline_name in baselines:
                print(f"=== Baseline: {baseline_name} ===")
                folder_path = f"{RESULTS_BASE}/rq2_logs/{item}/{time_phase}/{baseline_name}"

                if os.path.exists(folder_path):
                    statistics, best_cost, best_option = calculate_statistics_for_folder(folder_path, False)
                    if statistics:
                        time_stats_all[time_phase][baseline_name] = statistics
                        if baseline_name == "AQUA":
                            # Evaluate AQUA's choice on the SAQURE DTMC of the SAME time phase.
                            # Using the T1 folder for T2 silently reports a T1 cost whenever the
                            # environment change affects the option AQUA picked.
                            aqua_cost = extract_cost_from_SAQURE(folder_path_SAQURE, best_option)
                            cost_values_all[time_phase]['AQUA'] = aqua_cost
                            print(f'when baselinename = AQUA, cost_SAQURE_{time_phase}_AQUA: {aqua_cost}\n best_option: {best_option}')
                        else:
                            if best_option == option_SAQURE:
                                cost_values_all[time_phase][baseline_name] = cost_SAQURE
                                print(f'when option is same, cost_SAQURE_{time_phase}_{baseline_name}: {cost_SAQURE}\n best_option: {best_option}')
                            else:
                                cost_values_all[time_phase][baseline_name] = extract_cost_from_SAQURE(folder_path_SAQURE, best_option)
                                print(f'when option is different, cost_SAQURE_{time_phase}_{baseline_name}: {extract_cost_from_SAQURE(folder_path_SAQURE, best_option)}\n best_option: {best_option}')
                    else:
                        print(f"Warning: {baseline_name} has no valid data")
                else:
                    print(f"Folder does not exist: {folder_path}")

        # AQUA does not update at runtime: at T2 it keeps its T1 choice and (static) risk scores,
        # which its T2 run reproduces. The chosen option is still priced on the SAQURE DTMC of
        # the same phase (above), so a runtime change that degrades that option shows up as a
        # higher T2 cost and a lower T2 Adaptation Gain.
        if time_stats_all and cost_values_all:
            gains = {ph: to_gain('RQ2 ' + item, ph, costs, current_config_cost(f"{RESULTS_BASE}/rq2_logs/{item}/{ph}/SAQURE"))
                     for ph, costs in cost_values_all.items()}
            gcfg = [cfg[0], cfg[1], GAIN_AXIS_RQ23[0], GAIN_AXIS_RQ23[1], GAIN_GRID_RQ23, GAIN_AXIS_RQ23[2]]
            plot_rq2_rq3(time_stats_all, gains, gcfg, f'{GAIN_PLOTS_DIR}/RQ2_TeaStore_{item}_gain.png')
        else:
            print(f"== RQ2 {item} has no valid data, skipping plot ==")


def run_rq3():
    """Load data and plot RQ3 (SAQURE_nodyPa vs SAQURE, with T1/T2)"""
    experiments_RQ3 = {
        'S1': {"T1": ['SAQURE_nodyPa', 'SAQURE'], "T2": ['SAQURE_nodyPa', 'SAQURE']},
        'S2': {"T1": ['SAQURE_nodyPa', 'SAQURE'], "T2": ['SAQURE_nodyPa', 'SAQURE']},
        'S3': {"T1": ['SAQURE_nodyPa', 'SAQURE'], "T2": ['SAQURE_nodyPa', 'SAQURE']},
    }

    # [Y_MIN_MARGIN_RATIO, Y_MARGIN_RATIO] of the decision-time axis.
    configs = {
        'S1': [0.0, 1.02],
        'S2': [0.0, 1.02],
        'S3': [0.0, 1.02],
    }

    for item, times in experiments_RQ3.items():
        print(f"=== RQ3 {item} ===")
        time_stats_all = {}
        cost_values_all = {}
        cfg = configs[item]

        folder_path_SAQURE_T1 = f"{RESULTS_BASE}/rq3_logs/{item}/T1/SAQURE"
        if os.path.exists(folder_path_SAQURE_T1):
            time_SAQURE_T1, cost_SAQURE_T1, option_SAQURE_T1 = calculate_statistics_for_folder(folder_path_SAQURE_T1, False)
            print('option_SAQURE_T1: ' + option_SAQURE_T1)
        else:
            print(f"Folder does not exist: {folder_path_SAQURE_T1}")
            continue

        for time_phase, baselines in times.items():
            print(f"=== Sub-scenario: {time_phase} ===")
            time_stats_all[time_phase] = {}
            cost_values_all[time_phase] = {}

            folder_path_SAQURE = f"{RESULTS_BASE}/rq3_logs/{item}/{time_phase}/SAQURE"
            if os.path.exists(folder_path_SAQURE):
                time_SAQURE, cost_SAQURE, option_SAQURE = calculate_statistics_for_folder(folder_path_SAQURE, False)
                print('option_SAQURE:: ' + option_SAQURE)
            else:
                print(f"Folder does not exist: {folder_path_SAQURE}")
                continue

            for baseline_name in baselines:
                print(f"=== Baseline: {baseline_name} ===")
                folder_path = f"{RESULTS_BASE}/rq3_logs/{item}/{time_phase}/{baseline_name}"

                if os.path.exists(folder_path):
                    statistics, best_cost, best_option = calculate_statistics_for_folder(folder_path, False)
                    if statistics:
                        time_stats_all[time_phase][baseline_name] = statistics
                        if best_option == option_SAQURE:
                            cost_values_all[time_phase][baseline_name] = cost_SAQURE
                            print(f'when option is same, cost_SAQURE_{time_phase}_{baseline_name}: {cost_SAQURE}\n best_option: {best_option}')
                        else:
                            cost_values_all[time_phase][baseline_name] = extract_cost_from_SAQURE(folder_path_SAQURE, best_option)
                            print(f'when option is different, cost_SAQURE_{time_phase}_{baseline_name}: {extract_cost_from_SAQURE(folder_path_SAQURE, best_option)}\n best_option: {best_option}')
                    else:
                        print(f"Warning: {baseline_name} has no valid data")
                else:
                    print(f"Folder does not exist: {folder_path}")

        if time_stats_all and cost_values_all:
            gains = {ph: to_gain('RQ3 ' + item, ph, costs, current_config_cost(f"{RESULTS_BASE}/rq3_logs/{item}/{ph}/SAQURE"))
                     for ph, costs in cost_values_all.items()}
            gcfg = [cfg[0], cfg[1], GAIN_AXIS_RQ23[0], GAIN_AXIS_RQ23[1], GAIN_GRID_RQ23, GAIN_AXIS_RQ23[2]]
            plot_rq2_rq3(time_stats_all, gains, gcfg, f'{GAIN_PLOTS_DIR}/RQ3_TeaStore_{item}_gain.png')
        else:
            print(f"== RQ3 {item} has no valid data, skipping plot ==")

# ═══════════════════════════════════════════════════════════════
# CLI entry point
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate experiment plots for RQ1-RQ3")
    parser.add_argument(
        '--experiment', type=str, nargs='?', default='all',
        choices=['RQ1', 'RQ2', 'RQ3', 'gain', 'all'],
        help="Which experiment to plot (default: all)"
    )
    args = parser.parse_args()

    ensure_plots_dir()

    dispatch = {
        'RQ1': run_rq1,
        'RQ2': run_rq2,
        'RQ3': run_rq3,
        'gain': run_gain,
    }

    if args.experiment == 'all':
        for name, fn in dispatch.items():
            if name in ('RQ1', 'RQ2', 'RQ3'):
                continue  # drawn by 'gain', which also writes adaptation_gain_values.csv
            print(f"\n{'='*60}")
            print(f"  Plotting {name}")
            print(f"{'='*60}")
            fn()
    else:
        dispatch[args.experiment]()
