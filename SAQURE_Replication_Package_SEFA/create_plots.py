# Frozen 2026-09-25. Reads the archived monolithic-AED EADSA logs next to this file.
# The package's own create_plots.py reads the independent-domain re-run instead.
import re
import os
from typing import Dict, List, Optional
import glob
import numpy as np

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import Rectangle, Patch
from matplotlib.ticker import (AutoMinorLocator, MultipleLocator, FormatStrFormatter,
                               ScalarFormatter)
from matplotlib.lines import Line2D

import argparse

RESULTS_BASE = "SAQURE-simulator/results"
# The plot keys are the paper's names for the arms; run_experiments.sh writes some of them
# to a differently named directory. Keys without an entry use their own name as the folder.
LOG_DIR_BY_KEY = {"QoS": "RAMSES"}
# Experiment2 (1-21 vulnerabilities) is not in the paper; RQ4.1.2 and RQ4.2.1 are served by
# Vuln_vs_RuntimeDeTime / Vuln_vs_RiskAssessTime (1-100). run_experiments.sh rq4 still produces
# it, so its two plots read this run's logs rather than the 2025 archive (old build, 500x scale).
EXP2_BASE = f"{RESULTS_BASE}/rq4_logs/Experiment2"
OLD_VS_NEW_CSV = "SAQURE-vulnerability-scalability/results/old_vs_new/old_vs_new_summary.csv"
PLOTS_DIR = "experiments/plots"

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

def extract_risk_assessment_time(log_content: str) -> Optional[float]:
    """Risk assessment cost logged by VulnAxisAPProfiler (Vuln_vs_RiskAssessTime).

    The value is the critical path: the maximum over the M domains of each domain's
    wall clock with its 6 STRIDE calls running in parallel. Since the M x 6 calls are
    independent, that is what the risk assessment costs when they all run at once, and
    it does not depend on how many cores the test machine has.
    """
    m = re.search(r'Risk assessment time cost for \d+ vulnerabilities:\s*([\d.]+)ms', log_content)
    return float(m.group(1)) if m else None


def calculate_risk_assessment_statistics_for_folder(folder_path):
    times = [t for log in read_log_files(folder_path)
             if (t := extract_risk_assessment_time(log['content'])) is not None]
    return calculate_statistics(times) if times else {}


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

def plot_rq1(time_stats_all, cost_values_all, experiment_name, save_path):
    """
    Plot all sub-scenarios of RQ1 in one figure (bar chart + boxplot)
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
    Y_MAX_MARGIN = 5500
    Y_MIN_MARGIN = -8000
    # Long-term cumulative cost: bars span 3.2-6.5, so 9.5 puts the tallest at 68% of the
    # axis while the lowest boxplot point sits at 74%, so the two never overlap. Kept below 10
    # so the forced scientific tick format needs no 1e1 offset.
    RECT_YLIM = 9.5
    RECT_YMIN = 0
    DOT_HLINE_DENSITY = 5

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
    ax1.set_ylabel('Long-term Cost (unitless)', fontsize=FONT_SIZE_TICK)
    ax2.set_ylabel('Runtime Decision Time (ms)', fontsize=FONT_SIZE_TICK)
    ax1.set_ylim(RECT_YMIN, RECT_YLIM)

    ax1.tick_params(axis='x', labelsize=TICK_LABEL_SIZE)
    ax1.tick_params(axis='y', labelsize=TICK_LABEL_SIZE)
    ax2.tick_params(axis='y', labelsize=TICK_LABEL_SIZE)

    ax1.ticklabel_format(style='sci', axis='y', scilimits=(0, 0))
    ax2.ticklabel_format(style='sci', axis='y', scilimits=(0, 0))
    ax2.locator_params(axis='y', nbins=10)
    ax1.yaxis.set_major_locator(MultipleLocator(2))
    ax1.yaxis.set_minor_locator(AutoMinorLocator())

    ax1.set_xlim(-X_BLOCK_WIDTH, current_pos - GROUP_SPACING + X_BLOCK_WIDTH)

    # Grid lines
    for y in np.arange(0, RECT_YLIM, DOT_HLINE_DENSITY):
        ax1.axhline(y=y, color='gray', linestyle='--', linewidth=0.75, alpha=0.0, zorder=0)
    ax1.set_axisbelow(True)

    fig.tight_layout()
    plt.savefig(save_path, dpi=200)
    plt.show()


# ═══════════════════════════════════════════════════════════════
# Plot: RQ2 / RQ3 (dual-axis: cost bar + time boxplot, T1/T2)
# ═══════════════════════════════════════════════════════════════

def plot_rq2_rq3(time_stats_all, cost_values_all, config, save_path):
    """
    Plot RQ2 or RQ3 sub-scenario (dual-axis: cost bar + time boxplot).
    config = [Y_MIN_MARGIN_RATIO, Y_MARGIN_RATIO, RECT_YMIN, RECT_YLIM,
              DOT_HLINE_DENSITY, y_settick]
    """
    FIG_SIZE = (6.7, 6.7)
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
    ax1.set_ylabel('Long-term Cost (unitless)', fontsize=FONT_SIZE_TICK)
    ax2.set_ylabel('Runtime Decision Time (ms)', fontsize=FONT_SIZE_TICK)
    ax1.set_ylim(RECT_YMIN, RECT_YLIM)

    ax1.yaxis.set_major_locator(MultipleLocator(Y_SETTICK))
    ax1.ticklabel_format(style='sci', axis='y', scilimits=(0, 0))
    ax2.ticklabel_format(style='sci', axis='y', scilimits=(0, 0))

    ax1.tick_params(axis='both', which='major', labelsize=TICK_LABEL_SIZE)
    ax2.tick_params(axis='y', which='major', labelsize=TICK_LABEL_SIZE)

    ax1.set_xlim(-X_BLOCK_WIDTH, current_pos - GROUP_SPACING + X_BLOCK_WIDTH)

    # Grid lines
    for y in np.arange(0, RECT_YLIM, DOT_HLINE_DENSITY):
        ax1.axhline(y=y, color='gray', linestyle='--', linewidth=0.75, alpha=0.15, zorder=0)
    ax1.set_axisbelow(True)

    fig.tight_layout()
    plt.savefig(save_path, dpi=200)
    plt.show()


# ═══════════════════════════════════════════════════════════════
# Plot: RQ4_1_1 (time-only boxplot + trend, param 1-15)
# ═══════════════════════════════════════════════════════════════

def plot_rq4_1_1(time_stats_all, experiment_name, save_path):
    """
    Plot RQ4_1_1 (was RQ3.1): time boxplot only, param 1-15
    """
    FIG_SIZE = (6.4, 6)   # 3.2:3 aspect ratio
    BAR_WIDTH = 0.08
    BOX_WIDTH = 0.08
    GROUP_SPACING = 0.15
    X_BLOCK_WIDTH = 0.1
    TREND_LING_LINEWIDTH = 1.0
    IQR_LINEWIDTH = 0.8
    HATCH_LINE_WIDTH = 0.5

    POINTSIZE = 2
    Y_MARGIN_RATIO = 0.05
    DOT_HLINE_DENSITY = 10000

    # Same rendered font sizes as RQ4_1_3, so the two figures match when set side by side.
    FONT_SIZE_TICK = 22.5
    TICK_LABEL_SIZE = 18.75
    FONT_SIZE_LEGEND = 16.875
    FONT_SIZE_LEGEND_TITLE = 18.75

    colors = COLORS

    baseline_colors = {
        'AQUA': colors['cyan-blue'],
        'QoS': colors['purple'],
        'SAQURE_seq': colors['orange'],
        'SAQURE_para': colors['pink_red'],
        'SAQURE': colors['pink_red']
    }
    edge_colors = {
        'AQUA': colors['dark cyan-blue'],
        'QoS': colors['dark purple'],
        'SAQURE_seq': colors['dark orange'],
        'SAQURE_para': colors['red'],
        'SAQURE': colors['red']
    }
    hatch_patterns = {
        'AQUA': '///',
        'QoS': '\\\\\\',
        'SAQURE_seq': '---',
        'SAQURE_para': '',
        'SAQURE': ''
    }
    line_styles = {
        'AQUA': '-',
        'QoS': (0, (10, 5)),
        'SAQURE_seq': '-.',
        'SAQURE_para': '--',
        'SAQURE': '--'
    }
    marker_styles = {
        'AQUA': 'D',
        'QoS': 's',
        'SAQURE_seq': '^',
        'SAQURE_para': 'D',
        'SAQURE': 'o'
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

    fig, ax = plt.subplots(figsize=FIG_SIZE)

    all_time_values = []
    for sub_scenario in sub_scenarios:
        for baseline in baselines:
            if baseline in time_stats_all[sub_scenario]:
                stats = time_stats_all[sub_scenario][baseline]
                all_time_values.extend([stats['min'], stats['max'], stats['q1'], stats['q3'], stats['mean']])

    if all_time_values:
        y_min = min(all_time_values)
        y_max = max(all_time_values)
        margin = (y_max - y_min) * Y_MARGIN_RATIO
        ax.set_ylim(0, y_max + margin)

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
                ax.add_patch(rect)
                ax.vlines(x_pos, stats['min'], stats['q1'], colors=edge_colors[baseline], linewidth=1, zorder=2)
                ax.vlines(x_pos, stats['q3'], stats['max'], colors=edge_colors[baseline], linewidth=1, zorder=2)
                ax.plot(x_pos, stats['mean'], marker=marker_styles[baseline],
                        color=edge_colors[baseline],
                        markersize=POINTSIZE+5 if marker_styles[baseline] else POINTSIZE,
                        zorder=6,
                        markeredgecolor=edge_colors[baseline],
                        markeredgewidth=0)
                ax.hlines(stats['mean'], x_pos - BOX_WIDTH / 2, x_pos + BOX_WIDTH / 2,
                          colors=edge_colors[baseline], linewidth=1.2, zorder=5)

    # Mean trend lines
    mean_trend_lines = []
    for baseline in baselines:
        if baseline_mean_positions[baseline]:
            positions = sorted(baseline_mean_positions[baseline], key=lambda x: x[0])
            x_coords = [pos[0] for pos in positions]
            y_coords = [pos[1] for pos in positions]
            line, = ax.plot(x_coords, y_coords, color=edge_colors[baseline],
                            linestyle=line_styles[baseline], linewidth=TREND_LING_LINEWIDTH,
                            marker=marker_styles[baseline],
                            markersize=0 if marker_styles[baseline] else POINTSIZE,
                            zorder=3,
                            markeredgecolor=edge_colors[baseline],
                            markeredgewidth=0,
                            label=f'{mapping.get(baseline, baseline)}')
            mean_trend_lines.append(line)

    # Axis settings
    ax.set_xticks(x_ticks)
    x_tick_labels = [f'{i}' for i in range(1, len(sub_scenarios)+1)]
    # The square figure leaves the two digit options too close together for
    # horizontal labels.
    ax.set_xticklabels(x_tick_labels, rotation=45, ha='right')
    ax.set_xlabel('Number of Options', fontsize=FONT_SIZE_TICK)
    ax.set_ylabel('Runtime Decision Time (ms)', fontsize=FONT_SIZE_TICK)

    ax.tick_params(axis='x', labelsize=TICK_LABEL_SIZE)
    ax.tick_params(axis='y', labelsize=TICK_LABEL_SIZE)

    ax.ticklabel_format(style='sci', axis='y', scilimits=(0, 0))
    ax.yaxis.get_offset_text().set_fontsize(TICK_LABEL_SIZE)

    ax.set_xlim(-X_BLOCK_WIDTH, current_pos - GROUP_SPACING + X_BLOCK_WIDTH)

    ax.legend(handles=mean_trend_lines, loc='upper left', title='Methods',
              title_fontsize=FONT_SIZE_LEGEND_TITLE, fontsize=FONT_SIZE_LEGEND, frameon=True,
              handlelength=3, markerscale=1.5, labelspacing=0.3, handletextpad=1.5,
              edgecolor='lightgray', framealpha=0.9)

    # Grid lines
    if all_time_values:
        y_max_val = max(all_time_values)
        y_min = min(all_time_values)
        for y in np.arange(0, y_max_val + y_min, DOT_HLINE_DENSITY):
            ax.axhline(y=y, color='gray', linestyle='--', linewidth=0.75, alpha=0.15, zorder=0)
    ax.set_axisbelow(True)

    fig.tight_layout()
    plt.savefig(save_path, dpi=200)
    # A vector copy for the paper, next to the png
    plt.savefig(os.path.splitext(save_path)[0] + '.pdf')
    plt.show()


# ═══════════════════════════════════════════════════════════════
# Plot: RQ4_1_2 (time-only boxplot + trend, param 1-21)
# ═══════════════════════════════════════════════════════════════

def plot_rq4_1_2(time_stats_all, experiment_name, save_path):
    """
    Plot RQ4_1_2 (was RQ3.2): time boxplot only, param 1-21
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
    Y_MARGIN_RATIO = 0.3
    Y_MIN_LIM = 1.8e3  # data 2211-2709 ms, room below for the legend; the old 5.2e4 was the 500x archive scale
    DOT_HLINE_DENSITY = 500

    FONT_SIZE_TICK = 24
    TICK_LABEL_SIZE = 20
    FONT_SIZE_LEGEND = 18
    FONT_SIZE_LEGEND_TITLE = 20

    colors = COLORS

    baseline_colors = {
        'AQUA': colors['cyan-blue'],
        'QoS': colors['purple'],
        'SAQURE_seq': colors['orange'],
        'SAQURE_para': colors['pink_red'],
        'SAQURE': colors['pink_red']
    }
    edge_colors = {
        'AQUA': colors['dark cyan-blue'],
        'QoS': colors['dark purple'],
        'SAQURE_seq': colors['dark orange'],
        'SAQURE_para': colors['red'],
        'SAQURE': colors['red']
    }
    hatch_patterns = {
        'AQUA': '///',
        'QoS': '\\\\\\',
        'SAQURE_seq': '---',
        'SAQURE_para': '',
        'SAQURE': ''
    }
    line_styles = {
        'AQUA': '-',
        'QoS': (0, (10, 5)),
        'SAQURE_seq': '-.',
        'SAQURE_para': '--',
        'SAQURE': '--'
    }
    marker_styles = {
        'AQUA': 'o',
        'QoS': 's',
        'SAQURE_seq': '^',
        'SAQURE_para': 'D',
        'SAQURE': 'D'
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

    fig, ax = plt.subplots(figsize=FIG_SIZE)

    all_time_values = []
    for sub_scenario in sub_scenarios:
        for baseline in baselines:
            if baseline in time_stats_all[sub_scenario]:
                stats = time_stats_all[sub_scenario][baseline]
                all_time_values.extend([stats['min'], stats['max'], stats['q1'], stats['q3'], stats['mean']])

    if all_time_values:
        y_min = min(all_time_values)
        y_max = max(all_time_values)
        margin = (y_max - y_min) * Y_MARGIN_RATIO
        ax.set_ylim(Y_MIN_LIM, y_max + margin)

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
                ax.add_patch(rect)
                ax.vlines(x_pos, stats['min'], stats['q1'], colors=edge_colors[baseline], linewidth=1, zorder=2)
                ax.vlines(x_pos, stats['q3'], stats['max'], colors=edge_colors[baseline], linewidth=1, zorder=2)
                ax.plot(x_pos, stats['mean'], marker=marker_styles[baseline],
                        color=edge_colors[baseline],
                        markersize=POINTSIZE+5 if marker_styles[baseline] else POINTSIZE,
                        zorder=6,
                        markeredgecolor='black' if marker_styles[baseline] else None,
                        markeredgewidth=0.5 if marker_styles[baseline] else 0)
                ax.hlines(stats['mean'], x_pos - BOX_WIDTH / 2, x_pos + BOX_WIDTH / 2,
                          colors=edge_colors[baseline], linewidth=1.2, zorder=5)

    # Mean trend lines
    mean_trend_lines = []
    for baseline in baselines:
        if baseline_mean_positions[baseline]:
            positions = sorted(baseline_mean_positions[baseline], key=lambda x: x[0])
            x_coords = [pos[0] for pos in positions]
            y_coords = [pos[1] for pos in positions]
            line, = ax.plot(x_coords, y_coords, color=edge_colors[baseline],
                            linestyle=line_styles[baseline], linewidth=TREND_LING_LINEWIDTH,
                            marker=marker_styles[baseline],
                            markersize=0 if marker_styles[baseline] else POINTSIZE,
                            zorder=3,
                            markeredgecolor='black' if marker_styles[baseline] else None,
                            markeredgewidth=0.5 if marker_styles[baseline] else 0,
                            label=f'{mapping.get(baseline, baseline)}')
            mean_trend_lines.append(line)

    # Axis settings
    plt.rcParams['text.usetex'] = True
    ax.set_xticks(x_ticks)
    x_tick_labels = [f'{i}' for i in range(1, len(sub_scenarios)+1)]
    ax.set_xticklabels(x_tick_labels)
    ax.set_xlabel('Number of Vulnerabilities', fontsize=FONT_SIZE_TICK)
    ax.set_ylabel('Runtime Decision Time (ms)', fontsize=FONT_SIZE_TICK)

    ax.tick_params(axis='x', labelsize=TICK_LABEL_SIZE)
    ax.tick_params(axis='y', labelsize=TICK_LABEL_SIZE)

    ax.ticklabel_format(style='sci', axis='y', scilimits=(0, 0))
    ax.yaxis.get_offset_text().set_fontsize(TICK_LABEL_SIZE)

    ax.set_xlim(-X_BLOCK_WIDTH, current_pos - GROUP_SPACING + X_BLOCK_WIDTH)

    ax.legend(handles=mean_trend_lines, loc='lower right', title='Methods',
              title_fontsize=FONT_SIZE_LEGEND_TITLE, fontsize=FONT_SIZE_LEGEND, frameon=True,
              handlelength=3, markerscale=1.5, labelspacing=0.3, handletextpad=1.5,
              edgecolor='lightgray', framealpha=0.9)

    # Grid lines
    if all_time_values:
        for y in np.arange(Y_MIN_LIM, Y_MIN_LIM + 50000, DOT_HLINE_DENSITY):
            ax.axhline(y=y, color='gray', linestyle='--', linewidth=0.75, alpha=0.15, zorder=0)
    ax.set_axisbelow(True)

    fig.tight_layout()
    plt.savefig(save_path, dpi=200)
    plt.show()


# ═══════════════════════════════════════════════════════════════
# Plot: RQ4 EADSA boxplot (data from RQ4_1_2 logs)
# ═══════════════════════════════════════════════════════════════

def plot_eadsa_boxplot(eadsa_stats_all, experiment_name, save_path):
    """
    Plot boxplot + mean line for SAQURE baseline EADSA implementation time
    """
    FIG_SIZE = (12, 4.5)
    BOX_WIDTH = 4
    TREND_LING_LINEWIDTH = 1.0
    IQR_LINEWIDTH = 0.8
    GROUP_SPACING = 10.0
    LEFT_MARGIN = 6.0
    RIGHT_MARGIN = LEFT_MARGIN

    POINTSIZE = 2
    Y_MARGIN_RATIO = 0.505
    Y_MIN_LIM = 100
    DOT_HLINE_DENSITY = 20

    FONT_SIZE_TICK = 24
    TICK_LABEL_SIZE = 20
    FONT_SIZE_LEGEND = 18
    FONT_SIZE_LEGEND_TITLE = 20

    colors = COLORS
    eadsa_colors = {
        'facecolor': colors['pink'],
        'edgecolor': colors['pink_red'],
        'linecolor': colors['red']
    }

    # Data preparation
    sub_scenarios = list(eadsa_stats_all.keys())

    x_positions = []
    current_pos = LEFT_MARGIN
    for i, sub_scenario in enumerate(sub_scenarios):
        x_positions.append(current_pos)
        current_pos += 1 + GROUP_SPACING

    fig, ax = plt.subplots(figsize=FIG_SIZE)

    all_time_values = []
    for sub_scenario in sub_scenarios:
        stats = eadsa_stats_all[sub_scenario]
        all_time_values.extend([stats['min'], stats['max'], stats['q1'], stats['q3'], stats['mean']])

    if all_time_values:
        y_min = min(all_time_values)
        y_max = max(all_time_values)
        margin = (y_max - y_min) * Y_MARGIN_RATIO
        ax.set_ylim(Y_MIN_LIM, y_max + margin)

    mean_positions = []
    for i, sub_scenario in enumerate(sub_scenarios):
        stats = eadsa_stats_all[sub_scenario]
        x_pos = x_positions[i]
        mean_positions.append((x_pos, stats['mean']))

        rect = Rectangle(
            (x_pos - BOX_WIDTH / 2, stats['q1']),
            BOX_WIDTH, stats['q3'] - stats['q1'],
            facecolor=eadsa_colors['facecolor'], edgecolor=eadsa_colors['edgecolor'],
            linewidth=IQR_LINEWIDTH, zorder=4
        )
        ax.add_patch(rect)
        ax.vlines(x_pos, stats['min'], stats['q1'], colors=eadsa_colors['edgecolor'], linewidth=1, zorder=2)
        ax.vlines(x_pos, stats['q3'], stats['max'], colors=eadsa_colors['edgecolor'], linewidth=1, zorder=2)
        ax.plot(x_pos, stats['mean'], 'o', color=eadsa_colors['linecolor'], markersize=POINTSIZE+5, zorder=6)
        ax.hlines(stats['mean'], x_pos - BOX_WIDTH / 2, x_pos + BOX_WIDTH / 2,
                  colors=eadsa_colors['linecolor'], linewidth=1.2, zorder=5)

    if mean_positions:
        positions = sorted(mean_positions, key=lambda x: x[0])
        x_coords = [pos[0] for pos in positions]
        y_coords = [pos[1] for pos in positions]
        line, = ax.plot(x_coords, y_coords, color=eadsa_colors['linecolor'],
                        linestyle='-', linewidth=TREND_LING_LINEWIDTH, marker='o',
                        markersize=0, zorder=3, label='Mean Runtime Risk\nAssessment Time')

    # Axis settings
    plt.rcParams['text.usetex'] = True
    ax.set_xticks(x_positions)
    x_tick_labels = [f'{i}' for i in range(1, len(sub_scenarios)+1)]
    ax.set_xticklabels(x_tick_labels)
    ax.set_xlabel('Number of Vulnerabilities', fontsize=FONT_SIZE_TICK)
    ax.set_ylabel('Runtime Risk Assess-\nment Time (ms)', fontsize=FONT_SIZE_TICK)

    ax.tick_params(axis='x', labelsize=TICK_LABEL_SIZE)
    ax.tick_params(axis='y', labelsize=TICK_LABEL_SIZE)

    if max(all_time_values) > 10000:
        ax.ticklabel_format(style='sci', axis='y', scilimits=(0, 0))
        ax.yaxis.get_offset_text().set_fontsize(TICK_LABEL_SIZE)

    if x_positions:
        x_min = x_positions[0] - LEFT_MARGIN
        x_max = x_positions[-1] + RIGHT_MARGIN
        ax.set_xlim(x_min, x_max)

    ax.legend(loc='upper right',
              title_fontsize=FONT_SIZE_LEGEND_TITLE, fontsize=FONT_SIZE_LEGEND, frameon=True,
              handlelength=4, markerscale=3, labelspacing=0.4, handletextpad=1.0)

    # Grid lines
    if all_time_values:
        y_max_val = max(all_time_values)
        y_range = y_max_val - Y_MIN_LIM
        if y_range > 0:
            for y in np.arange(Y_MIN_LIM, y_max_val + margin, DOT_HLINE_DENSITY):
                ax.axhline(y=y, color='gray', linestyle='--', linewidth=0.75, alpha=0.15, zorder=0)
    ax.set_axisbelow(True)

    fig.tight_layout()
    plt.savefig(save_path, dpi=200)
    plt.show()


# ═══════════════════════════════════════════════════════════════
# Data loading + main
# ═══════════════════════════════════════════════════════════════

def ensure_plots_dir():
    os.makedirs(PLOTS_DIR, exist_ok=True)


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
            plot_rq1(time_stats_all, cost_values_all, experiment, f'{PLOTS_DIR}/RQ1_SEFA.png')
        else:
            print(f"== {experiment} has no valid data, skipping plot ==")


def run_rq2():
    """Load data and plot RQ2 (AQUA vs SAQURE, with T1/T2)"""
    experiments_RQ2 = {
        'S1': {"T1": ['AQUA', 'SAQURE'], "T2": ['AQUA', 'SAQURE']},
        'S2': {"T1": ['AQUA', 'SAQURE'], "T2": ['AQUA', 'SAQURE']},
        'S3': {"T1": ['AQUA', 'SAQURE'], "T2": ['AQUA', 'SAQURE']},
    }

    # [Y_MIN_MARGIN_RATIO, Y_MARGIN_RATIO, RECT_YMIN, RECT_YLIM, DOT_HLINE_DENSITY, Y_SETTICK]
    # Long-term cumulative cost; one scale for all three sub-scenarios so they compare directly.
    # Bars peak at 4.40, i.e. 68% of the axis, under the boxplots.
    configs = {
        'S1': [0.0, 1.02, 0, 6.5, 0.5, 1],
        'S2': [0.0, 1.02, 0, 6.5, 0.5, 1],
        'S3': [0.0, 1.02, 0, 6.5, 0.5, 1],
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

        if time_stats_all and cost_values_all:
            plot_rq2_rq3(time_stats_all, cost_values_all, cfg, f'{PLOTS_DIR}/RQ2_SEFA_{item}.png')
        else:
            print(f"== RQ2 {item} has no valid data, skipping plot ==")


def run_rq3():
    """Load data and plot RQ3 (SAQURE_nodyPa vs SAQURE, with T1/T2)"""
    experiments_RQ3 = {
        'S1': {"T1": ['SAQURE_nodyPa', 'SAQURE'], "T2": ['SAQURE_nodyPa', 'SAQURE']},
        'S2': {"T1": ['SAQURE_nodyPa', 'SAQURE'], "T2": ['SAQURE_nodyPa', 'SAQURE']},
        'S3': {"T1": ['SAQURE_nodyPa', 'SAQURE'], "T2": ['SAQURE_nodyPa', 'SAQURE']},
    }

    # Long-term cumulative cost; one scale for all three sub-scenarios so they compare directly.
    # Bars peak at 4.40, i.e. 68% of the axis, under the boxplots.
    configs = {
        'S1': [0.0, 1.02, 0, 6.5, 0.5, 1],
        'S2': [0.0, 1.02, 0, 6.5, 0.5, 1],
        'S3': [0.0, 1.02, 0, 6.5, 0.5, 1],
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
                            # Convention: every arm's choice is priced on SAQURE's DTMC, so arms
                            # that pick the same option necessarily get identical bars. For RQ3
                            # that hides the ablation's own cost -- see its logged Best cost value.
                            cost_values_all[time_phase][baseline_name] = cost_SAQURE
                            print(f'when option is same (bar = SAQURE-model price, not {baseline_name}\'s own), '
                                  f'cost_SAQURE_{time_phase}_{baseline_name}: {cost_SAQURE}\n best_option: {best_option}')
                        else:
                            cost_values_all[time_phase][baseline_name] = extract_cost_from_SAQURE(folder_path_SAQURE, best_option)
                            print(f'when option is different, cost_SAQURE_{time_phase}_{baseline_name}: {extract_cost_from_SAQURE(folder_path_SAQURE, best_option)}\n best_option: {best_option}')
                    else:
                        print(f"Warning: {baseline_name} has no valid data")
                else:
                    print(f"Folder does not exist: {folder_path}")

        if time_stats_all and cost_values_all:
            plot_rq2_rq3(time_stats_all, cost_values_all, cfg, f'{PLOTS_DIR}/RQ3_SEFA_{item}.png')
        else:
            print(f"== RQ3 {item} has no valid data, skipping plot ==")


def run_rq4_1_1():
    """Load data and plot RQ4_1_1 (param 1-15)"""
    sub_scenarios_def = {f'S{i}': ['AQUA', 'SAQURE'] for i in range(1, 16)}

    print("=== RQ4_1_1 (Option_vs_RuntimeDeTime) ===")
    time_stats_all = {}

    for sub_scenario, baselines in sub_scenarios_def.items():
        print(f"=== Sub-scenario: {sub_scenario} ===")
        time_stats_all[sub_scenario] = {}

        for baseline_name in baselines:
            print(f"=== Baseline: {baseline_name} ===")
            folder_path = f"{RESULTS_BASE}/rq4_logs/Option_vs_RuntimeDeTime/{sub_scenario}/{baseline_name}"

            if os.path.exists(folder_path):
                if "SAQURE-longcul" in baseline_name:
                    statistics, best_cost, best_option = calculate_statistics_for_folder(folder_path, True)
                else:
                    statistics, best_cost, best_option = calculate_statistics_for_folder(folder_path, False)
                if statistics:
                    time_stats_all[sub_scenario][baseline_name] = statistics
                else:
                    print(f"Warning: {baseline_name} has no valid data")
            else:
                print(f"Folder does not exist: {folder_path}")

    if time_stats_all:
        plot_rq4_1_1(time_stats_all, "Option_vs_RuntimeDeTime", f'{PLOTS_DIR}/RQ4_1_1_SEFA.png')
    else:
        print("== RQ4_1_1 has no valid data, skipping plot ==")


def run_rq4_1_2():
    """Load data and plot RQ4_1_2 (param 1-21)"""
    sub_scenarios_def = {f'S{i}': ['AQUA', 'SAQURE'] for i in range(1, 22)}

    print("=== RQ4_1_2 (Experiment2) ===")
    time_stats_all = {}

    for sub_scenario, baselines in sub_scenarios_def.items():
        print(f"=== Sub-scenario: {sub_scenario} ===")
        time_stats_all[sub_scenario] = {}

        for baseline_name in baselines:
            print(f"=== Baseline: {baseline_name} ===")
            folder_path = f"{EXP2_BASE}/{sub_scenario}/{baseline_name}"

            if os.path.exists(folder_path):
                if "SAQURE-longcul" in baseline_name:
                    statistics, best_cost, best_option = calculate_statistics_for_folder(folder_path, True)
                else:
                    statistics, best_cost, best_option = calculate_statistics_for_folder(folder_path, False)
                if statistics:
                    time_stats_all[sub_scenario][baseline_name] = statistics
                else:
                    print(f"Warning: {baseline_name} has no valid data")
            else:
                print(f"Folder does not exist: {folder_path}")

    if time_stats_all:
        plot_rq4_1_2(time_stats_all, "Experiment2", f'{PLOTS_DIR}/RQ4_superseded_Experiment2_SEFA.png')
    else:
        print("== RQ4_1_2 has no valid data, skipping plot ==")


def run_rq4_eadsa():
    """Load EADSA data from RQ4_1_2 logs and plot"""
    sub_scenarios_def = {f'S{i}': ['SAQURE'] for i in range(1, 22)}

    print("\n====== RQ4 EADSA boxplot (data from RQ4_1_2) ======")
    eadsa_stats_all = {}

    for sub_scenario, baselines in sub_scenarios_def.items():
        print(f"--- Sub-scenario: {sub_scenario}")
        eadsa_stats_all[sub_scenario] = {}

        if "SAQURE" in baselines:
            folder_path = f"{EXP2_BASE}/{sub_scenario}/SAQURE"

            if not os.path.exists(folder_path):
                print(f"Folder not found: {folder_path}")
                continue

            eadsa_stats = calculate_eadsa_statistics_for_folder(folder_path)
            if eadsa_stats:
                eadsa_stats_all[sub_scenario] = eadsa_stats
            else:
                print(f"No valid EADSA time detected in {folder_path}")

    if eadsa_stats_all:
        plot_eadsa_boxplot(eadsa_stats_all, "Experiment2", f'{PLOTS_DIR}/RQ4_eadsa_boxplot_SEFA.png')
    else:
        print("No EADSA data found, skip plotting.")


# ═══════════════════════════════════════════════════════════════
# RQ4 size axis: offline configuration, risk assessment and decision
# time against the size of the managed system (1x - 500x SEFA)
# ═══════════════════════════════════════════════════════════════

SIZE_AXIS_PATTERNS = {
    # Runtime decision time is the risk assessment plus the Planner; the old
    # 'Time to extract best option RamsesV3' line covered the Planner only.
    'decision': r'Runtime decision time:\s*([\d.]+)ms',
    # Size_vs_RuntimeDeTime used to report EADSA on the monolithic AED; since 2026-09-25
    # it reports the independent-domain critical path, the same quantity RQ4.2 uses.
    'risk_per_replica': r'Risk assessment time cost for replica_\d+(?:, \d+ vulnerabilities)?:\s*([\d.]+)ms',
    'risk_total': r'Total risk assessment time for \d+ replicas:\s*([\d.]+)ms',
    'offline_config': r'Offline configuration time for \d+ vulnerabilities:\s*([\d.]+)ms',
}

# Series that occur once per replica / per implementation inside a single log and are averaged.
SIZE_AXIS_REPEATED = ('risk_per_replica', 'offline_config')


def extract_size_axis_times(log_content: str) -> Dict[str, float]:
    """Extract one value per series from a single size-axis log."""
    values = {}
    for key, pattern in SIZE_AXIS_PATTERNS.items():
        found = [float(v) for v in re.findall(pattern, log_content)]
        if not found:
            continue
        values[key] = float(np.mean(found)) if key in SIZE_AXIS_REPEATED else found[0]
    return values


def calculate_size_axis_statistics_for_folder(folder_path):
    """Statistics per series over all logs of one managed system size"""
    series = {key: [] for key in SIZE_AXIS_PATTERNS}
    for log in read_log_files(folder_path):
        for key, value in extract_size_axis_times(log['content']).items():
            series[key].append(value)
    return {key: calculate_statistics(values) for key, values in series.items() if values}


def _size_axis_box(ax, x_pos, stats, box_factor, style, point_size, iqr_linewidth):
    """One IQR box with min/max whiskers and a mean marker, as used by the other RQ4 plots.
    The size axis is logarithmic, so the box width is multiplicative."""
    left, right = x_pos / box_factor, x_pos * box_factor
    rect = Rectangle((left, stats['q1']), right - left, stats['q3'] - stats['q1'],
                     facecolor=style['facecolor'], edgecolor=style['edgecolor'],
                     linewidth=iqr_linewidth, zorder=4)
    ax.add_patch(rect)
    ax.vlines(x_pos, stats['min'], stats['q1'], colors=style['edgecolor'], linewidth=1, zorder=2)
    ax.vlines(x_pos, stats['q3'], stats['max'], colors=style['edgecolor'], linewidth=1, zorder=2)
    ax.plot(x_pos, stats['mean'], marker=style.get('marker', 'o'), color=style['linecolor'],
            markersize=point_size + 5, markeredgewidth=0, zorder=6)
    ax.hlines(stats['mean'], left, right, colors=style['linecolor'], linewidth=1.2, zorder=5)


class FixedOrderFormatter(ScalarFormatter):
    """Force the scientific offset to a chosen power of ten.

    Matplotlib picks the offset from the data range, so 200-350 would be labelled
    2.0-3.5 with a 1e2 offset; pinning the order to 3 gives 0.20-0.35 with 1e3.
    """

    def __init__(self, order):
        super().__init__(useOffset=False, useMathText=False)
        self._fixed_order = order

    def _set_order_of_magnitude(self):
        self.orderOfMagnitude = self._fixed_order


def plot_size_axis(stats_all, primary, ylabel, save_path,
                   primary_label, secondary=None, secondary_ylabel=None, secondary_label=None,
                   legend_loc='upper left', legend_bbox=None, primary_ymin=None,
                   figsize=(12, 4.5), ylim=None, ymajor=None, yminor=None, yorder=None,
                   ylabel_fontsize=None):
    """
    Boxplot + mean trend line against the managed system size. With `secondary` a second series
    is drawn on a twin axis, which is how the two readings of the risk assessment time
    (per microservice, and summed over the whole managed system) are shown together.
    """
    FIG_SIZE = figsize
    BOX_FACTOR = 1.10         # multiplicative half width of a box on the logarithmic size axis
    TREND_LING_LINEWIDTH = 1.0
    IQR_LINEWIDTH = 0.8
    MARGIN_RATIO = 0.04
    POINTSIZE = 2
    Y_MARGIN_RATIO = 0.15
    # Same sizes as RQ4_1_1 and the vulnerability-axis figures.
    FONT_SIZE_TICK = 27.5
    TICK_LABEL_SIZE = 23.75
    FONT_SIZE_LEGEND = 21.875
    FONT_SIZE_LEGEND_TITLE = 23.75

    colors = COLORS
    primary_style = {'facecolor': colors['pink'], 'edgecolor': colors['pink_red'],
                     'linecolor': colors['red'], 'linestyle': '--'}
    secondary_style = {'facecolor': colors['cyan-blue'], 'edgecolor': colors['dark cyan-blue'],
                       'linecolor': colors['dark purple']}

    # The managed system size is plotted on its true numeric scale, so a series that grows
    # linearly in the number of replicas shows up as a straight line.
    scales = sorted(stats_all.keys())
    x_positions = list(scales)

    fig, ax = plt.subplots(figsize=FIG_SIZE)
    handles = []

    def draw(axis, key, style, label, offset, ymin=None):
        values, means = [], []
        for i, scale in enumerate(scales):
            stats = stats_all[scale].get(key)
            if not stats:
                continue
            _size_axis_box(axis, x_positions[i] * offset, stats, BOX_FACTOR, style,
                           POINTSIZE, IQR_LINEWIDTH)
            values.extend([stats['min'], stats['max'], stats['mean']])
            means.append((x_positions[i] * offset, stats['mean']))
        if means:
            line, = axis.plot([m[0] for m in means], [m[1] for m in means],
                              color=style['linecolor'], linestyle=style.get('linestyle', '-'),
                              linewidth=TREND_LING_LINEWIDTH, marker='o', markersize=0,
                              zorder=3, label=label)
            handles.append(line)
        if values:
            axis.set_ylim(0.0 if ymin is None else ymin, max(values) * (1 + Y_MARGIN_RATIO))
        return values

    # Two series are pulled slightly apart so their boxes stay readable side by side.
    offset = 1.0 if secondary is None else 1 / BOX_FACTOR
    draw(ax, primary, primary_style, primary_label, offset, primary_ymin)
    # A long label does not fit the axis height at the shared tick size.
    ax.set_ylabel(ylabel, fontsize=ylabel_fontsize or FONT_SIZE_TICK)
    ax.tick_params(axis='y', labelsize=TICK_LABEL_SIZE, colors='black')

    if secondary is not None:
        ax2 = ax.twinx()
        draw(ax2, secondary, secondary_style, secondary_label, 1 / offset)
        ax2.set_ylabel(secondary_ylabel, fontsize=FONT_SIZE_TICK)
        ax2.tick_params(axis='y', labelsize=TICK_LABEL_SIZE, colors='black')

    # The size axis spans 1x - 500x, so it is drawn logarithmically: every scale keeps its own
    # label and the tick spacing reflects the actual magnitudes.
    ax.set_xscale('log')
    ax.set_xticks(x_positions)
    # Labelled as multiples, like RQ4_1_3: the axis is the size in SEFA replicas.
    ax.set_xticklabels([f'{v}x' for v in scales])
    ax.xaxis.set_minor_formatter(plt.NullFormatter())
    ax.set_xlabel('Managed System Size', fontsize=FONT_SIZE_TICK)
    ax.tick_params(axis='x', labelsize=TICK_LABEL_SIZE)
    ax.set_xlim(x_positions[0] / (1 + MARGIN_RATIO * 10), x_positions[-1] * (1 + MARGIN_RATIO * 10))

    # An explicit range and tick spacing override what draw() autoscaled to.
    if ylim is not None:
        ax.set_ylim(*ylim)
    if ymajor is not None:
        ax.yaxis.set_major_locator(MultipleLocator(ymajor))
    if yminor is not None:
        ax.yaxis.set_minor_locator(MultipleLocator(yminor))

    if yorder is not None:
        ax.yaxis.set_major_formatter(FixedOrderFormatter(yorder))
        ax.yaxis.get_offset_text().set_fontsize(TICK_LABEL_SIZE)
    elif max(ax.get_ylim()) > 10000:
        ax.ticklabel_format(style='sci', axis='y', scilimits=(0, 0))
        ax.yaxis.get_offset_text().set_fontsize(TICK_LABEL_SIZE)

    ax.legend(handles=handles, loc=legend_loc, bbox_to_anchor=legend_bbox,
              title_fontsize=FONT_SIZE_LEGEND_TITLE, fontsize=FONT_SIZE_LEGEND, frameon=True,
              handlelength=3, labelspacing=0.3, handletextpad=1.0)
    ax.grid(axis='y', which='major', color='gray', linestyle='--', linewidth=0.75,
            alpha=0.15, zorder=0)
    # The minor grid is only drawn where a minor locator was asked for.
    ax.grid(axis='y', which='minor', color='gray', linestyle='--', linewidth=0.5,
            alpha=0.10, zorder=0)
    ax.set_axisbelow(True)

    fig.tight_layout()
    plt.savefig(save_path, dpi=200)
    plt.close(fig)


# Box/line styling of the two approaches, following the palette the other RQ4 plots use.
SIZE_AXIS_APPROACH_STYLE = {
    'SAQURE': {'facecolor': COLORS['pink'], 'edgecolor': COLORS['pink_red'],
               'linecolor': COLORS['red'], 'linestyle': '--', 'marker': 'o'},
    'AQUA':   {'facecolor': COLORS['cyan-blue'], 'edgecolor': COLORS['dark cyan-blue'],
               'linecolor': COLORS['dark cyan-blue'], 'linestyle': '-', 'marker': 'D'},
}


def plot_size_axis_comparison(stats_by_approach, key, ylabel, save_path,
                              legend_loc='upper left', legend_bbox=None, figsize=(12, 4.5),
                              xtick_rotation=0):
    """
    SAQURE against AQUA on the managed system size axis: one IQR box plus a mean trend line per
    approach, both on the same y axis so the two costs are directly comparable.
    """
    FIG_SIZE = figsize
    BOX_FACTOR = 1.10         # multiplicative half width of a box on the logarithmic size axis
    TREND_LING_LINEWIDTH = 1.0
    IQR_LINEWIDTH = 0.8
    MARGIN_RATIO = 0.04
    POINTSIZE = 2
    Y_MARGIN_RATIO = 0.15
    # Kept byte for byte in step with RQ4_1_1 so the two figures share one style.
    FONT_SIZE_TICK = 22.5
    TICK_LABEL_SIZE = 18.75
    FONT_SIZE_LEGEND = 16.875
    FONT_SIZE_LEGEND_TITLE = 18.75

    approaches = [a for a in ('SAQURE', 'AQUA') if a in stats_by_approach]
    scales = sorted(set().union(*[set(stats_by_approach[a]) for a in approaches]))

    fig, ax = plt.subplots(figsize=FIG_SIZE)
    handles, all_values = [], []
    # Pull the two approaches slightly apart so their boxes stay readable side by side.
    offsets = {'SAQURE': 1 / BOX_FACTOR, 'AQUA': BOX_FACTOR}

    for approach in approaches:
        style = SIZE_AXIS_APPROACH_STYLE[approach]
        means = []
        for scale in scales:
            stats = stats_by_approach[approach].get(scale, {}).get(key)
            if not stats:
                continue
            # Boxes are nudged apart so they stay readable, but the trend lines keep the true
            # size on the x axis so the two approaches can be compared point by point.
            _size_axis_box(ax, scale * offsets[approach], stats, BOX_FACTOR, style,
                           POINTSIZE, IQR_LINEWIDTH)
            all_values.extend([stats['min'], stats['max'], stats['mean']])
            means.append((scale, stats['mean']))
        if means:
            line, = ax.plot([m[0] for m in means], [m[1] for m in means],
                            color=style['linecolor'], linestyle=style['linestyle'],
                            linewidth=TREND_LING_LINEWIDTH, marker='o', markersize=0,
                            zorder=3, label=approach)
            handles.append(line)

    # Boxes are drawn SAQURE first so AQUA stays on top; the legend lists AQUA above SAQURE.
    legend_order = {'AQUA': 0, 'SAQURE': 1}
    handles.sort(key=lambda h: legend_order.get(h.get_label(), 99))

    if all_values:
        ax.set_ylim(0.0, max(all_values) * (1 + Y_MARGIN_RATIO))
    ax.set_ylabel(ylabel, fontsize=FONT_SIZE_TICK)
    ax.tick_params(axis='y', labelsize=TICK_LABEL_SIZE, colors='black')

    # The size axis spans 1x - 500x, so it is drawn logarithmically: every scale keeps its own
    # label and the tick spacing reflects the actual magnitudes.
    ax.set_xscale('log')
    ax.set_xticks(scales)
    # A narrow figure leaves the largest sizes too close together for horizontal labels.
    # Labelled as multiples: the axis is the managed system size in SEFA replicas.
    ax.set_xticklabels([f'{v}x' for v in scales], rotation=xtick_rotation,
                       ha='right' if xtick_rotation else 'center')
    ax.xaxis.set_minor_formatter(plt.NullFormatter())
    ax.set_xlabel('Managed System Size', fontsize=FONT_SIZE_TICK)
    ax.tick_params(axis='x', labelsize=TICK_LABEL_SIZE)
    ax.set_xlim(scales[0] / (1 + MARGIN_RATIO * 10), scales[-1] * (1 + MARGIN_RATIO * 10))

    if max(ax.get_ylim()) > 10000:
        ax.ticklabel_format(style='sci', axis='y', scilimits=(0, 0))
        ax.yaxis.get_offset_text().set_fontsize(TICK_LABEL_SIZE)

    ax.legend(handles=handles, loc=legend_loc, bbox_to_anchor=legend_bbox, title='Methods',
              title_fontsize=FONT_SIZE_LEGEND_TITLE, fontsize=FONT_SIZE_LEGEND, frameon=True,
              handlelength=3, markerscale=1.5, labelspacing=0.3, handletextpad=1.5,
              edgecolor='lightgray', framealpha=0.9)
    # RQ4_1_1 rules a horizontal line every 0.1 of the scientific unit its y axis is labelled
    # in (10000 on a 1e5 axis); deriving the step the same way keeps both grids equally dense.
    y_top = max(ax.get_ylim())
    DOT_HLINE_DENSITY = 10 ** np.floor(np.log10(y_top)) / 10
    for y in np.arange(0, y_top, DOT_HLINE_DENSITY):
        ax.axhline(y=y, color='gray', linestyle='--', linewidth=0.75, alpha=0.15, zorder=0)
    ax.set_axisbelow(True)

    fig.tight_layout()
    plt.savefig(save_path, dpi=200)
    plt.close(fig)



def _save_vector_and_raster(save_path):
    """Write both a .pdf for the paper and a 200 dpi .png for quick viewing."""
    stem = os.path.splitext(save_path)[0]
    plt.savefig(stem + '.pdf')
    plt.savefig(stem + '.png', dpi=200)


def _linear_axis_box(ax, x_pos, stats, half_width, style, point_size, iqr_linewidth):
    """Same box as _size_axis_box, but on a linear x axis the width is absolute so
    every box is drawn equally wide instead of growing with x."""
    left, right = x_pos - half_width, x_pos + half_width
    rect = Rectangle((left, stats['q1']), right - left, stats['q3'] - stats['q1'],
                     facecolor=style['facecolor'], edgecolor=style['edgecolor'],
                     linewidth=iqr_linewidth, zorder=4)
    ax.add_patch(rect)
    ax.vlines(x_pos, stats['min'], stats['q1'], colors=style['edgecolor'], linewidth=1, zorder=2)
    ax.vlines(x_pos, stats['q3'], stats['max'], colors=style['edgecolor'], linewidth=1, zorder=2)
    ax.plot(x_pos, stats['mean'], marker=style.get('marker', 'o'), color=style['linecolor'],
            markersize=point_size + 5, markeredgewidth=0, zorder=6)
    ax.hlines(stats['mean'], left, right, colors=style['linecolor'], linewidth=1.2, zorder=5)


# ═══════════════════════════════════════════════════════════════
# Plot: monolithic AED vs 136 independent domains (1-21 CVEs)
# ═══════════════════════════════════════════════════════════════

OLD_VS_NEW_STYLE = {
    'old': {'facecolor': COLORS['cyan-blue'], 'edgecolor': COLORS['dark cyan-blue'],
            'linecolor': COLORS['dark cyan-blue'], 'linestyle': '-', 'marker': 'D',
            'label': 'Monolithic AED'},
    'new': {'facecolor': COLORS['pink'], 'edgecolor': COLORS['pink_red'],
            'linecolor': COLORS['red'], 'linestyle': '--', 'marker': 'o',
            'label': 'Independent domains'},
}


def load_old_vs_new_stats(column, csv_path=OLD_VS_NEW_CSV):
    import csv as _csv
    samples = {}
    with open(csv_path, newline='') as fh:
        for row in _csv.DictReader(fh):
            samples.setdefault(row['workflow'], {}).setdefault(
                int(row['n_vulns']), []).append(float(row[column]))
    return {
        wf: {n: {'min': float(np.min(v)), 'max': float(np.max(v)),
                 'q1': float(np.percentile(v, 25)), 'q3': float(np.percentile(v, 75)),
                 'mean': float(np.mean(v))}
             for n, v in by_n.items()}
        for wf, by_n in samples.items()
    }


def plot_old_vs_new(stats_by_wf, save_path, ylabel, figsize=(10, 6), logy=False,
                    style_map=None, order=('old', 'new'), legend_title='Workflow',
                    legend_loc='upper left', xtick_rotation=0, ylim=None,
                    grid_step_units=0.1, ylabel_fontsize=None, font_delta=0.0):
    """Two series against a linear vulnerability-count axis."""
    style_map = OLD_VS_NEW_STYLE if style_map is None else style_map
    FIG_SIZE = figsize
    TREND_LING_LINEWIDTH = 1.0
    IQR_LINEWIDTH = 0.8
    MARGIN_RATIO = 0.04
    POINTSIZE = 2
    Y_MARGIN_RATIO = 0.15
    FONT_SIZE_TICK = 22.5 + font_delta
    TICK_LABEL_SIZE = 18.75 + font_delta
    FONT_SIZE_LEGEND = 16.875 + font_delta
    FONT_SIZE_LEGEND_TITLE = 18.75 + font_delta

    workflows = [w for w in order if w in stats_by_wf]
    scales = sorted(set().union(*[set(stats_by_wf[w]) for w in workflows]))

    fig, ax = plt.subplots(figsize=FIG_SIZE)
    handles, all_values = [], []
    half_width = max(scales) * 0.012
    # Boxes are nudged apart in the order the series are drawn.
    offsets = ({w: 0.0 for w in workflows} if len(workflows) == 1
               else {w: (-half_width if i == 0 else half_width) for i, w in enumerate(workflows)})

    for wf in workflows:
        style = style_map[wf]
        means = []
        for n in scales:
            stats = stats_by_wf[wf].get(n)
            if not stats:
                continue
            _linear_axis_box(ax, n + offsets[wf], stats, half_width, style,
                             POINTSIZE, IQR_LINEWIDTH)
            all_values.extend([stats['min'], stats['max'], stats['mean']])
            means.append((n, stats['mean']))
        if means:
            line, = ax.plot([m[0] for m in means], [m[1] for m in means],
                            color=style['linecolor'], linestyle=style['linestyle'],
                            linewidth=TREND_LING_LINEWIDTH, marker='o', markersize=0,
                            zorder=3, label=style['label'])
            handles.append(line)

    if logy:
        # The two workflows differ by orders of magnitude on the grounding figures.
        ax.set_yscale('log')
    elif ylim is not None:
        # An explicit window: two nearly coincident curves are indistinguishable on a
        # zero-based axis that spans ten times their separation.
        ax.set_ylim(*ylim)
    elif all_values:
        ax.set_ylim(0.0, max(all_values) * (1 + Y_MARGIN_RATIO))
    # A long label does not fit the axis height at the shared tick size.
    ax.set_ylabel(ylabel, fontsize=ylabel_fontsize or FONT_SIZE_TICK)
    ax.tick_params(axis='y', labelsize=TICK_LABEL_SIZE, colors='black')

    ax.set_xticks(scales)
    # Every count keeps its tick, but on a narrow figure labels closer together than
    # ~7% of the axis would overlap (1 and 5 sit 4% apart), so those are left blank.
    min_gap = (scales[-1] - scales[0]) * 0.07
    labels, last_labelled = [], None
    for v in scales:
        if last_labelled is None or v - last_labelled >= min_gap:
            labels.append(str(v))
            last_labelled = v
        else:
            labels.append('')
    ax.set_xticklabels(labels, rotation=xtick_rotation,
                       ha='right' if xtick_rotation else 'center')
    ax.set_xlabel('Number of Vulnerabilities', fontsize=FONT_SIZE_TICK)
    ax.tick_params(axis='x', labelsize=TICK_LABEL_SIZE)
    span = scales[-1] - scales[0]
    ax.set_xlim(scales[0] - span * MARGIN_RATIO, scales[-1] + span * MARGIN_RATIO)

    if not logy and max(ax.get_ylim()) > 10000:
        ax.ticklabel_format(style='sci', axis='y', scilimits=(0, 0))
        ax.yaxis.get_offset_text().set_fontsize(TICK_LABEL_SIZE)

    ax.legend(handles=handles, loc=legend_loc, title=legend_title,
              title_fontsize=FONT_SIZE_LEGEND_TITLE, fontsize=FONT_SIZE_LEGEND, frameon=True,
              handlelength=3, markerscale=1.5, labelspacing=0.3, handletextpad=1.5,
              edgecolor='lightgray', framealpha=0.9)

    if logy:
        ax.grid(axis='y', which='both', color='gray', linestyle='--',
                linewidth=0.75, alpha=0.15, zorder=0)
    else:
        y_bot, y_top = ax.get_ylim()
        # grid_step_units is expressed in the scientific unit the axis is labelled in,
        # so 0.02 on a 1e4 axis rules a line every 200 ms.
        step = 10 ** np.floor(np.log10(y_top)) * grid_step_units
        for y in np.arange(np.ceil(y_bot / step) * step, y_top, step):
            ax.axhline(y=y, color='gray', linestyle='--', linewidth=0.75, alpha=0.15, zorder=0)
    ax.set_axisbelow(True)

    fig.tight_layout()
    _save_vector_and_raster(save_path)
    plt.close(fig)


VULN_DECISION_STYLE = {
    'AQUA':   {'facecolor': COLORS['cyan-blue'], 'edgecolor': COLORS['dark cyan-blue'],
               'linecolor': COLORS['dark cyan-blue'], 'linestyle': '-', 'marker': 'D',
               'label': 'AQUA'},
    'SAQURE': {'facecolor': COLORS['pink'], 'edgecolor': COLORS['pink_red'],
               'linecolor': COLORS['red'], 'linestyle': '--', 'marker': 'o',
               'label': 'SAQURE'},
}

# The risk-assessment figures label their single series the same way on both axes.
RISK_SERIES_LABEL = 'Mean Runtime Risk Assessment Time'

VULN_SCALES = [1, 5, 10, 25, 50, 75, 100]
VULN_DECISION_FIGSIZE = (6.2, 6)    # 3:3.1 (height:width)
VULN_RISK_FIGSIZE = (12, 6)         # 2:1 landscape
# The critical path sits in a narrow band, so a zero-based axis would flatten it
# against the top; the window is cropped to 5-15 ms.
VULN_RISK_YLIM = (5, 17)          # data 5.9-14.3 ms; top kept clear of the legend
# Decision time varies by 1.7% over the whole axis, so the window is cropped to
# 5-5.6e4; on a zero-based axis the two methods' curves cannot be told apart.
VULN_DECISION_YLIM = (2000, 4000)  # data 2213-3667 ms; the old 50000-56000 was the 500x scale


def run_rq4_vuln():
    """The two vulnerability-axis figures, both from the Vuln_vs_RuntimeDeTime logs.

    Decision time covers SAQURE and AQUA; risk assessment is SAQURE only, because
    AQUA reads static scores instead of assessing the environment.
    """
    print("\n====== RQ4 vulnerability axis (Vuln_vs_RuntimeDeTime, 1-100 CVEs) ======")

    decision, risk = {}, {}
    for n in VULN_SCALES:
        for baseline in ('AQUA', 'SAQURE'):
            folder = f"{RESULTS_BASE}/rq4_logs/Vuln_vs_RuntimeDeTime/S{n}/{baseline}"
            if not os.path.exists(folder):
                print(f"Folder does not exist: {folder}")
                continue
            try:
                stats, _, _ = calculate_statistics_for_folder(folder, False)
            except (TypeError, ValueError):
                # An interrupted run leaves a log without a best option; skip it rather
                # than taking down the whole figure.
                print(f"Incomplete logs in {folder}, skipping")
                continue
            if stats:
                decision.setdefault(baseline, {})[n] = stats
        # Risk assessment is SAQURE only (AQUA reads static scores) and comes from the
        # measurement-only Vuln_vs_RiskAssessTime run, so the decision-time logs stay untouched.
        risk_folder = f"{RESULTS_BASE}/rq4_logs/Vuln_vs_RiskAssessTime/S{n}/SAQURE"
        if os.path.exists(risk_folder):
            stats = calculate_risk_assessment_statistics_for_folder(risk_folder)
            if stats:
                risk.setdefault('SAQURE', {})[n] = stats

    for label, data in (('decision time', decision), ('risk assessment time', risk)):
        print(f"--- {label}")
        for method in sorted(data):
            means = '  '.join(f"N={n}:{data[method][n]['mean']:.0f}ms" for n in sorted(data[method]))
            print(f"    {method:7s} {means}")

    if decision:
        # No y-axis label: the caption carries the quantity, as in RQ4_2_2.
        plot_old_vs_new(decision, f'{PLOTS_DIR}/RQ4_1_2_SEFA.pdf', '',
                        figsize=VULN_DECISION_FIGSIZE, style_map=VULN_DECISION_STYLE,
                        order=('AQUA', 'SAQURE'), legend_title='Methods',
                        legend_loc='upper left', xtick_rotation=45,
                        ylim=VULN_DECISION_YLIM, grid_step_units=0.02)
    if risk:
        risk_style = {'SAQURE': {**VULN_DECISION_STYLE['SAQURE'],
                                 'label': RISK_SERIES_LABEL}}
        plot_old_vs_new(risk, f'{PLOTS_DIR}/RQ4_2_1_SEFA.pdf',
                        'Runtime Risk\nAssessment Time (ms)',
                        figsize=VULN_RISK_FIGSIZE, style_map=risk_style,
                        order=('SAQURE',), legend_title=None,
                        legend_loc='upper left', font_delta=5,
                        ylim=VULN_RISK_YLIM)


def run_rq4_size():
    """Load the RQ4 size axis logs (Size_vs_RuntimeDeTime) and plot the three timings"""
    print("\n====== RQ4 size axis (Size_vs_RuntimeDeTime) ======")
    stats_by_approach = {}
    for approach in ('SAQURE', 'AQUA'):
        stats_all = {}
        for folder in sorted(glob.glob(f"{RESULTS_BASE}/rq4_logs/Size_vs_RuntimeDeTime/S*/{approach}")):
            scale = int(re.search(r'/S(\d+)/', folder).group(1))
            stats = calculate_size_axis_statistics_for_folder(folder)
            if stats:
                stats_all[scale] = stats
                print(f"--- {approach} {scale}x: " + ", ".join(
                    f"{k}={v['mean']:.1f}ms" for k, v in stats.items()))
            else:
                print(f"No valid timings in {folder}")
        if stats_all:
            stats_by_approach[approach] = stats_all

    if not stats_by_approach:
        print("No size axis data found, skip plotting.")
        return

    # Figures that go into the paper: the decision figure is square, the risk one 5:3 landscape
    DECISION_FIGSIZE = (6, 6)
    PAPER_FIGSIZE = (11.4, 6)   # 1.9:1 aspect ratio
    plot_size_axis_comparison(stats_by_approach, 'decision', '',
                              f'{PLOTS_DIR}/RQ4_1_3_SEFA.pdf',
                              figsize=DECISION_FIGSIZE, xtick_rotation=45)
    if 'SAQURE' in stats_by_approach:
        # Risk assessment is SAQURE only, reported per microservice: the time each replica costs
        # stays flat as the managed system grows, so the axis is pinned to 100-500 ms.
        # Risk assessment now comes from Size_vs_RiskAssessTime: the same independent domains and
        # the same critical-path definition as the vulnerability-axis figure, measured
        # by VulnAxisAPProfiler rather than EADSA on the monolithic AED. Size_vs_RuntimeDeTime is
        # still used for the decision and configuration figures.
        risk_by_scale = {}
        for scale in (1, 10, 25, 50, 100, 250, 500):
            folder = f"{RESULTS_BASE}/rq4_logs/Size_vs_RiskAssessTime/S{scale}/SAQURE"
            if not os.path.exists(folder):
                continue
            # Two levels of aggregation. A single run logs one reading per replica, so
            # the number of readings grows with the scale (10 at 1x, 5000 at 500x) while
            # every replica measures the same thing -- SizeAxisExperiment gives them all
            # domainFiles.get(0). Pooling them would let min/max lengthen purely because
            # more readings means a higher chance of catching one scheduling outlier.
            # Instead each run is reduced to its mean, and the box is built from the 10
            # runs, which keeps the sample size constant across scales and matches how
            # every other RQ figure is computed.
            per_run = []
            for log in read_log_files(folder):
                readings = [float(v) for v in re.findall(
                    r'Risk assessment time cost for replica_\d+:\s*([\d.]+)ms', log['content'])]
                if readings:
                    per_run.append(float(np.mean(readings)))
            if per_run:
                risk_by_scale[scale] = calculate_statistics(per_run)
        if risk_by_scale:
            print("--- risk assessment (Size_vs_RiskAssessTime, critical path)")
            for scale in sorted(risk_by_scale):
                print(f"    {scale}x: {risk_by_scale[scale]['mean']:.1f}ms")
            plot_size_axis({s: {'risk_per_replica': st} for s, st in risk_by_scale.items()},
                           'risk_per_replica', '',
                           f'{PLOTS_DIR}/RQ4_2_2_SEFA.pdf',
                           RISK_SERIES_LABEL,
                           legend_loc='upper left', figsize=PAPER_FIGSIZE,
                           ylim=(12, 17), ymajor=1, yminor=0.2)
        # Configuration cost in the sense AQUA's Figure 4b uses it: generating the
        # initial model. AED_Processor's "offline configuration" is text switching over
        # the monolithic AED and depends only on the vulnerability count, not on the
        # managed system size, so it is not the quantity this axis is about.
        # Two levels of aggregation, as in the risk figure: each run is reduced to its
        # mean, and the box is built from the 10 runs.
        model_by_scale = {}
        for scale in (1, 10, 25, 50, 100, 250, 500):
            folder = f"{RESULTS_BASE}/rq4_logs/Size_vs_RuntimeDeTime/S{scale}/SAQURE"
            if not os.path.exists(folder):
                continue
            per_run = []
            for log in read_log_files(folder):
                readings = [float(v) for v in re.findall(
                    r'Time to generate and save PRISM model:\s*([\d.]+)ms', log['content'])]
                if readings:
                    per_run.append(float(np.mean(readings)))
            if per_run:
                model_by_scale[scale] = calculate_statistics(per_run)
        if model_by_scale:
            print("--- initial model generation (Size_vs_RuntimeDeTime)")
            for scale in sorted(model_by_scale):
                print(f"    {scale}x: {model_by_scale[scale]['mean']:.2f}ms")
            plot_size_axis({s: {'offline_config': st} for s, st in model_by_scale.items()},
                           'offline_config', '',
                           f'{PLOTS_DIR}/RQ4_3_2_SEFA.pdf',
                           'Mean Initial Model Generation Time',
                           legend_loc='upper left', figsize=PAPER_FIGSIZE,
                           ylim=(0, 11), ymajor=2, yminor=0.5)


# ═══════════════════════════════════════════════════════════════
# CLI entry point
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate experiment plots for RQ1-RQ4")
    parser.add_argument(
        '--experiment', type=str, nargs='?', default='all',
        choices=['RQ1', 'RQ2', 'RQ3', 'RQ4.1', 'RQ4.2', 'RQ4_eadsa', 'RQ4_size', 'RQ4_vuln', 'RQ4', 'all'],
        help="Which experiment to plot (default: all)"
    )
    args = parser.parse_args()

    ensure_plots_dir()

    dispatch = {
        'RQ1': run_rq1,
        'RQ2': run_rq2,
        'RQ3': run_rq3,
        'RQ4.1': run_rq4_1_1,
        'RQ4.2': run_rq4_1_2,
        'RQ4_eadsa': run_rq4_eadsa,
        'RQ4_size': run_rq4_size,
        'RQ4_vuln': run_rq4_vuln,
    }

    if args.experiment == 'all':
        for name, fn in dispatch.items():
            print(f"\n{'='*60}")
            print(f"  Plotting {name}")
            print(f"{'='*60}")
            fn()
    elif args.experiment == 'RQ4':
        # RQ4 = RQ4.1 + RQ4.2 + RQ4_eadsa
        run_rq4_1_1()
        run_rq4_1_2()
        run_rq4_eadsa()
        run_rq4_size()
    else:
        dispatch[args.experiment]()
