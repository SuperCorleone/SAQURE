import re
import os
from typing import Dict, List, Optional
import glob
import numpy as np

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import Rectangle, Patch
from matplotlib.ticker import AutoMinorLocator
from matplotlib.lines import Line2D

import argparse

def extract_log_fields(log_content: str) -> Dict[str, str]:
    """
    Extract the required fields from the log content

    Args:
        log_content: log content

    Returns:
        Dictionary containing extracted fields for the experiment
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
        # check if there's "No better option found"
        no_better_match = re.search(r'No better option found', log_content)
        if no_better_match:
            no_better_found = True
            # Extract the service name from the current diagram and set it as default to 1.
            current_graph_match = re.search(
                r'"currentImplementationId":"([\w-]+?)-service"',
                log_content
            )
            if current_graph_match:
                service_base = current_graph_match.group(1)
                # Remove any possible numerical suffixes and then add -1
                base_name = re.sub(r'-\d+$', '', service_base)
                best_option = f"{base_name}-1-service"

    # 2. extract best_option_cost_values
    cost_match = re.search(r'Best cost value:\s*([\d.]+)', log_content)
    if cost_match:
        best_option_cost_values = cost_match.group(1)
    elif no_better_found:
        # When "No better option found" is displayed, use the cost value of the first implementation
        first_cost_match = re.search(r'Cost Value:\s*([\d.]+)', log_content)
        if first_cost_match:
            best_option_cost_values = first_cost_match.group(1)

    # 3. extract extract_time
    time_match = re.search(
        r'Time to extract best option RamsesV3:\s*([\d.]+)ms',
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
    # Initialize fields
    best_option = None
    best_option_cost_values = None
    extract_time = None

    # 1. extract best_option
    best_option_match = re.search(
        r'Key with min value:\s+([\w-]+?)-service',
        log_content
    )

    no_better_found = False
    if best_option_match:
        best_option = best_option_match.group(1) + "-service"
    else:
        # Check if there is "No better option found"
        print("error: extract_log_fields_RQ1_longcul: no best option found")
        return {}

    # 2. extract best_option_cost_values
    cost_match = re.search(r'Min value:\s*([\d.]+)', log_content)
    if cost_match:
        best_option_cost_values = cost_match.group(1)
    else:
        # Check if there is "No better option found"
        print("error: extract_log_fields_RQ1_longcul: no best option found")
        return {}

    # 3. extract extract_time
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
    # Basic statistics
    min_val = np.min(data)
    max_val = np.max(data)
    mean_val = np.mean(data)
    # Quartiles
    q1 = np.percentile(data, 25)  # First quartile (Q1)
    q2 = np.percentile(data, 50)  # Second quartile (Q2, median)
    q3 = np.percentile(data, 75)  # Third quartile (Q3)

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

    # Match all .log files
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
        if spacial_case: # for SAQURE-longcul case
            result = extract_log_fields_RQ1_longcul(log['content'])
        else:
            result = extract_log_fields(log['content'])  # Get single result directly
        best_option = result['best_option']
        best_cost = float(result['best_option_cost_values'])

        if result['extract_time']:
            times.append(float(result['extract_time']))

    # Calculate statistics after processing all files
    if times:
        time_stats = calculate_statistics(times)
        return time_stats, best_cost, best_option
    else:
        return {}

def extract_cost_from_SAQURE(folder_path: str, target_service: str) -> float | None:
    """
    Extract the Cost Value corresponding to target_service from the log.
    If no match is found, return the Cost Value of the current graph.
    """
    logs_dic = read_log_files(folder_path)

    # Convert dictionary/list content to string lines
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

    # Split into lines
    lines = "\n".join(lines).splitlines()

    # === Stage 1: Find "from ... to target_service" ===
    for i, line in enumerate(lines):
        match = re.search(r'from\s+.*?\s+to\s+([\w-]+)', line)
        if match and match.group(1) == target_service:
            # Found target service, search backward for the nearest Cost Value
            for next_line in lines[i+1:]:
                cost_match = re.search(r'Cost Value:\s*([\d.eE+-]+)', next_line)
                if cost_match:
                    return float(cost_match.group(1))

    # === Stage 2: If target service not found, find Cost Value after "Current graph:" ===
    for i, line in enumerate(lines):
        if "Current graph:" in line:
            # Search for the first Cost Value after this line
            for next_line in lines[i+1:]:
                cost_match = re.search(r'Cost Value:\s*([\d.eE+-]+)', next_line)
                if cost_match:
                    return float(cost_match.group(1))

    # If none found
    print("error in extract_cost_from_SAQURE func: wrong service")
    return None

def extract_eadsa_time(log_content: str) -> Optional[float]:
    """
    Extract EADSA implementation time from log, e.g.:
    Time to implement EADSA for restaurant_0: 245ms
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

def plot_eadsa_boxplot(eadsa_stats_all, experiment_name):
    """
    Plot boxplot + mean line for SAQURE baseline EADSA implementation time (separate figure)
    """
    # ───────────────────────────────────────
    # 🎛️ Configurable parameters - consistent with plot_rq312_all_subscenarios
    # ───────────────────────────────────────
    FIG_SIZE = (12, 4.5)
    BOX_WIDTH = 4 #box
    TREND_LING_LINEWIDTH = 1.0 #line
    IQR_LINEWIDTH = 0.8 #box line
    GROUP_SPACING = 10.0 #group spacing
    LEFT_MARGIN = 6.0   # Adjustable (in axis coordinates)
    RIGHT_MARGIN = LEFT_MARGIN

    POINTSIZE = 2
    Y_MARGIN_RATIO = 0.505
    Y_MIN_LIM = 100  # EADSA time may be small, start from 0
    DOT_HLINE_DENSITY = 20

    FONT_SIZE_TICK = 24 #axis title
    TICK_LABEL_SIZE = 20 #axis tick font
    FONT_SIZE_LEGEND = 18 #legend item font
    FONT_SIZE_LEGEND_TITLE = 20 #legend title

    colors ={'red': (163/255, 81/255, 57/255),
             'dark pink': (202/255, 162/255, 173/255),
             'dark orange': (234/255, 177/255, 112/255),
             'dark purple': (182/255, 175/255, 197/255),
             'dark cyan-blue': (182/255, 207/255, 212/255),
             'cyan-blue': (225/255, 241/255, 246/255),
             'purple': (230/255, 226/255, 245/255),
             'orange': (244/255, 224/255, 155/255),
             'pink': (246/255, 223/255, 224/255),
             'pink_red': (221/255, 185/255, 172/255)}

    # EADSA uses SAQURE color scheme
    eadsa_colors = {
        'facecolor': colors.get('pink'),
        'edgecolor': colors.get('pink_red'),
        'linecolor': colors.get('red')
    }

    # ───────────────────────────────────────
    # Data preparation
    # ───────────────────────────────────────
    sub_scenarios = list(eadsa_stats_all.keys())

    # Calculate x-axis positions (considering group spacing)
    x_positions = []
    current_pos = LEFT_MARGIN  # Start from left margin

    for i, sub_scenario in enumerate(sub_scenarios):
        # Position for each sub-scenario
        x_positions.append(current_pos)
        # Move to next position: current position + group spacing
        current_pos += 1 + GROUP_SPACING

    # === Create figure ===
    fig, ax = plt.subplots(figsize=FIG_SIZE)

    # === Plot EADSA boxplot ===
    all_time_values = []
    for sub_scenario in sub_scenarios:
        stats = eadsa_stats_all[sub_scenario]
        all_time_values.extend([stats['min'], stats['max'], stats['q1'], stats['q3'], stats['mean']])

    # Set Y-axis range
    if all_time_values:
        y_min = min(all_time_values)
        y_max = max(all_time_values)
        margin = (y_max - y_min) * Y_MARGIN_RATIO
        ax.set_ylim(Y_MIN_LIM, y_max + margin)

    # Store mean positions for line plot
    mean_positions = []

    # Draw boxplot
    for i, sub_scenario in enumerate(sub_scenarios):
        stats = eadsa_stats_all[sub_scenario]
        x_pos = x_positions[i]

        # Record mean position
        mean_positions.append((x_pos, stats['mean']))

        # IQR box
        rect = Rectangle(
            (x_pos - BOX_WIDTH / 2, stats['q1']),
            BOX_WIDTH,
            stats['q3'] - stats['q1'],
            facecolor=eadsa_colors['facecolor'],
            edgecolor=eadsa_colors['edgecolor'],
            linewidth=IQR_LINEWIDTH,
            zorder=4
        )
        ax.add_patch(rect)

        # Whiskers
        ax.vlines(x_pos, stats['min'], stats['q1'], colors=eadsa_colors['edgecolor'], linewidth=1, zorder=2)
        ax.vlines(x_pos, stats['q3'], stats['max'], colors=eadsa_colors['edgecolor'], linewidth=1, zorder=2)

        # Mean point and line
        ax.plot(x_pos, stats['mean'], 'o', color=eadsa_colors['linecolor'], markersize=POINTSIZE+5, zorder=6)
        ax.hlines(stats['mean'], x_pos - BOX_WIDTH / 2, x_pos + BOX_WIDTH / 2,
                  colors=eadsa_colors['linecolor'], linewidth=1.2, zorder=5)

    # === Draw mean line ===
    if mean_positions:
        # Sort by x position to ensure correct line connection
        positions = sorted(mean_positions, key=lambda x: x[0])
        x_coords = [pos[0] for pos in positions]
        y_coords = [pos[1] for pos in positions]

        # Draw line
        line, = ax.plot(x_coords, y_coords,
                        color=eadsa_colors['linecolor'],
                        linestyle='-', linewidth=TREND_LING_LINEWIDTH, marker='o',
                        markersize=0, zorder=3,
                        label='Mean Runtime Risk\nAssessment Time')

    # === Axis settings ===
    plt.rcParams['text.usetex'] = True
    ax.set_xticks(x_positions)

    # Set x-axis labels (consistent with RQ1)
    x_tick_labels = []
    for i in range(1, len(sub_scenarios)+1):
        x_tick_label = f'{i}'
        x_tick_labels.append(x_tick_label)
    ax.set_xticklabels(x_tick_labels)
    ax.set_xlabel('Number of Vulnerabilities', fontsize=FONT_SIZE_TICK)
    ax.set_ylabel('Runtime Risk Assess-\nment Time (ms)', fontsize=FONT_SIZE_TICK)

    # Set tick label size
    ax.tick_params(axis='x', labelsize=TICK_LABEL_SIZE)
    ax.tick_params(axis='y', labelsize=TICK_LABEL_SIZE)

    # Scientific notation formatting (if needed)
    if max(all_time_values) > 10000:  # Use scientific notation only for large values
        ax.ticklabel_format(style='sci', axis='y', scilimits=(0, 0))
        ax.yaxis.get_offset_text().set_fontsize(TICK_LABEL_SIZE)

    # === Fix: Set x-axis range, ensure left and right margins ===
    if x_positions:
        # Calculate x-axis range: from first position minus left margin to last position plus right margin
        x_min = x_positions[0] - LEFT_MARGIN
        x_max = x_positions[-1] + RIGHT_MARGIN
        ax.set_xlim(x_min, x_max)

    # === Legend ===
    ax.legend(loc='upper right',
              title_fontsize=FONT_SIZE_LEGEND_TITLE, fontsize=FONT_SIZE_LEGEND, frameon=True,
              handlelength=4,    # Longer lines for line plot legend
              markerscale=3,     # Scale marker size in line plot
              labelspacing=0.4,  # Vertical spacing
              handletextpad=1.0) # Horizontal distance between line and text label

    # === Grid lines ===
    # Enable horizontal dashed background
    if all_time_values:
        y_max_val = max(all_time_values)
        y_min = min(all_time_values)
        # Adjust grid line density dynamically
        y_range = y_max_val - Y_MIN_LIM
        if y_range > 0:
            density = DOT_HLINE_DENSITY  # Adaptive density
            for y in np.arange(Y_MIN_LIM, y_max_val + margin, density):
                ax.axhline(
                    y=y,
                    color='gray',
                    linestyle='--',
                    linewidth=0.75,
                    alpha=0.15,
                    zorder=0
                )

    # Place grid lines at the bottom layer to avoid covering boxplot
    ax.set_axisbelow(True)

    fig.tight_layout()
    plt.savefig('experiments/plots/RQ4_SEFA.png',
                dpi=200)
    plt.show()

def plot_rq31_all_subscenarios(time_stats_all, experiment_name):
    """
    Plot all sub-scenarios of RQ1 in one figure
    """
    # ───────────────────────────────────────
    # 🎛️ Configurable parameters
    # ───────────────────────────────────────
    FIG_SIZE = (12, 6)
    BAR_WIDTH = 0.08
    BOX_WIDTH = 0.08 #box
    GROUP_SPACING = 0.15 #group spacing
    X_BLOCK_WIDTH = 0.1 #both sides width
    TREND_LING_LINEWIDTH = 1.0 #line
    IQR_LINEWIDTH = 0.8 #box line

    # New: Pattern parameters (for black and white display)
    HATCH_LINE_WIDTH = 0.5  # Pattern line thickness

    POINTSIZE = 2
    Y_MARGIN_RATIO = 0.05
    DOT_HLINE_DENSITY = 10000

    FONT_SIZE_TICK = 24 #axis title
    TICK_LABEL_SIZE = 20 #axis tick font
    FONT_SIZE_LEGEND = 18 #legend item font
    FONT_SIZE_LEGEND_TITLE = 20 #legend title

    colors ={'red': (163/255, 81/255, 57/255),
             'dark pink': (202/255, 162/255, 173/255),
             'dark orange': (234/255, 177/255, 112/255),
             'dark purple': (182/255, 175/255, 197/255),
             'dark cyan-blue': (182/255, 207/255, 212/255),
             'cyan-blue': (225/255, 241/255, 246/255),
             'purple': (230/255, 226/255, 245/255),
             'orange': (244/255, 224/255, 155/255),
             'pink': (246/255, 223/255, 224/255),
             'pink_red': (221/255, 185/255, 172/255)}

    # Color configuration - assign fixed colors to each baseline
    baseline_colors = {
        'AQUA': colors.get('cyan-blue'),
        'QoS': colors.get('purple'),
        'SAQURE_seq': colors.get('orange'),
        'SAQURE_para': colors.get('pink_red'),
        'SAQURE': colors.get('pink_red')
    }
    edge_colors = {
        'AQUA': colors.get('dark cyan-blue'),
        'QoS': colors.get('dark purple'),
        'SAQURE_seq': colors.get('dark orange'),
        'SAQURE_para': colors.get('red'),
        'SAQURE': colors.get('red')
    }
    # New: Assign different fill patterns to each baseline (for black and white display)
    hatch_patterns = {
        'AQUA': '///',      # slash
        'QoS': '\\\\\\',    # backslash
        'SAQURE_seq': '---', # horizontal line
        'SAQURE_para': '', # solid
        'SAQURE': ''
    }

    # New: Assign different line styles to each baseline (for black and white display)
    line_styles = {
        'AQUA': '-',        # solid
        'QoS': (0, (10, 5)),        # custom long dash
        'SAQURE_seq': '-.', # dash-dot
        'SAQURE_para': '--', # dash
        'SAQURE': '--'
    }

    # New: Assign different marker styles to each baseline (for black and white display)
    marker_styles = {
        'AQUA': 'o',        # circle
        'QoS': 's',         # square
        'SAQURE_seq': '^',  # triangle up
        'SAQURE_para': 'D', # diamond
        'SAQURE': 'D'
    }
    mapping = {
        'QoS': 'RAMSES',
        'SAQURE_seq': 'SAQURE$^{-}_{para}$',
        'SAQURE_para': 'SAQURE'
    }

    # ───────────────────────────────────────
    # Data preparation
    # ───────────────────────────────────────
    sub_scenarios = list(time_stats_all.keys())
    baselines = list(time_stats_all[sub_scenarios[0]].keys())

    # Calculate x-axis positions
    x_positions = {}
    x_ticks = []
    current_pos = 0

    for i, sub_scenario in enumerate(sub_scenarios):
        scenario_positions = []
        for j, baseline in enumerate(baselines):
            pos = current_pos + j * (BAR_WIDTH + 0.02)
            scenario_positions.append(pos)
        x_positions[sub_scenario] = scenario_positions
        # Sub-scenario label position in the middle of the group
        x_ticks.append(np.mean(scenario_positions))
        current_pos = max(scenario_positions) + GROUP_SPACING

    # === Create figure ===
    fig, ax = plt.subplots(figsize=FIG_SIZE)

    # === Draw Time boxplot ===
    all_time_values = []
    for sub_scenario in sub_scenarios:
        for baseline in baselines:
            if baseline in time_stats_all[sub_scenario]:
                stats = time_stats_all[sub_scenario][baseline]
                all_time_values.extend([stats['min'], stats['max'], stats['q1'], stats['q3'], stats['mean']])

    # Set Y-axis range
    if all_time_values:
        y_min = min(all_time_values)
        y_max = max(all_time_values)
        margin = (y_max - y_min) * Y_MARGIN_RATIO
        ax.set_ylim(0, y_max + margin)

    # Prepare mean data for line plot for each baseline
    baseline_mean_positions = {baseline: [] for baseline in baselines}

    # Draw boxplot
    for sub_scenario in sub_scenarios:
        for j, baseline in enumerate(baselines):
            if baseline in time_stats_all[sub_scenario]:
                stats = time_stats_all[sub_scenario][baseline]
                x_pos = x_positions[sub_scenario][j]
                baseline_mean_positions[baseline].append((x_pos, stats['mean']))

                # IQR box - add pattern fill
                rect = Rectangle(
                    (x_pos - BOX_WIDTH / 2, stats['q1']),
                    BOX_WIDTH,
                    stats['q3'] - stats['q1'],
                    facecolor=baseline_colors[baseline],
                    edgecolor=edge_colors[baseline],
                    linewidth=IQR_LINEWIDTH,
                    hatch=hatch_patterns[baseline],  # Add pattern
                    hatch_linewidth=HATCH_LINE_WIDTH,  # Set pattern line thickness
                    zorder=4
                )
                ax.add_patch(rect)

                # Whiskers
                ax.vlines(x_pos, stats['min'], stats['q1'], colors=edge_colors[baseline], linewidth=1, zorder=2)
                ax.vlines(x_pos, stats['q3'], stats['max'], colors=edge_colors[baseline], linewidth=1, zorder=2)

                # Mean point and line - use different marker styles
                ax.plot(x_pos, stats['mean'],
                        marker=marker_styles[baseline],  # Use different markers
                        color=edge_colors[baseline],
                        markersize=POINTSIZE+5 if marker_styles[baseline] else POINTSIZE,
                        zorder=6,
                        markeredgecolor='black' if marker_styles[baseline] else None,
                        markeredgewidth=0.5 if marker_styles[baseline] else 0)
                ax.hlines(stats['mean'], x_pos - BOX_WIDTH / 2, x_pos + BOX_WIDTH / 2,
                          colors=edge_colors[baseline], linewidth=1.2, zorder=5)

        # === Draw mean line for each baseline ===
    mean_trend_lines = []
    for baseline in baselines:
        if baseline_mean_positions[baseline]:  # Ensure data exists
            # Sort by x position to ensure correct line connection
            positions = sorted(baseline_mean_positions[baseline], key=lambda x: x[0])
            x_coords = [pos[0] for pos in positions]
            y_coords = [pos[1] for pos in positions]

            # Draw line, using different line styles and markers
            line, = ax.plot(x_coords, y_coords,
                            color=edge_colors[baseline],
                            linestyle=line_styles[baseline],  # Use different line styles
                            linewidth=TREND_LING_LINEWIDTH,  # Use different line widths
                            marker=marker_styles[baseline],  # Use different markers
                            markersize=0 if marker_styles[baseline] else POINTSIZE,
                            zorder=3,
                            markeredgecolor='black' if marker_styles[baseline] else None,
                            markeredgewidth=0.5 if marker_styles[baseline] else 0,
                            label=f'{mapping.get(baseline, baseline)}')
            mean_trend_lines.append(line)

    # === Axis settings ===
    plt.rcParams['text.usetex'] = True
    ax.set_xticks(x_ticks)
    x_tick_labels = []
    num_opts_comments={
        '1': '2 options',
        '2': '2 options',
        '3': '3 options',
        '4': '3 options',
        '5': '3 options'
    }

    for i in range(1, len(sub_scenarios)+1):
        x_tick_label = f'{i}'
        x_tick_labels.append(x_tick_label)
    ax.set_xticklabels(x_tick_labels)
    ax.set_xlabel('Number of Options', fontsize=FONT_SIZE_TICK)
    ax.set_ylabel('Runtime Decision Time (ms)', fontsize=FONT_SIZE_TICK)

    # Set tick label size
    ax.tick_params(axis='x', labelsize=TICK_LABEL_SIZE)
    ax.tick_params(axis='y', labelsize=TICK_LABEL_SIZE)

    ax.ticklabel_format(style='sci', axis='y', scilimits=(0, 0))
    ax.yaxis.get_offset_text().set_fontsize(TICK_LABEL_SIZE) #Scientific notation label font size

    # Set x-axis range
    ax.set_xlim(-X_BLOCK_WIDTH, current_pos - GROUP_SPACING + X_BLOCK_WIDTH)

    # # === Legend ===
    # # Time legend elements - include mean trend line
    # ax.legend(handles=mean_trend_lines, loc='lower right', title='Mean Runtime Decision Time',
    #           title_fontsize=FONT_SIZE_LEGEND_TITLE, fontsize=FONT_SIZE_LEGEND, frameon=True,
    #           handlelength=4,    # Longer lines for line plot legend
    #           markerscale=3,     # Scale marker size in line plot
    #           labelspacing=0.4,  # Vertical spacing
    #           handletextpad=2.0) # Horizontal distance between line and text label
    # === Legend ===
    # Import necessary classes
    from matplotlib.patches import Patch
    from matplotlib.lines import Line2D

    # Method 1: Use line plot legend (already includes line style and marker)
    # Directly use mean_trend_lines as legend elements
    ax.legend(handles=mean_trend_lines, loc='lower right', title='Methods',
              title_fontsize=FONT_SIZE_LEGEND_TITLE, fontsize=FONT_SIZE_LEGEND, frameon=True,
              handlelength=3,    # Line length in line plot legend
              markerscale=1.5,   # Scale marker size in line plot
              labelspacing=0.3,  # Vertical spacing
              handletextpad=1.5, # Horizontal distance between line and text label
              edgecolor='lightgray',  # Legend border color
              framealpha=0.9)     # Legend background transparency

    # === Grid lines ===
    # Enable horizontal dashed background
    if all_time_values:
        y_max_val = max(all_time_values)
        y_min = min(all_time_values)
        for y in np.arange(0, y_max_val + y_min , DOT_HLINE_DENSITY):
            ax.axhline(
                y=y,
                color='gray',
                linestyle='--',
                linewidth=0.75,
                alpha=0.15,
                zorder=0
            )
    # Place grid lines at the bottom layer to avoid covering boxplot
    ax.set_axisbelow(True)

    fig.tight_layout()
    plt.savefig('experiments/plots/RQ31_SEFA.png',
                dpi=200)
    plt.show()

def plot_rq32_all_subscenarios(time_stats_all, experiment_name):
    """
    Plot all sub-scenarios of RQ1 in one figure
    """
    # ───────────────────────────────────────
    # 🎛️ Configurable parameters
    # ───────────────────────────────────────
    FIG_SIZE = (12, 6)
    BAR_WIDTH = 0.08
    BOX_WIDTH = 0.08 #box
    GROUP_SPACING = 0.15 #group spacing
    X_BLOCK_WIDTH = 0.1 #both sides width
    TREND_LING_LINEWIDTH = 1.0 #line
    IQR_LINEWIDTH = 0.8 #box line

    # New: Black and white display compatibility parameters
    HATCH_LINE_WIDTH = 0.5  # Pattern line thickness

    POINTSIZE = 2
    Y_MARGIN_RATIO = 0.3
    Y_MIN_LIM = 5.2e4
    DOT_HLINE_DENSITY = 500

    FONT_SIZE_TICK = 24 #axis title
    TICK_LABEL_SIZE = 20 #axis tick font
    FONT_SIZE_LEGEND = 18 #legend item font
    FONT_SIZE_LEGEND_TITLE = 20 #legend title

    colors ={'red': (163/255, 81/255, 57/255),
             'dark pink': (202/255, 162/255, 173/255),
             'dark orange': (234/255, 177/255, 112/255),
             'dark purple': (182/255, 175/255, 197/255),
             'dark cyan-blue': (182/255, 207/255, 212/255),
             'cyan-blue': (225/255, 241/255, 246/255),
             'purple': (230/255, 226/255, 245/255),
             'orange': (244/255, 224/255, 155/255),
             'pink': (246/255, 223/255, 224/255),
             'pink_red': (221/255, 185/255, 172/255)}

    # Color configuration - assign fixed colors to each baseline
    baseline_colors = {
        'AQUA': colors.get('cyan-blue'),
        'QoS': colors.get('purple'),
        'SAQURE_seq': colors.get('orange'),
        'SAQURE_para': colors.get('pink_red'),
        'SAQURE': colors.get('pink_red')
    }
    edge_colors = {
        'AQUA': colors.get('dark cyan-blue'),
        'QoS': colors.get('dark purple'),
        'SAQURE_seq': colors.get('dark orange'),
        'SAQURE_para': colors.get('red'),
        'SAQURE': colors.get('red')
    }
    # New: Assign different fill patterns to each baseline (for black and white display)
    hatch_patterns = {
        'AQUA': '///',      # slash
        'QoS': '\\\\\\',    # backslash
        'SAQURE_seq': '---', # horizontal line
        'SAQURE_para': '', # solid
        'SAQURE': ''
    }

    # New: Assign different line styles to each baseline (for black and white display)
    line_styles = {
        'AQUA': '-',        # solid
        'QoS': (0, (10, 5)),        # custom long dash
        'SAQURE_seq': '-.', # dash-dot
        'SAQURE_para': '--', # dash
        'SAQURE': '--'
    }

    # New: Assign different marker styles to each baseline (for black and white display)
    marker_styles = {
        'AQUA': 'o',        # circle
        'QoS': 's',         # square
        'SAQURE_seq': '^',  # triangle up
        'SAQURE_para': 'D', # diamond
        'SAQURE': 'D'
    }
    mapping = {
        'QoS': 'RAMSES',
        'SAQURE_seq': 'SAQURE$^{-}_{para}$',
        'SAQURE_para': 'SAQURE'
    }

    # ───────────────────────────────────────
    # Data preparation
    # ───────────────────────────────────────
    sub_scenarios = list(time_stats_all.keys())
    baselines = list(time_stats_all[sub_scenarios[0]].keys())

    # Calculate x-axis positions
    x_positions = {}
    x_ticks = []
    current_pos = 0

    for i, sub_scenario in enumerate(sub_scenarios):
        scenario_positions = []
        for j, baseline in enumerate(baselines):
            pos = current_pos + j * (BAR_WIDTH + 0.02)
            scenario_positions.append(pos)
        x_positions[sub_scenario] = scenario_positions
        # Sub-scenario label position in the middle of the group
        x_ticks.append(np.mean(scenario_positions))
        current_pos = max(scenario_positions) + GROUP_SPACING

    # === Create figure ===
    fig, ax = plt.subplots(figsize=FIG_SIZE)

    # === Draw Time boxplot ===
    all_time_values = []
    for sub_scenario in sub_scenarios:
        for baseline in baselines:
            if baseline in time_stats_all[sub_scenario]:
                stats = time_stats_all[sub_scenario][baseline]
                all_time_values.extend([stats['min'], stats['max'], stats['q1'], stats['q3'], stats['mean']])

    # Set Y-axis range
    if all_time_values:
        y_min = min(all_time_values)
        y_max = max(all_time_values)
        margin = (y_max - y_min) * Y_MARGIN_RATIO
        ax.set_ylim(Y_MIN_LIM, y_max + margin)

    # Prepare mean data for line plot for each baseline
    baseline_mean_positions = {baseline: [] for baseline in baselines}

    # Draw boxplot
    for sub_scenario in sub_scenarios:
        for j, baseline in enumerate(baselines):
            if baseline in time_stats_all[sub_scenario]:
                stats = time_stats_all[sub_scenario][baseline]
                x_pos = x_positions[sub_scenario][j]
                baseline_mean_positions[baseline].append((x_pos, stats['mean']))

                # IQR box - add pattern fill
                rect = Rectangle(
                    (x_pos - BOX_WIDTH / 2, stats['q1']),
                    BOX_WIDTH,
                    stats['q3'] - stats['q1'],
                    facecolor=baseline_colors[baseline],
                    edgecolor=edge_colors[baseline],
                    linewidth=IQR_LINEWIDTH,
                    hatch=hatch_patterns[baseline],  # Add pattern
                    hatch_linewidth=HATCH_LINE_WIDTH,  # Set pattern line thickness
                    zorder=4
                )
                ax.add_patch(rect)

                # Whiskers
                ax.vlines(x_pos, stats['min'], stats['q1'], colors=edge_colors[baseline], linewidth=1, zorder=2)
                ax.vlines(x_pos, stats['q3'], stats['max'], colors=edge_colors[baseline], linewidth=1, zorder=2)

                # Mean point and line - use different marker styles
                ax.plot(x_pos, stats['mean'],
                        marker=marker_styles[baseline],  # Use different markers
                        color=edge_colors[baseline],
                        markersize=POINTSIZE+5 if marker_styles[baseline] else POINTSIZE,
                        zorder=6,
                        markeredgecolor='black' if marker_styles[baseline] else None,
                        markeredgewidth=0.5 if marker_styles[baseline] else 0)
                ax.hlines(stats['mean'], x_pos - BOX_WIDTH / 2, x_pos + BOX_WIDTH / 2,
                          colors=edge_colors[baseline], linewidth=1.2, zorder=5)

        # === Draw mean line for each baseline ===
    mean_trend_lines = []
    for baseline in baselines:
        if baseline_mean_positions[baseline]:  # Ensure data exists
            # Sort by x position to ensure correct line connection
            positions = sorted(baseline_mean_positions[baseline], key=lambda x: x[0])
            x_coords = [pos[0] for pos in positions]
            y_coords = [pos[1] for pos in positions]

            # Draw line, using different line styles and markers
            line, = ax.plot(x_coords, y_coords,
                            color=edge_colors[baseline],
                            linestyle=line_styles[baseline],  # Use different line styles
                            linewidth=TREND_LING_LINEWIDTH,  # Use different line widths
                            marker=marker_styles[baseline],  # Use different markers
                            markersize=0 if marker_styles[baseline] else POINTSIZE,
                            zorder=3,
                            markeredgecolor='black' if marker_styles[baseline] else None,
                            markeredgewidth=0.5 if marker_styles[baseline] else 0,
                            label=f'{mapping.get(baseline, baseline)}')
            mean_trend_lines.append(line)

    # === Axis settings ===
    plt.rcParams['text.usetex'] = True
    ax.set_xticks(x_ticks)
    x_tick_labels = []
    num_opts_comments={
        '1': '2 options',
        '2': '2 options',
        '3': '3 options',
        '4': '3 options',
        '5': '3 options'
    }

    for i in range(1, len(sub_scenarios)+1):
        x_tick_label = f'{i}'
        x_tick_labels.append(x_tick_label)
    ax.set_xticklabels(x_tick_labels)
    ax.set_xlabel('Number of Vulnerabilities', fontsize=FONT_SIZE_TICK)
    ax.set_ylabel('Runtime Decision Time (ms)', fontsize=FONT_SIZE_TICK)

    # Set tick label size
    ax.tick_params(axis='x', labelsize=TICK_LABEL_SIZE)
    ax.tick_params(axis='y', labelsize=TICK_LABEL_SIZE)

    ax.ticklabel_format(style='sci', axis='y', scilimits=(0, 0))
    ax.yaxis.get_offset_text().set_fontsize(TICK_LABEL_SIZE) #Scientific notation label font size

    # Set x-axis range
    ax.set_xlim(-X_BLOCK_WIDTH, current_pos - GROUP_SPACING + X_BLOCK_WIDTH)

    # # === Legend ===
    # # Time legend elements - include mean trend line
    # ax.legend(handles=mean_trend_lines, loc='upper right', title='Mean Runtime Decision Time',
    #           title_fontsize=FONT_SIZE_LEGEND_TITLE, fontsize=FONT_SIZE_LEGEND, frameon=True,
    #           handlelength=4,    # Longer lines for line plot legend
    #           markerscale=3,     # Scale marker size in line plot
    #           labelspacing=0.4,  # Vertical spacing
    #           handletextpad=2.0) # Horizontal distance between line and text label
    # === Legend ===
    # Import necessary classes
    from matplotlib.patches import Patch
    from matplotlib.lines import Line2D

    # Directly use mean_trend_lines as legend elements
    ax.legend(handles=mean_trend_lines, loc='lower right', title='Methods',
              title_fontsize=FONT_SIZE_LEGEND_TITLE, fontsize=FONT_SIZE_LEGEND, frameon=True,
              handlelength=3,    # Line length in line plot legend
              markerscale=1.5,   # Scale marker size in line plot
              labelspacing=0.3,  # Vertical spacing
              handletextpad=1.5, # Horizontal distance between line and text label
              edgecolor='lightgray',  # Legend border color
              framealpha=0.9)     # Legend background transparency

    # === Grid lines ===
    # Enable horizontal dashed background
    if all_time_values:
        y_max_val = max(all_time_values)
        y_min = min(all_time_values)
        for y in np.arange(Y_MIN_LIM,Y_MIN_LIM+50000 , DOT_HLINE_DENSITY):
            ax.axhline(
                y=y,
                color='gray',
                linestyle='--',
                linewidth=0.75,
                alpha=0.15,
                zorder=0
            )
    # Place grid lines at the bottom layer to avoid covering boxplot
    ax.set_axisbelow(True)

    fig.tight_layout()
    plt.savefig('experiments/plots/RQ32_SEFA.png',
                dpi=200)
    plt.show()

def plot_rq1_all_subscenarios(time_stats_all, cost_values_all, experiment_name):
    """
    Plot all sub-scenarios of RQ1 in one figure
    """
    # ───────────────────────────────────────
    # 🎛️ Configurable parameters - add black and white display related parameters
    # ───────────────────────────────────────
    FIG_SIZE = (12, 6)
    BAR_WIDTH = 0.08
    BOX_WIDTH = 0.08
    GROUP_SPACING = 0.15
    X_BLOCK_WIDTH = 0.1
    TREND_LING_LINEWIDTH = 1.0
    IQR_LINEWIDTH = 0.8

    # New: Pattern parameters (for black and white display)
    HATCH_DENSITY = 2.5  # Pattern density
    HATCH_LINE_WIDTH = 0.5  # Pattern line thickness

    # Original parameters unchanged...
    POINTSIZE = 2
    Y_MARGIN_RATIO = 1.02
    Y_MAX_MARGIN = 75000
    Y_MIN_MARGIN = -20000
    RECT_YLIM = 800000
    RECT_YMIN = 250000
    DOT_HLINE_DENSITY = 10000

    FONT_SIZE_TICK = 24
    TICK_LABEL_SIZE = 18
    FONT_SIZE_LEGEND = 15
    FONT_SIZE_LEGEND_TITLE = 18

    # Color configuration - add patterns for black and white display
    colors = {
        'red': (163/255, 81/255, 57/255),
        'dark pink': (202/255, 162/255, 173/255),
        'dark orange': (234/255, 177/255, 112/255),
        'dark purple': (182/255, 175/255, 197/255),
        'dark cyan-blue': (182/255, 207/255, 212/255),
        'cyan-blue': (225/255, 241/255, 246/255),
        'purple': (230/255, 226/255, 245/255),
        'orange': (244/255, 224/255, 155/255),
        'pink': (246/255, 223/255, 224/255),
        'pink_red': (221/255, 185/255, 172/255)
    }

    # Color configuration - assign fixed colors to each baseline
    baseline_colors = {
        'AQUA': colors.get('cyan-blue'),
        'QoS': colors.get('purple'),
        'SAQURE_seq': colors.get('orange'),
        'SAQURE_para': colors.get('pink_red'),
    }

    edge_colors = {
        'AQUA': colors.get('dark cyan-blue'),
        'QoS': colors.get('dark purple'),
        'SAQURE_seq': colors.get('dark orange'),
        'SAQURE_para': colors.get('red'),
    }

    # New: Assign different fill patterns to each baseline (for black and white display)
    hatch_patterns = {
        'AQUA': '///',      # slash
        'QoS': '\\\\\\',    # backslash
        'SAQURE_seq': '---', # horizontal line
        'SAQURE_para': '', # solid
    }

    # New: Assign different line styles to each baseline (for black and white display)
    line_styles = {
        'AQUA': '-',        # solid
        'QoS': (0, (10, 5)),        # custom long dash
        'SAQURE_seq': '-.', # dash-dot
        'SAQURE_para': ':', # dotted
    }

    # New: Assign different marker styles to each baseline (for black and white display)
    marker_styles = {
        'AQUA': 'o',        # circle
        'QoS': 's',         # square
        'SAQURE_seq': '^',  # triangle up
        'SAQURE_para': 'D', # diamond
    }

    mapping = {
        'QoS': 'RAMSES',
        'SAQURE_seq': 'SAQURE$^{-}_{para}$',
        'SAQURE_para': 'SAQURE'
    }

    # ───────────────────────────────────────
    # Data preparation
    # ───────────────────────────────────────
    sub_scenarios = list(time_stats_all.keys())
    baselines = list(time_stats_all[sub_scenarios[0]].keys())

    # Calculate x-axis positions
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

    # === Create figure ===
    fig, ax1 = plt.subplots(figsize=FIG_SIZE)
    ax2 = ax1.twinx()

    # === Draw Cost bar chart ===
    bars = []
    bar_labels = []
    for sub_scenario in sub_scenarios:
        for j, baseline in enumerate(baselines):
            if baseline in cost_values_all[sub_scenario]:
                x_pos = x_positions[sub_scenario][j]
                bar = ax1.bar(
                    x_pos,
                    cost_values_all[sub_scenario][baseline],
                    width=BAR_WIDTH,
                    color=baseline_colors[baseline],
                    edgecolor=edge_colors[baseline],
                    # New: add pattern fill, set transparency to avoid covering color
                    hatch=hatch_patterns[baseline],
                    hatch_linewidth=HATCH_LINE_WIDTH,
                    zorder=2,
                    label=baseline if sub_scenario == sub_scenarios[0] else ""
                )
                if sub_scenario == sub_scenarios[0]:
                    bars.append(bar)
                    bar_labels.append(mapping.get(baseline, baseline))

    # === Draw Time boxplot ===
    all_time_values = []
    for sub_scenario in sub_scenarios:
        for baseline in baselines:
            if baseline in time_stats_all[sub_scenario]:
                stats = time_stats_all[sub_scenario][baseline]
                all_time_values.extend([stats['min'], stats['max'], stats['q1'], stats['q3'], stats['mean']])

    # Set Y-axis range
    ax2.set_ylim(Y_MIN_MARGIN, Y_MAX_MARGIN)

    # Prepare mean data for line plot for each baseline
    baseline_mean_positions = {baseline: [] for baseline in baselines}

    # Draw boxplot
    for sub_scenario in sub_scenarios:
        for j, baseline in enumerate(baselines):
            if baseline in time_stats_all[sub_scenario]:
                stats = time_stats_all[sub_scenario][baseline]
                x_pos = x_positions[sub_scenario][j]
                baseline_mean_positions[baseline].append((x_pos, stats['mean']))

                # IQR box - add pattern fill
                rect = Rectangle(
                    (x_pos - BOX_WIDTH / 2, stats['q1']),
                    BOX_WIDTH,
                    stats['q3'] - stats['q1'],
                    facecolor=baseline_colors[baseline],
                    edgecolor=edge_colors[baseline],
                    linewidth=IQR_LINEWIDTH,
                    hatch=hatch_patterns[baseline],  # New: add pattern
                    hatch_linewidth=HATCH_LINE_WIDTH,
                    zorder=4
                )
                ax2.add_patch(rect)

                # Whiskers
                ax2.vlines(
                    x_pos, stats['min'], stats['q1'],
                    colors=edge_colors[baseline],
                    linewidth=1,
                    zorder=2
                )
                ax2.vlines(
                    x_pos, stats['q3'], stats['max'],
                    colors=edge_colors[baseline],
                    linewidth=1,
                    zorder=2
                )

                # Mean point and line - use different marker styles
                ax2.plot(
                    x_pos, stats['mean'],
                    marker=marker_styles[baseline],  # Use different markers
                    color=edge_colors[baseline],
                    markersize=POINTSIZE+5,  # Slightly larger
                    zorder=6,
                    markeredgecolor='black',  # Black border for contrast
                    markeredgewidth=0.5
                )
                ax2.hlines(
                    stats['mean'],
                    x_pos - BOX_WIDTH / 2,
                    x_pos + BOX_WIDTH / 2,
                    colors=edge_colors[baseline],
                    linewidth=1.2,
                    zorder=5
                )

    # === Draw mean line for each baseline ===
    mean_trend_lines = []
    for baseline in baselines:
        if baseline_mean_positions[baseline]:
            positions = sorted(baseline_mean_positions[baseline], key=lambda x: x[0])
            x_coords = [pos[0] for pos in positions]
            y_coords = [pos[1] for pos in positions]

            # Draw line, using different line styles and markers
            line, = ax2.plot(
                x_coords, y_coords,
                color=edge_colors[baseline],
                linestyle=line_styles[baseline],  # Use different line styles
                linewidth=TREND_LING_LINEWIDTH,
                marker=marker_styles[baseline],  # Use different markers
                markersize=0,#POINTSIZE+5,
                zorder=3,
                markeredgecolor='black',  # Black border for contrast
                markeredgewidth=0.5,
                label=f'{mapping.get(baseline, baseline)}'
            )
            mean_trend_lines.append(line)

    # === Axis settings ===
    plt.rcParams['text.usetex'] = True
    ax1.set_xticks(x_ticks)
    x_tick_labels = []
    num_opts_comments = {
        '1': '3 options',
        '2': '3 options',
        '3': '4 options',
        '4': '4 options',
        '5': '4 options'
    }

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

    # Set tick label size
    ax1.tick_params(axis='x', labelsize=TICK_LABEL_SIZE)
    ax1.tick_params(axis='y', labelsize=TICK_LABEL_SIZE)
    ax2.tick_params(axis='y', labelsize=TICK_LABEL_SIZE)

    ax1.ticklabel_format(style='sci', axis='y', scilimits=(0, 0))
    ax2.ticklabel_format(style='sci', axis='y', scilimits=(0, 0))
    ax2.locator_params(axis='y', nbins=10)
    ax1.yaxis.set_major_locator(MultipleLocator(5e4))
    ax1.yaxis.set_minor_locator(AutoMinorLocator()) #sub ticks

    # Set x-axis range
    ax1.set_xlim(-X_BLOCK_WIDTH, current_pos - GROUP_SPACING + X_BLOCK_WIDTH)

    # # === Legend ===
    # # Create custom legend handles for black and white display
    # from matplotlib.patches import Patch
    # from matplotlib.lines import Line2D
    #
    # # Create combined legend: display both color and pattern
    # legend_elements = []
    # for baseline in baselines:
    #     if baseline in baseline_colors:
    #         legend_elements.append(
    #             Patch(
    #                 facecolor=baseline_colors[baseline],
    #                 edgecolor=edge_colors[baseline],
    #                 hatch=hatch_patterns[baseline],
    #                 label=mapping.get(baseline, baseline),
    #                 linewidth=0.5
    #             )
    #         )
    #
    # # Or use line plot legend (already includes line style and marker)
    # # Place legend in appropriate position
    # ax1.legend(
    #     handles=legend_elements,
    #     loc='center right',
    #     title='Long-term Cost',#Methods
    #     title_fontsize=FONT_SIZE_LEGEND_TITLE,
    #     fontsize=FONT_SIZE_LEGEND,
    #     frameon=True,
    #     handlelength=2.0,
    #     handleheight=1.5,
    #     labelspacing=0.3,
    #     borderpad=0.5,
    #     handletextpad=0.8
    # )

    # Enable horizontal dashed background
    for y in np.arange(0, RECT_YLIM, DOT_HLINE_DENSITY):
        ax1.axhline(
            y=y,
            color='gray',
            linestyle='--',
            linewidth=0.75,
            alpha=0.0,#0.15
            zorder=0
        )

    ax1.set_axisbelow(True)
    fig.tight_layout()

    # Save
    plt.savefig('experiments/plots/RQ1_SEFA.png', dpi=200)

    plt.show()

from matplotlib.ticker import MultipleLocator, FormatStrFormatter, AutoMinorLocator

def plot_rq2_all_subscenarios(time_stats_all, cost_values_all):
    """
    Plot all sub-scenarios of RQ1 in one figure
    """
    # ───────────────────────────────────────
    # 🎛️ Configurable parameters
    # ───────────────────────────────────────
    FIG_SIZE = (6.7, 6.7)#(7.5, 6.7)
    BAR_WIDTH = 0.1#0.12 0.1 #rectangle
    BOX_WIDTH = 0.1 #box
    GROUP_SPACING = 0.16 #group spacing
    X_BLOCK_WIDTH = 0.07 #both sides width
    IQR_LINEWIDTH = 0.8 #box line

    # New: Pattern parameters (for black and white display)
    HATCH_LINE_WIDTH = 0.5  # Pattern line thickness

    POINTSIZE = 2
    Y_MIN_MARGIN_RATIO = config[0]
    Y_MARGIN_RATIO = config[1]# 1.6 1.8 #Time axis compression ratio
    RECT_YLIM = config[3]#1100000 900000
    RECT_YMIN = config[2]
    DOT_HLINE_DENSITY = config[5]

    FONT_SIZE_TICK = 25 #axis title
    TICK_LABEL_SIZE = 22 #axis tick font
    FONT_SIZE_LEGEND = 15 #legend item font
    FONT_SIZE_LEGEND_TITLE = 18 #legend title

    colors ={'red': (163/255, 81/255, 57/255),
             'dark pink': (202/255, 162/255, 173/255),
             'dark orange': (238/255, 197/255, 160/255),
             'dark purple': (182/255, 175/255, 197/255),
             'dark cyan-blue': (182/255, 207/255, 212/255),
             'cyan-blue': (225/255, 241/255, 246/255),
             'purple': (230/255, 226/255, 245/255),
             'orange': (249/255, 235/255, 221/255),
             'pink': (246/255, 223/255, 224/255),
             'pink_red': (221/255, 185/255, 172/255)}

    # Color configuration - assign fixed colors to each baseline
    baseline_colors = {
        'AQUA': colors.get('cyan-blue'),
        'SAQURE_nodyPa': colors.get('orange'),
        'SAQURE': colors.get('pink_red')
    }
    edge_colors = {
        'AQUA': colors.get('dark cyan-blue'),
        'SAQURE_nodyPa': colors.get('dark orange'),
        'SAQURE': colors.get('red')
    }
    # New: Assign different fill patterns to each baseline (for black and white display)
    hatch_patterns = {
        'AQUA': '///',      # slash
        'SAQURE_nodyPa': '\\\\\\',    # backslash
        'SAQURE': '', # horizontal line
    }

    # New: Assign different marker styles to each baseline (for black and white display)
    marker_styles = {
        'AQUA': 'o',        # circle
        'SAQURE_nodyPa': 's',         # square
        'SAQURE': 'D',  # triangle up
    }

    mapping = {
        'AQUA': 'AQUA',
        'SAQURE_nodyPa': 'SAQURE$^{-}_{dyPa}$',
        'SAQURE': 'SAQURE'
    }

    # ───────────────────────────────────────
    # Data preparation
    # ───────────────────────────────────────
    sub_scenarios = list(time_stats_all.keys())
    baselines = list(time_stats_all[sub_scenarios[0]].keys())

    # Calculate x-axis positions
    x_positions = {}
    x_ticks = []
    current_pos = 0

    for i, sub_scenario in enumerate(sub_scenarios):
        scenario_positions = []
        for j, baseline in enumerate(baselines):
            pos = current_pos + j * (BAR_WIDTH + 0.02)
            scenario_positions.append(pos)
        x_positions[sub_scenario] = scenario_positions
        # Sub-scenario label position in the middle of the group
        x_ticks.append(np.mean(scenario_positions))
        current_pos = max(scenario_positions) + GROUP_SPACING

    # === Create figure ===
    fig, ax1 = plt.subplots(figsize=FIG_SIZE)
    ax2 = ax1.twinx()

    # === Draw Cost bar chart ===
    bars = []
    bar_labels = []
    for sub_scenario in sub_scenarios:
        for j, baseline in enumerate(baselines):
            if baseline in cost_values_all[sub_scenario]:
                x_pos = x_positions[sub_scenario][j]
                bar = ax1.bar(x_pos, cost_values_all[sub_scenario][baseline],
                              width=BAR_WIDTH, color=baseline_colors[baseline],
                              edgecolor=edge_colors[baseline],
                              hatch=hatch_patterns[baseline],  # Add pattern fill
                              hatch_linewidth=HATCH_LINE_WIDTH,  # Set pattern line thickness
                              zorder=2, label=baseline if sub_scenario == sub_scenarios[0] else "")
                if sub_scenario == sub_scenarios[0]:
                    bars.append(bar)
                    bar_labels.append(mapping.get(baseline, baseline))

    # === Draw Time boxplot ===
    all_time_values = []
    for sub_scenario in sub_scenarios:
        for baseline in baselines:
            if baseline in time_stats_all[sub_scenario]:
                stats = time_stats_all[sub_scenario][baseline]
                all_time_values.extend([stats['min'], stats['max'], stats['q1'], stats['q3'], stats['mean']])

    # Set Y-axis range
    if all_time_values:
        y_min = min(all_time_values)
        y_max = max(all_time_values)
        ax2.set_ylim(y_min * Y_MIN_MARGIN_RATIO, y_max * Y_MARGIN_RATIO)

    # Prepare mean data for line plot for each baseline
    baseline_mean_positions = {baseline: [] for baseline in baselines}

    # Draw boxplot
    for sub_scenario in sub_scenarios:
        for j, baseline in enumerate(baselines):
            if baseline in time_stats_all[sub_scenario]:
                stats = time_stats_all[sub_scenario][baseline]
                x_pos = x_positions[sub_scenario][j]
                baseline_mean_positions[baseline].append((x_pos, stats['mean']))

                # IQR box - add pattern fill
                rect = Rectangle(
                    (x_pos - BOX_WIDTH / 2, stats['q1']),
                    BOX_WIDTH,
                    stats['q3'] - stats['q1'],
                    facecolor=baseline_colors[baseline],
                    edgecolor=edge_colors[baseline],
                    linewidth=IQR_LINEWIDTH,
                    hatch=hatch_patterns[baseline],  # Add pattern
                    hatch_linewidth=HATCH_LINE_WIDTH,  # Set pattern line thickness
                    zorder=4
                )
                ax2.add_patch(rect)

                # Whiskers
                ax2.vlines(x_pos, stats['min'], stats['q1'], colors=edge_colors[baseline], linewidth=1, zorder=2)
                ax2.vlines(x_pos, stats['q3'], stats['max'], colors=edge_colors[baseline], linewidth=1, zorder=2)

                # Mean point and line - use different marker styles
                ax2.plot(x_pos, stats['mean'],
                         marker=marker_styles[baseline],  # Use different markers
                         color=edge_colors[baseline],
                         markersize=POINTSIZE+5 if marker_styles[baseline] else POINTSIZE,  # Slightly larger
                         zorder=6,
                         markeredgecolor='black' if marker_styles[baseline] else None,  # Black border for contrast
                         markeredgewidth=0.5 if marker_styles[baseline] else 0)
                ax2.hlines(stats['mean'], x_pos - BOX_WIDTH / 2, x_pos + BOX_WIDTH / 2,
                           colors=edge_colors[baseline], linewidth=1.2, zorder=5)

    # === Draw mean line for each baseline ===
    # mean_trend_lines = []
    # for baseline in baselines:
    #     proxy = Line2D(
    #         [], [],
    #         color=edge_colors[baseline],
    #         marker='o',
    #         linestyle='-',
    #         linewidth=1.0, #Legend line width
    #         markersize=POINTSIZE,
    #         label=f'{mapping.get(baseline, baseline)}'
    #     )
    #     mean_trend_lines.append(proxy)

    # === Axis settings ===
    plt.rcParams['text.usetex'] = True
    ax1.set_xticks(x_ticks)
    x_tick_labels = []
    num_opts_comments={
        # '1': '3 options',
        # '2': '3 options'
    }

    for ss in sub_scenarios:
        main_part = ss[0:-1]
        num = ss[-1]
        if num_opts_comments:
            x_tick_label = f'{main_part}$_{num}$'+ f' ({num_opts_comments.get(num)})'
        else:
            x_tick_label = f'{main_part}$_{num}$'
        x_tick_labels.append(x_tick_label)
    ax1.set_xticklabels(x_tick_labels)
    #     ax1.set_xlabel('Sub-scenario')
    ax1.set_ylabel('Long-term Cost (unitless)', fontsize=FONT_SIZE_TICK)
    ax2.set_ylabel('Runtime Decision Time (ms)', fontsize=FONT_SIZE_TICK)
    ax1.set_ylim(RECT_YMIN, RECT_YLIM)

    # Force display ticks in units
    ax1.yaxis.set_major_locator(MultipleLocator(config[6]))

    # Enable scientific notation
    ax1.ticklabel_format(style='sci', axis='y', scilimits=(0,0))
    ax2.ticklabel_format(style='sci', axis='y', scilimits=(0,0))

    # ============ Font size ============
    ax1.tick_params(axis='both', which='major', labelsize=TICK_LABEL_SIZE)
    ax2.tick_params(axis='y',     which='major', labelsize=TICK_LABEL_SIZE)

    # Set x-axis range
    ax1.set_xlim(-X_BLOCK_WIDTH, current_pos - GROUP_SPACING + X_BLOCK_WIDTH)

    # # === Legend ===
    # # Create combined legend: maintain colors consistent with rectangles
    # legend_elements = []
    # for baseline in baselines:
    #     if baseline in baseline_colors:
    #         # Create rectangle legend element, maintain same colors as in the figure
    #         rect_legend = Patch(
    #             facecolor=baseline_colors[baseline],  # Match bar chart fill color
    #             edgecolor=edge_colors[baseline],      # Match bar chart border color
    #             hatch=hatch_patterns[baseline],       # Same pattern
    #             label=mapping.get(baseline, baseline),
    #             linewidth=IQR_LINEWIDTH               # Match boxplot border line width
    #         )
    #         legend_elements.append(rect_legend)
    #
    # # Place legend in appropriate position
    # ax1.legend(
    #     handles=legend_elements,
    #     loc='center right',
    #     title='Methods',
    #     title_fontsize=FONT_SIZE_LEGEND_TITLE,
    #     fontsize=FONT_SIZE_LEGEND,
    #     frameon=True,
    #     handlelength=2.0,
    #     handleheight=1.5,
    #     labelspacing=0.3,
    #     borderpad=0.5,
    #     handletextpad=0.8,
    #     # Legend box style settings
    #     edgecolor='lightgray',  # Legend border color
    #     framealpha=0.9          # Legend background transparency
    # )

    # === Title and layout ===
    #     plt.title(f'TS-RQ1: Cost vs Time Distribution Across All Sub-scenarios', fontsize=15, pad=20)
    # Enable horizontal dashed background
    for y in np.arange(0, RECT_YLIM, DOT_HLINE_DENSITY):
        ax1.axhline(
            y=y,
            color='gray',
            linestyle='--',
            linewidth=0.75,
            alpha=0.15,
            zorder=0
        )
    # Place grid lines at the bottom layer to avoid covering bars
    ax1.set_axisbelow(True)

    fig.tight_layout()
    plt.savefig('experiments/plots/'+config[4],
                dpi=200)
    plt.show()

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('--experiment', type=str, choices=['RQ1', 'RQ2', 'RQ3.1', 'RQ3.2','RQ4'],
                        required=True)

    args = parser.parse_args()

    experiments_RQ1 = {
        'RQ1': {'S1': ['QoS', 'AQUA', 'SAQURE_seq', 'SAQURE_para'],
                'S2': ['QoS', 'AQUA', 'SAQURE_seq', 'SAQURE_para'],
                'S3': ['QoS', 'AQUA', 'SAQURE_seq', 'SAQURE_para'],
                'S4': ['QoS', 'AQUA', 'SAQURE_seq', 'SAQURE_para'],
                'S5': ['QoS', 'AQUA', 'SAQURE_seq', 'SAQURE_para']
                }
    }
    experiments_RQ2 = {
        'S1_Part1': {
            "T1":['AQUA', 'SAQURE'],
            "T2":['AQUA', 'SAQURE']
        },
        'S1_Part2': {
            "T1":['SAQURE_nodyPa', 'SAQURE'],
            "T2":['SAQURE_nodyPa', 'SAQURE']
        },
        'S2_Part1': {
            "T1":['AQUA', 'SAQURE'],
            "T2":['AQUA', 'SAQURE']
        },
        'S2_Part2': {
            "T1":['SAQURE_nodyPa', 'SAQURE'],
            "T2":['SAQURE_nodyPa', 'SAQURE']
        },
        'S3_Part1': {
            "T1":['AQUA', 'SAQURE'],
            "T2":['AQUA', 'SAQURE']
        },
        'S3_Part2': {
            "T1":['SAQURE_nodyPa', 'SAQURE'],
            "T2":['SAQURE_nodyPa', 'SAQURE']
        }
    }

    experiments_RQ31 = {
        "Experiment1": {'S1': ['AQUA', 'SAQURE'],
                        'S2': ['AQUA', 'SAQURE'],
                        'S3': ['AQUA', 'SAQURE'],
                        'S4': ['AQUA', 'SAQURE'],
                        'S5': ['AQUA', 'SAQURE'],
                        'S6': ['AQUA', 'SAQURE'],
                        'S7': ['AQUA', 'SAQURE'],
                        'S8': ['AQUA', 'SAQURE'],
                        'S9': ['AQUA', 'SAQURE'],
                        'S10': ['AQUA', 'SAQURE'],
                        'S11': ['AQUA', 'SAQURE'],
                        'S12': ['AQUA', 'SAQURE'],
                        'S13': ['AQUA', 'SAQURE'],
                        'S14': ['AQUA', 'SAQURE'],
                        'S15': ['AQUA', 'SAQURE']
                        }
    }

    experiments_RQ32 = {
        "Experiment2": {'S1': ['AQUA', 'SAQURE'],
                        'S2': ['AQUA', 'SAQURE'],
                        'S3': ['AQUA', 'SAQURE'],
                        'S4': ['AQUA', 'SAQURE'],
                        'S5': ['AQUA', 'SAQURE'],
                        'S6': ['AQUA', 'SAQURE'],
                        'S7': ['AQUA', 'SAQURE'],
                        'S8': ['AQUA', 'SAQURE'],
                        'S9': ['AQUA', 'SAQURE'],
                        'S10': ['AQUA', 'SAQURE'],
                        'S11': ['AQUA', 'SAQURE'],
                        'S12': ['AQUA', 'SAQURE'],
                        'S13': ['AQUA', 'SAQURE'],
                        'S14': ['AQUA', 'SAQURE'],
                        'S15': ['AQUA', 'SAQURE'],
                        'S16': ['AQUA', 'SAQURE'],
                        'S17': ['AQUA', 'SAQURE'],
                        'S18': ['AQUA', 'SAQURE'],
                        'S19': ['AQUA', 'SAQURE'],
                        'S20': ['AQUA', 'SAQURE'],
                        'S21': ['AQUA', 'SAQURE']
                        }
    }

    experiments_RQ4 = {
        'Experiment2': {'S1': ['SAQURE'], 'S2': ['SAQURE'], 'S3': ['SAQURE'], 'S4': ['SAQURE'], 'S5': ['SAQURE'], 'S6': ['SAQURE'], 'S7': ['SAQURE'], 'S8': ['SAQURE'], 'S9': ['SAQURE'], 'S10': ['SAQURE'], 'S11': ['SAQURE'], 'S12': ['SAQURE'], 'S13': ['SAQURE'], 'S14': ['SAQURE'], 'S15': ['SAQURE'], 'S16': ['SAQURE'], 'S17': ['SAQURE'], 'S18': ['SAQURE'], 'S19': ['SAQURE'], 'S20': ['SAQURE'], 'S21': ['SAQURE']}
    }

    # Process RQ2 experiment
    if args.experiment == 'RQ2':
        configs = {
            'S1_Part1':[0.0, #Time axis compression ratio min
                        1.02, #Time axis expansion ratio max
                        2e5, #ymin
                        6e5, #ylim
                        'RQ2_SEFA_S1_Part1.png',
                        5e3, #dot_density
                        5e4 ], #y_settick
            'S1_Part2':[0.0, #Time axis compression ratio min
                        1.02, #Time axis expansion ratio max
                        2e5, #ymin
                        6e5, #ylim
                        'RQ2_SEFA_S1_Part2.png',
                        5e3, #dot_density
                        5e4 ], #y_settick
            'S2_Part1':[0.0, 1.08, 2e5, 6e5, 'RQ2_SEFA_S2_Part1.png', 5e3, 5e4],
            'S2_Part2':[0.0, 1.08, 2e5, 6e5, 'RQ2_SEFA_S2_Part2.png', 5e3, 5e4],
            'S3_Part1':[0.0, 1.13, 2e5, 6e5, 'RQ2_SEFA_S3_Part1.png', 5e3, 5e4],
            'S3_Part2':[0.0, 1.13, 2e5, 6e5, 'RQ2_SEFA_S3_Part2.png', 5e3, 5e4]
        }
        for item, times in experiments_RQ2.items():
            sub_scenario = item[:2]
            print(f"=== {sub_scenario} ===")

            time_stats_all = {}
            cost_values_all = {}
            config = configs[item]
            print(config)

            folder_path_SAQURE_T1 = f"SAQURE-simulator/results/rq2_logs/{sub_scenario}/T1/SAQURE"
            if os.path.exists(folder_path_SAQURE_T1):
                time_SAQURE_T1, cost_SAQURE_T1, option_SAQURE_T1 = calculate_statistics_for_folder(folder_path_SAQURE_T1, False)
                print('option_SAQURE_T1: '+option_SAQURE_T1)
            else:
                print(f"Folder does not exist: {folder_path_SAQURE_T1}")

            # Process each sub-scenario separately
            for time, baselines in times.items():
                print(f"=== Sub-scenario: {time} ===")

                time_stats_all[time] = {}
                cost_values_all[time] = {}
                folder_path_SAQURE = f"SAQURE-simulator/results/rq2_logs/{sub_scenario}/{time}/SAQURE"
                if os.path.exists(folder_path_SAQURE):
                    time_SAQURE, cost_SAQURE, option_SAQURE = calculate_statistics_for_folder(folder_path_SAQURE, False)
                    print('option_SAQURE:: '+option_SAQURE)
                else:
                    print(f"Folder does not exist: {folder_path_SAQURE}")

                # Process each baseline separately
                for baseline_name in baselines:
                    print(f"=== Baseline: {baseline_name} ===")
                    folder_path = f"SAQURE-simulator/results/rq2_logs/{sub_scenario}/{time}/{baseline_name}"

                    if os.path.exists(folder_path):
                        statistics, best_cost, best_option = calculate_statistics_for_folder(folder_path, False)
                        if statistics:  # Ensure valid data exists
                            time_stats_all[time][baseline_name] = statistics
                            if baseline_name == "AQUA":
                                cost_values_all[time]['AQUA'] =extract_cost_from_SAQURE(folder_path_SAQURE_T1, best_option)
                                print('when baselinename = AQUA, '+f'cost_SAQURE_{time}_AQUA: {cost_SAQURE_T1}\n best_option: {best_option}')
                            else:
                                if best_option == option_SAQURE: #Use own time, cost from SAQURE
                                    cost_values_all[time][baseline_name] = cost_SAQURE
                                    print('when option is same, '+f'cost_SAQURE_{time}_{baseline_name}: {cost_SAQURE}\n best_option: {best_option}')
                                else: #Extract cost matching own best option from SAQURE log
                                    cost_values_all[time][baseline_name] = extract_cost_from_SAQURE(folder_path_SAQURE, best_option)
                                    print('when option is different, '+f'cost_SAQURE_{time}_{baseline_name}: {extract_cost_from_SAQURE(folder_path_SAQURE, best_option)}\n best_option: {best_option}')
                        else:
                            print(f"Warning: {baseline_name} has no valid data")
                    else:
                        print(f"Folder does not exist: {folder_path}")

            # Plot only when data exists
            if time_stats_all and cost_values_all:
                plot_rq2_all_subscenarios(time_stats_all, cost_values_all)
            else:
                print(f"== {sub_scenario} has no valid data, skipping plot ==")

    # Process unified comparison experiment
    if args.experiment == 'RQ1':
        for experiment, sub_scenarios in experiments_RQ1.items():
            print(f"=== {experiment} ===")

            time_stats_all = {}
            cost_values_all = {}

            # Process each sub-scenario separately
            for sub_scenario, baselines in sub_scenarios.items():
                print(f"=== Sub-scenario: {sub_scenario} ===")

                time_stats_all[sub_scenario] = {}
                cost_values_all[sub_scenario] = {}

                folder_path_SAQURE = f"SAQURE-simulator/results/rq1_logs/{sub_scenario}/SAQURE_para"
                if os.path.exists(folder_path_SAQURE):
                    time_SAQURE, cost_SAQURE, option_SAQURE = calculate_statistics_for_folder(folder_path_SAQURE, False)
                    print('option_SAQURE:: '+option_SAQURE)
                else:
                    print(f"Folder does not exist: {folder_path_SAQURE}")

                # Process each baseline separately
                for baseline_name in baselines:
                    print(f"=== Baseline: {baseline_name} ===")
                    folder_path = f"SAQURE-simulator/results/rq1_logs/{sub_scenario}/{baseline_name}"

                    if os.path.exists(folder_path):
                        if "SAQURE-longcul" in baseline_name:
                            statistics, best_cost, best_option = calculate_statistics_for_folder(folder_path, True)
                        #                             statistics = {k: v * 10000 for k,v in statistics.items()}
                        #                             best_cost *= 50000
                        else:
                            statistics, best_cost, best_option = calculate_statistics_for_folder(folder_path, False)
                        if statistics:  # Ensure valid data exists
                            time_stats_all[sub_scenario][baseline_name] = statistics
                            if best_option == option_SAQURE: #Use own time, cost from SAQURE
                                cost_values_all[sub_scenario][baseline_name] = cost_SAQURE
                                print(f'cost_SAQURE_{sub_scenario}_{baseline_name}: {cost_SAQURE}\n best_option: {best_option}')
                            else:
                                cost_values_all[sub_scenario][baseline_name] = extract_cost_from_SAQURE(folder_path_SAQURE, best_option)
                                print(f'cost_SAQURE_{sub_scenario}_{baseline_name}: {extract_cost_from_SAQURE(folder_path_SAQURE, best_option)}\n best_option: {best_option}')
                        else:
                            print(f"Warning: {baseline_name} has no valid data")
                    else:
                        print(f"Folder does not exist: {folder_path}")

            # Plot only when data exists
            if time_stats_all and cost_values_all:
                plot_rq1_all_subscenarios(time_stats_all, cost_values_all, experiment)
            else:
                print(f"== {experiment} has no valid data, skipping plot ==")

    elif args.experiment == 'RQ3.1':
        for e in [experiments_RQ31]:
            for experiment, sub_scenarios in e.items():
                print(f"=== {experiment} ===")

                time_stats_all = {}
                cost_values_all = {}

                # Process each sub-scenario separately
                for sub_scenario, baselines in sub_scenarios.items():
                    print(f"=== Sub-scenario: {sub_scenario} ===")

                    time_stats_all[sub_scenario] = {}
                    cost_values_all[sub_scenario] = {}

                    # Process each baseline separately
                    for baseline_name in baselines:
                        print(f"=== Baseline: {baseline_name} ===")
                        folder_path = f"SAQURE-simulator/results/rq3_logs/{experiment}/{sub_scenario}/{baseline_name}"

                        if os.path.exists(folder_path):
                            if "SAQURE-longcul" in baseline_name:
                                statistics, best_cost, best_option = calculate_statistics_for_folder(folder_path, True)
                            #                             statistics = {k: v * 10000 for k,v in statistics.items()}
                            #                             best_cost *= 50000
                            else:
                                statistics, best_cost, best_option = calculate_statistics_for_folder(folder_path, False)
                            if statistics:  # Ensure valid data exists
                                time_stats_all[sub_scenario][baseline_name] = statistics
                                cost_values_all[sub_scenario][baseline_name] = best_cost
                            else:
                                print(f"Warning: {baseline_name} has no valid data")
                        else:
                            print(f"Folder does not exist: {folder_path}")

                # Plot only when data exists
                if time_stats_all:
                    plot_rq31_all_subscenarios(time_stats_all, experiment)
                else:
                    print(f"== {experiment} has no valid data, skipping plot ==")

    if args.experiment == 'RQ3.2':
        for e in [experiments_RQ32]:
            for experiment, sub_scenarios in e.items():
                print(f"=== {experiment} ===")

                time_stats_all = {}
                cost_values_all = {}

                # Process each sub-scenario separately
                for sub_scenario, baselines in sub_scenarios.items():
                    print(f"=== Sub-scenario: {sub_scenario} ===")

                    time_stats_all[sub_scenario] = {}
                    cost_values_all[sub_scenario] = {}

                    # Process each baseline separately
                    for baseline_name in baselines:
                        print(f"=== Baseline: {baseline_name} ===")
                        folder_path = f"SAQURE-simulator/results/rq3_logs/{experiment}/{sub_scenario}/{baseline_name}"

                        if os.path.exists(folder_path):
                            if "SAQURE-longcul" in baseline_name:
                                statistics, best_cost, best_option = calculate_statistics_for_folder(folder_path, True)
                            else:
                                statistics, best_cost, best_option = calculate_statistics_for_folder(folder_path, False)
                            if statistics:  # Ensure valid data exists
                                time_stats_all[sub_scenario][baseline_name] = statistics
                                cost_values_all[sub_scenario][baseline_name] = best_cost
                            else:
                                print(f"Warning: {baseline_name} has no valid data")
                        else:
                            print(f"Folder does not exist: {folder_path}")

                # Plot only when data exists
                if time_stats_all:
                    plot_rq32_all_subscenarios(time_stats_all, experiment)
                else:
                    print(f"== {experiment} has no valid data, skipping plot ==")

    if args.experiment == 'RQ4':
        for experiment, sub_scenarios in experiments_RQ4.items():
            print(f"\n====== EADSA-only process for {experiment} ======")

            eadsa_stats_all = {}

            # Iterate through all S
            for sub_scenario, baselines in sub_scenarios.items():
                print(f"--- Sub-scenario: {sub_scenario}")

                eadsa_stats_all[sub_scenario] = {}

                # Process only if SAQURE exists in this S
                if "SAQURE" in baselines:

                    folder_path = (
                        f"SAQURE-simulator/results/rq3_logs/{experiment}/{sub_scenario}/SAQURE"
                    )

                    if not os.path.exists(folder_path):
                        print(f"❗ Folder not found: {folder_path}")
                        continue

                    # Calculate EADSA time for SAQURE
                    eadsa_stats = calculate_eadsa_statistics_for_folder(folder_path)

                    if eadsa_stats:
                        eadsa_stats_all[sub_scenario] = eadsa_stats
                    else:
                        print(f"No valid EADSA time detected in {folder_path}")

            # Plot after processing all S
            if eadsa_stats_all:
                plot_eadsa_boxplot(eadsa_stats_all, experiment)
            else:
                print(f"No EADSA data found for experiment {experiment}, skip plotting.")