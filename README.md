# SAQURE — replication package

This package contains the raw data as well as scripts used to replicate the results presented in the following research paper:

"SAQURE: AI Planning-Driven Self-Adaptation for Runtime Security and QoS of Microservice Applications"

This branch (`SEFA`) holds the SEFA package; the TeaStore package is on the [`TeaStore`](https://github.com/SuperCorleone/SAQURE/tree/TeaStore) branch.


### Structure
This replication package contains the implementation of `SAQURE` (Java sources), together with all experimental scripts, raw logs, plot-generation code, and the **AED** dataset. The directory layout is as follows:
- `AED/`: the extensible, generic Adversarial Environment Domain (AED) released with the paper.
    - `vulnerabilities_100.md`: the complete list of the 100 vulnerabilities of the AED (CVSS, affected component, and whether a vulnerability was specified by experts or generated with CVE2AP). Table 2 of the paper lists five of them.
    - `AED.pddl`: the AED of the 21 expert-specified vulnerabilities, covering attacker, application, user, and infrastructure behaviors.
    - `AEDIs/`: exemplar AEDIs of SEFA, one problem file per STRIDE threat category.
    - `readme.md`: how to generate an attack path from `AED.pddl` and an AEDI with Metric-FF.
- `SAQURE_Replication_Package_SEFA/`:
    - `SAQURE-simulator/`: Gradle project of `SAQURE`, including the implementation of the MAPE-K (Monitor, Analyzer, Planner) modules for SEFA.
        - `prism/`: the `PRISM` 4.8.1 model checker, used by the Planner module to compute long-term cumulative costs for adaptation option selection.
        - `Metric-FF/`: A fixed `Metric-FF 2.0` tool package, invoked by the `EADSA` of the Analyzer module for generating Attack Paths (APs).
        - `src/`: Java sources implementing the MAPE-K loop (`SaqureSimulatorApplication` entry point).
          - `Analyzer/`: Analyzer module, including `EADSA` (Environment-Aware Dynamic Security Assessment) and service–vulnerability lookup files.
          - `Planner/`: Planner module wrapping the `PRISM` model checker for adaptation-option selection.
          - `Knowledge/`: Knowledge base containing `AED`/`AEDI` PDDL domain definitions and `DTMC` models.
          - `utils/`: Shared utilities for AED processing, infrastructure modelling, and simulation support.
        - `AED/`, `AEDI/`, `AP/`: Runtime PDDL domain files, AED Instance files, and generated Attack Paths, organised per research question.
        - `results/`: Experiment output logs (`rq1_logs/`–`rq4_logs/`).
    - `SAQURE-vulnerability-scalability/`: the vulnerability specifications and scripts behind the vulnerability axis of RQ4.
        - `pddl-ap-passall/post-proposs/`: PDDL action specifications of the vulnerabilities, one file per attack path (`<CVE-ID>/AP<k>.pddl`). `expert-authored/` holds the 21 expert-specified vulnerabilities (279 actions); `auto-generated/` holds the vulnerabilities generated with CVE2AP, 79 of which belong to the 100 vulnerabilities of the AED and add 1,054 actions (the other two, CVE-2023-34053 and CVE-2023-34054, do not).
        - `merged_AEDIs/`: the six STRIDE AEDIs of SEFA used on the vulnerability axis.
        - `prepared/`: the problem files derived from them for every attack path and STRIDE goal.
        - `scripts/`: helper scripts, see [RQ4 vulnerability axis](#rq4-vulnerability-axis-1100-cves).
        - `results/offline_config/`: CVE2AP generation logs behind RQ4(3)(i), see [RQ4(3)(i)](#rq43i-offline-configuration-time).
        - `results/vuln_axis/`: logs of a stand-alone timing sweep of attack-path generation (`scripts/vuln_scalability.py`).
    - `Plan/RQ4_option/`: attack paths generated on the options axis of RQ4.
    - `experiments/`:
      - `experiment_config/`: Configuration spreadsheets (`.xlsx`) for RQ1–RQ4.
      - `plots/`: The figures of the paper (`.pdf`, plus `.png` previews).
    - `run_experiments.sh`: Bash script for reproducing the experiments (RQ1–RQ4).
    - `create_plots.py`: Python script that generates the figures from the produced logs/results.
    - `RQ431_plot_offline_config_time.ipynb`: Jupyter notebook that draws the RQ4(3)(i) figure (the same figure as `python3 create_plots.py --experiment RQ431`).
- `Supplementary Experimental Configuration for RQ1, RQ2, and RQ3.pdf`: Supplementary configuration tables for RQ1, RQ2, and RQ3.

### Requirements

- Java 17 (JDK) to build and run `SAQURE`; the Gradle wrapper is included.
- Python 3 with `numpy` and `matplotlib` for the figures, and a LaTeX installation, which the RQ1–RQ3 figures use for their text. The scripts in `SAQURE-vulnerability-scalability/scripts/` also need `openpyxl`; the notebook needs Jupyter.
- The bundled `PRISM` 4.8.1 and `Metric-FF` builds are for macOS on Apple Silicon, where all experiments were run. The bundled PRISM runs from its own directory and needs no installation step. On another platform, replace `SAQURE-simulator/prism` with PRISM 4.8.1 for that platform and run its `./install.sh`, and rebuild Metric-FF with `make` in `SAQURE-simulator/Metric-FF`.

### Instructions

#### 1. Build

From the directory `SAQURE_Replication_Package_SEFA/SAQURE-simulator`, run:

```bash
./gradlew clean bootJar
```

#### 2. Run experiments

All experiments are driven by a single script `run_experiments.sh`. From the directory `SAQURE_Replication_Package_SEFA`, execute:

```bash
# Run all experiments (RQ1–RQ4)
./run_experiments.sh all

# Or run a specific RQ
./run_experiments.sh rq1
./run_experiments.sh rq2
./run_experiments.sh rq3
./run_experiments.sh rq4

# Or run a single RQ4 axis
./run_experiments.sh rq4_option   # number of implementation options (1-15): RQ4(1)(i)
./run_experiments.sh rq4_vuln     # number of vulnerabilities (1-100): RQ4(1)(ii), RQ4(2)(i)
./run_experiments.sh rq4_size     # managed system size (1x-500x): RQ4(1)(iii), RQ4(2)(ii)
```

Every case is repeated 10 times. `REPEATS` (and `VULN_REPEATS` for the decision-time runs of the vulnerability axis) overrides that, e.g. `REPEATS=1 ./run_experiments.sh rq1`, and `START_RUN` sets the first repeat index, so that an interrupted batch can be topped up. On the RQ4 axes, AQUA and SAQURE alternate run by run at every point, so that both see the same machine state. RQ4(3)(i), the offline configuration time, is computed from the CVE2AP generation logs and has no run of its own (see [RQ4(3)(i)](#rq43i-offline-configuration-time)).

Each experiment case is controlled via command-line arguments passed to the Java application:

| Flag | Description | Example |
|------|-------------|---------|
| `-c, --config` | Experiment case name (**required**) | `-c RQ1_SAQURE_para_S1` |
| `-s, --service` | Service name override (auto-detected if omitted) | `-s RESTAURANT-SERVICE` |
| `-t, --time` | Runtime phase, for RQ2/RQ3 | `-t T2` |
| `-d, --dynamic` | Dynamic parameter value, for the RQ4 options and vulnerability axes | `-d 5` |
| `-x, --scale` | SEFA scale factor of the DTMC (default `500`) | `-x 500` |

To run a single experiment case manually:

```bash
java -jar SAQURE-simulator/build/libs/SAQURE-simulator-0.0.1-SNAPSHOT.jar -c <case> [options]
```

**Available experiment cases:**

| RQ | Cases | Options |
|----|-------|---------|
| RQ1 | `RQ1_SAQURE_para_S1`..`S5`, `RQ1_SAQURE_seq_S1`..`S5`, `RQ1_Aqua_s1`..`s5`, `RQ1_RAMSES_s1`..`s5` | — |
| RQ2 | `RQ2_SAQURE_s1`..`s3`, `RQ2_AQUA_s1`..`s3` | `-t T1` or `-t T2` |
| RQ3 | `RQ3_SAQURE_s1`..`s3`, `RQ3_SAQURE_s1_nodyPa`..`s3_nodyPa` | `-t T1` or `-t T2` |
| RQ4(1)(i) | `RQ4_option_SAQURE`, `RQ4_option_AQUA` | `-d <1-15>` (number of payment implementations) |
| RQ4(1)(ii) | `RQ4_vuln_SAQURE`, `RQ4_vuln_AQUA` | `-d <N>` (vulnerabilities per restaurant implementation) |
| RQ4(2)(i) | `RQ4_vuln_risk_wall_SAQURE` | `-d <N>` |
| RQ4(1)(iii) | `RQ4_size_SAQURE`, `RQ4_size_AQUA` | `-x <scale>` |
| RQ4(2)(ii) | `RQ4_size_risk_wall_SAQURE` | `-x <scale>` |

Logs are saved under `SAQURE-simulator/results/` with the following directory structure:

```
SAQURE-simulator/results/
├── rq1_logs/S{N}/{approach}/                          e.g. S1/SAQURE_para/, S3/AQUA/, S2/RAMSES/
├── rq2_logs/S{N}/{T1|T2}/{approach}/                  e.g. S1/T2/SAQURE/, S2/T1/AQUA/
├── rq3_logs/S{N}/{T1|T2}/{approach}/                  e.g. S1/T1/SAQURE/, S2/T2/SAQURE_nodyPa/
└── rq4_logs/
    ├── Option_vs_RuntimeDeTime/S{1-15}/{AQUA|SAQURE}/    RQ4(1)(i)
    ├── Vuln_vs_RuntimeDeTime/S{N}/{AQUA|SAQURE}/         RQ4(1)(ii)
    ├── Vuln_vs_RiskAssessTime/S{N}/SAQURE/               RQ4(2)(i)
    ├── Size_vs_RuntimeDeTime/S{scale}/{AQUA|SAQURE}/     RQ4(1)(iii)
    └── Size_vs_RiskAssessTime/S{scale}/SAQURE/           RQ4(2)(ii)
```

#### 3. Generate plots

From the directory `SAQURE_Replication_Package_SEFA`, execute:

```bash
# Generate all plots (RQ1–RQ4)
python3 create_plots.py

# Or generate plots for a specific RQ
python3 create_plots.py --experiment gain   # RQ1-RQ3, plus adaptation_gain_values.csv
python3 create_plots.py --experiment RQ1
python3 create_plots.py --experiment RQ2
python3 create_plots.py --experiment RQ3
python3 create_plots.py --experiment RQ4    # every RQ4 figure
```

RQ4 can also be plotted individually:

```bash
python3 create_plots.py --experiment RQ4.1      # RQ411_SEFA: decision time vs number of options
python3 create_plots.py --experiment RQ4_vuln   # RQ412_SEFA, RQ421_SEFA: decision / risk assessment time vs number of vulnerabilities
python3 create_plots.py --experiment RQ4_size   # RQ413_SEFA, RQ422_SEFA: decision / risk assessment time vs managed system size
python3 create_plots.py --experiment RQ431      # RQ431_SEFA: offline configuration time vs number of vulnerabilities
```

All plots are generated under the `experiments/plots/` directory; the RQ4 files carry the names used in the paper (`RQ411_SEFA.pdf` … `RQ431_SEFA.pdf`). The RQ1–RQ3
figures report the Adaptation Gain and are written to `experiments/plots/adaptation_gain/` as `.png`, next to the `.pdf` versions used in the paper;
`python3 create_plots.py` (or `--experiment gain`) also writes `adaptation_gain_values.csv` there,
with the long-term costs behind each gain.
