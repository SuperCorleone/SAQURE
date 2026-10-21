# SAQURE — replication package

This package contains the raw data as well as scripts used to replicate the results presented in the following research paper:

"SAQURE: AI Planning-Driven Self-Adaptation for Runtime Security and QoS of Microservice Applications", Anonymous Author(s)

This branch (`TeaStore`) holds the TeaStore package, which the paper evaluates in RQ1 and RQ2. The SEFA package, including RQ3 and RQ4, is on the [`SEFA`](https://github.com/SuperCorleone/SAQURE/tree/SEFA) branch.


### Structure
This replication package contains the implementation of `SAQURE` (Java sources), together with all experimental scripts, raw logs, plot-generation code, and the **AED** dataset. The directory layout is as follows:
- `SAQURE_Replication_Package_TeaStore/`:
    - `SAQURE-simulator/`: Gradle project of `SAQURE`, including the implementation of the MAPE-K (Monitor, Analyzer, Planner) modules for TeaStore.
        - `prism/`: the `PRISM` 4.8.1 model checker, used by the Planner module to compute long-term cumulative costs for adaptation option selection.
        - `Metric-FF/`: A fixed `Metric-FF 2.0` tool package, invoked by the `EADSA` of the Analyzer module for generating Attack Paths (APs).
        - `src/`: Java sources implementing the MAPE-K loop (`SaqureSimulatorApplication` entry point).
          - `Analyzer/`: Analyzer module, including `EADSA` (Environment-Aware Dynamic Security Assessment) and service–vulnerability lookup files.
          - `Planner/`: Planner module wrapping the `PRISM` model checker for adaptation-option selection.
          - `Knowledge/`: Knowledge base containing `AED`/`AEDI` PDDL domain definitions and `DTMC` models.
          - `utils/`: Shared utilities for AED processing, infrastructure modelling, and simulation support.
        - `AED/`, `AEDI/`, `AP/`: Runtime PDDL domain files, AED Instance files, and generated Attack Paths, organised per research question.
        - `results/`: Experiment output logs (`rq1_logs/`, `rq2_logs/`).
    - `run_experiments.sh`: Bash script for reproducing the experiments.
    - `create_plots.py`: Python script that generates the plots from the produced logs/results.
    - `experiments/`:
      - `experiment_config/`: Configuration spreadsheets (`.xlsx`).
      - `plots/adaptation_gain/`: The RQ1 and RQ2 figures of the paper.
- `AED/`: the extensible, generic Adversarial Environment Domain (AED) released with the paper.
    - `vulnerabilities_100.md`: the complete list of the 100 vulnerabilities of the AED (CVSS, affected component, and whether a vulnerability was specified by experts or generated with CVE2AP). Table 2 of the paper lists five of them.
    - `AED.pddl`: the AED of the 21 expert-specified vulnerabilities, covering attacker, application, user, and infrastructure behaviors.
    - `AEDIs/`: exemplar AEDIs of SEFA, one problem file per STRIDE threat category.
    - The PDDL action specifications of all 100 vulnerabilities, 1,333 actions in total, are in the SEFA package: [`SAQURE_Replication_Package_SEFA/SAQURE-vulnerability-scalability/pddl-ap-passall/post-proposs/`](https://github.com/SuperCorleone/SAQURE/tree/SEFA/SAQURE_Replication_Package_SEFA/SAQURE-vulnerability-scalability/pddl-ap-passall/post-proposs).
- `Supplementary Experimental Configuration for RQ1, RQ2, and RQ3.pdf`: Supplementary configuration tables for RQ1, RQ2, and RQ3.

### Requirements

- Java 17 (JDK) to build and run `SAQURE`; the Gradle wrapper is included.
- Python 3 with `numpy` and `matplotlib` for the figures, and a LaTeX installation, which the figures use for their text.
- The bundled `PRISM` 4.8.1 and `Metric-FF` builds are for macOS on Apple Silicon, where all experiments were run. The bundled PRISM runs from its own directory and needs no installation step. On another platform, replace `SAQURE-simulator/prism` with PRISM 4.8.1 for that platform and run its `./install.sh`, and rebuild Metric-FF with `make` in `SAQURE-simulator/Metric-FF`.

### Instructions

#### 1. Build

From the directory `SAQURE_Replication_Package_TeaStore/SAQURE-simulator`, run:

```bash
./gradlew clean bootJar
```

#### 2. Run experiments

All experiments are driven by a single script `run_experiments.sh`. From the directory `SAQURE_Replication_Package_TeaStore`, execute:

```bash
# Run the TeaStore experiments of the paper
./run_experiments.sh rq1
./run_experiments.sh rq2
```

Every case is repeated 10 times; `REPEATS` overrides that, e.g. `REPEATS=1 ./run_experiments.sh rq1`. `./run_experiments.sh all` runs `rq1`, `rq2` and `rq3`; the paper reports RQ3 for SEFA only.

Each experiment case is controlled via command-line arguments passed to the Java application:

| Flag | Description | Example |
|------|-------------|---------|
| `-c, --config` | Experiment case name (**required**) | `-c RQ1_SAQURE_para_S1` |
| `-s, --service` | Service name override (auto-detected if omitted) | `-s WEBUI-SERVICE` |
| `-t, --time` | Runtime phase, for RQ2/RQ3 | `-t T2` |

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

Logs are saved under `SAQURE-simulator/results/` with the following directory structure:

```
SAQURE-simulator/results/
├── rq1_logs/S{N}/{approach}/               e.g. S1/SAQURE_para/, S3/AQUA/, S2/RAMSES/
├── rq2_logs/S{N}/{T1|T2}/{approach}/       e.g. S1/T2/SAQURE/, S2/T1/AQUA/
└── rq3_logs/S{N}/{T1|T2}/{approach}/       e.g. S1/T1/SAQURE/, S2/T2/SAQURE_nodyPa/
```

#### 3. Generate plots

From the directory `SAQURE_Replication_Package_TeaStore`, execute:

```bash
# Generate all plots
python3 create_plots.py

# Or generate plots for a specific RQ
python3 create_plots.py --experiment gain   # RQ1-RQ3, plus adaptation_gain_values.csv
python3 create_plots.py --experiment RQ1
python3 create_plots.py --experiment RQ2
```

The figures report the Adaptation Gain and are written to `experiments/plots/adaptation_gain/` as `.png`, next to the `.pdf` versions used in the paper;
`python3 create_plots.py` (or `--experiment gain`) also writes `adaptation_gain_values.csv` there,
with the long-term costs behind each gain.
