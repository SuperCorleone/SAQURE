# SAQURE — replication package

This package contains the raw data as well as scripts used to replicate the results presented in the following research paper:

"SAQURE: Real-Time AI-Driven Environment-Aware Self-Adaptation for Security and QoS", Anonymous Author(s) 


### Structure
This replication package contains the implementation of `SAQURE` (Java sources), together with all experimental scripts, raw logs, plot-generation code, and the **AED** dataset. The directory layout is as follows:
- `SAQURE-simulator/`: Gradle project of `SAQURE`, including the implementation of the MAPE-K (Monitor, Aanalyzer, Planner) modules.
  - `AED/`:
  1. An extensible generic Adversarial Environment Domain `AED.pddl` with ~300 atomic action specifications, covering attacker, application, user, and infrastructure behaviors.
  2. Exemplar `AEDIs/` (e.g., TeaStore instances).
  - `Analyzer/`
    - `EADSA/`: Implementation of `Environment-Aware Dynamic Security Assessment (EADSA)`.
    - `Updater/`: Applies the predefined runtime changes to `AED` or `AEDIs`.
    - `Metric-FF/`: A fixed `Metric-FF 2.0` tool package, invoked by the `EADSA` of the Analyzer module for generating Attack Paths (APs).
  - `SqureSimulatorApplication/`: Simulation of the Planner module.
  - `prism/`: `PRISM` models of `SEFA` and `TeaStore`, as well as corresponding properties used by the Planner module to compute long-term cumulative costs for adaptation option selection.
  - `experiments/`:
    - `run_all_experiments/`: Bash scripts for reproducing the sub-experiments (RQ1, RQ2, RQ3, RQ4) presented in the paper.
    - Configuration? include configuration table? lookup file? AED AEDIs? (where to put this part?)
    - `plots/`: Bash and Python scripts that generate the plots for RQ1–RQ4 from the produced logs/results.
    - `Supplementary Experimental Configuration for RQ1, RQ2, and RQ3.pdf`: Supplementary configuration tables for RQ1, RQ2 and RQ3.

### Instructions

#### 1. Build

You need the [Gradle build tool](https://gradle.org/). From the directory `SAQURE_Replication_Package_TeaStore/SAQURE-simulator`, run:

```bash
./gradlew clean bootJar
```

#### 2. Run experiments

All experiments are driven by a single script `run_experiments.sh`. From the directory `SAQURE_Replication_Package_TeaStore`, execute:

```bash
# Run all experiments (RQ1–RQ4)
./run_experiments.sh all

# Or run a specific RQ
./run_experiments.sh rq1
./run_experiments.sh rq2
./run_experiments.sh rq3
./run_experiments.sh rq4
```

Each experiment case is controlled via command-line arguments passed to the Java application:

| Flag | Description | Example |
|------|-------------|---------|
| `-c, --config` | Experiment case name (**required**) | `-c RQ1_SAQURE_para_S1` |
| `-s, --service` | Service name override (auto-detected if omitted) | `-s RESTAURANT-SERVICE` |
| `-t, --time` | Runtime phase, for RQ2/RQ3 | `-t T2` |
| `-d, --dynamic` | Dynamic parameter value, for RQ4 | `-d 5` |

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
| RQ4 | `RQ4_1_1_SAQURE`, `RQ4_1_1_AQUA`, `RQ4_1_2_SAQURE`, `RQ4_1_2_AQUA` | `-d <param>` |

Logs are saved under `SAQURE-simulator/results/` with the following directory structure:

```
SAQURE-simulator/results/
├── rq1_logs/S{N}/{approach}/               e.g. S1/SAQURE_para/, S3/AQUA/, S2/RAMSES/
├── rq2_logs/S{N}/{T1|T2}/{approach}/       e.g. S1/T2/SAQURE/, S2/T1/AQUA/
├── rq3_logs/S{N}/{T1|T2}/{approach}/       e.g. S1/T1/SAQURE/, S2/T2/SAQURE_nodyPa/
└── rq4_logs/Experiment{1|2}/S{param}/{approach}/  e.g. Experiment1/S5/SAQURE/
```

#### 3. Generate plots

You need [Python 3](https://www.python.org/) with `matplotlib` and `numpy`. From the directory `SAQURE_Replication_Package_TeaStore`, execute:

```bash
# Generate all plots (RQ1–RQ4)
python3 create_plots.py

# Or generate plots for a specific RQ
python3 create_plots.py --experiment RQ1
python3 create_plots.py --experiment RQ2
python3 create_plots.py --experiment RQ3
python3 create_plots.py --experiment RQ4
```

RQ4 can also be plotted individually:

```bash
python3 create_plots.py --experiment RQ4.1
python3 create_plots.py --experiment RQ4.2
python3 create_plots.py --experiment RQ4_eadsa
```

All plots are generated in `.png` format under the `experiments/plots/` directory.
