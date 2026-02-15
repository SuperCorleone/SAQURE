# SAQURE — replication package

This package contains the raw data as well as scripts used to replicate the results presented in the following research paper:

"SAQURE: Real-Time AI-Driven Environment-Aware Self-Adaptation for Security and QoS", Anonymous Author(s) 


### Structure
This replication package contains the implementation of `SAQURE` (Java sources), together with all experimental scripts, raw logs, plot-generation code, and the **AED** dataset. The directory layout is as follows:
- `SAQURE-simulator/`: Gradle project of `SAQURE`, including the implementation of the MAPE-K (Monitor, Aanalyzer, Planner) modules.
  - `Analyzer/`
    - `EADSA/`: Implementation of `Environment-Aware Dynamic Security Assessment (EADSA)`.
    - `Updater/`: Applies the predefined runtime changes to `AED` or `AEDIs`.
    - `Metric-FF/`: A fixed `Metric-FF 2.0` tool package, invoked by the `EADSA` of the Analyzer module for generating Attack Paths (APs).
  - `Planner-simulator/`: Simulation of the Planner module.
    - `prism/`: `PRISM` models of `SEFA` and `TeaStore`, as well as corresponding properties used by the Planner module to compute long-term cumulative costs for adaptation option selection.
  - `experiments/`: Bash and Python scripts for reproducing the sub-experiments (RQ1, RQ2, RQ3, RQ4) presented in the paper.
    - Configuration? include configuration table? lookup file? AED AEDIs? (where to put this part?)
- `plots/`: Bash and Python scripts that generate the plots for RQ1–RQ4 from the produced logs/results.
- `AED/`:
  1. An extensible generic Adversarial Environment Domain `AED.pddl` with ~300 atomic action specifications, covering attacker, application, user, and infrastructure behaviors.
  2. Exemplar `AEDIs/` (e.g., SEFA instances).
- `Supplementary Experimental Configuration for RQ1, RQ2, and RQ3.pdf`: Supplementary configuration tables for RQ1, RQ2 and RQ3.

### Instructions

To build the sources of `RAMSES` you need the [Gradle build tool](https://gradle.org/). From the directory `ramses-planner-simulator` you can run:

```
gradle clean build
```

To replicate the results of all the experiments in the paper you can run seperately (which might take few minutes):

```
./experiments/run_experiments/run_all_rq1.sh
./experiments/run_experiments/run_all_rq2.sh
./experiments/run_experiments/run_all_rq3.sh
./experiments/run_experiments/run_all_rq4.sh
```

To generate all plots from the data you need [Python 3](https://www.python.org/). You can run:

```
python3 experiments/plots/create_plot_RQ1.py
python3 experiments/plots/create_plot_RQ2.py
python3 experiments/plots/create_plot_RQ3.py
python3 experiments/plots/create_plot_RQ4.py
```

All the plots are generated in `.png` format in the same directory.
