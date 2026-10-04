# SAQURE — replication package

This package contains the raw data as well as scripts used to replicate the results presented in the following research paper:

"SAQURE: Real-Time AI-Driven Environment-Aware Self-Adaptation for Security and QoS", Anonymous Author(s) 


### Structure
This replication package contains the implementation of `SAQURE` (Java sources), together with all experimental scripts, raw logs, plot-generation code, and the **AED** dataset. The directory layout is as follows:
- `SAQURE-Replication-Package-(SEFA/TeaStore)/`: Gradle project of `SAQURE`, including the implementation of the MAPE-K (Monitor, Aanalyzer, Planner) modules for SEFA/TeaStore.
    - `prism/`: `PRISM` models of `SEFA` and `TeaStore`, as well as corresponding properties used by the Planner module to compute long-term cumulative costs for adaptation option selection.
    - `Metric-FF/`: A fixed `Metric-FF 2.0` tool package, invoked by the `EADSA` of the Analyzer module for generating Attack Paths (APs).
    - `src/`: Java sources implementing the MAPE-K loop (`SaqureSimulatorApplication` entry point).
      - `Analyzer/`: Analyzer module, including `EADSA` (Environment-Aware Dynamic Security Assessment) and service–vulnerability lookup files.
      - `Planner/`: Planner module wrapping the `PRISM` model checker for adaptation-option selection.
      - `Knowledge/`: Knowledge base containing `AED`/`AEDI` PDDL domain definitions and `DTMC` models.
      - `utils/`: Shared utilities for AED processing, infrastructure modelling, and simulation support.
    - `AED/`, `AEDI/`, `AP/`: Runtime PDDL domain files, AED Instance files, and generated Attack Paths, organised per research question.
    - `results/`: Experiment output logs (`rq1_logs/`–`rq4_logs/`).
    - `run_experiments.sh`: Bash script for reproducing the experiments (RQ1–RQ4).
    - `create_plots.py`: Python script that generates the plots from the produced logs/results.
    - `experiments/`:
      - `experiment_config/`: Configuration spreadsheets (`.xlsx`) for RQ1–RQ4.
      - `plots/`: Pre-generated plot images (`.png`) for RQ1–RQ4.
- `AED/`:
     1. An extensible generic Adversarial Environment Domain `AED.pddl` with ~300 atomic action specifications, covering attacker, application, user, and infrastructure behaviors.
     2. Exemplar `AEDIs/` (e.g., SEFA instances).
- `Supplementary Experimental Configuration for RQ1, RQ2, RQ3 and RQ4.pdf`: Supplementary configuration tables for RQ1, RQ2, RQ3 and RQ4.

### Instructions

#### 1. Build

You need the [Gradle build tool](https://gradle.org/). From the directory `SAQURE_Replication_Package_SEFA/SAQURE-simulator`, run:

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

# Or run only the RQ4 size axis (1x - 500x)
./run_experiments.sh rq4_size
```

Each experiment case is controlled via command-line arguments passed to the Java application:

| Flag | Description | Example |
|------|-------------|---------|
| `-c, --config` | Experiment case name (**required**) | `-c RQ1_SAQURE_para_S1` |
| `-s, --service` | Service name override (auto-detected if omitted) | `-s RESTAURANT-SERVICE` |
| `-t, --time` | Runtime phase, for RQ2/RQ3 | `-t T2` |
| `-d, --dynamic` | Dynamic parameter value, for RQ4 | `-d 5` |
| `-x, --scale` | SEFA scale factor of the DTMC (default `500`) | `-x 500` |

To run a single experiment case manually:

```bash
java -jar SAQURE-simulator/build/libs/SAQURE-simulator-0.0.1-SNAPSHOT.jar -c <case> [options]
```

**DTMC size and the `500x` scale factor.** The base SEFA business process is modelled as **4 core structural states** (ordering, payment + delivery, delivery retry, restaurant), which is the `1x` model. The Planner replicates this block `n` times and chains the replicas (the restaurant state of replica `i` leads to the ordering state of replica `i+1`), so an `n x` model has `4 * n` core structural states, each carrying its own PRISM reward. All experiments except the RQ4 size axis use `500x`, i.e. `4 * 500 = 2000` core structural states, and rely on the default; only `rq4_size` varies `-x`. Counting the three auxiliary states — `START` (`s=0`), `success` (`s=2001`) and `failure` (`s=2002`) — the `500x` model has **2003 reachable states**. Use `-x` to reproduce the model at other scales, e.g. `-x 1` (4 core states) or `-x 25` (100 core states).

**Available experiment cases:**

| RQ | Cases | Options |
|----|-------|---------|
| RQ1 | `RQ1_SAQURE_para_S1`..`S5`, `RQ1_SAQURE_seq_S1`..`S5`, `RQ1_Aqua_s1`..`s5`, `RQ1_RAMSES_s1`..`s5` | — |
| RQ2 | `RQ2_SAQURE_s1`..`s3`, `RQ2_AQUA_s1`..`s3` | `-t T1` or `-t T2` |
| RQ3 | `RQ3_SAQURE_s1`..`s3`, `RQ3_SAQURE_s1_nodyPa`..`s3_nodyPa` | `-t T1` or `-t T2` |
| RQ4 | `RQ4_1_1_SAQURE`, `RQ4_1_1_AQUA`, `RQ4_1_2_SAQURE`, `RQ4_1_2_AQUA` | `-d <param>` |
| RQ4 size axis | `RQ4_size_SAQURE`, `RQ4_size_AQUA` | `-x <scale>` |

`RQ4_size_SAQURE` and `RQ4_size_AQUA` scale the managed system itself: one run measures the offline configuration time, the runtime risk assessment time and the runtime decision time of a system built from `-x` stacked SEFA replicas, so all three size-axis sub-questions come from the same log. Two remarks on this case:

- Risk assessment and offline configuration are per microservice, so the log reports both the per-microservice time (constant in the system size) and the whole-system time (the sum over replicas).
- `RQ4_size_AQUA` keeps the DTMC and the PRISM call identical and only replaces the runtime risk assessment: AQUA reads the risk scores instead of assessing the environment, exactly as its other configurations in this package do. It therefore has no offline configuration stage.
- The availability of the two microservices that carry a failure edge in the DTMC is set to `0.999` instead of going through `DynamicNormalize`, which clamps every value into `[0.1, 0.9]`. At `0.9` a 500x stack is traversed with probability of the order of `0.81^500`, the cumulative reward stops converging, and PRISM reports whatever its relative convergence test stalls on. See `SizeAxisExperiment` for details.

Logs are saved under `SAQURE-simulator/results/` with the following directory structure:

```
SAQURE-simulator/results/
├── rq1_logs/S{N}/{approach}/               e.g. S1/SAQURE_para/, S3/AQUA/, S2/RAMSES/
├── rq2_logs/S{N}/{T1|T2}/{approach}/       e.g. S1/T2/SAQURE/, S2/T1/AQUA/
├── rq3_logs/S{N}/{T1|T2}/{approach}/       e.g. S1/T1/SAQURE/, S2/T2/SAQURE_nodyPa/
└── rq4_logs/Option_vs_RuntimeDeTime/S{param}/{approach}/   e.g. Option_vs_RuntimeDeTime/S5/SAQURE/
    rq4_logs/Size_vs_RuntimeDeTime/S{scale}/{approach}/   size axis, e.g. Size_vs_RuntimeDeTime/S500/SAQURE/
```

#### 3. Generate plots

You need [Python 3](https://www.python.org/) with `matplotlib` and `numpy`. From the directory `SAQURE_Replication_Package_SEFA`, execute:

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
python3 create_plots.py --experiment RQ4_size
python3 create_plots.py --experiment RQ4_vuln
python3 create_plots.py --experiment RQ4_vuln_compare
python3 create_plots.py --experiment RQ4_vuln_decision
```

All plots are generated under the `experiments/plots/` directory (`.png`, plus `.pdf`
for the figures that go into the paper).

### RQ4 vulnerability axis (1–100 CVEs)

`SAQURE-vulnerability-scalability/` holds a second attack-path encoding: instead of one
monolithic AED whose vulnerability sections are commented in and out, the 100 CVEs are
split into **136 independent attack-path domains** (21 expert-authored CVEs → 55 domains,
81 auto-generated CVEs → 81 domains), paired with **6 merged STRIDE AEDIs**. Selecting a
STRIDE attack path is then done outside the planner: every selected domain is run against
every AEDI, and the cheapest solvable plan wins the target. `new_AP_workflow_cn.md`
describes the workflow; `scripts/aedi_filter.py` does the AEDI filtering.

This encoding is used **only** for the vulnerability-count scalability experiment. The
Java application, `run_experiments.sh` and every other RQ still use the monolithic AED
through `AED_Processor.AED_process`, and are unaffected.

```bash
cd SAQURE_Replication_Package_SEFA/SAQURE-vulnerability-scalability

# One-off: derive the extended lookup table, the 100-vulnerability configuration
# sheet, and the 816 pre-filtered (domain, problem) pairs
python3 scripts/build_lookup.py
python3 scripts/build_config.py
python3 scripts/prepare_all.py

# Sweep 1 - 100 vulnerabilities, 10 repetitions, sequential and parallel timing
python3 scripts/vuln_scalability.py

# Monolithic AED vs independent domains over the 21 CVEs both encodings share
python3 scripts/compare_old_new.py

# Runtime decision time over the same axis, driven by the Java application
cd .. && ./run_experiments.sh rq4_vuln
```

The sweep times the two workflow stages separately, matching the stages the monolithic
pipeline has: **offline configuration** (steps 1–3: select the domains of the exposed
CVEs, filter each of the 6 AEDIs down to each domain, write the problem files) and
**runtime attack-path generation** (steps 4–5: M × 6 planner calls, then pick the
cheapest AP per STRIDE target). Results land in `results/vuln_axis/` and
`results/old_vs_new/` as per-run logs plus a summary CSV, which `create_plots.py` reads.

Risk parameters are not stored separately: each domain encodes them in its action costs
as `c = round(-100 * ln(p))`, so `CVSS = 10*exp(-c/100)` for an entry action and
`Ppre*Puc = exp(-c/100)` for every other step (`c = 1` encodes `p = 1`). `build_lookup.py`
inverts that to extend `Sv_Pa_lookupfile.json` from 19.7 % to 100 % coverage of the 1355
actions, keeping the 283 original entries at their hand-curated values. The original file
is left untouched, so the other RQs are unaffected.

The Java side adds `RQ4_vuln_SAQURE` / `RQ4_vuln_AQUA`, which reuse the RQ3.1.2 scenario
but take their attack paths from `Analyzer/VulnAxisAP` instead of the monolithic AED, so
they are not capped at 21 CVEs. `RQ3_1_2_*_ExpConfig`, `AED_Processor` and `EADSA` are
unchanged.

One limit remains: the monolithic AED carries 21 switchable vulnerability sections, so
the old-vs-new comparison is bounded at 21 CVEs. All 21 are present in the new package,
so that comparison runs over an identical CVE set.
