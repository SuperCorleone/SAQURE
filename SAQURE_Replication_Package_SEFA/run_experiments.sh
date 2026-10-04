#!/bin/bash

JAR="SAQURE-simulator/build/libs/SAQURE-simulator-0.0.1-SNAPSHOT.jar"
JAVA_CMD="java -jar $JAR"
export PRISM_JAVA="${PRISM_JAVA:-$(command -v java)}"

# The T1/T2 experiments mutate AED/AEDI files and restore them afterwards. An interrupted
# run leaves them mutated, which silently turns later T1 runs into T2 runs. Snapshot the
# files up front and verify after every run so that never goes unnoticed again.
AEDI_GUARD_FILES="SAQURE-simulator/AEDI/RQ2 SAQURE-simulator/src/main/java/saqure/Knowledge/AED:AEDI"
aedi_snapshot() { find $AEDI_GUARD_FILES -name "*.pddl" -type f -exec shasum {} + 2>/dev/null | sort; }
AEDI_BASELINE=""
aedi_guard_init() { AEDI_BASELINE=$(aedi_snapshot); }
aedi_guard_check() {
    if [ "$(aedi_snapshot)" != "$AEDI_BASELINE" ]; then
        echo "!! ABORT: AED/AEDI files were left modified after $1 -- restore them before continuing"
        aedi_snapshot > /tmp/aedi_now.txt
        echo "$AEDI_BASELINE" > /tmp/aedi_baseline.txt
        diff /tmp/aedi_baseline.txt /tmp/aedi_now.txt | head -20
        exit 1
    fi
}
REPEATS=${REPEATS:-10} # repeated experiments to reduce randomness (override: REPEATS=1 ./run_experiments.sh rq1)
START_RUN=${START_RUN:-1} # first repeat index, so an interrupted or partial batch can be topped up
LOG_BASE="./SAQURE-simulator/results"
SIZE_SCALES="1 10 25 50 100 250 500" # managed system size, in SEFA replicas, for the RQ4 size axis
VULN_SCALES="1 5 10 25 50 75 100"    # exposed vulnerabilities, for the RQ4 vulnerability axis
VULN_REPEATS=${VULN_REPEATS:-5}       # decision time is flat along this axis, so fewer repeats suffice (override: VULN_REPEATS=10)

run_rq1() {
    echo "========== RQ1 Experiments =========="

    # Scenario outermost so that a scenario completes across all four arms before the next
    # one starts, which is what the paper's per-scenario comparison needs.
    # Arms follow the paper: RAMSES and AQUA are the baselines, SAQURE_seq is the
    # SAQURE_para- ablation (sequential AP planning), SAQURE_para is SAQURE.
    for n in 1 2 3 4 5; do
        s="S${n}"
        for arm in "RAMSES:RQ1_RAMSES_s${n}" "AQUA:RQ1_Aqua_s${n}" \
                   "SAQURE_seq:RQ1_SAQURE_seq_S${n}" "SAQURE_para:RQ1_SAQURE_para_S${n}"; do
            DIR_NAME="${arm%%:*}"
            CASE="${arm##*:}"
            LOG_DIR="$LOG_BASE/rq1_logs/$s/$DIR_NAME"
            mkdir -p "$LOG_DIR"
            for run in $(seq $START_RUN $REPEATS); do
                LOG_FILE="$LOG_DIR/SEFA_${CASE}_run${run}.log"
                echo "--- $CASE [run $run/$REPEATS] ---"
                $JAVA_CMD -c "$CASE" > "$LOG_FILE" 2>&1
                [ $? -eq 0 ] && echo "  completed" || echo "  FAILED"
            done
        done
        echo "========== RQ1 $s done =========="
    done

    echo "========== RQ1 Done =========="
}

run_rq2() {
    echo "========== RQ2 Experiments =========="
    aedi_guard_init

    for approach in SAQURE AQUA; do
        for n in 1 2 3; do
            CASE="RQ2_${approach}_s${n}"
            for t in T1 T2; do
                LOG_DIR="$LOG_BASE/rq2_logs/S${n}/${t}/${approach}"
                mkdir -p "$LOG_DIR"
                for run in $(seq $START_RUN $REPEATS); do
                    LOG_FILE="$LOG_DIR/SEFA_RQ2_S${n}_${approach}_${t}_run${run}.log"
                    echo "--- $CASE ${t} [run $run/$REPEATS] ---"
                    $JAVA_CMD -c "$CASE" -t "$t" > "$LOG_FILE" 2>&1
                    [ $? -eq 0 ] && echo "  completed" || echo "  FAILED"
                    aedi_guard_check "$CASE $t run $run"
                done
            done
        done
    done

    echo "========== RQ2 Done =========="
}

run_rq3() {
    echo "========== RQ3 Experiments =========="
    aedi_guard_init

    # SAQURE
    for n in 1 2 3; do
        CASE="RQ3_SAQURE_s${n}"
        for t in T1 T2; do
            LOG_DIR="$LOG_BASE/rq3_logs/S${n}/${t}/SAQURE"
            mkdir -p "$LOG_DIR"
            for run in $(seq $START_RUN $REPEATS); do
                LOG_FILE="$LOG_DIR/SEFA_RQ3_S${n}_SAQURE_${t}_run${run}.log"
                echo "--- $CASE ${t} [run $run/$REPEATS] ---"
                $JAVA_CMD -c "$CASE" -t "$t" > "$LOG_FILE" 2>&1
                [ $? -eq 0 ] && echo "  completed" || echo "  FAILED"
                aedi_guard_check "$CASE $t run $run"
            done
        done
    done

    # SAQURE_nodyPa
    for n in 1 2 3; do
        CASE="RQ3_SAQURE_s${n}_nodyPa"
        for t in T1 T2; do
            LOG_DIR="$LOG_BASE/rq3_logs/S${n}/${t}/SAQURE_nodyPa"
            mkdir -p "$LOG_DIR"
            for run in $(seq $START_RUN $REPEATS); do
                LOG_FILE="$LOG_DIR/SEFA_RQ3_S${n}_SAQURE_nodyPa_${t}_run${run}.log"
                echo "--- $CASE ${t} [run $run/$REPEATS] ---"
                $JAVA_CMD -c "$CASE" -t "$t" > "$LOG_FILE" 2>&1
                [ $? -eq 0 ] && echo "  completed" || echo "  FAILED"
                aedi_guard_check "$CASE $t run $run"
            done
        done
    done

    echo "========== RQ3 Done =========="
}

run_rq4_vuln() {
    echo "========== RQ4 vulnerability axis (1-100 CVEs) =========="
    # Attack paths come from the 136 independent domains; scripts/prepare_all.py must have
    # been run once so the (domain, problem) pairs exist.
    if [ ! -d "SAQURE-vulnerability-scalability/prepared" ]; then
        echo "Missing prepared pairs. Run:"
        echo "  (cd SAQURE-vulnerability-scalability && python3 scripts/prepare_all.py)"
        return 1
    fi
    for approach in SAQURE AQUA; do
        CASE="RQ4_vuln_${approach}"
        for param in $VULN_SCALES; do
            LOG_DIR="$LOG_BASE/rq4_logs/Vuln_vs_RuntimeDeTime/S${param}/${approach}"
            mkdir -p "$LOG_DIR"
            for run in $(seq 1 $VULN_REPEATS); do
                LOG_FILE="$LOG_DIR/SEFA_RQ4_vuln_${approach}_S${param}_${run}.log"
                echo "--- $CASE param=$param [run $run/$VULN_REPEATS] ---"
                $JAVA_CMD -c "$CASE" -d "$param" > "$LOG_FILE" 2>&1
                [ $? -eq 0 ] && echo "  completed" || echo "  FAILED"
            done
        done
    done

    # RQ4.2.1: risk assessment against the number of exposed vulnerabilities, same profiler.
    for param in $VULN_SCALES; do
        LOG_DIR="$LOG_BASE/rq4_logs/Vuln_vs_RiskAssessTime/S${param}/SAQURE"
        mkdir -p "$LOG_DIR"
        for run in $(seq $START_RUN $REPEATS); do
            LOG_FILE="$LOG_DIR/SEFA_RQ4_vuln_risk_SAQURE_S${param}_${run}.log"
            echo "--- RQ4_vuln_risk_SAQURE param=$param [run $run/$REPEATS] ---"
            $JAVA_CMD -c RQ4_vuln_risk_SAQURE -d "$param" > "$LOG_FILE" 2>&1
            [ $? -eq 0 ] && echo "  completed" || echo "  FAILED"
        done
    done

    echo "========== RQ4 vulnerability axis Done =========="
}

run_rq4_size() {
    echo "========== RQ4 size axis (Size_vs_RuntimeDeTime) =========="
    # The managed system is scaled from 1x to 500x SEFA. One run measures offline configuration,
    # risk assessment and decision time at the same scale.
    for approach in SAQURE AQUA; do
        CASE="RQ4_size_${approach}"
        for scale in $SIZE_SCALES; do
            LOG_DIR="$LOG_BASE/rq4_logs/Size_vs_RuntimeDeTime/S${scale}/${approach}"
            mkdir -p "$LOG_DIR"
            for run in $(seq $START_RUN $REPEATS); do
                LOG_FILE="$LOG_DIR/SEFA_RQ4_size_${approach}_S${scale}_${run}.log"
                echo "--- $CASE scale=${scale}x [run $run/$REPEATS] ---"
                $JAVA_CMD -c "$CASE" -x "$scale" > "$LOG_FILE" 2>&1
                [ $? -eq 0 ] && echo "  completed" || echo "  FAILED"
            done
        done
    done

    # RQ4.2.2: risk assessment against the size of the managed system. Uses the profiler case,
    # which skips the DTMC and PRISM, so it is the assessment cost on its own.
    for scale in $SIZE_SCALES; do
        LOG_DIR="$LOG_BASE/rq4_logs/Size_vs_RiskAssessTime/S${scale}/SAQURE"
        mkdir -p "$LOG_DIR"
        for run in $(seq $START_RUN $REPEATS); do
            LOG_FILE="$LOG_DIR/SEFA_RQ4_size_risk_SAQURE_S${scale}_${run}.log"
            echo "--- RQ4_size_risk_SAQURE scale=${scale}x [run $run/$REPEATS] ---"
            $JAVA_CMD -c RQ4_size_risk_SAQURE -x "$scale" > "$LOG_FILE" 2>&1
            [ $? -eq 0 ] && echo "  completed" || echo "  FAILED"
        done
    done

    echo "========== RQ4 size axis Done =========="
}

run_rq4() {
    echo "========== RQ4 Experiments =========="

    # RQ4_1_1 (Option_vs_RuntimeDeTime): param from 1 to 15
    for approach in SAQURE AQUA; do
        CASE="RQ4_1_1_${approach}"
        for param in $(seq 1 15); do
            LOG_DIR="$LOG_BASE/rq4_logs/Option_vs_RuntimeDeTime/S${param}/${approach}"
            mkdir -p "$LOG_DIR"
            for run in $(seq $START_RUN $REPEATS); do
                LOG_FILE="$LOG_DIR/SEFA_RQ4_1_1_${approach}_S${param}_${run}.log"
                echo "--- $CASE param=$param [run $run/$REPEATS] ---"
                $JAVA_CMD -c "$CASE" -d "$param" > "$LOG_FILE" 2>&1
                [ $? -eq 0 ] && echo "  completed" || echo "  FAILED"
            done
        done
    done

    # RQ4_1_2 (Experiment2): param from 1 to 21
    for approach in SAQURE AQUA; do
        CASE="RQ4_1_2_${approach}"
        for param in $(seq 1 21); do
            LOG_DIR="$LOG_BASE/rq4_logs/Experiment2/S${param}/${approach}"
            mkdir -p "$LOG_DIR"
            for run in $(seq $START_RUN $REPEATS); do
                LOG_FILE="$LOG_DIR/SEFA_RQ4_1_2_${approach}_S${param}_${run}.log"
                echo "--- $CASE param=$param [run $run/$REPEATS] ---"
                $JAVA_CMD -c "$CASE" -d "$param" > "$LOG_FILE" 2>&1
                [ $? -eq 0 ] && echo "  completed" || echo "  FAILED"
            done
        done
    done

    run_rq4_size
    run_rq4_vuln

    echo "========== RQ4 Done =========="
}

run_all() {
    run_rq1
    run_rq2
    run_rq3
    run_rq4
}

print_help() {
    echo "Usage: $0 <command>"
    echo ""
    echo "Commands:"
    echo "  rq1              Run all RQ1 experiments (4 approaches x 5 scenarios x $REPEATS runs)"
    echo "  rq2              Run all RQ2 experiments (2 approaches x 3 scenarios x T1/T2 x $REPEATS runs)"
    echo "  rq3              Run all RQ3 experiments (3 scenarios + 3 nodyPa x T1/T2 x $REPEATS runs)"
    echo "  rq4              Run all RQ4 experiments (RQ4_1_1 param 1-15, RQ4_1_2 param 1-21,"
    echo "                   size axis ${SIZE_SCALES// /x, }x x $REPEATS runs)"
    echo "  rq4_size         Run only the RQ4 size axis (${SIZE_SCALES// /x, }x x $REPEATS runs)"
    echo "  all              Run all experiments (RQ1-RQ4)"
    echo "  rq4_vuln         Run the RQ4 vulnerability axis (1-100 CVEs, independent domains)"
    echo "  help             Show this help message"
    echo ""
    echo "Log structure: $LOG_BASE/{rq1_logs,rq2_logs,rq3_logs,rq4_logs}/..."
}

case "${1}" in
    rq1)  run_rq1 ;;
    rq2)  run_rq2 ;;
    rq3)  run_rq3 ;;
    rq4)  run_rq4 ;;
    rq4_size) run_rq4_size ;;
    rq4_vuln) run_rq4_vuln ;;
    all)  run_all ;;
    help) print_help ;;
    *)    print_help ;;
esac
