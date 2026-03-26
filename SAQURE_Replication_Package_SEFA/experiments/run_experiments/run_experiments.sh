#!/bin/bash

JAR="SAQURE-simulator/build/libs/SAQURE-simulator-0.0.1-SNAPSHOT.jar"
JAVA_CMD="java -jar $JAR"
REPEATS=10 # repeated experiments to reduce randomness
LOG_BASE="./SAQURE-simulator/results_reproduction"

run_rq1() {
    echo "========== RQ1 Experiments =========="

    # SAQURE parallel
    for s in S1 S2 S3 S4 S5; do
        CASE="RQ1_SAQURE_para_$s"
        LOG_DIR="$LOG_BASE/rq1_logs/$s/SAQURE_para"
        mkdir -p "$LOG_DIR"
        for run in $(seq 1 $REPEATS); do
            LOG_FILE="$LOG_DIR/SEFA_${CASE}_run${run}.log"
            echo "--- $CASE [run $run/$REPEATS] ---"
            $JAVA_CMD -c "$CASE" > "$LOG_FILE" 2>&1
            [ $? -eq 0 ] && echo "  completed" || echo "  FAILED"
        done
    done

    # SAQURE sequential
    for s in S1 S2 S3 S4 S5; do
        CASE="RQ1_SAQURE_seq_$s"
        LOG_DIR="$LOG_BASE/rq1_logs/$s/SAQURE_seq"
        mkdir -p "$LOG_DIR"
        for run in $(seq 1 $REPEATS); do
            LOG_FILE="$LOG_DIR/SEFA_${CASE}_run${run}.log"
            echo "--- $CASE [run $run/$REPEATS] ---"
            $JAVA_CMD -c "$CASE" > "$LOG_FILE" 2>&1
            [ $? -eq 0 ] && echo "  completed" || echo "  FAILED"
        done
    done

    # Aqua (sequential)
    for n in 1 2 3 4 5; do
        CASE="RQ1_Aqua_s${n}"
        LOG_DIR="$LOG_BASE/rq1_logs/S${n}/AQUA"
        mkdir -p "$LOG_DIR"
        for run in $(seq 1 $REPEATS); do
            LOG_FILE="$LOG_DIR/SEFA_${CASE}_run${run}.log"
            echo "--- $CASE [run $run/$REPEATS] ---"
            $JAVA_CMD -c "$CASE" > "$LOG_FILE" 2>&1
            [ $? -eq 0 ] && echo "  completed" || echo "  FAILED"
        done
    done

    # RAMSES (sequential)
    for n in 1 2 3 4 5; do
        CASE="RQ1_RAMSES_s${n}"
        LOG_DIR="$LOG_BASE/rq1_logs/S${n}/RAMSES"
        mkdir -p "$LOG_DIR"
        for run in $(seq 1 $REPEATS); do
            LOG_FILE="$LOG_DIR/SEFA_${CASE}_run${run}.log"
            echo "--- $CASE [run $run/$REPEATS] ---"
            $JAVA_CMD -c "$CASE" > "$LOG_FILE" 2>&1
            [ $? -eq 0 ] && echo "  completed" || echo "  FAILED"
        done
    done

    echo "========== RQ1 Done =========="
}

run_rq2() {
    echo "========== RQ2 Experiments =========="

    for approach in SAQURE AQUA; do
        for n in 1 2 3; do
            CASE="RQ2_${approach}_s${n}"
            for t in T1 T2; do
                LOG_DIR="$LOG_BASE/rq2_logs/S${n}/${t}/${approach}"
                mkdir -p "$LOG_DIR"
                for run in $(seq 1 $REPEATS); do
                    LOG_FILE="$LOG_DIR/SEFA_RQ2_S${n}_${approach}_${t}_run${run}.log"
                    echo "--- $CASE ${t} [run $run/$REPEATS] ---"
                    $JAVA_CMD -c "$CASE" -t "$t" > "$LOG_FILE" 2>&1
                    [ $? -eq 0 ] && echo "  completed" || echo "  FAILED"
                done
            done
        done
    done

    echo "========== RQ2 Done =========="
}

run_rq3() {
    echo "========== RQ3 Experiments =========="

    # SAQURE
    for n in 1 2 3; do
        CASE="RQ3_SAQURE_s${n}"
        for t in T1 T2; do
            LOG_DIR="$LOG_BASE/rq3_logs/S${n}/${t}/SAQURE"
            mkdir -p "$LOG_DIR"
            for run in $(seq 1 $REPEATS); do
                LOG_FILE="$LOG_DIR/SEFA_RQ3_S${n}_SAQURE_${t}_run${run}.log"
                echo "--- $CASE ${t} [run $run/$REPEATS] ---"
                $JAVA_CMD -c "$CASE" -t "$t" > "$LOG_FILE" 2>&1
                [ $? -eq 0 ] && echo "  completed" || echo "  FAILED"
            done
        done
    done

    # SAQURE_nodyPa
    for n in 1 2 3; do
        CASE="RQ3_SAQURE_s${n}_nodyPa"
        for t in T1 T2; do
            LOG_DIR="$LOG_BASE/rq3_logs/S${n}/${t}/SAQURE_nodyPa"
            mkdir -p "$LOG_DIR"
            for run in $(seq 1 $REPEATS); do
                LOG_FILE="$LOG_DIR/SEFA_RQ3_S${n}_SAQURE_nodyPa_${t}_run${run}.log"
                echo "--- $CASE ${t} [run $run/$REPEATS] ---"
                $JAVA_CMD -c "$CASE" -t "$t" > "$LOG_FILE" 2>&1
                [ $? -eq 0 ] && echo "  completed" || echo "  FAILED"
            done
        done
    done

    echo "========== RQ3 Done =========="
}

run_rq4() {
    echo "========== RQ4 Experiments =========="

    # RQ4_1_1 (Experiment1): param from 1 to 15
    for approach in SAQURE AQUA; do
        CASE="RQ4_1_1_${approach}"
        for param in $(seq 1 15); do
            LOG_DIR="$LOG_BASE/rq4_logs/Experiment1/S${param}/${approach}"
            mkdir -p "$LOG_DIR"
            for run in $(seq 1 $REPEATS); do
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
            for run in $(seq 1 $REPEATS); do
                LOG_FILE="$LOG_DIR/SEFA_RQ4_1_2_${approach}_S${param}_${run}.log"
                echo "--- $CASE param=$param [run $run/$REPEATS] ---"
                $JAVA_CMD -c "$CASE" -d "$param" > "$LOG_FILE" 2>&1
                [ $? -eq 0 ] && echo "  completed" || echo "  FAILED"
            done
        done
    done

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
    echo "  rq4              Run all RQ4 experiments (RQ4_1_1 param 1-15, RQ4_1_2 param 1-21 x $REPEATS runs)"
    echo "  all              Run all experiments (RQ1-RQ4)"
    echo "  help             Show this help message"
    echo ""
    echo "Log structure: $LOG_BASE/{rq1_logs,rq2_logs,rq3_logs,rq4_logs}/..."
}

case "${1}" in
    rq1)  run_rq1 ;;
    rq2)  run_rq2 ;;
    rq3)  run_rq3 ;;
    rq4)  run_rq4 ;;
    all)  run_all ;;
    help) print_help ;;
    *)    print_help ;;
esac
