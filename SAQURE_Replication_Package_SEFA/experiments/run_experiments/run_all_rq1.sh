#!/bin/bash

# RQ1 Experiment Execution Script

# Build executable JAR
echo "🔧 Building executable JAR..."
./gradlew clean bootJar --quiet
JAR_PATH="SAQURE-simulator/build/libs/SAQURE-simulator-0.0.1-SNAPSHOT.jar"

if [ ! -f "$JAR_PATH" ]; then
    echo "❌ JAR file not found: $JAR_PATH"
    exit 1
fi

LOG_DIR="./SAQURE-simulator/results_reproduction/rq1_logs"
mkdir -p "$LOG_DIR"

# All RQ1 experiment enumerations
RQ1_EXPERIMENTS=(
    "RQ1_SAQURE_para_S1" "RQ1_SAQURE_para_S2" "RQ1_SAQURE_para_S3" "RQ1_SAQURE_para_S4" "RQ1_SAQURE_para_S5"
    "RQ1_SAQURE_seq_S1" "RQ1_SAQURE_seq_S2" "RQ1_SAQURE_seq_S3" "RQ1_SAQURE_seq_S4" "RQ1_SAQURE_seq_S5"
    "RQ1_Aqua_s1" "RQ1_Aqua_s2" "RQ1_Aqua_s3" "RQ1_Aqua_s4" "RQ1_Aqua_s5"
    "RQ1_RAMSES_s1" "RQ1_RAMSES_s2" "RQ1_RAMSES_s3" "RQ1_RAMSES_s4" "RQ1_RAMSES_s5"
)

echo "✅ Starting RQ1 experiments, total ${#RQ1_EXPERIMENTS[@]} experiments, each running 10 times..."

echo "RQ1" > /tmp/serviceName.txt

for experiment in "${RQ1_EXPERIMENTS[@]}"
do
    echo "$experiment" > /tmp/cmd.txt
    for run in {1..10}
    do
        echo "===== Experiment $experiment, Run $run started ====="
        LOG_FILE="$LOG_DIR/SEFA_${experiment}_run${run}.log"

        # Run Java program
        java -jar "$JAR_PATH" > "$LOG_FILE" 2>&1

        # Check if the program executed successfully
        if [ $? -eq 0 ]; then
            echo "✅ Experiment $experiment, Run $run completed successfully"
        else
            echo "❌ Experiment $experiment, Run $run failed"
        fi

        echo "===== Experiment $experiment, Run $run completed, log saved to $LOG_FILE ====="
        echo ""

        # Optional: add short delay to avoid resource contention
        sleep 1
    done
done

echo "✅ All RQ1 experiments completed, logs saved in $LOG_DIR directory."