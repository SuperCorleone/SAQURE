#!/bin/bash

# RQ2 Experiment Execution Script

# Build executable JAR
echo "🔧 Building executable JAR..."
./gradlew clean bootJar --quiet
JAR_PATH="SAQURE-simulator/build/libs/SAQURE-simulator-0.0.1-SNAPSHOT.jar"

if [ ! -f "$JAR_PATH" ]; then
    echo "❌ JAR file not found: $JAR_PATH"
    exit 1
fi

LOG_DIR="./SAQURE-simulator/results_reproduction/rq2_logs"
mkdir -p "$LOG_DIR"

# All RQ2 experiment enumerations
RQ2_EXPERIMENTS=(
    "RQ2_SAQURE_s1"
    "RQ2_SAQURE_s2"
    "RQ2_SAQURE_s3"
    "RQ2_SAQURE_s1_nodyPa"
    "RQ2_SAQURE_s2_nodyPa"
    "RQ2_SAQURE_s3_nodyPa"
)

echo "✅ Starting RQ2 experiments, total ${#RQ2_EXPERIMENTS[@]} experiments, each running 10 times..."

echo "RQ2" > /tmp/serviceName.txt

for experiment in "${RQ2_EXPERIMENTS[@]}"
do
    echo "$experiment" > /tmp/cmd.txt
    for run in {1..10}
    do
        echo "===== Experiment $experiment, Run $run started ====="
        LOG_FILE="$LOG_DIR/SEFA_${experiment}_T2_run${run}.log"

        # Create experiment parameter file for Java program to read
        echo "$experiment" > /tmp/experiment_name.txt

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

        sleep 1
    done
done

echo "✅ All RQ2 experiments completed, logs saved in $LOG_DIR directory."