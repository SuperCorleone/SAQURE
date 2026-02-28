#!/bin/bash

# Build executable JAR
echo "🔧 Building executable JAR..."
./gradlew clean bootJar --quiet
JAR_PATH="SAQURE-simulator/build/libs/SAQURE-simulator-0.0.1-SNAPSHOT.jar"

if [ ! -f "$JAR_PATH" ]; then
    echo "❌ JAR file not found: $JAR_PATH"
    exit 1
fi

# Define log directory and create base directory
LOG_DIR="./SAQURE-simulator/results_reproduction/rq3_logs"
mkdir -p "$LOG_DIR"

RQ3_EXPERIMENTS=("RQ3_1_1_SAQURE" "RQ3_1_1_AQUA" "RQ3_1_2_SAQURE" "RQ3_1_2_AQUA")

echo "RQ3" > /tmp/serviceName.txt

for experiment in "${RQ3_EXPERIMENTS[@]}"
do
    echo "$experiment" > /tmp/cmd.txt
    # Select parameter range based on experiment
    if [ "$experiment" = "RQ3_1_1_SAQURE" ] || [ "$experiment" = "RQ3_1_1_AQUA" ]; then
        PARAMS=$(seq 1 15)   # RQ3.1.1 parameters 1 to 15
    elif [ "$experiment" = "RQ3_1_2_SAQURE" ] || [ "$experiment" = "RQ3_1_2_AQUA" ]; then
        PARAMS=$(seq 1 21)   # RQ3.1.2 parameters 1 to 21
    else
        echo "❌ Unknown experiment: $experiment"
        continue
    fi

    # Check if PARAMS is set successfully
    if [ -z "$PARAMS" ]; then
        echo "❌ PARAMS not set for experiment: $experiment"
        continue
    fi

    echo "Executing experiment: $experiment, parameter range: $PARAMS"

    for param in $PARAMS
    do
        for run in $(seq 1 10);
        do
            echo "===== Experiment $experiment, Parameter $param, Run $run started ====="

            # Build different log file paths based on experiment name
            case "$experiment" in
                "RQ3_1_1_SAQURE")
                    LOG_FILE="$LOG_DIR/Experiment1/S${param}/SAQURE/SEFA_${experiment}_S${param}_${run}.log"
                    ;;
                "RQ3_1_1_AQUA")
                    LOG_FILE="$LOG_DIR/Experiment1/S${param}/AQUA/SEFA_${experiment}_S${param}_${run}.log"
                    ;;
                "RQ3_1_2_SAQURE")
                    LOG_FILE="$LOG_DIR/Experiment2/S${param}/SAQURE/SEFA_${experiment}_S${param}_${run}.log"
                    ;;
                "RQ3_1_2_AQUA")
                    LOG_FILE="$LOG_DIR/Experiment2/S${param}/SEFA_${experiment}_S${param}_${run}.log"
                    ;;
                *)
                    echo "❌ Unknown experiment type: $experiment"
                    continue 3
                    ;;
            esac

            # Ensure log directory exists
            mkdir -p "$(dirname "$LOG_FILE")"

            # Write parameter file for Java program to read
            echo "$param" > /tmp/param.txt

            # Run Java program and check execution status
            echo "Executing command: java -jar \"$JAR_PATH\" > \"$LOG_FILE\" 2>&1"
            if java -jar "$JAR_PATH" > "$LOG_FILE" 2>&1; then
                echo "✅ Experiment $experiment, Parameter $param, Run $run completed successfully"
            else
                echo "❌ Experiment $experiment, Parameter $param, Run $run failed"
                # Option to continue running or exit
                # exit 1
            fi

            echo "===== Experiment $experiment, Parameter $param, Run $run completed, log saved to $LOG_FILE ====="
            sleep 1
        done
    done
done

echo "✅ All runs completed, logs saved in $LOG_DIR directory."