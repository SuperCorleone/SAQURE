#!/bin/bash
# RQ4.1.2 timing benchmark: decision time vs. number of exposed vulnerabilities, plus a
# thread sweep of the vulnerability-axis risk assessment. Same script on macOS and Linux,
# so the two machines are compared under identical code, configuration and protocol.
#
#   bash server_rq412/run_rq412_bench.sh                 # full run
#   REPEATS=3 THREADS="1 8 32" bash server_rq412/run_rq412_bench.sh
#   PARTS=A bash server_rq412/run_rq412_bench.sh         # only the RQ4.1.2 axis
#
# Part A  RQ4_vuln_SAQURE / RQ4_vuln_AQUA at 1..100 CVEs, default thread pool
#         (= all logical CPUs the JVM sees), REPEATS runs each.  -> the RQ4.1.2 curve
# Part B  RQ4_vuln_SAQURE at THREAD_N CVEs with saqure.vulnaxis.threads = 1..32.
#         -> how far the risk assessment scales with cores on this machine
# Logs: server_rq412/logs/<host>_<timestamp>/{A,B}/...; summarise with summarize.py.
cd "$(dirname "$0")/.."

REPEATS=${REPEATS:-5}
SCALES=${SCALES:-"1 5 10 25 50 75 100"}
THREAD_N=${THREAD_N:-100}
PARTS=${PARTS:-AB}
NCPU=$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.logicalcpu)
if [ -z "$THREADS" ]; then
    THREADS=""
    for t in 1 2 4 6 8 12 16 24 32 48 64; do [ "$t" -le "$NCPU" ] && THREADS="$THREADS $t"; done
fi

JAR="SAQURE-simulator/build/libs/SAQURE-simulator-0.0.1-SNAPSHOT.jar"
export PRISM_JAVA="${PRISM_JAVA:-$(command -v java)}"
JAVA_DBG="-Dlogging.level.saqure.SaqureSimulatorApplication=DEBUG"
HOST=$(hostname -s 2>/dev/null || hostname)
OUT="server_rq412/logs/${HOST}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT"

# --- machine fingerprint -----------------------------------------------------
{
    echo "host: $HOST"; echo "date: $(date)"; uname -a
    echo "logical CPUs: $NCPU"
    if command -v lscpu >/dev/null 2>&1; then lscpu | grep -E 'Model name|^CPU\(s\)|Thread|Core|Socket|MHz'; else sysctl -n machdep.cpu.brand_string 2>/dev/null; fi
    [ -f /sys/fs/cgroup/cpu.max ] && echo "cgroup cpu.max: $(cat /sys/fs/cgroup/cpu.max)"
    command -v free >/dev/null 2>&1 && free -g | head -2
    java -version 2>&1
    echo "REPEATS=$REPEATS SCALES=$SCALES THREAD_N=$THREAD_N THREADS=$THREADS PARTS=$PARTS"
    echo "jar sha256: $( (sha256sum "$JAR" 2>/dev/null || shasum -a 256 "$JAR") | cut -d' ' -f1)"
} > "$OUT/machine.txt"
cat "$OUT/machine.txt"

run_one() {  # $1 log file, rest: extra java args before -jar, then -- and app args
    local log="$1"; shift
    local jvm=(); while [ "$1" != "--" ]; do jvm+=("$1"); shift; done; shift
    java "${jvm[@]}" -jar "$JAR" "$@" > "$log" 2>&1
    local t; t=$(grep -o 'Runtime decision time: [0-9.]*ms' "$log" | tail -1)
    [ -n "$t" ] && echo "  $t" || echo "  FAILED (see $log)"
}

# Warm-up: first JVM/PRISM/Metric-FF start pays disk and page-cache costs; discard it.
echo "== warm-up"
run_one "$OUT/warmup.log" $JAVA_DBG -- -c RQ4_vuln_SAQURE -d 1

if [[ "$PARTS" == *A* ]]; then
    echo "== Part A: RQ4.1.2 axis"
    for approach in SAQURE AQUA; do
        for n in $SCALES; do
            d="$OUT/A/S${n}/${approach}"; mkdir -p "$d"
            for run in $(seq 1 "$REPEATS"); do
                echo "-- RQ4_vuln_${approach} d=$n run $run/$REPEATS"
                run_one "$d/run${run}.log" $JAVA_DBG -- -c "RQ4_vuln_${approach}" -d "$n"
            done
        done
    done
fi

if [[ "$PARTS" == *B* ]]; then
    echo "== Part B: thread sweep at $THREAD_N CVEs:$THREADS"
    for t in $THREADS; do
        d="$OUT/B/T${t}"; mkdir -p "$d"
        for run in $(seq 1 "$REPEATS"); do
            echo "-- threads=$t run $run/$REPEATS"
            run_one "$d/run${run}.log" $JAVA_DBG "-Dsaqure.vulnaxis.threads=$t" -- -c RQ4_vuln_SAQURE -d "$THREAD_N"
        done
    done
fi

echo "== done: $OUT"
python3 server_rq412/summarize.py "$OUT" | tee "$OUT/summary.txt"
