#!/bin/bash
# One-time setup of the SEFA package on a Linux x86_64 host for the RQ4.1.2 timing benchmark.
# Run from anywhere; it works on the package root that contains this directory.
#   1. builds the simulator jar if it is missing (fresh git clone)
#   2. rebuilds Metric-FF for Linux (the shipped binary is macOS arm64)
#   3. installs the Linux PRISM 4.8.1 build into SAQURE-simulator/prism
#   4. runs one smoke decision (RQ4_vuln_SAQURE, 1 CVE)
set -e
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
echo "Package root: $ROOT"

# --- Java 17 ---------------------------------------------------------------
if ! command -v java >/dev/null 2>&1; then
    echo "!! java not found. Install Java 17, e.g.:"
    echo "     conda install -y -c conda-forge openjdk=17"
    exit 1
fi
JAVA_MAJOR=$(java -version 2>&1 | sed -n 's/.*version "\([0-9]*\).*/\1/p' | head -1)
echo "Java major version: $JAVA_MAJOR ($(command -v java))"
if [ -z "$JAVA_MAJOR" ] || [ "$JAVA_MAJOR" -lt 17 ]; then
    echo "!! Java >= 17 required (conda install -y -c conda-forge openjdk=17)"
    exit 1
fi

# --- Simulator jar -----------------------------------------------------------
# build/ is git-ignored, so a fresh clone has no jar: build it (needs Maven Central access).
JAR="SAQURE-simulator/build/libs/SAQURE-simulator-0.0.1-SNAPSHOT.jar"
if [ ! -f "$JAR" ]; then
    echo "== Building simulator jar (gradlew bootJar)"
    ( cd SAQURE-simulator && chmod +x gradlew && ./gradlew bootJar -x test -q ) || { echo "!! jar build failed; alternatively copy the jar from the Mac to $JAR"; exit 1; }
fi
ls -la "$JAR"

# --- Metric-FF ---------------------------------------------------------------
command -v gcc >/dev/null 2>&1 || { echo "!! gcc not found (apt-get install build-essential, or conda install -c conda-forge gcc make)"; exit 1; }
command -v make >/dev/null 2>&1 || { echo "!! make not found"; exit 1; }
echo "== Building Metric-FF"
(
    cd SAQURE-simulator/Metric-FF
    # Keep the pre-generated flex/bison sources (make clean would delete them and require
    # flex/bison); only drop objects and the macOS binary. -fcommon is needed for GCC >= 10,
    # whose -fno-common default rejects Metric-FF's tentative global definitions.
    rm -f ./*.o ff
    make ff CFLAGS="-O6 -ansi -fcommon -g" > build_linux.log 2>&1 || { tail -30 build_linux.log; exit 1; }
)
file SAQURE-simulator/Metric-FF/ff 2>/dev/null || ls -la SAQURE-simulator/Metric-FF/ff

# --- PRISM -------------------------------------------------------------------
echo "== Installing PRISM 4.8.1 (linux64-x86)"
TARBALL="server_rq412/prism-4.8.1-linux64-x86.tar.gz"
if [ ! -f "$TARBALL" ]; then
    echo "   $TARBALL missing, downloading"
    curl -L -o "$TARBALL" https://github.com/prismmodelchecker/prism/releases/download/v4.8.1/prism-4.8.1-linux64-x86.tar.gz
fi
rm -rf SAQURE-simulator/prism
tar xzf "$TARBALL" -C SAQURE-simulator
mv SAQURE-simulator/prism-4.8.1-linux64-x86 SAQURE-simulator/prism
( cd SAQURE-simulator/prism && ./install.sh silent )
grep -m1 '^PRISM_DIR=' SAQURE-simulator/prism/bin/prism
export PRISM_JAVA="$(command -v java)"
SAQURE-simulator/prism/bin/prism -version | head -3 || { echo "!! PRISM does not start"; exit 1; }

# --- Smoke test --------------------------------------------------------------
export PRISM_JAVA="$(command -v java)"
mkdir -p server_rq412/logs
echo "== Smoke test: RQ4_vuln_SAQURE -d 1"
java -jar SAQURE-simulator/build/libs/SAQURE-simulator-0.0.1-SNAPSHOT.jar -c RQ4_vuln_SAQURE -d 1 > server_rq412/logs/smoke.log 2>&1 || true
if grep -q 'Runtime decision time' server_rq412/logs/smoke.log; then
    grep 'Runtime decision time' server_rq412/logs/smoke.log
    echo "Setup OK. Next: bash server_rq412/run_rq412_bench.sh"
else
    echo "!! Smoke test failed, see server_rq412/logs/smoke.log"; tail -30 server_rq412/logs/smoke.log; exit 1
fi
