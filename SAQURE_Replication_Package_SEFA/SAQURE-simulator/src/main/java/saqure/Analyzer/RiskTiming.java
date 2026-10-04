package saqure.Analyzer;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Accumulates the wall clock the Analyzer spends assessing the risk of candidate
 * implementations, so it can be folded into the runtime decision time.
 *
 * <p>One sample is one call to {@link EADSA#computeScenario} or
 * {@link VulnAxisAP#computeScenario}, i.e. the risk assessment of exactly one
 * implementation. Both methods record themselves, so every caller in the package is
 * covered without instrumenting its ~40 call sites.
 *
 * <p>The runtime decision time reported at the end of a run is
 * {@link #totalMillis()} plus the Planner's own window. Callers that measure something
 * other than one MAPE-K pass -- the per-replica profiling loop behind the risk
 * assessment figures, for instance -- must {@link #pause()} around it so it is not
 * charged to the decision.
 */
public final class RiskTiming {

    private static final List<Duration> SAMPLES = Collections.synchronizedList(new ArrayList<>());
    private static volatile boolean recording = true;
    private static final java.util.concurrent.atomic.AtomicInteger IMPLEMENTATIONS = new java.util.concurrent.atomic.AtomicInteger();

    private RiskTiming() {}

    /** Drops every sample. Call once before the measured pass begins. */
    public static void reset() {
        SAMPLES.clear();
        IMPLEMENTATIONS.set(0);
        recording = true;
    }

    /** Stops accumulating, for work that is not part of the adaptation decision. */
    public static void pause() {
        recording = false;
    }

    /** Resumes accumulating. */
    public static void resume() {
        recording = true;
    }

    public static void record(Duration d) {
        if (recording) {
            SAMPLES.add(d);
            IMPLEMENTATIONS.incrementAndGet();
        }
    }


    /** Per-implementation assessment times, in submission order. */
    public static List<Duration> samples() {
        return List.copyOf(SAMPLES);
    }

    /** Number of implementations assessed, which a parallel batch reports in one sample. */
    public static int count() {
        return IMPLEMENTATIONS.get();
    }

    public static long totalMillis() {
        long nanos = 0;
        synchronized (SAMPLES) {
            for (Duration d : SAMPLES) {
                nanos += d.toNanos();
            }
        }
        return nanos / 1_000_000L;
    }
}
