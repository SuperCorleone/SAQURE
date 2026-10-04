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
 * {@link EADSA#planner_command_compute}, i.e. the risk assessment of exactly one
 * implementation. Both methods record themselves, so every caller is covered without
 * instrumenting each call site.
 *
 * <p>The runtime decision time reported at the end of a run is {@link #totalMillis()}
 * plus the Planner's own window.
 */
public final class RiskTiming {

    private static final List<Duration> SAMPLES = Collections.synchronizedList(new ArrayList<>());
    private static volatile boolean recording = true;

    private RiskTiming() {}

    /** Drops every sample. Call once before the measured pass begins. */
    public static void reset() {
        SAMPLES.clear();
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
        }
    }

    /** Per-implementation assessment times, in submission order. */
    public static List<Duration> samples() {
        return List.copyOf(SAMPLES);
    }

    /** Number of implementations assessed. */
    public static int count() {
        return SAMPLES.size();
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
