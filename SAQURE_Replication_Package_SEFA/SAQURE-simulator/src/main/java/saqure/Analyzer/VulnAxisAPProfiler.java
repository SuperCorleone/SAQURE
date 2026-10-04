package saqure.Analyzer;

import lombok.extern.slf4j.Slf4j;
import saqure.utils.FilePathConstants;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Measurement-only copy of {@link VulnAxisAP}, used solely to produce the
 * "risk assessment time vs number of vulnerabilities" figure.
 *
 * <p>{@link VulnAxisAP} is the production path and is left untouched: it submits all
 * M x 6 planner calls to a pool sized by the machine's core count, which is the fastest
 * thing to do but makes the measured wall clock depend on how many cores the test
 * machine happens to have.
 *
 * <p>This copy measures the quantity the paper reports instead. Step 4 of the workflow
 * states that the M x 6 calls are independent, so with enough workers the risk
 * assessment finishes when its slowest call finishes -- the cost is the critical path,
 * not the sum. To measure that without letting the calls compete for CPU, the 6 STRIDE
 * calls of one domain run together on a pool of exactly 6 threads (6 is far below the
 * core count, so there is no contention), the domains are walked one at a time, and the
 * reported cost is the maximum over the per-domain wall clocks. The pool size is fixed
 * at 6 rather than taken from the machine, so the number does not move with the host.
 */
@Slf4j
public class VulnAxisAPProfiler {

    private static List<Path> selectDomains(String[] cveIds) {
        List<Path> dirs = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (String cve : cveIds) {
            String id = cve.trim();
            if (!seen.add(id)) {
                continue;
            }
            Path base = Paths.get(FilePathConstants.PreparedAPPath, id);
            if (!Files.isDirectory(base)) {
                log.warn("No prepared domain for {}", id);
                continue;
            }
            try (Stream<Path> s = Files.list(base)) {
                dirs.addAll(s.filter(Files::isDirectory).sorted().collect(Collectors.toList()));
            } catch (Exception e) {
                log.error("Cannot list {}: {}", base, e.getMessage());
            }
        }
        return dirs;
    }

    /** One measurement: the critical path plus the counters behind it. */
    public record Measurement(long criticalPathNanos, int domains, int calls, int stridesCovered) {}

    /** Runs the sweep for one implementation and logs the critical path. */
    public static void profile(int nVulnerabilities, String[] cveIds) {
        Measurement m = criticalPath(cveIds);
        log.info("Risk assessment time cost for {} vulnerabilities: {}ms",
                nVulnerabilities, String.format("%.1f", m.criticalPathNanos() / 1e6));
    }

    /** Same measurement, reported per replica, for the managed-system size axis. */
    public static void profileReplica(int replica, String[] cveIds) {
        Measurement m = criticalPath(cveIds);
        log.info("Risk assessment time cost for replica_{}: {}ms",
                replica, String.format("%.1f", m.criticalPathNanos() / 1e6));
    }

    public static Measurement criticalPath(String[] cveIds) {
        List<Path> apDirs = selectDomains(cveIds);
        ExecutorService pool = Executors.newFixedThreadPool(VulnAxisAP.STRIDES.length);
        long criticalPathNanos = 0;
        int calls = 0;
        Set<String> covered = new HashSet<>();

        try {
            // One untimed pass over the first domain: without it the very first batch
            // carries JVM class loading and JIT warm-up, which shows up as an inflated
            // reading at the smallest vulnerability counts.
            if (!apDirs.isEmpty()) {
                Path warmup = apDirs.get(0);
                List<Future<String>> warm = new ArrayList<>(VulnAxisAP.STRIDES.length);
                for (String stride : VulnAxisAP.STRIDES) {
                    Path problem = warmup.resolve(stride + ".pddl");
                    Path domain = warmup.resolve("domain.pddl");
                    warm.add(pool.submit(() -> plan(domain, problem) ? stride : null));
                }
                for (Future<String> f : warm) {
                    try {
                        f.get();
                    } catch (Exception ignored) {
                        // warm-up result is discarded
                    }
                }
            }

            for (Path apDir : apDirs) {
                Path domain = apDir.resolve("domain.pddl");

                long t0 = System.nanoTime();
                List<Future<String>> futures = new ArrayList<>(VulnAxisAP.STRIDES.length);
                for (String stride : VulnAxisAP.STRIDES) {
                    Path problem = apDir.resolve(stride + ".pddl");
                    futures.add(pool.submit(() -> plan(domain, problem) ? stride : null));
                }
                for (Future<String> f : futures) {
                    try {
                        String solved = f.get();
                        if (solved != null) {
                            covered.add(solved);
                        }
                    } catch (Exception e) {
                        // a failed call still costs time; it just contributes no target
                    }
                }
                // Wall clock of this domain's 6 parallel calls.
                criticalPathNanos = Math.max(criticalPathNanos, System.nanoTime() - t0);
                calls += VulnAxisAP.STRIDES.length;
            }
        } finally {
            pool.shutdown();
        }

        return new Measurement(criticalPathNanos, apDirs.size(), calls, covered.size());
    }

    private static boolean plan(Path domain, Path problem) {
        try {
            ProcessBuilder pb = new ProcessBuilder(
                    FilePathConstants.FFPath,
                    "-o", domain.toString(),
                    "-f", problem.toString(),
                    "-s", "4",
                    "-w", "1");
            pb.redirectErrorStream(true);
            Process p = pb.start();
            boolean solved = false;
            try (BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String line;
                while ((line = br.readLine()) != null) {
                    if (line.contains("found legal plan")) {
                        solved = true;
                    }
                }
            }
            p.waitFor();
            return solved;
        } catch (Exception e) {
            log.error("Planner failed for {}: {}", problem, e.getMessage());
            return false;
        }
    }

    private VulnAxisAPProfiler() {}
}
