package saqure.utils;

import lombok.extern.slf4j.Slf4j;
import saqure.Analyzer.EADSA;
import saqure.Analyzer.RiskTiming;
import saqure.Analyzer.VulnAxisAP;
import saqure.Analyzer.VulnAxisAPProfiler;
import saqure.utils.infrastructure.adaptation.options.AdaptationOption;
import saqure.utils.infrastructure.adaptation.options.ChangeImplementationOption;
import saqure.utils.infrastructure.adaptation.specifications.Availability;
import saqure.utils.infrastructure.adaptation.specifications.AverageResponseTime;
import saqure.utils.infrastructure.adaptation.specifications.QoSSpecification;
import saqure.utils.infrastructure.adaptation.specifications.Vulnerability;
import saqure.utils.infrastructure.architecture.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

import static saqure.Planner.PrismModelChecker.coreStatesForScale;
import static saqure.utils.AED_Processor.AED_process;
import static saqure.utils.ServiceGraphUtils.buildPossibleGraphs;
import static saqure.utils.ServiceGraphUtils.jsonGraph;
import static saqure.utils.SimulationsUtils.createServiceMap;

/**
 * RQ4 size axis: one MAPE-K cycle over a managed system built from {@code scale} stacked SEFA
 * replicas, i.e. 4 * scale core structural states and 4 * scale microservices.
 * <p>
 * A single run produces all three timings the size axis needs:
 * <ul>
 *   <li>offline configuration time, once per implementation ({@link AED_Processor});</li>
 *   <li>runtime risk assessment time, once per replica. EADSA assesses one microservice at a
 *       time, so the whole managed system costs the sum over its replicas while the per-replica
 *       time stays constant;</li>
 *   <li>runtime decision time, from the DTMC of the whole stack.</li>
 * </ul>
 */
@Slf4j
public class SizeAxisExperiment {

    private SizeAxisExperiment() {
        throw new IllegalStateException("Utility class");
    }

    // Three vulnerabilities per implementation, as fixed by the size-axis setup.
    private static final String[][] VULNERABILITIES_PER_IMPLEMENTATION = {
            {"CVE-2024-38286", "CVE-2024-12798", "CVE-2024-38820"},
            {"CVE-2024-22243", "CVE-2024-34447", "CVE-2023-6378"},
            {"CVE-2022-40150", "CVE-2024-38816", "CVE-2022-1471"}
    };

    // Availability of the two microservices that carry a failure edge in the SEFA DTMC
    // (ordering and restaurant). A stack of n replicas is traversed with probability of the
    // order of (a_ordering * a_restaurant)^n, so these values decide whether the deep replicas
    // are reachable at all. They are handed to createServiceMap directly instead of going
    // through DynamicNormalize, which clamps every value into [0.1, 0.9]: at 0.9 the cumulative
    // reward of a 500x stack stops converging and PRISM returns whatever its relative
    // convergence test happens to stall on. 0.999 keeps 500x well posed.
    private static final double AVAILABILITY_ORDERING = 0.999;
    private static final double AVAILABILITY_RESTAURANT = 0.999;
    private static final double AVAILABILITY_PAYMENT = 0.9;
    private static final double AVAILABILITY_DELIVERY = 0.9;
    private static final double RESPONSE_TIME = 0.5;

    private static final String AED_OUTPUT_DIR = FilePathConstants.AED_path_RQ3 + "size_axis/";
    private static final String AP_OUTPUT_DIR = "SAQURE-simulator/AP/RQ4_size/";

    /** The two approaches compared on the size axis. */
    public enum Approach {
        /** Assesses risk at runtime with EADSA, one Metric-FF run per microservice. */
        SAQURE,
        /** Takes the risk scores as given, the way AQUA does elsewhere in this package. */
        AQUA
    }

    // Risk scores AQUA reads instead of assessing the environment, on the scale the package uses
    // for its other AQUA configurations.
    private static final double[] AQUA_STATIC_RISK = {0.304462475, 0.322312373, 0.313116971};

    public static void run(int scale, Approach approach) {
        log.info("SEFA size axis: {} replicas -> {} microservices, {} core structural states, approach {}",
                scale, 4 * scale, coreStatesForScale(scale), approach);
        createDirectories();

        VulnAxisAP.warmUpLookup();
        RiskTiming.reset();

        double[] riskPerImplementation = (approach == Approach.SAQURE)
                ? saqureRiskAssessmentIndependentDomains(scale)
                : aquaRiskAssessment(scale);

        // ---- runtime decision: DTMC of the whole stack ----
        Map<String, Service> servicesMap = servicesMap(riskPerImplementation);
        Service serviceToAdapt = servicesMap.get("RESTAURANT-SERVICE");
        Map<String, List<AdaptationOption>> options = new HashMap<>();
        options.put(serviceToAdapt.getServiceId(), List.of(
                changeImplementationOption(serviceToAdapt, Availability.class)));
        String currentGraph = jsonGraph(servicesMap, null);

        Instant plannerStart = Instant.now();
        buildPossibleGraphs(servicesMap, options, currentGraph, coreStatesForScale(scale));
        Instant plannerEnd = Instant.now();

        long riskAssessmentMillis = RiskTiming.totalMillis();
        long plannerMillis = Duration.between(plannerStart, plannerEnd).toMillis();
        log.debug("Risk assessment: {} implementations, {}ms; Planner: {}ms",
                RiskTiming.count(), riskAssessmentMillis, plannerMillis);
        log.info("Runtime decision time: {}ms", riskAssessmentMillis + plannerMillis);
    }

    /**
     * SAQURE on the independent per-CVE domains. The risk of each implementation comes from
     * {@link VulnAxisAP}, and the per-replica cost is the critical path reported by
     * {@link VulnAxisAPProfiler} -- the max over each domain's six parallel STRIDE calls, with
     * one untimed warm-up pass first. This is the same quantity, on the same three CVEs and the
     * same implementation, that the RQ4.2 figures report, so the size axis and the vulnerability
     * axis now answer the question the same way.
     *
     * <p>Replaces {@link #saqureRiskAssessment(int)}, which measured EADSA over the monolithic
     * AED (263 live actions vs 14) and reported ~249ms where this reports ~13ms. That method is
     * kept below for reference and is no longer called.
     */
    private static double[] saqureRiskAssessmentIndependentDomains(int scale) {
        // Risk of every implementation, needed to build the adaptation options. Not timed: it
        // does not depend on the managed system size.
        double[] risk = new double[VULNERABILITIES_PER_IMPLEMENTATION.length];
        for (int i = 0; i < VULNERABILITIES_PER_IMPLEMENTATION.length; i++) {
            risk[i] = VulnAxisAP.computeScenario(VULNERABILITIES_PER_IMPLEMENTATION[i]);
        }

        // ---- runtime risk assessment: restaurant_0's critical path, once per replica ----
        // Profiling only: it repeats one assessment `scale` times to draw the risk assessment
        // curve, which is not work a single MAPE-K pass does. Kept out of the decision time.
        RiskTiming.pause();
        Instant assessmentStart = Instant.now();
        for (int replica = 1; replica <= scale; replica++) {
            VulnAxisAPProfiler.profileReplica(replica, VULNERABILITIES_PER_IMPLEMENTATION[0]);
        }
        log.debug("Total risk assessment time for {} replicas: {}ms", scale,
                Duration.between(assessmentStart, Instant.now()).toMillis());
        RiskTiming.resume();
        return normalise(risk);
    }

    /**
     * SAQURE: build one AED domain per implementation, then assess the risk of restaurant_0 once
     * per replica. The per-replica time is what the whole managed system pays per microservice.
     */
    private static double[] saqureRiskAssessment(int scale) {
        // ---- offline configuration: one AED domain per implementation ----
        List<String> domainFiles = new ArrayList<>();
        for (int i = 0; i < VULNERABILITIES_PER_IMPLEMENTATION.length; i++) {
            domainFiles.add(AED_process(AED_OUTPUT_DIR + "restaurant_" + i + ".pddl",
                    VULNERABILITIES_PER_IMPLEMENTATION[i]));
        }

        // Risk of every implementation of the target service, needed to build the adaptation
        // options. This does not depend on the managed system size, so it is measured separately
        // from the per-replica assessment below.
        double[] risk = new double[domainFiles.size()];
        for (int i = 0; i < domainFiles.size(); i++) {
            risk[i] = EADSA.computeScenario(domainFiles.get(i), attackGoals(i));
        }

        // ---- runtime risk assessment: the risk score of restaurant_0, once per replica ----
        // Profiling only, as in the method above: kept out of the decision time.
        RiskTiming.pause();
        Instant assessmentStart = Instant.now();
        for (int replica = 1; replica <= scale; replica++) {
            Instant replicaStart = Instant.now();
            EADSA.computeScenario(domainFiles.get(0), attackGoals(0));
            Instant replicaEnd = Instant.now();
            log.debug("Time to implement EADSA for replica_{}: {}ms", replica,
                    Duration.between(replicaStart, replicaEnd).toMillis());
        }
        log.debug("Total risk assessment time for {} replicas: {}ms", scale,
                Duration.between(assessmentStart, Instant.now()).toMillis());
        RiskTiming.resume();
        return normalise(risk);
    }

    /**
     * AQUA: the risk scores are given rather than assessed, so there is no runtime assessment to
     * time here. The copy is still done once per replica to mirror the SAQURE branch, but nothing
     * is timed or logged: an "EADSA" reading for AQUA would report a measurement that does not
     * exist, and what it actually recorded was the cost of System.arraycopy.
     */
    private static double[] aquaRiskAssessment(int scale) {
        double[] risk = new double[AQUA_STATIC_RISK.length];
        for (int replica = 1; replica <= scale; replica++) {
            System.arraycopy(AQUA_STATIC_RISK, 0, risk, 0, AQUA_STATIC_RISK.length);
        }
        return risk;
    }

    private static void createDirectories() {
        try {
            Files.createDirectories(Path.of(AED_OUTPUT_DIR));
            Files.createDirectories(Path.of(AP_OUTPUT_DIR));
        } catch (IOException e) {
            log.error("Cannot create size-axis output directories: {}", e.getMessage());
        }
    }

    private static EADSA.outputPath attackGoals(int implementation) {
        String prefix = AP_OUTPUT_DIR + "restaurant_" + implementation + "_";
        return new EADSA.outputPath(
                prefix + "spoofing_plan.pddl",
                prefix + "tampering_plan.pddl",
                prefix + "repudiation_plan.pddl",
                prefix + "information_disclosure_plan.pddl",
                prefix + "denial_of_service_plan.pddl",
                prefix + "elevation_of_privilege_plan.pddl");
    }

    /** Same option construction as the standard experiment path, restricted to the target service. */
    private static AdaptationOption changeImplementationOption(Service service,
                                                              Class<? extends QoSSpecification> goal) {
        List<String> possibleImplementations = new LinkedList<>();
        for (String implementationId : service.getPossibleImplementations().keySet())
            if (!implementationId.equals(service.getCurrentImplementationId()))
                possibleImplementations.add(implementationId);
        ChangeImplementationOption option = new ChangeImplementationOption(service.getServiceId(),
                service.getCurrentImplementationId(), service.getInstances().size(),
                possibleImplementations, goal, "Changing implementation");
        return saqure.SaqureSimulatorApplication.handleChangeImplementation(option, service);
    }

    /** Takes risk scores already on the [0.1, 0.9] scale the package uses for QoS values. */
    private static Map<String, Service> servicesMap(double[] normalisedRisk) {
        Map<String, List<String>> serviceImplementations = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> benchmarks = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> currentQoS = new HashMap<>();

        List<String> restaurantImplementations = new ArrayList<>();
        for (int i = 0; i < normalisedRisk.length; i++) {
            String id = "restaurant-" + (i + 1) + "-service";
            restaurantImplementations.add(id);
            // Alternatives differ slightly in availability so that the option is not a no-op.
            benchmarks.put(id, qos(AVAILABILITY_RESTAURANT + (i == 0 ? 0.0 : 0.0005),
                    RESPONSE_TIME, normalisedRisk[i]));
        }
        serviceImplementations.put("RESTAURANT-SERVICE", restaurantImplementations);
        currentQoS.put("RESTAURANT-SERVICE", qos(AVAILABILITY_RESTAURANT, RESPONSE_TIME, normalisedRisk[0]));

        singleImplementationService("ORDERING-SERVICE", "ordering-service", AVAILABILITY_ORDERING,
                normalisedRisk[0], serviceImplementations, benchmarks, currentQoS);
        singleImplementationService("DELIVERY-PROXY-SERVICE", "delivery-proxy-1-service", AVAILABILITY_DELIVERY,
                normalisedRisk[0], serviceImplementations, benchmarks, currentQoS);
        singleImplementationService("PAYMENT-PROXY-SERVICE", "payment-proxy-1-service", AVAILABILITY_PAYMENT,
                normalisedRisk[0], serviceImplementations, benchmarks, currentQoS);

        return createServiceMap(0.3, 0.3, 0.4, serviceImplementations, benchmarks, currentQoS);
    }

    private static void singleImplementationService(
            String serviceId, String implementationId, double availability, double risk,
            Map<String, List<String>> serviceImplementations,
            Map<String, Map<Class<? extends QoSSpecification>, Double>> benchmarks,
            Map<String, Map<Class<? extends QoSSpecification>, Double>> currentQoS) {
        serviceImplementations.put(serviceId, List.of(implementationId));
        benchmarks.put(implementationId, qos(availability, RESPONSE_TIME, risk));
        currentQoS.put(serviceId, qos(availability, RESPONSE_TIME, risk));
    }

    private static Map<Class<? extends QoSSpecification>, Double> qos(double availability,
                                                                      double responseTime,
                                                                      double vulnerability) {
        Map<Class<? extends QoSSpecification>, Double> values = new HashMap<>();
        values.put(Availability.class, availability);
        values.put(AverageResponseTime.class, responseTime);
        values.put(Vulnerability.class, vulnerability);
        return values;
    }

    /** Min-max normalisation of the EADSA risk scores into [0.1, 0.9], as elsewhere in the package. */
    private static double[] normalise(double[] risk) {
        double min = Arrays.stream(risk).min().orElse(0.0);
        double max = Arrays.stream(risk).max().orElse(0.0);
        double[] out = new double[risk.length];
        for (int i = 0; i < risk.length; i++)
            out[i] = (max - min) < 1e-12 ? 0.5 : 0.1 + 0.8 * (risk[i] - min) / (max - min);
        return out;
    }
}
