package saqure.utils;

import lombok.extern.slf4j.Slf4j;
import saqure.Analyzer.EADSA;
import saqure.Analyzer.ModularEADSA;
import saqure.Analyzer.RiskTiming;
import saqure.Analyzer.VulnAxisAP;
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
 * A single run produces the size-axis timings that come from one decision:
 * <ul>
 *   <li>runtime decision time, i.e. the risk assessment of every implementation plus the
 *       Planner on the DTMC of the whole stack;</li>
 *   <li>initial model generation time, logged by the Planner for each PRISM model.</li>
 * </ul>
 * The per-replica runtime risk assessment time (RQ4.2.2) is measured by its own case,
 * {@code RQ4_size_risk_wall_SAQURE}, and is not logged here.
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
                ? saqureRiskAssessmentModules()
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
     * SAQURE with ModularEADSA, as in RQ1-RQ3: each implementation's
     * CVEs are assessed against the default (SEFA) AEDI, and the assessment's wall
     * clock is added to the runtime decision time by RiskTiming.
     */
    private static double[] saqureRiskAssessmentModules() {
        double[] risk = new double[VULNERABILITIES_PER_IMPLEMENTATION.length];
        for (int i = 0; i < VULNERABILITIES_PER_IMPLEMENTATION.length; i++) {
            risk[i] = ModularEADSA.computeScenario(VULNERABILITIES_PER_IMPLEMENTATION[i], FilePathConstants.AEDI_path, attackGoals(i));
        }
        return normalise(risk);
    }

    /**
     * RQ4.2.2 with ModularEADSA: wall clock of restaurant_0's assessment,
     * once per replica, after one untimed warm-up pass. No DTMC is built and PRISM is never called.
     */
    public static void riskWallClockModules(int scale) {
        createDirectories();
        RiskTiming.pause();
        ModularEADSA.computeScenario(VULNERABILITIES_PER_IMPLEMENTATION[0], FilePathConstants.AEDI_path, attackGoals(0));
        RiskTiming.resume();
        log.info("Risk assessment wall clock per replica (restaurant0; independent modules, {} replicas)", scale);
        for (int replica = 1; replica <= scale; replica++) {
            RiskTiming.reset();
            ModularEADSA.computeScenario(VULNERABILITIES_PER_IMPLEMENTATION[0], FilePathConstants.AEDI_path, attackGoals(0));
            long nanos = RiskTiming.samples().stream().mapToLong(Duration::toNanos).sum();
            log.info("Risk assessment time cost for replica_{}: {}ms", replica, String.format("%.1f", nanos / 1e6));
        }
    }

    // Superseded by saqureRiskAssessmentModules; kept for reference.
    /**
     * SAQURE with EADSA: one AED domain per
     * implementation, then EADSA's wall clock is added to the runtime decision time by RiskTiming.
     */
    private static double[] saqureRiskAssessmentSystemAED() {
        double[] risk = new double[VULNERABILITIES_PER_IMPLEMENTATION.length];
        for (int i = 0; i < VULNERABILITIES_PER_IMPLEMENTATION.length; i++) {
            String domainFile = AED_process(AED_OUTPUT_DIR + "restaurant_" + i + ".pddl",
                    VULNERABILITIES_PER_IMPLEMENTATION[i]);
            risk[i] = EADSA.computeScenario(domainFile, attackGoals(i));
        }
        return normalise(risk);
    }

    // Superseded by riskWallClockModules; kept for reference.
    /**
     * RQ4.2.2 with EADSA: wall clock of restaurant_0's assessment, once per
     * replica, after one untimed warm-up pass. No DTMC is built and PRISM is never called.
     */
    public static void riskWallClockSystemAED(int scale) {
        createDirectories();
        String domainFile = AED_process(AED_OUTPUT_DIR + "restaurant_0.pddl", VULNERABILITIES_PER_IMPLEMENTATION[0]);
        RiskTiming.pause();
        EADSA.computeScenario(domainFile, attackGoals(0));
        RiskTiming.resume();
        log.info("Risk assessment wall clock per replica (restaurant0; system-level AED, {} replicas)", scale);
        for (int replica = 1; replica <= scale; replica++) {
            RiskTiming.reset();
            EADSA.computeScenario(domainFile, attackGoals(0));
            long nanos = RiskTiming.samples().stream().mapToLong(Duration::toNanos).sum();
            log.info("Risk assessment time cost for replica_{}: {}ms", replica, String.format("%.1f", nanos / 1e6));
        }
    }

    /**
     * Superseded by {@link #saqureRiskAssessmentSystemAED()}; kept for reference. SAQURE with
     * {@link VulnAxisAP}, which gives the risk of each implementation.
     */
    private static double[] saqureRiskAssessmentIndependentDomains() {
        double[] risk = new double[VULNERABILITIES_PER_IMPLEMENTATION.length];
        for (int i = 0; i < VULNERABILITIES_PER_IMPLEMENTATION.length; i++) {
            risk[i] = VulnAxisAP.computeScenario(VULNERABILITIES_PER_IMPLEMENTATION[i]);
        }
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
