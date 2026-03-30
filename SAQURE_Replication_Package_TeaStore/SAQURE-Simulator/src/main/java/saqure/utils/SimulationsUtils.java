package saqure.utils;

import saqure.Analyzer.EADSA;
import saqure.utils.infrastructure.adaptation.specifications.Availability;
import saqure.utils.infrastructure.adaptation.specifications.AverageResponseTime;
import saqure.utils.infrastructure.adaptation.specifications.QoSSpecification;
import saqure.utils.infrastructure.adaptation.specifications.Vulnerability;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import saqure.utils.infrastructure.architecture.*;

import static saqure.utils.AED_Processor.AED_process;
import static saqure.utils.AED_Processor.AED_process_nodyPa;

import java.io.IOException;
import java.util.*;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

public class SimulationsUtils {
    public static final Logger log = LoggerFactory.getLogger(SimulationsUtils.class);

    private SimulationsUtils() {
        throw new IllegalStateException("Utility class");
    }
    public static String experiment_num;
    private static ExcelToJsonConverter converter;

    public static void setCompMode(EADSA.ComputationMode mode){
        EADSA.setComputationMode(mode);
    }
    static {
        // setCompMode(DynamicDTMC.ComputationMode.SEQUENTIAL);//Comment out this line when using a .sh script; otherwise, uncomment it. Control is performed here; parallelism is the default.)
    }

    public static class DynamicNormalize {
        private double MAX;
        private double MIN;
        private double MEAN;
        private double STDDEV;
        private double DATA_MAX;  // Maximum value of original data
        private double DATA_MIN;  // Minimum value of original data
        private boolean initialized = false;
        private static final double EPSILON = 1e-12;

        public double normalize(double l_vulnerability) {
            if (!initialized) {
                throw new IllegalStateException("Normalizer not initialized. Call preProcessing first.");
            }

            double standardized = standralize(l_vulnerability);

            // Scenario 1: All values are the same after standardization, but the original data may differ.
            if (Math.abs(MAX - MIN) < EPSILON) {
                // Revert to normalization based on the original data
                return normalizeByOriginal(l_vulnerability);
            }

            // Case 2: Under normal circumstances, use the standardized value.
            double normalized = 0.1 + (1 - 2 * 0.1) * (standardized - MIN) / (MAX - MIN);
            return Math.max(0.1, Math.min(0.9, normalized));
        }

        private double normalizeByOriginal(double value) {
            // When standardization fails, use min-max normalization of the original data.
            if (Math.abs(DATA_MAX - DATA_MIN) < EPSILON) {
                // If the original data is exactly the same, return the median value.
                return 0.5;
            }

            // Normalization is performed based on the relative relationships of the original data.
            return 0.1 + (1 - 2 * 0.1) * (value - DATA_MIN) / (DATA_MAX - DATA_MIN);
        }

        public double standralize(double l_vulnerability) {
            if (!initialized) {
                throw new IllegalStateException("Normalizer not initialized. Call preProcessing first.");
            }

            if (Math.abs(STDDEV) < EPSILON) {
                return 0.0;
            }

            return (l_vulnerability - MEAN) / STDDEV;
        }

        public void preProcessing(double[] costValues) {
            if (costValues == null || costValues.length == 0) {
                throw new IllegalArgumentException("costValues cannot be null or empty");
            }

            // Scope of storing raw data
            DATA_MAX = Arrays.stream(costValues).max().getAsDouble();
            DATA_MIN = Arrays.stream(costValues).min().getAsDouble();
            MEAN = Arrays.stream(costValues).average().getAsDouble();

            // Calculate the standard deviation
            double variance = Arrays.stream(costValues)
                    .map(c -> Math.pow(c - MEAN, 2))
                    .sum() / costValues.length;
            STDDEV = Math.sqrt(variance);

            // Calculate the standardized range
            double[] standardizedValues = Arrays.stream(costValues)
                    .map(v -> Math.abs(STDDEV) < EPSILON ? 0.0 : (v - MEAN) / STDDEV)
                    .toArray();

            MAX = Arrays.stream(standardizedValues).max().getAsDouble();
            MIN = Arrays.stream(standardizedValues).min().getAsDouble();

            initialized = true;
        }
    }

    private static Map<String, Service> createSAQUREScenario(
            String scenarioName,
            Map<String, List<String>> serviceImplementations,
            Map<String, String> domainFiles,
            Map<String, EADSA.outputPath> planPaths) {

        double availabilityWeight = 0.3;
        double responseTimeWeight = 0.3;
        double vulnerabilityWeight = 0.4;
        try {
            converter = new ExcelToJsonConverter(FilePathConstants.configration_rq1_path);
        } catch (Exception e) {
            throw new ExceptionInInitializerError("Failed to initialize Excel converter: " + e.getMessage());
        }

        // === Availability + ResponseTime ===
        Map<String, Map<Class<? extends QoSSpecification>, Double>> benchmarkForImplementation = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> currentQoSValues = new HashMap<>();

        DynamicNormalize availabilityNormalizer = new DynamicNormalize();
        DynamicNormalize responseTimeNormalizer = new DynamicNormalize();

        // Collect all values
        List<Double> availabilities = new ArrayList<>();
        List<Integer> responseTimes = new ArrayList<>();

        for (Map.Entry<String, List<String>> entry : serviceImplementations.entrySet()) {
            String service = entry.getKey();
            for (String impl : entry.getValue()) {
                double a = (double) converter.getValue(scenarioName, service, impl, "availability");
                int t = (int) converter.getValue(scenarioName, service, impl, "responseTime");
                availabilities.add(a);
                responseTimes.add(t);
                }
        }
        availabilityNormalizer.preProcessing(availabilities.stream().mapToDouble(Double::doubleValue).toArray());
        responseTimeNormalizer.preProcessing(responseTimes.stream().mapToDouble(Integer::intValue).toArray());

        Map<String, String[]> cveIdsForImplementations = new HashMap<>();
        String serviceName = "";
        for (Map.Entry<String, String> entry_ : domainFiles.entrySet()) {
            String impl_ = entry_.getKey();
            if(serviceName.equals("")){
                serviceName = serviceImplementations.entrySet().stream().filter(e->e.getValue().contains(impl_)).map(Map.Entry::getKey).findFirst().orElse(null);
//                System.out.print("serviceNme: "+serviceName+"\n");
            }
            List<String> vulnerabilityList = new ArrayList<>();

            // In addition to the current vulnerability corresponding to impl
            List<String> serviceVulns = (List<String>) converter.getValue(scenarioName,
                    serviceName,
                    impl_, "vulnerabilitylist");
//            System.out.print("serviceVulns: " + serviceVulns);
            if (serviceVulns != null) {
                vulnerabilityList.addAll(serviceVulns);
            }
            // In addition to the vulnerabilities of the other four fixed services
            for (Map.Entry<String, List<String>> entry : serviceImplementations.entrySet()) {
                String service = entry.getKey();
                if (serviceName.equals(service)) continue; // Skip services with options

                for (String subService : entry.getValue()) {
                    List<String> vulns = (List<String>) converter.getValue(scenarioName, service, subService, "vulnerabilitylist");
                    if (vulns != null) {
                        vulnerabilityList.addAll(vulns);
                    }
                    else {log.info("Error: SimulationsUtils.java, line 124, vulns from converter is null");}
                }
            }
//            System.out.println("impl: " + impl_ + " vulnerabilityList: " + vulnerabilityList+"\n");
            cveIdsForImplementations.put(impl_, vulnerabilityList.toArray(new String[0]));
        }

        // === Vulnerability Normalization ===
        Map<String, Double> vulnerabilityCosts = new LinkedHashMap<>();
        for (Map.Entry<String, String> entry : domainFiles.entrySet()) {
            String impl = entry.getKey();
            String domainFile = AED_process(entry.getValue(), cveIdsForImplementations.get(impl));
            EADSA.outputPath outputPath = planPaths.get(impl);
            double cost = EADSA.computeScenario(domainFile, outputPath);
            log.info("Risk of " + impl + ": " + cost);
            vulnerabilityCosts.put(impl, cost);
        }
        double defaultCost = vulnerabilityCosts.values().iterator().next();
        DynamicNormalize costNormalizer = new DynamicNormalize();
        costNormalizer.preProcessing(vulnerabilityCosts.values().stream().mapToDouble(Double::doubleValue).toArray());

        // === Benchmark and Current QoS ===
        for (Map.Entry<String, List<String>> entry : serviceImplementations.entrySet()) {
            String service = entry.getKey();
            List<String> impls = entry.getValue();

            for (String impl : impls) {
                double a = (double) converter.getValue(scenarioName, service, impl, "availability");
                int t = (int) converter.getValue(scenarioName, service, impl, "responseTime");
                double v = vulnerabilityCosts.containsKey(impl) ? vulnerabilityCosts.get(impl) : defaultCost;
                Map<Class<? extends QoSSpecification>, Double> benchmark = new HashMap<>();
                benchmark.put(Availability.class, availabilityNormalizer.normalize(a));
                benchmark.put(AverageResponseTime.class, responseTimeNormalizer.normalize(t));
                benchmark.put(Vulnerability.class, costNormalizer.normalize(v));
                benchmarkForImplementation.put(impl, benchmark);
//                System.out.printf(" impl: "+impl+" avail: "+a+" time: "+t + " cost: "+v+"\n");
            }

            // The first implementation is used as currentQoS by default.
            String firstImpl = impls.get(0);
            double a0 = (double) converter.getValue(scenarioName, service, firstImpl, "availability");
            int t0 = (int) converter.getValue(scenarioName, service, firstImpl, "responseTime");

            Map<Class<? extends QoSSpecification>, Double> currentQoS = new HashMap<>();
            currentQoS.put(Availability.class, availabilityNormalizer.normalize(a0));
            currentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(t0));
            currentQoSValues.put(service, currentQoS);
        }

        return createServiceMap(availabilityWeight,
                responseTimeWeight,
                vulnerabilityWeight,
                serviceImplementations,
                benchmarkForImplementation,
                currentQoSValues);
    }

    public static Map<String, Service> RQ1_s1_SAQURE_ExpConfig() {
        Map<String, List<String>> serviceImplementations = new HashMap<>();
        serviceImplementations.put("WEBUI-SERVICE", List.of("webui-1-service","webui-2-service","webui-3-service"));
        serviceImplementations.put("AUTHENTICATION-SERVICE", List.of("authentication-service"));
        serviceImplementations.put("PERSISTENCE-SERVICE", List.of("persistence-service"));
        serviceImplementations.put("IMAGE-SERVICE", List.of("image-service"));
        serviceImplementations.put("RECOMMENDER-SERVICE", List.of("recommender-service"));

        Map<String, String> domainFiles = new LinkedHashMap<>();
        domainFiles.put("webui-1-service", FilePathConstants.AED_path_RQ1 + "S1_W0_A0_P0_I0.pddl");
        domainFiles.put("webui-2-service", FilePathConstants.AED_path_RQ1 + "S1_W1_A0_P0_I0.pddl");
        domainFiles.put("webui-3-service", FilePathConstants.AED_path_RQ1 + "S1_W2_A0_P0_I0.pddl");

        Map<String, EADSA.outputPath> planPaths = new HashMap<>();
        planPaths.put("webui-1-service", new EADSA.outputPath(
                FilePathConstants.AP_path + "RQ1/S1_W0_A0_P0_I0_plan/spoofing_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S1_W0_A0_P0_I0_plan/tampering_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S1_W0_A0_P0_I0_plan/repudiation_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S1_W0_A0_P0_I0_plan/information_disclosure_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S1_W0_A0_P0_I0_plan/denial_of_service_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S1_W0_A0_P0_I0_plan/elevation_of_privilege_plan.pddl"));
        planPaths.put("webui-2-service", new EADSA.outputPath(
                FilePathConstants.AP_path + "RQ1/S1_W1_A0_P0_I0_plan/spoofing_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S1_W1_A0_P0_I0_plan/tampering_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S1_W1_A0_P0_I0_plan/repudiation_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S1_W1_A0_P0_I0_plan/information_disclosure_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S1_W1_A0_P0_I0_plan/denial_of_service_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S1_W1_A0_P0_I0_plan/elevation_of_privilege_plan.pddl"));
        planPaths.put("webui-3-service", new EADSA.outputPath(
                FilePathConstants.AP_path + "RQ1/S1_W2_A0_P0_I0_plan/spoofing_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S1_W2_A0_P0_I0_plan/tampering_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S1_W2_A0_P0_I0_plan/repudiation_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S1_W2_A0_P0_I0_plan/information_disclosure_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S1_W2_A0_P0_I0_plan/denial_of_service_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S1_W2_A0_P0_I0_plan/elevation_of_privilege_plan.pddl"));

        return createSAQUREScenario("Sub-scenario1", serviceImplementations, domainFiles, planPaths);
    }
    public static Map<String, Service> RQ1_s2_SAQURE_ExpConfig() {
    Map<String, List<String>> serviceImplementations = new HashMap<>();
    serviceImplementations.put("WEBUI-SERVICE", List.of("webui-1-service","webui-2-service","webui-3-service"));
    serviceImplementations.put("AUTHENTICATION-SERVICE", List.of("authentication-service"));
    serviceImplementations.put("PERSISTENCE-SERVICE", List.of("persistence-service"));
    serviceImplementations.put("IMAGE-SERVICE", List.of("image-service"));
    serviceImplementations.put("RECOMMENDER-SERVICE", List.of("recommender-service"));

    Map<String, String> domainFiles = new LinkedHashMap<>();
    domainFiles.put("webui-1-service", FilePathConstants.AED_path_RQ1 + "S2_W0_A0_P0_I0.pddl");
    domainFiles.put("webui-2-service", FilePathConstants.AED_path_RQ1 + "S2_W1_A0_P0_I0.pddl");
    domainFiles.put("webui-3-service", FilePathConstants.AED_path_RQ1 + "S2_W2_A0_P0_I0.pddl");

    Map<String, EADSA.outputPath> planPaths = new HashMap<>();
        planPaths.put("webui-1-service", new EADSA.outputPath(
                FilePathConstants.AP_path + "RQ1/S2_W0_A0_P0_I0_plan/spoofing_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S2_W0_A0_P0_I0_plan/tampering_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S2_W0_A0_P0_I0_plan/repudiation_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S2_W0_A0_P0_I0_plan/information_disclosure_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S2_W0_A0_P0_I0_plan/denial_of_service_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S2_W0_A0_P0_I0_plan/elevation_of_privilege_plan.pddl"));
        planPaths.put("webui-2-service", new EADSA.outputPath(
                FilePathConstants.AP_path + "RQ1/S2_W1_A0_P0_I0_plan/spoofing_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S2_W1_A0_P0_I0_plan/tampering_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S2_W1_A0_P0_I0_plan/repudiation_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S2_W1_A0_P0_I0_plan/information_disclosure_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S2_W1_A0_P0_I0_plan/denial_of_service_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S2_W1_A0_P0_I0_plan/elevation_of_privilege_plan.pddl"));
        planPaths.put("webui-3-service", new EADSA.outputPath(
                FilePathConstants.AP_path + "RQ1/S2_W2_A0_P0_I0_plan/spoofing_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S2_W2_A0_P0_I0_plan/tampering_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S2_W2_A0_P0_I0_plan/repudiation_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S2_W2_A0_P0_I0_plan/information_disclosure_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S2_W2_A0_P0_I0_plan/denial_of_service_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S2_W2_A0_P0_I0_plan/elevation_of_privilege_plan.pddl"));

        return createSAQUREScenario("Sub-scenario2", serviceImplementations, domainFiles, planPaths);
}
    public static Map<String, Service> RQ1_s3_SAQURE_ExpConfig() {
        Map<String, List<String>> serviceImplementations = new HashMap<>();
        serviceImplementations.put("WEBUI-SERVICE", List.of("webui-service"));
        serviceImplementations.put("AUTHENTICATION-SERVICE", List.of("authentication-1-service", "authentication-2-service", "authentication-3-service", "authentication-4-service"));
        serviceImplementations.put("PERSISTENCE-SERVICE", List.of("persistence-service"));
        serviceImplementations.put("IMAGE-SERVICE", List.of("image-service"));
        serviceImplementations.put("RECOMMENDER-SERVICE", List.of("recommender-service"));

        Map<String, String> domainFiles = new LinkedHashMap<>();
        domainFiles.put("authentication-1-service", FilePathConstants.AED_path_RQ1 + "S3_W0_A0_P0_I0.pddl");
        domainFiles.put("authentication-2-service", FilePathConstants.AED_path_RQ1 + "S3_W0_A1_P0_I0.pddl");
        domainFiles.put("authentication-3-service", FilePathConstants.AED_path_RQ1 + "S3_W0_A2_P0_I0.pddl");
        domainFiles.put("authentication-4-service", FilePathConstants.AED_path_RQ1 + "S3_W0_A3_P0_I0.pddl");

        Map<String, EADSA.outputPath> planPaths = new HashMap<>();
        planPaths.put("authentication-1-service", new EADSA.outputPath(
                FilePathConstants.AP_path + "RQ1/S3_W0_A0_P0_I0_plan/spoofing_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S3_W0_A0_P0_I0_plan/tampering_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S3_W0_A0_P0_I0_plan/repudiation_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S3_W0_A0_P0_I0_plan/information_disclosure_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S3_W0_A0_P0_I0_plan/denial_of_service_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S3_W0_A0_P0_I0_plan/elevation_of_privilege_plan.pddl"));
        planPaths.put("authentication-2-service", new EADSA.outputPath(
                FilePathConstants.AP_path + "RQ1/S3_W0_A1_P0_I0_plan/spoofing_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S3_W0_A1_P0_I0_plan/tampering_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S3_W0_A1_P0_I0_plan/repudiation_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S3_W0_A1_P0_I0_plan/information_disclosure_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S3_W0_A1_P0_I0_plan/denial_of_service_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S3_W0_A1_P0_I0_plan/elevation_of_privilege_plan.pddl"));
        planPaths.put("authentication-3-service", new EADSA.outputPath(
                FilePathConstants.AP_path + "RQ1/S3_W0_A2_P0_I0_plan/spoofing_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S3_W0_A2_P0_I0_plan/tampering_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S3_W0_A2_P0_I0_plan/repudiation_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S3_W0_A2_P0_I0_plan/information_disclosure_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S3_W0_A2_P0_I0_plan/denial_of_service_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S3_W0_A2_P0_I0_plan/elevation_of_privilege_plan.pddl"));
        planPaths.put("authentication-4-service", new EADSA.outputPath(
                FilePathConstants.AP_path + "RQ1/S3_W0_A3_P0_I0_plan/spoofing_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S3_W0_A3_P0_I0_plan/tampering_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S3_W0_A3_P0_I0_plan/repudiation_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S3_W0_A3_P0_I0_plan/information_disclosure_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S3_W0_A3_P0_I0_plan/denial_of_service_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S3_W0_A3_P0_I0_plan/elevation_of_privilege_plan.pddl"));

        return createSAQUREScenario("Sub-scenario3", serviceImplementations, domainFiles, planPaths);
    }
    public static Map<String, Service> RQ1_s4_SAQURE_ExpConfig() {
        Map<String, List<String>> serviceImplementations = new HashMap<>();
        serviceImplementations.put("WEBUI-SERVICE", List.of("webui-service"));
        serviceImplementations.put("AUTHENTICATION-SERVICE", List.of("authentication-service"));
        serviceImplementations.put("PERSISTENCE-SERVICE", List.of("persistence-1-service", "persistence-2-service", "persistence-3-service", "persistence-4-service"));
        serviceImplementations.put("IMAGE-SERVICE", List.of("image-service"));
        serviceImplementations.put("RECOMMENDER-SERVICE", List.of("recommender-service"));

        Map<String, String> domainFiles = new LinkedHashMap<>();
        domainFiles.put("persistence-1-service", FilePathConstants.AED_path_RQ1 + "S4_W0_A0_P0_I0.pddl");
        domainFiles.put("persistence-2-service", FilePathConstants.AED_path_RQ1 + "S4_W0_A0_P1_I0.pddl");
        domainFiles.put("persistence-3-service", FilePathConstants.AED_path_RQ1 + "S4_W0_A0_P2_I0.pddl");
        domainFiles.put("persistence-4-service", FilePathConstants.AED_path_RQ1 + "S4_W0_A0_P3_I0.pddl");

        Map<String, EADSA.outputPath> planPaths = new HashMap<>();
        planPaths.put("persistence-1-service", new EADSA.outputPath(
                FilePathConstants.AP_path + "RQ1/S4_W0_A0_P0_I0_plan/spoofing_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S4_W0_A0_P0_I0_plan/tampering_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S4_W0_A0_P0_I0_plan/repudiation_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S4_W0_A0_P0_I0_plan/information_disclosure_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S4_W0_A0_P0_I0_plan/denial_of_service_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S4_W0_A0_P0_I0_plan/elevation_of_privilege_plan.pddl"));
        planPaths.put("persistence-2-service", new EADSA.outputPath(
                FilePathConstants.AP_path + "RQ1/S4_W0_A0_P1_I0_plan/spoofing_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S4_W0_A0_P1_I0_plan/tampering_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S4_W0_A0_P1_I0_plan/repudiation_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S4_W0_A0_P1_I0_plan/information_disclosure_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S4_W0_A0_P1_I0_plan/denial_of_service_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S4_W0_A0_P1_I0_plan/elevation_of_privilege_plan.pddl"));
        planPaths.put("persistence-3-service", new EADSA.outputPath(
                FilePathConstants.AP_path + "RQ1/S4_W0_A0_P2_I0_plan/spoofing_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S4_W0_A0_P2_I0_plan/tampering_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S4_W0_A0_P2_I0_plan/repudiation_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S4_W0_A0_P2_I0_plan/information_disclosure_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S4_W0_A0_P2_I0_plan/denial_of_service_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S4_W0_A0_P2_I0_plan/elevation_of_privilege_plan.pddl"));
        planPaths.put("persistence-4-service", new EADSA.outputPath(
                FilePathConstants.AP_path + "RQ1/S4_W0_A0_P3_I0_plan/spoofing_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S4_W0_A0_P3_I0_plan/tampering_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S4_W0_A0_P3_I0_plan/repudiation_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S4_W0_A0_P3_I0_plan/information_disclosure_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S4_W0_A0_P3_I0_plan/denial_of_service_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S4_W0_A0_P3_I0_plan/elevation_of_privilege_plan.pddl"));

        return createSAQUREScenario("Sub-scenario4", serviceImplementations, domainFiles, planPaths);
    }
    public static Map<String, Service> RQ1_s5_SAQURE_ExpConfig() {
        Map<String, List<String>> serviceImplementations = new HashMap<>();
        serviceImplementations.put("WEBUI-SERVICE", List.of("webui-service"));
        serviceImplementations.put("AUTHENTICATION-SERVICE", List.of("authentication-service"));
        serviceImplementations.put("PERSISTENCE-SERVICE", List.of("persistence-service"));
        serviceImplementations.put("IMAGE-SERVICE", List.of("image-1-service", "image-2-service", "image-3-service", "image-4-service"));
        serviceImplementations.put("RECOMMENDER-SERVICE", List.of("recommender-service"));

        Map<String, String> domainFiles = new LinkedHashMap<>();
        domainFiles.put("image-1-service", FilePathConstants.AED_path_RQ1 + "S5_W0_A0_P0_I0.pddl");
        domainFiles.put("image-2-service", FilePathConstants.AED_path_RQ1 + "S5_W0_A0_P0_I1.pddl");
        domainFiles.put("image-3-service", FilePathConstants.AED_path_RQ1 + "S5_W0_A0_P0_I2.pddl");
        domainFiles.put("image-4-service", FilePathConstants.AED_path_RQ1 + "S5_W0_A0_P0_I3.pddl");

        Map<String, EADSA.outputPath> planPaths = new HashMap<>();
        planPaths.put("image-1-service", new EADSA.outputPath(
                FilePathConstants.AP_path + "RQ1/S5_W0_A0_P0_I0_plan/spoofing_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S5_W0_A0_P0_I0_plan/tampering_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S5_W0_A0_P0_I0_plan/repudiation_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S5_W0_A0_P0_I0_plan/information_disclosure_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S5_W0_A0_P0_I0_plan/denial_of_service_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S5_W0_A0_P0_I0_plan/elevation_of_privilege_plan.pddl"));
        planPaths.put("image-2-service", new EADSA.outputPath(
                FilePathConstants.AP_path + "RQ1/S5_W0_A0_P0_I1_plan/spoofing_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S5_W0_A0_P0_I1_plan/tampering_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S5_W0_A0_P0_I1_plan/repudiation_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S5_W0_A0_P0_I1_plan/information_disclosure_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S5_W0_A0_P0_I1_plan/denial_of_service_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S5_W0_A0_P0_I1_plan/elevation_of_privilege_plan.pddl"));
        planPaths.put("image-3-service", new EADSA.outputPath(
                FilePathConstants.AP_path + "RQ1/S5_W0_A0_P0_I2_plan/spoofing_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S5_W0_A0_P0_I2_plan/tampering_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S5_W0_A0_P0_I2_plan/repudiation_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S5_W0_A0_P0_I2_plan/information_disclosure_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S5_W0_A0_P0_I2_plan/denial_of_service_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S5_W0_A0_P0_I2_plan/elevation_of_privilege_plan.pddl"));
        planPaths.put("image-4-service", new EADSA.outputPath(
                FilePathConstants.AP_path + "RQ1/S5_W0_A0_P0_I3_plan/spoofing_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S5_W0_A0_P0_I3_plan/tampering_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S5_W0_A0_P0_I3_plan/repudiation_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S5_W0_A0_P0_I3_plan/information_disclosure_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S5_W0_A0_P0_I3_plan/denial_of_service_plan.pddl",
                FilePathConstants.AP_path + "RQ1/S5_W0_A0_P0_I3_plan/elevation_of_privilege_plan.pddl"));

        return createSAQUREScenario("Sub-scenario5", serviceImplementations, domainFiles, planPaths);
    }

    private static Map<String, Service> createAquaScenario(String scenarioName,
                                                          Map<String, List<String>> serviceImplementations,
                                                          Map<String, ServiceQoSConfig> qosConfig,
                                                          Map<String, String> defaultImplementations,
                                                           double availabilityWeight,
                                                           double responseTimeWeight,
                                                           double vulnerabilityWeight){

        Map<String, Map<Class<? extends QoSSpecification>, Double>> benchmarkForImplementation = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> currentQoSValues = new HashMap<>();

        for (Map.Entry<String, List<String>> entry : serviceImplementations.entrySet()) {
            String service = entry.getKey();
            List<String> impls = entry.getValue();
            String defaultImpl = defaultImplementations.getOrDefault(service, impls.get(0));
            if (!impls.contains(defaultImpl)) {
                throw new IllegalArgumentException("Default implementation '" + defaultImpl + "' not found in service '" + service + "'");
            }

            for (String impl : impls) {
                ServiceQoSConfig config = qosConfig.get(impl);
                if(config == null){
                    throw new IllegalArgumentException("Missing QoS configuration for implementation: " + impl);
                }
                double a = config.availability;
                double t = config.responseTime;
                double v = config.vulnerability;
                Map<Class<? extends QoSSpecification>, Double> benchmark = new HashMap<>();
                benchmark.put(Availability.class, a);
                benchmark.put(AverageResponseTime.class, t);
                benchmark.put(Vulnerability.class, v);
                benchmarkForImplementation.put(impl, benchmark);
//                System.out.printf(" impl: "+impl+" avail: "+a+" time: "+t + " cost: "+v);
            }

            // The first implementation is used as currentQoS by default.
            ServiceQoSConfig defaultConfig = qosConfig.get(defaultImpl);

            Map<Class<? extends QoSSpecification>, Double> currentQoS = new HashMap<>();
            currentQoS.put(Availability.class, defaultConfig.availability);
            currentQoS.put(AverageResponseTime.class, defaultConfig.responseTime);
            currentQoSValues.put(service, currentQoS);
        }

        return  createServiceMap(availabilityWeight,
                responseTimeWeight,
                vulnerabilityWeight,
                serviceImplementations,
                benchmarkForImplementation,
                currentQoSValues);
    }
    public static class ServiceQoSConfig{
        public final double availability;
        public final double responseTime;
        public final double vulnerability;

        public ServiceQoSConfig(double availability, double responseTime, double vulnerability){
            this.availability = availability;
            this.responseTime = responseTime;
            this.vulnerability = vulnerability;
        }
    }
    public static Map<String, Service> RQ1_s1_Aqua_ExpConfig(){
        Map<String, List<String>> serviceImplementations = new HashMap<>();
        serviceImplementations.put("WEBUI-SERVICE", List.of("webui-1-service","webui-2-service","webui-3-service"));
        serviceImplementations.put("AUTHENTICATION-SERVICE", List.of("authentication-service"));
        serviceImplementations.put("PERSISTENCE-SERVICE", List.of("persistence-service"));
        serviceImplementations.put("IMAGE-SERVICE", List.of("image-service"));
        serviceImplementations.put("RECOMMENDER-SERVICE", List.of("recommender-service"));

        Map<String, ServiceQoSConfig> qosConfig = new HashMap<>();
        qosConfig.put("webui-1-service", new ServiceQoSConfig(0.731578947, 0.263636364, 0.4136));
        qosConfig.put("webui-2-service", new ServiceQoSConfig(0.773684211, 0.227272727, 0.1));
        qosConfig.put("webui-3-service", new ServiceQoSConfig(0.857894737, 0.190909091, 0.6536));
        qosConfig.put("authentication-service", new ServiceQoSConfig(0.773684211, 0.809090909, 0.3368));
        qosConfig.put("persistence-service", new ServiceQoSConfig(0.626315789, 0.627272727, 0.5864));
        qosConfig.put("image-service", new ServiceQoSConfig(0.773684211, 0.809090909, 0.2888));
        qosConfig.put("recommender-service", new ServiceQoSConfig(0.731578947, 0.9, 0.34));

        Map<String, String> defaultImplementations = new HashMap<>();
        defaultImplementations.put("WEBUI-SERVICE", "webui-1-service");
        defaultImplementations.put("AUTHENTICATION-SERVICE", "authentication-service");
        defaultImplementations.put("PERSISTENCE-SERVICE", "persistence-service");
        defaultImplementations.put("IMAGE-SERVICE", "image-service");
        defaultImplementations.put("RECOMMENDER-SERVICE", "recommender-service");

        return createAquaScenario("Sub-scenario1", serviceImplementations, qosConfig, defaultImplementations, 0.3, 0.3, 0.4);
    }
    public static Map<String, Service> RQ1_s2_Aqua_ExpConfig(){
        Map<String, List<String>> serviceImplementations = new HashMap<>();
        serviceImplementations.put("WEBUI-SERVICE", List.of("webui-1-service","webui-2-service","webui-3-service"));
        serviceImplementations.put("AUTHENTICATION-SERVICE", List.of("authentication-service"));
        serviceImplementations.put("PERSISTENCE-SERVICE", List.of("persistence-service"));
        serviceImplementations.put("IMAGE-SERVICE", List.of("image-service"));
        serviceImplementations.put("RECOMMENDER-SERVICE", List.of("recommender-service"));

        Map<String, ServiceQoSConfig> qosConfig = new HashMap<>();
        qosConfig.put("webui-1-service", new ServiceQoSConfig(0.731578947, 0.263636364, 0.4136));
        qosConfig.put("webui-2-service", new ServiceQoSConfig(0.857894737, 0.1, 0.2888));
        qosConfig.put("webui-3-service", new ServiceQoSConfig(0.836842105, 0.136363636, 0.1));
        qosConfig.put("authentication-service", new ServiceQoSConfig(0.773684211, 0.809090909, 0.3368));
        qosConfig.put("persistence-service", new ServiceQoSConfig(0.626315789, 0.627272727, 0.5864));
        qosConfig.put("image-service", new ServiceQoSConfig(0.773684211, 0.809090909, 0.2888));
        qosConfig.put("recommender-service", new ServiceQoSConfig(0.731578947, 0.9, 0.34));

        Map<String, String> defaultImplementations = new HashMap<>();
        defaultImplementations.put("WEBUI-SERVICE", "webui-1-service");
        defaultImplementations.put("AUTHENTICATION-SERVICE", "authentication-service");
        defaultImplementations.put("PERSISTENCE-SERVICE", "persistence-service");
        defaultImplementations.put("IMAGE-SERVICE", "image-service");
        defaultImplementations.put("RECOMMENDER-SERVICE", "recommender-service");

        return createAquaScenario("Sub-scenario2", serviceImplementations, qosConfig, defaultImplementations, 0.3, 0.3, 0.4);
    }
    public static Map<String, Service> RQ1_s3_Aqua_ExpConfig(){
        Map<String, List<String>> serviceImplementations = new HashMap<>();
        serviceImplementations.put("WEBUI-SERVICE", List.of("webui-service"));
        serviceImplementations.put("AUTHENTICATION-SERVICE", List.of("authentication-1-service", "authentication-2-service", "authentication-3-service", "authentication-4-service"));
        serviceImplementations.put("PERSISTENCE-SERVICE", List.of("persistence-service"));
        serviceImplementations.put("IMAGE-SERVICE", List.of("image-service"));
        serviceImplementations.put("RECOMMENDER-SERVICE", List.of("recommender-service"));

        Map<String, ServiceQoSConfig> qosConfig = new HashMap<>();
        qosConfig.put("webui-service", new ServiceQoSConfig(0.626315789, 0.809090909, 0.34));
        qosConfig.put("authentication-1-service", new ServiceQoSConfig(0.773684211, 0.718181818, 0.564));
        qosConfig.put("authentication-2-service", new ServiceQoSConfig(0.731578947, 0.809090909, 0.564));
        qosConfig.put("authentication-3-service", new ServiceQoSConfig(0.626315789, 0.627272727, 0.564));
        qosConfig.put("authentication-4-service", new ServiceQoSConfig(0.626315789, 0.809090909, 0.1728));
        qosConfig.put("persistence-service", new ServiceQoSConfig(0.415789474, 0.809090909, 0.3592));
        qosConfig.put("image-service", new ServiceQoSConfig(0.415789474, 0.718181818, 0.2888));
        qosConfig.put("recommender-service", new ServiceQoSConfig(0.731578947, 0.9, 0.34));

        Map<String, String> defaultImplementations = new HashMap<>();
        defaultImplementations.put("WEBUI-SERVICE", "webui-service");
        defaultImplementations.put("AUTHENTICATION-SERVICE", "authentication-1-service");
        defaultImplementations.put("PERSISTENCE-SERVICE", "persistence-service");
        defaultImplementations.put("IMAGE-SERVICE", "image-service");
        defaultImplementations.put("RECOMMENDER-SERVICE", "recommender-service");

        return createAquaScenario("Sub-scenario3", serviceImplementations, qosConfig, defaultImplementations, 0.3, 0.3, 0.4);
    }
    public static Map<String, Service> RQ1_s4_Aqua_ExpConfig(){
        Map<String, List<String>> serviceImplementations = new HashMap<>();
        serviceImplementations.put("WEBUI-SERVICE", List.of("webui-service"));
        serviceImplementations.put("AUTHENTICATION-SERVICE", List.of("authentication-service"));
        serviceImplementations.put("PERSISTENCE-SERVICE", List.of("persistence-1-service", "persistence-2-service", "persistence-3-service", "persistence-4-service"));
        serviceImplementations.put("IMAGE-SERVICE", List.of("image-service"));
        serviceImplementations.put("RECOMMENDER-SERVICE", List.of("recommender-service"));

        Map<String, ServiceQoSConfig> qosConfig = new HashMap<>();
        qosConfig.put("webui-service", new ServiceQoSConfig(0.731578947, 0.172727273, 0.34));
        qosConfig.put("authentication-service", new ServiceQoSConfig(0.521052632, 0.445454545, 0.3368));
        qosConfig.put("persistence-1-service", new ServiceQoSConfig(0.310526316, 0.627272727, 0.5864));
        qosConfig.put("persistence-2-service", new ServiceQoSConfig(0.352631579, 0.627272727, 0.9));
        qosConfig.put("persistence-3-service", new ServiceQoSConfig(0.310526316, 0.554545455, 0.9));
        qosConfig.put("persistence-4-service", new ServiceQoSConfig(0.310526316, 0.627272727, 0.1));
        qosConfig.put("image-service", new ServiceQoSConfig(0.1, 0.809090909, 0.34));
        qosConfig.put("recommender-service", new ServiceQoSConfig(0.731578947, 0.9, 0.34));

        Map<String, String> defaultImplementations = new HashMap<>();
        defaultImplementations.put("WEBUI-SERVICE", "webui-service");
        defaultImplementations.put("AUTHENTICATION-SERVICE", "authentication-service");
        defaultImplementations.put("PERSISTENCE-SERVICE", "persistence-1-service");
        defaultImplementations.put("IMAGE-SERVICE", "image-service");
        defaultImplementations.put("RECOMMENDER-SERVICE", "recommender-service");

        return createAquaScenario("Sub-scenario4", serviceImplementations, qosConfig, defaultImplementations, 0.3, 0.3, 0.4);
    }
    public static Map<String, Service> RQ1_s5_Aqua_ExpConfig(){
        Map<String, List<String>> serviceImplementations = new HashMap<>();
        serviceImplementations.put("WEBUI-SERVICE", List.of("webui-service"));
        serviceImplementations.put("AUTHENTICATION-SERVICE", List.of("authentication-service"));
        serviceImplementations.put("PERSISTENCE-SERVICE", List.of("persistence-service"));
        serviceImplementations.put("IMAGE-SERVICE", List.of("image-1-service", "image-2-service", "image-3-service", "image-4-service"));
        serviceImplementations.put("RECOMMENDER-SERVICE", List.of("recommender-service"));

        Map<String, ServiceQoSConfig> qosConfig = new HashMap<>();
        qosConfig.put("webui-service", new ServiceQoSConfig(0.836842105, 0.172727273, 0.34));
        qosConfig.put("authentication-service", new ServiceQoSConfig(0.773684211, 0.263636364, 0.2856));
        qosConfig.put("persistence-service", new ServiceQoSConfig(0.626315789, 0.627272727, 0.3592));
        qosConfig.put("image-1-service", new ServiceQoSConfig(0.731578947, 0.445454545, 0.58));
        qosConfig.put("image-2-service", new ServiceQoSConfig(0.9, 0.809090909, 0.7496));
        qosConfig.put("image-3-service", new ServiceQoSConfig(0.1, 0.354545455, 0.7496));
        qosConfig.put("image-4-service", new ServiceQoSConfig(0.310526316, 0.627272727, 0.34));
        qosConfig.put("recommender-service", new ServiceQoSConfig(0.731578947, 0.9, 0.34));

        Map<String, String> defaultImplementations = new HashMap<>();
        defaultImplementations.put("WEBUI-SERVICE", "webui-service");
        defaultImplementations.put("AUTHENTICATION-SERVICE", "authentication-service");
        defaultImplementations.put("PERSISTENCE-SERVICE", "persistence-service");
        defaultImplementations.put("IMAGE-SERVICE", "image-1-service");
        defaultImplementations.put("RECOMMENDER-SERVICE", "recommender-service");

        return createAquaScenario("Sub-scenario5", serviceImplementations, qosConfig, defaultImplementations, 0.3, 0.3, 0.4);
    }

    public static Map<String, Service> RQ1_s1_RAMSES_ExpConfig(){
        Map<String, List<String>> serviceImplementations = new HashMap<>();
        serviceImplementations.put("WEBUI-SERVICE", List.of("webui-1-service","webui-2-service","webui-3-service"));
        serviceImplementations.put("AUTHENTICATION-SERVICE", List.of("authentication-service"));
        serviceImplementations.put("PERSISTENCE-SERVICE", List.of("persistence-service"));
        serviceImplementations.put("IMAGE-SERVICE", List.of("image-service"));
        serviceImplementations.put("RECOMMENDER-SERVICE", List.of("recommender-service"));

        Map<String, ServiceQoSConfig> qosConfig = new HashMap<>();
        qosConfig.put("webui-1-service", new ServiceQoSConfig(0.731578947, 0.263636364, 0.486206897));
        qosConfig.put("webui-2-service", new ServiceQoSConfig(0.773684211, 0.227272727, 0.1));
        qosConfig.put("webui-3-service", new ServiceQoSConfig(0.857894737, 0.190909091, 0.781773399));
        qosConfig.put("authentication-service", new ServiceQoSConfig(0.773684211, 0.809090909, 0.391625616));
        qosConfig.put("persistence-service", new ServiceQoSConfig(0.626315789, 0.627272727, 0.699014778));
        qosConfig.put("image-service", new ServiceQoSConfig(0.773684211, 0.809090909, 0.332512315));
        qosConfig.put("recommender-service", new ServiceQoSConfig(0.731578947, 0.9, 0.395566502));

        Map<String, String> defaultImplementations = new HashMap<>();
        defaultImplementations.put("WEBUI-SERVICE", "webui-1-service");
        defaultImplementations.put("AUTHENTICATION-SERVICE", "authentication-service");
        defaultImplementations.put("PERSISTENCE-SERVICE", "persistence-service");
        defaultImplementations.put("IMAGE-SERVICE", "image-service");
        defaultImplementations.put("RECOMMENDER-SERVICE", "recommender-service");

        return createAquaScenario("Sub-scenario1", serviceImplementations, qosConfig, defaultImplementations, 0.5, 0.5, 0.0);
    }
    public static Map<String, Service> RQ1_s2_RAMSES_ExpConfig(){
        Map<String, List<String>> serviceImplementations = new HashMap<>();
        serviceImplementations.put("WEBUI-SERVICE", List.of("webui-1-service","webui-2-service","webui-3-service"));
        serviceImplementations.put("AUTHENTICATION-SERVICE", List.of("authentication-service"));
        serviceImplementations.put("PERSISTENCE-SERVICE", List.of("persistence-service"));
        serviceImplementations.put("IMAGE-SERVICE", List.of("image-service"));
        serviceImplementations.put("RECOMMENDER-SERVICE", List.of("recommender-service"));

        Map<String, ServiceQoSConfig> qosConfig = new HashMap<>();
        qosConfig.put("webui-1-service", new ServiceQoSConfig(0.731578947, 0.263636364, 0.486206897));
        qosConfig.put("webui-2-service", new ServiceQoSConfig(0.857894737, 0.1, 0.332512315));
        qosConfig.put("webui-3-service", new ServiceQoSConfig(0.836842105, 0.136363636, 0.1));
        qosConfig.put("authentication-service", new ServiceQoSConfig(0.773684211, 0.809090909, 0.391625616));
        qosConfig.put("persistence-service", new ServiceQoSConfig(0.626315789, 0.627272727, 0.699014778));
        qosConfig.put("image-service", new ServiceQoSConfig(0.773684211, 0.809090909, 0.332512315));
        qosConfig.put("recommender-service", new ServiceQoSConfig(0.731578947, 0.9, 0.395566502));

        Map<String, String> defaultImplementations = new HashMap<>();
        defaultImplementations.put("WEBUI-SERVICE", "webui-1-service");
        defaultImplementations.put("AUTHENTICATION-SERVICE", "authentication-service");
        defaultImplementations.put("PERSISTENCE-SERVICE", "persistence-service");
        defaultImplementations.put("IMAGE-SERVICE", "image-service");
        defaultImplementations.put("RECOMMENDER-SERVICE", "recommender-service");

        return createAquaScenario("Sub-scenario2", serviceImplementations, qosConfig, defaultImplementations, 0.5, 0.5, 0.0);
    }
    public static Map<String, Service> RQ1_s3_RAMSES_ExpConfig(){
        Map<String, List<String>> serviceImplementations = new HashMap<>();
        serviceImplementations.put("WEBUI-SERVICE", List.of("webui-service"));
        serviceImplementations.put("AUTHENTICATION-SERVICE", List.of("authentication-1-service", "authentication-2-service", "authentication-3-service", "authentication-4-service"));
        serviceImplementations.put("PERSISTENCE-SERVICE", List.of("persistence-service"));
        serviceImplementations.put("IMAGE-SERVICE", List.of("image-service"));
        serviceImplementations.put("RECOMMENDER-SERVICE", List.of("recommender-service"));

        Map<String, ServiceQoSConfig> qosConfig = new HashMap<>();
        qosConfig.put("webui-service", new ServiceQoSConfig(0.626315789, 0.809090909, 0.395566502));
        qosConfig.put("authentication-1-service", new ServiceQoSConfig(0.626315789, 0.718181818, 0.671428571));
        qosConfig.put("authentication-2-service", new ServiceQoSConfig(0.731578947, 0.809090909, 0.671428571));
        qosConfig.put("authentication-3-service", new ServiceQoSConfig(0.626315789, 0.627272727, 0.671428571));
        qosConfig.put("authentication-4-service", new ServiceQoSConfig(0.626315789, 0.809090909, 0.312807882));
        qosConfig.put("persistence-service", new ServiceQoSConfig(0.415789474, 0.809090909, 0.419211823));
        qosConfig.put("image-service", new ServiceQoSConfig(0.415789474, 0.718181818, 0.332512315));
        qosConfig.put("recommender-service", new ServiceQoSConfig(0.731578947, 0.9, 0.395566502));

        Map<String, String> defaultImplementations = new HashMap<>();
        defaultImplementations.put("WEBUI-SERVICE", "webui-service");
        defaultImplementations.put("AUTHENTICATION-SERVICE", "authentication-1-service");
        defaultImplementations.put("PERSISTENCE-SERVICE", "persistence-service");
        defaultImplementations.put("IMAGE-SERVICE", "image-service");
        defaultImplementations.put("RECOMMENDER-SERVICE", "recommender-service");

        return createAquaScenario("Sub-scenario3", serviceImplementations, qosConfig, defaultImplementations, 0.5, 0.5, 0.0);
    }
    public static Map<String, Service> RQ1_s4_RAMSES_ExpConfig(){
        Map<String, List<String>> serviceImplementations = new HashMap<>();
        serviceImplementations.put("WEBUI-SERVICE", List.of("webui-service"));
        serviceImplementations.put("AUTHENTICATION-SERVICE", List.of("authentication-service"));
        serviceImplementations.put("PERSISTENCE-SERVICE", List.of("persistence-1-service", "persistence-2-service", "persistence-3-service", "persistence-4-service"));
        serviceImplementations.put("IMAGE-SERVICE", List.of("image-service"));
        serviceImplementations.put("RECOMMENDER-SERVICE", List.of("recommender-service"));

        Map<String, ServiceQoSConfig> qosConfig = new HashMap<>();
        qosConfig.put("webui-service", new ServiceQoSConfig(0.731578947, 0.172727273, 0.395566502));
        qosConfig.put("authentication-service", new ServiceQoSConfig(0.521052632, 0.445454545, 0.391625616));
        qosConfig.put("persistence-1-service", new ServiceQoSConfig(0.310526316, 0.627272727, 0.699014778));
        qosConfig.put("persistence-2-service", new ServiceQoSConfig(0.352631579, 0.627272727, 0.699014778));
        qosConfig.put("persistence-3-service", new ServiceQoSConfig(0.310526316, 0.554545455, 0.699014778));
        qosConfig.put("persistence-4-service", new ServiceQoSConfig(0.310526316, 0.627272727, 0.1));
        qosConfig.put("image-service", new ServiceQoSConfig(0.1, 0.809090909, 0.395566502));
        qosConfig.put("recommender-service", new ServiceQoSConfig(0.731578947, 0.9, 0.395566502));

        Map<String, String> defaultImplementations = new HashMap<>();
        defaultImplementations.put("WEBUI-SERVICE", "webui-service");
        defaultImplementations.put("AUTHENTICATION-SERVICE", "authentication-service");
        defaultImplementations.put("PERSISTENCE-SERVICE", "persistence-1-service");
        defaultImplementations.put("IMAGE-SERVICE", "image-service");
        defaultImplementations.put("RECOMMENDER-SERVICE", "recommender-service");

        return createAquaScenario("Sub-scenario4", serviceImplementations, qosConfig, defaultImplementations, 0.5, 0.5, 0.0);
    }
    public static Map<String, Service> RQ1_s5_RAMSES_ExpConfig(){
        Map<String, List<String>> serviceImplementations = new HashMap<>();
        serviceImplementations.put("WEBUI-SERVICE", List.of("webui-service"));
        serviceImplementations.put("AUTHENTICATION-SERVICE", List.of("authentication-service"));
        serviceImplementations.put("PERSISTENCE-SERVICE", List.of("persistence-service"));
        serviceImplementations.put("IMAGE-SERVICE", List.of("image-1-service", "image-2-service", "image-3-service", "image-4-service"));
        serviceImplementations.put("RECOMMENDER-SERVICE", List.of("recommender-service"));

        Map<String, ServiceQoSConfig> qosConfig = new HashMap<>();
        qosConfig.put("webui-service", new ServiceQoSConfig(0.836842105, 0.172727273, 0.395566502));
        qosConfig.put("authentication-service", new ServiceQoSConfig(0.773684211, 0.263636364, 0.328571429));
        qosConfig.put("persistence-service", new ServiceQoSConfig(0.626315789, 0.627272727, 0.419211823));
        qosConfig.put("image-1-service", new ServiceQoSConfig(0.731578947, 0.445454545, 0.691133005));
        qosConfig.put("image-2-service", new ServiceQoSConfig(0.9, 0.809090909, 0.9));
        qosConfig.put("image-3-service", new ServiceQoSConfig(0.1, 0.354545455, 0.9));
        qosConfig.put("image-4-service", new ServiceQoSConfig(0.310526316, 0.627272727, 0.395566502));
        qosConfig.put("recommender-service", new ServiceQoSConfig(0.731578947, 0.9, 0.395566502));

        Map<String, String> defaultImplementations = new HashMap<>();
        defaultImplementations.put("WEBUI-SERVICE", "webui-service");
        defaultImplementations.put("AUTHENTICATION-SERVICE", "authentication-service");
        defaultImplementations.put("PERSISTENCE-SERVICE", "persistence-service");
        defaultImplementations.put("IMAGE-SERVICE", "image-1-service");
        defaultImplementations.put("RECOMMENDER-SERVICE", "recommender-service");

        return createAquaScenario("Sub-scenario5", serviceImplementations, qosConfig, defaultImplementations, 0.5, 0.5, 0.0);
    }

    private static Map<String, Service> createSAQUREScenario_RQ2(
            String scenarioName,
            Map<String, List<String>> serviceImplementations,
            Map<String, String> domainFiles,
            Map<String, String> problemPaths,
            Map<String, String> planPaths,
            double[] implementaryCost) throws IOException {

        double availabilityWeight = 0.3;
        double responseTimeWeight = 0.3;
        double vulnerabilityWeight = 0.4;
        try {
            converter = new ExcelToJsonConverter(FilePathConstants.configration_rq2_path);
        } catch (Exception e) {
            throw new ExceptionInInitializerError("Failed to initialize Excel converter: " + e.getMessage());
        }

        // === Availability + ResponseTime ===
        Map<String, Map<Class<? extends QoSSpecification>, Double>> benchmarkForImplementation = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> currentQoSValues = new HashMap<>();

        DynamicNormalize availabilityNormalizer = new DynamicNormalize();
        DynamicNormalize responseTimeNormalizer = new DynamicNormalize();

        // Collect all values
        List<Double> availabilities = new ArrayList<>();
        List<Integer> responseTimes = new ArrayList<>();

        for (Map.Entry<String, List<String>> entry : serviceImplementations.entrySet()) {
            String service = entry.getKey();
            for (String impl : entry.getValue()) {
                double a = (double) converter.getValue(scenarioName, service, impl, "availability");
                int t = (int) converter.getValue(scenarioName, service, impl, "responseTime");
                availabilities.add(a);
                responseTimes.add(t);
            }
        }
        availabilityNormalizer.preProcessing(availabilities.stream().mapToDouble(Double::doubleValue).toArray());
        responseTimeNormalizer.preProcessing(responseTimes.stream().mapToDouble(Integer::intValue).toArray());

        Map<String, String[]> cveIdsForImplementations = new HashMap<>();
        String serviceName = "";
        for (Map.Entry<String, String> entry_ : domainFiles.entrySet()) {
            String impl_ = entry_.getKey();
            if(serviceName.equals("")){
                serviceName = serviceImplementations.entrySet().stream().filter(e->e.getValue().contains(impl_)).map(Map.Entry::getKey).findFirst().orElse(null);
//                System.out.print("serviceNme: "+serviceName+"\n");
            }
            List<String> vulnerabilityList = new ArrayList<>();

            // In addition to the current vulnerability corresponding to impl
            List<String> serviceVulns = (List<String>) converter.getValue(scenarioName,
                    serviceName,
                    impl_, "vulnerabilitylist");
            if (serviceVulns != null) {
                vulnerabilityList.addAll(serviceVulns);
            }
            // In addition to the vulnerabilities of the other four fixed services
            for (Map.Entry<String, List<String>> entry : serviceImplementations.entrySet()) {
                String service = entry.getKey();
                if (serviceName.equals(service)) continue; // Skip services with options

                for (String subService : entry.getValue()) {
                    List<String> vulns = (List<String>) converter.getValue(scenarioName, service, subService, "vulnerabilitylist");
                    if (vulns != null) {
                        vulnerabilityList.addAll(vulns);
                    }
                    else {log.info("Error: SimulationsUtils.java, line 124, vulns from converter is null");}
                }
            }
//            System.out.println("impl: " + impl_ + " vulnerabilityList: " + vulnerabilityList+"\n");
            cveIdsForImplementations.put(impl_, vulnerabilityList.toArray(new String[0]));
        }

        // === Vulnerability Normalization ===
        Map<String, Double> vulnerabilityCosts = new LinkedHashMap<>();
        for (Map.Entry<String, String> entry : domainFiles.entrySet()) {
            String impl = entry.getKey();
            String domainFile = AED_process_nodyPa(entry.getValue(), cveIdsForImplementations.get(impl));
            String problemPath = problemPaths.get(impl);
            String planPath = planPaths.get(impl);
            double cost = EADSA.planner_command_compute(domainFile, planPath, problemPath, "no test");
            log.info("Risk of " + entry.getKey() + ": " + cost);
            vulnerabilityCosts.put(impl, cost);
        }
        double defaultCost = vulnerabilityCosts.values().iterator().next();
        DynamicNormalize costNormalizer = new DynamicNormalize();
        costNormalizer.preProcessing(Stream.concat(
                        vulnerabilityCosts.values().stream(),
                        Arrays.stream(implementaryCost).boxed()
                ).mapToDouble(Double::doubleValue).toArray());
//        costNormalizer.preProcessing(vulnerabilityCosts.values().stream().mapToDouble(Double::doubleValue).toArray());

        // === Benchmark and Current QoS ===
        for (Map.Entry<String, List<String>> entry : serviceImplementations.entrySet()) {
            String service = entry.getKey();
            List<String> impls = entry.getValue();

            for (String impl : impls) {
                double a = (double) converter.getValue(scenarioName, service, impl, "availability");
                int t = (int) converter.getValue(scenarioName, service, impl, "responseTime");
                double v = vulnerabilityCosts.containsKey(impl) ? vulnerabilityCosts.get(impl) : defaultCost;
                Map<Class<? extends QoSSpecification>, Double> benchmark = new HashMap<>();
                benchmark.put(Availability.class, availabilityNormalizer.normalize(a));
                benchmark.put(AverageResponseTime.class, responseTimeNormalizer.normalize(t));
                benchmark.put(Vulnerability.class, costNormalizer.normalize(v));
                benchmarkForImplementation.put(impl, benchmark);
//                System.out.printf(" impl: "+impl+" avail: "+a+" time: "+t + " cost: "+v+"\n");
            }

            // The first implementation is used by default as currentQoS.
            String firstImpl = impls.get(0);
            double a0 = (double) converter.getValue(scenarioName, service, firstImpl, "availability");
            int t0 = (int) converter.getValue(scenarioName, service, firstImpl, "responseTime");

            Map<Class<? extends QoSSpecification>, Double> currentQoS = new HashMap<>();
            currentQoS.put(Availability.class, availabilityNormalizer.normalize(a0));
            currentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(t0));
            currentQoSValues.put(service, currentQoS);
        }

        return createServiceMap(availabilityWeight,
                responseTimeWeight,
                vulnerabilityWeight,
                serviceImplementations,
                benchmarkForImplementation,
                currentQoSValues);
    }

    public static Map<String, Service> RQ2_s1_SAQURE_ExpConfig() throws IOException {
        Map<String, List<String>> serviceImplementations = new HashMap<>();
        serviceImplementations.put("WEBUI-SERVICE", List.of("webui-1-service","webui-2-service","webui-3-service"));
        serviceImplementations.put("AUTHENTICATION-SERVICE", List.of("authentication-service"));
        serviceImplementations.put("PERSISTENCE-SERVICE", List.of("persistence-service"));
        serviceImplementations.put("IMAGE-SERVICE", List.of("image-service"));
        serviceImplementations.put("RECOMMENDER-SERVICE", List.of("recommender-service"));

        Map<String, String> domainFiles = new LinkedHashMap<>();
        domainFiles.put("webui-1-service", FilePathConstants.AED_path_RQ2 + "S1_W0_A0_P0_I0.pddl");
        domainFiles.put("webui-2-service", FilePathConstants.AED_path_RQ2 + "S1_W1_A0_P0_I0.pddl");
        domainFiles.put("webui-3-service", FilePathConstants.AED_path_RQ2 + "S1_W2_A0_P0_I0.pddl");

        Map<String, String> problemPaths = new HashMap<>();
        problemPaths.put("webui-1-service", FilePathConstants.AEDI_path + "RQ2/S1/webui_1_service/");
        problemPaths.put("webui-2-service", FilePathConstants.AEDI_path + "RQ2/S1/webui_2_service/");
        problemPaths.put("webui-3-service", FilePathConstants.AEDI_path + "RQ2/S1/webui_3_service/");

        Map<String, String> planPaths = new HashMap<>();
        planPaths.put("webui-1-service", FilePathConstants.AP_path + "RQ2/S1_W0/");
        planPaths.put("webui-2-service", FilePathConstants.AP_path + "RQ2/S1_W1/");
        planPaths.put("webui-3-service", FilePathConstants.AP_path + "RQ2/S1_W2/");

        double[] implementaryCost = {23.23375, 36.93375};

        return createSAQUREScenario_RQ2("Sub-scenario1", serviceImplementations, domainFiles, problemPaths, planPaths, implementaryCost);
    }
    public static Map<String, Service> RQ2_s2_SAQURE_ExpConfig() {
        Map<String, List<String>> serviceImplementations = new HashMap<>();
        serviceImplementations.put("WEBUI-SERVICE", List.of("webui-service"));
        serviceImplementations.put("AUTHENTICATION-SERVICE", List.of("authentication-1-service", "authentication-2-service", "authentication-3-service"));
        serviceImplementations.put("PERSISTENCE-SERVICE", List.of("persistence-service"));
        serviceImplementations.put("IMAGE-SERVICE", List.of("image-service"));
        serviceImplementations.put("RECOMMENDER-SERVICE", List.of("recommender-service"));

        Map<String, String> domainFiles = new LinkedHashMap<>();
        domainFiles.put("authentication-1-service", FilePathConstants.AED_path_RQ2 + "S2_W0_A0_P0_I0.pddl");
        domainFiles.put("authentication-2-service", FilePathConstants.AED_path_RQ2 + "S2_W1_A1_P0_I0.pddl");
        domainFiles.put("authentication-3-service", FilePathConstants.AED_path_RQ2 + "S2_W2_A2_P0_I0.pddl");

        Map<String, String> problemPaths = new HashMap<>();
        problemPaths.put("authentication-1-service", FilePathConstants.AEDI_path + "RQ2/S2/authentication_1_service/");
        problemPaths.put("authentication-2-service", FilePathConstants.AEDI_path + "RQ2/S2/authentication_2_service/");
        problemPaths.put("authentication-3-service", FilePathConstants.AEDI_path + "RQ2/S2/authentication_3_service/");

        Map<String, String> planPaths = new HashMap<>();
        planPaths.put("authentication-1-service", FilePathConstants.AP_path + "RQ2/S2_A0/");
        planPaths.put("authentication-2-service", FilePathConstants.AP_path + "RQ2/S2_A1/");
        planPaths.put("authentication-3-service", FilePathConstants.AP_path + "RQ2/S2_A2/");

        double[] implementaryCost = {25.016, 32.116};

        try {
            return createSAQUREScenario_RQ2("Sub-scenario2", serviceImplementations, domainFiles, problemPaths, planPaths, implementaryCost);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    public static Map<String, Service> RQ2_s3_SAQURE_ExpConfig() {
        Map<String, List<String>> serviceImplementations = new HashMap<>();
        serviceImplementations.put("WEBUI-SERVICE", List.of("webui-service"));
        serviceImplementations.put("AUTHENTICATION-SERVICE", List.of("authentication-service"));
        serviceImplementations.put("PERSISTENCE-SERVICE", List.of("persistence-1-service", "persistence-2-service", "persistence-3-service"));
        serviceImplementations.put("IMAGE-SERVICE", List.of("image-service"));
        serviceImplementations.put("RECOMMENDER-SERVICE", List.of("recommender-service"));

        Map<String, String> domainFiles = new LinkedHashMap<>();
        domainFiles.put("persistence-1-service", FilePathConstants.AED_path_RQ2 + "S1_W0_A0_P0_I0.pddl");
        domainFiles.put("persistence-2-service", FilePathConstants.AED_path_RQ2 + "S1_W0_A0_P1_I0.pddl");
        domainFiles.put("persistence-3-service", FilePathConstants.AED_path_RQ2 + "S1_W0_A0_P2_I0.pddl");

        Map<String, String> problemPaths = new HashMap<>();
        problemPaths.put("persistence-1-service", FilePathConstants.AEDI_path + "RQ2/S3/persistence_1_service/");
        problemPaths.put("persistence-2-service", FilePathConstants.AEDI_path + "RQ2/S3/persistence_2_service/");
        problemPaths.put("persistence-3-service", FilePathConstants.AEDI_path + "RQ2/S3/persistence_3_service/");

        Map<String, String> planPaths = new HashMap<>();
        planPaths.put("persistence-1-service", FilePathConstants.AP_path + "RQ2/S3_P0/");
        planPaths.put("persistence-2-service", FilePathConstants.AP_path + "RQ2/S3_P1/");
        planPaths.put("persistence-3-service", FilePathConstants.AP_path + "RQ2/S3_P2/");

        double[] implementaryCost = {26.716, 33.216};

        try {
            return createSAQUREScenario_RQ2("Sub-scenario3", serviceImplementations, domainFiles, problemPaths, planPaths, implementaryCost);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static Map<String, Service> RQ2_s1_SAQURE_nodyPa_ExpConfig() {
        EADSA.IS_DEFAULT = false;

        Map<String, List<String>> serviceImplementations = new HashMap<>();
        serviceImplementations.put("WEBUI-SERVICE", List.of("webui-1-service","webui-2-service","webui-3-service"));
        serviceImplementations.put("AUTHENTICATION-SERVICE", List.of("authentication-service"));
        serviceImplementations.put("PERSISTENCE-SERVICE", List.of("persistence-service"));
        serviceImplementations.put("IMAGE-SERVICE", List.of("image-service"));
        serviceImplementations.put("RECOMMENDER-SERVICE", List.of("recommender-service"));

        Map<String, String> domainFiles = new LinkedHashMap<>();
        domainFiles.put("webui-1-service", FilePathConstants.AED_path_RQ2 + "S1_W0_A0_P0_I0.pddl");
        domainFiles.put("webui-2-service", FilePathConstants.AED_path_RQ2 + "S1_W1_A0_P0_I0.pddl");
        domainFiles.put("webui-3-service", FilePathConstants.AED_path_RQ2 + "S1_W2_A0_P0_I0.pddl");

        Map<String, String> problemPaths = new HashMap<>();
        problemPaths.put("webui-1-service", FilePathConstants.AEDI_path + "RQ2/S1/webui_1_service/");
        problemPaths.put("webui-2-service", FilePathConstants.AEDI_path + "RQ2/S1/webui_2_service/");
        problemPaths.put("webui-3-service", FilePathConstants.AEDI_path + "RQ2/S1/webui_3_service/");

        Map<String, String> planPaths = new HashMap<>();
        planPaths.put("webui-1-service", FilePathConstants.AP_path + "RQ2/S1_W0/");
        planPaths.put("webui-2-service", FilePathConstants.AP_path + "RQ2/S1_W1/");
        planPaths.put("webui-3-service", FilePathConstants.AP_path + "RQ2/S1_W2/");

        double[] implementaryCost = {45, 31.3};// max and min risk

        try {
            return createSAQUREScenario_RQ2("Sub-scenario1", serviceImplementations, domainFiles, problemPaths, planPaths, implementaryCost);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    public static Map<String, Service> RQ2_s2_SAQURE_nodyPa_ExpConfig() {
        EADSA.IS_DEFAULT = false;
        Map<String, List<String>> serviceImplementations = new HashMap<>();
        serviceImplementations.put("WEBUI-SERVICE", List.of("webui-service"));
        serviceImplementations.put("AUTHENTICATION-SERVICE", List.of("authentication-1-service", "authentication-2-service", "authentication-3-service"));
        serviceImplementations.put("PERSISTENCE-SERVICE", List.of("persistence-service"));
        serviceImplementations.put("IMAGE-SERVICE", List.of("image-service"));
        serviceImplementations.put("RECOMMENDER-SERVICE", List.of("recommender-service"));

        Map<String, String> domainFiles = new LinkedHashMap<>();
        domainFiles.put("authentication-1-service", FilePathConstants.AED_path_RQ2 + "S2_W0_A0_P0_I0.pddl");
        domainFiles.put("authentication-2-service", FilePathConstants.AED_path_RQ2 + "S2_W1_A1_P0_I0.pddl");
        domainFiles.put("authentication-3-service", FilePathConstants.AED_path_RQ2 + "S2_W2_A2_P0_I0.pddl");

        Map<String, String> problemPaths = new HashMap<>();
        problemPaths.put("authentication-1-service", FilePathConstants.AEDI_path + "RQ2/S2/authentication_1_service/");
        problemPaths.put("authentication-2-service", FilePathConstants.AEDI_path + "RQ2/S2/authentication_2_service/");
        problemPaths.put("authentication-3-service", FilePathConstants.AEDI_path + "RQ2/S2/authentication_3_service/");

        Map<String, String> planPaths = new HashMap<>();
        planPaths.put("authentication-1-service", FilePathConstants.AP_path + "RQ2/S2_A0/");
        planPaths.put("authentication-2-service", FilePathConstants.AP_path + "RQ2/S2_A1/");
        planPaths.put("authentication-3-service", FilePathConstants.AP_path + "RQ2/S2_A2/");

        double[] implementaryCost = {29.7, 36.9};

        try {
            return createSAQUREScenario_RQ2("Sub-scenario2", serviceImplementations, domainFiles, problemPaths, planPaths, implementaryCost);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    public static Map<String, Service> RQ2_s3_SAQURE_nodyPa_ExpConfig() {
        EADSA.IS_DEFAULT = false;

        Map<String, List<String>> serviceImplementations = new HashMap<>();
        serviceImplementations.put("WEBUI-SERVICE", List.of("webui-service"));
        serviceImplementations.put("AUTHENTICATION-SERVICE", List.of("authentication-service"));
        serviceImplementations.put("PERSISTENCE-SERVICE", List.of("persistence-1-service", "persistence-2-service", "persistence-3-service"));
        serviceImplementations.put("IMAGE-SERVICE", List.of("image-service"));
        serviceImplementations.put("RECOMMENDER-SERVICE", List.of("recommender-service"));

        Map<String, String> domainFiles = new LinkedHashMap<>();
        domainFiles.put("persistence-1-service", FilePathConstants.AED_path_RQ2 + "S1_W0_A0_P0_I0.pddl");
        domainFiles.put("persistence-2-service", FilePathConstants.AED_path_RQ2 + "S1_W0_A0_P1_I0.pddl");
        domainFiles.put("persistence-3-service", FilePathConstants.AED_path_RQ2 + "S1_W0_A0_P2_I0.pddl");

        Map<String, String> problemPaths = new HashMap<>();
        problemPaths.put("persistence-1-service", FilePathConstants.AEDI_path + "RQ2/S3/persistence_1_service/");
        problemPaths.put("persistence-2-service", FilePathConstants.AEDI_path + "RQ2/S3/persistence_2_service/");
        problemPaths.put("persistence-3-service", FilePathConstants.AEDI_path + "RQ2/S3/persistence_3_service/");

        Map<String, String> planPaths = new HashMap<>();
        planPaths.put("persistence-1-service", FilePathConstants.AP_path + "RQ2/S3_P0/");
        planPaths.put("persistence-2-service", FilePathConstants.AP_path + "RQ2/S3_P1/");
        planPaths.put("persistence-3-service", FilePathConstants.AP_path + "RQ2/S3_P2/");

        double[] implementaryCost = {38.099999999999994, 33.699999999999996};

        try {
            return createSAQUREScenario_RQ2("Sub-scenario3", serviceImplementations, domainFiles, problemPaths, planPaths, implementaryCost);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static Map<String, Service> RQ2_s1_Aqua_ExpConfig(){
        Map<String, List<String>> serviceImplementations = new HashMap<>();
        serviceImplementations.put("WEBUI-SERVICE", List.of("webui-1-service","webui-2-service","webui-3-service"));
        serviceImplementations.put("AUTHENTICATION-SERVICE", List.of("authentication-service"));
        serviceImplementations.put("PERSISTENCE-SERVICE", List.of("persistence-service"));
        serviceImplementations.put("IMAGE-SERVICE", List.of("image-service"));
        serviceImplementations.put("RECOMMENDER-SERVICE", List.of("recommender-service"));

        Map<String, ServiceQoSConfig> qosConfig = new HashMap<>();
        qosConfig.put("webui-1-service", new ServiceQoSConfig(0.1, 0.805882353, 0.786725664));
        qosConfig.put("webui-2-service", new ServiceQoSConfig(0.1, 0.805882353, 0.361946903));
        qosConfig.put("webui-3-service", new ServiceQoSConfig(0.1, 0.805882353, 0.174336283));
        qosConfig.put("authentication-service", new ServiceQoSConfig(0.9, 0.570588235, 0.46460177));
        qosConfig.put("persistence-service", new ServiceQoSConfig(0.633333333, 0.194117647, 0.227433628));
        qosConfig.put("image-service", new ServiceQoSConfig(0.366666667, 0.664705882, 0.386725664));
        qosConfig.put("recommender-service", new ServiceQoSConfig(0.1, 0.9, 0.485840708));

        Map<String, String> defaultImplementations = new HashMap<>();
        defaultImplementations.put("WEBUI-SERVICE", "webui-1-service");
        defaultImplementations.put("AUTHENTICATION-SERVICE", "authentication-service");
        defaultImplementations.put("PERSISTENCE-SERVICE", "persistence-service");
        defaultImplementations.put("IMAGE-SERVICE", "image-service");
        defaultImplementations.put("RECOMMENDER-SERVICE", "recommender-service");

        return createAquaScenario("Sub-scenario1", serviceImplementations, qosConfig, defaultImplementations, 0.3, 0.3, 0.4);
    }
    public static Map<String, Service> RQ2_s2_Aqua_ExpConfig(){
        Map<String, List<String>> serviceImplementations = new HashMap<>();
        serviceImplementations.put("WEBUI-SERVICE", List.of("webui-service"));
        serviceImplementations.put("AUTHENTICATION-SERVICE", List.of("authentication-1-service", "authentication-2-service", "authentication-3-service"));
        serviceImplementations.put("PERSISTENCE-SERVICE", List.of("persistence-service"));
        serviceImplementations.put("IMAGE-SERVICE", List.of("image-service"));
        serviceImplementations.put("RECOMMENDER-SERVICE", List.of("recommender-service"));

        Map<String, ServiceQoSConfig> qosConfig = new HashMap<>();
        qosConfig.put("webui-service", new ServiceQoSConfig(0.9, 0.194117647, 0.35840708));
        qosConfig.put("authentication-1-service", new ServiceQoSConfig(0.633333333, 0.429411765, 0.896460177));
        qosConfig.put("authentication-2-service", new ServiceQoSConfig(0.633333333, 0.429411765, 0.344247788));
        qosConfig.put("authentication-3-service", new ServiceQoSConfig(0.633333333, 0.429411765, 0.379646018));
        qosConfig.put("persistence-service", new ServiceQoSConfig(0.633333333, 0.664705882, 0.17079646));
        qosConfig.put("image-service", new ServiceQoSConfig(0.1, 0.9, 0.17079646));
        qosConfig.put("recommender-service", new ServiceQoSConfig(0.1, 0.664705882, 0.361946903));

        Map<String, String> defaultImplementations = new HashMap<>();
        defaultImplementations.put("WEBUI-SERVICE", "webui-service");
        defaultImplementations.put("AUTHENTICATION-SERVICE", "authentication-1-service");
        defaultImplementations.put("PERSISTENCE-SERVICE", "persistence-service");
        defaultImplementations.put("IMAGE-SERVICE", "image-service");
        defaultImplementations.put("RECOMMENDER-SERVICE", "recommender-service");

        return createAquaScenario("Sub-scenario2", serviceImplementations, qosConfig, defaultImplementations, 0.3, 0.3, 0.4);
    }
    public static Map<String, Service> RQ2_s3_Aqua_ExpConfig(){
        Map<String, List<String>> serviceImplementations = new HashMap<>();
        serviceImplementations.put("WEBUI-SERVICE", List.of("webui-service"));
        serviceImplementations.put("AUTHENTICATION-SERVICE", List.of("authentication-service"));
        serviceImplementations.put("PERSISTENCE-SERVICE", List.of("persistence-1-service", "persistence-2-service", "persistence-3-service"));
        serviceImplementations.put("IMAGE-SERVICE", List.of("image-service"));
        serviceImplementations.put("RECOMMENDER-SERVICE", List.of("recommender-service"));

        Map<String, ServiceQoSConfig> qosConfig = new HashMap<>();
        qosConfig.put("webui-service", new ServiceQoSConfig(0.633333333, 0.194117647, 0.117699115));
        qosConfig.put("authentication-service", new ServiceQoSConfig(0.9, 0.1, 0.124778761));
        qosConfig.put("persistence-1-service", new ServiceQoSConfig(0.9, 0.335294118, 0.9));
        qosConfig.put("persistence-2-service", new ServiceQoSConfig(0.9, 0.335294118, 0.1));
        qosConfig.put("persistence-3-service", new ServiceQoSConfig(0.9, 0.335294118, 0.17079646));
        qosConfig.put("image-service", new ServiceQoSConfig(0.366666667, 0.429411765, 0.305309735));
        qosConfig.put("recommender-service", new ServiceQoSConfig(0.633333333, 0.335294118, 0.379646018));

        Map<String, String> defaultImplementations = new HashMap<>();
        defaultImplementations.put("WEBUI-SERVICE", "webui-service");
        defaultImplementations.put("AUTHENTICATION-SERVICE", "authentication-service");
        defaultImplementations.put("PERSISTENCE-SERVICE", "persistence-1-service");
        defaultImplementations.put("IMAGE-SERVICE", "image-service");
        defaultImplementations.put("RECOMMENDER-SERVICE", "recommender-service");

        return createAquaScenario("Sub-scenario3", serviceImplementations, qosConfig, defaultImplementations, 0.3, 0.3, 0.4);
    }

    private static QoSContext collectRamsesData(
            String scenarioName,
            Map<String, List<String>> serviceImplementations) {

        Map<String, Double> availabilityCache = new HashMap<>();
        Map<String, Integer> responseTimeCache = new HashMap<>();
        Map<String, List<String>> vulnerabilityListCache = new HashMap<>();
        Map<String, String> implToService = new HashMap<>();

        List<Double> availabilities = new ArrayList<>();
        List<Integer> responseTimes = new ArrayList<>();

        for (var entry : serviceImplementations.entrySet()) {
            String service = entry.getKey();
            for (String impl : entry.getValue()) {
                double a = (double) converter.getValue(scenarioName, service, impl, "availability");
                int t = (int) converter.getValue(scenarioName, service, impl, "responseTime");
                List<String> vulns = (List<String>) converter.getValue(scenarioName, service, impl, "vulnerabilitylist");

                availabilityCache.put(impl, a);
                responseTimeCache.put(impl, t);
                vulnerabilityListCache.put(impl, vulns != null ? vulns : List.of());
                implToService.put(impl, service);

                availabilities.add(a);
                responseTimes.add(t);
            }
        }

        DynamicNormalize availabilityNormalizer = buildNormalizer(
                availabilities.stream().mapToDouble(Double::doubleValue).toArray());
        DynamicNormalize responseTimeNormalizer = buildNormalizer(
                responseTimes.stream().mapToDouble(Integer::intValue).toArray());

        return new QoSContext(availabilityCache, responseTimeCache, vulnerabilityListCache,
                implToService, availabilityNormalizer, responseTimeNormalizer);
    }
    private static Map<String, String[]> collectVulnerabilities(
            Map<String, List<String>> serviceImplementations,
            Map<String, List<String>> vulnerabilityListCache,
            Map<String, String> implToService) {

        Map<String, String[]> cveIdsForImpls = new HashMap<>();

        for (String impl : implToService.keySet()) {
            String service = implToService.get(impl);
            List<String> allVulns = new ArrayList<>(vulnerabilityListCache.get(impl));

            for (var entry : serviceImplementations.entrySet()) {
                if (entry.getKey().equals(service)) continue;
                for (String subImpl : entry.getValue()) {
                    allVulns.addAll(vulnerabilityListCache.get(subImpl));
                }
            }
            cveIdsForImpls.put(impl, allVulns.toArray(new String[0]));
        }

        return cveIdsForImpls;
    }
    private static Map<String, Double> computeVulnerabilityCosts(
            Map<String, String> domainFiles,
            Map<String, EADSA.outputPath> planPaths,
            Map<String, String[]> cveIdsForImpls) {

        Map<String, Double> vulnerabilityCosts = new LinkedHashMap<>();
        for (var e : domainFiles.entrySet()) {
            String impl = e.getKey();
            String domainFile = AED_process(e.getValue(), cveIdsForImpls.get(impl));
            double cost = EADSA.computeScenario(domainFile, planPaths.get(impl));
            vulnerabilityCosts.put(impl, cost);
        }
        return vulnerabilityCosts;
    }
    private static Map<String, Map<Class<? extends QoSSpecification>, Double>> buildBenchmark(
            Map<String, List<String>> serviceImplementations,
            QoSContext context,
            Map<String, Double> vulnerabilityCosts,
            DynamicNormalize vulnerabilityNormalizer) {

        double defaultCost = vulnerabilityCosts.values().iterator().next();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> benchmark = new HashMap<>();

        for (var entry : serviceImplementations.entrySet()) {
            for (String impl : entry.getValue()) {
                double a = context.availabilityCache.get(impl);
                int t = context.responseTimeCache.get(impl);
                double v = vulnerabilityCosts.getOrDefault(impl, defaultCost);

                benchmark.computeIfAbsent(impl, k -> new HashMap<>())
                        .put(Availability.class, context.availabilityNormalizer.normalize(a));
                benchmark.get(impl).put(AverageResponseTime.class, context.responseTimeNormalizer.normalize(t));
                benchmark.get(impl).put(Vulnerability.class, vulnerabilityNormalizer.normalize(v));
            }
        }
        return benchmark;
    }
    private static Map<String, Map<Class<? extends QoSSpecification>, Double>> buildCurrentQoS(
            Map<String, List<String>> serviceImplementations,
            QoSContext context) {

        Map<String, Map<Class<? extends QoSSpecification>, Double>> currentQoS = new HashMap<>();

        for (var entry : serviceImplementations.entrySet()) {
            String service = entry.getKey();
            String firstImpl = entry.getValue().get(0);

            Map<Class<? extends QoSSpecification>, Double> qos = new HashMap<>();
            qos.put(Availability.class, context.availabilityNormalizer.normalize(context.availabilityCache.get(firstImpl)));
            qos.put(AverageResponseTime.class, context.responseTimeNormalizer.normalize(context.responseTimeCache.get(firstImpl)));

            currentQoS.put(service, qos);
        }

        return currentQoS;
    }
    private static DynamicNormalize buildNormalizer(double[] values) {
        DynamicNormalize normalizer = new DynamicNormalize();
        normalizer.preProcessing(values);
        return normalizer;
    }
    private static class QoSContext {
        Map<String, Double> availabilityCache;
        Map<String, Integer> responseTimeCache;
        Map<String, List<String>> vulnerabilityListCache;
        Map<String, String> implToService;
        DynamicNormalize availabilityNormalizer;
        DynamicNormalize responseTimeNormalizer;

        public QoSContext(Map<String, Double> a,
                          Map<String, Integer> t,
                          Map<String, List<String>> v,
                          Map<String, String> m,
                          DynamicNormalize an,
                          DynamicNormalize rn) {
            this.availabilityCache = a;
            this.responseTimeCache = t;
            this.vulnerabilityListCache = v;
            this.implToService = m;
            this.availabilityNormalizer = an;
            this.responseTimeNormalizer = rn;
        }
    }


    public static Map<String, Service> createServiceMap(
            double availabilityWeight,
            double responseTimeWeight,
            double vulnerabilityWeight,
            Map<String, List<String>> serviceImplementations,
            Map<String, Map<Class<? extends QoSSpecification>, Double>> benchmarkForImplementation,
            Map<String, Map<Class<? extends QoSSpecification>, Double>> currentQoSValues) {
        //set weights
        Map<String, Service> servicesMap = new HashMap<>();
        QoSSpecification availability = new Availability();
        availability.setWeight(availabilityWeight);
        QoSSpecification averageResponseTime = new AverageResponseTime();
        averageResponseTime.setWeight(responseTimeWeight);
        QoSSpecification vulnerability = new Vulnerability();
        vulnerability.setWeight(vulnerabilityWeight);


        for (Map.Entry<String, List<String>> serviceEntry : serviceImplementations.entrySet()) {
            String serviceName = serviceEntry.getKey();
            Service service = new Service(serviceName);

            for (String implementationName : serviceEntry.getValue()) {
                //Iterate through the different implementations of each service and set QoS.
                Map<Class<? extends QoSSpecification>, Double> qoSBenchmarks = benchmarkForImplementation.get(implementationName);
                ServiceImplementation serviceImplementation = new ServiceImplementation(implementationName, 0.5, 5, 0.8);

                serviceImplementation.setBenchmark(Availability.class, qoSBenchmarks.getOrDefault(Availability.class, 0.0));
                serviceImplementation.setBenchmark(AverageResponseTime.class, qoSBenchmarks.getOrDefault(AverageResponseTime.class, 0.0));
                serviceImplementation.setVulnerabilityScore(qoSBenchmarks.getOrDefault(Vulnerability.class, 0.0));

                service.getPossibleImplementations().put(implementationName, serviceImplementation);
            }

            Map<Class<? extends QoSSpecification>, Double> currentQoS = currentQoSValues.get(serviceName);

            Instance instance = new Instance(serviceImplementations.get(serviceName).get(0) + "@1", serviceName);
            instance.setCurrentStatus(InstanceStatus.ACTIVE);
            instance.setVulnerabilityScore(benchmarkForImplementation.get(serviceImplementations.get(serviceName).get(0)).getOrDefault(Vulnerability.class, 0.0));
            instance.getQoSCollection().createHistory(new Availability());
            instance.getQoSCollection().createHistory(new AverageResponseTime());
            instance.getQoSCollection().changeCurrentValueForQoS(Availability.class, currentQoS.getOrDefault(Availability.class, 0.0), new Date());
            instance.getQoSCollection().changeCurrentValueForQoS(AverageResponseTime.class, currentQoS.getOrDefault(AverageResponseTime.class, 0.0), new Date());
            service.getPossibleImplementations().get(serviceImplementations.get(serviceName).get(0)).addInstance(instance);
            service.setCurrentImplementationId(serviceImplementations.get(serviceName).get(0));

            ServiceConfiguration serviceConfiguration = new ServiceConfiguration(serviceName);
            serviceConfiguration.setLoadBalancerType(ServiceConfiguration.LoadBalancerType.WEIGHTED_RANDOM);
            service.setConfiguration(serviceConfiguration);

            service.setAllQoS(List.of(availability, averageResponseTime, vulnerability));
            service.changeCurrentValueForQoS(Availability.class, currentQoS.getOrDefault(Availability.class, 0.0), new Date());
            service.changeCurrentValueForQoS(AverageResponseTime.class, currentQoS.getOrDefault(AverageResponseTime.class, 0.0), new Date());

            servicesMap.put(serviceName, service);
        }
        return servicesMap;
    }
}




