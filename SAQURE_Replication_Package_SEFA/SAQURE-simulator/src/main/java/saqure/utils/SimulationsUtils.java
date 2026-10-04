package saqure.utils;

import saqure.Analyzer.EADSA;
import saqure.Analyzer.VulnAxisAP;
import saqure.Analyzer.VulnAxisAPProfiler;
import saqure.utils.infrastructure.adaptation.specifications.Availability;
import saqure.utils.infrastructure.adaptation.specifications.AverageResponseTime;
import saqure.utils.infrastructure.adaptation.specifications.QoSSpecification;
import saqure.utils.infrastructure.adaptation.specifications.Vulnerability;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import saqure.utils.infrastructure.architecture.*;

import static saqure.utils.AED_Processor.AED_process;
import static saqure.utils.AED_Processor.AED_process_nodyPa;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class SimulationsUtils {
    private static final Logger log = LoggerFactory.getLogger(SimulationsUtils.class);

    private SimulationsUtils() {
        throw new IllegalStateException("Utility class");
    }
    public static String experiment_num;
    private static ExcelToJsonConverter converter;

    public static void setCompMode(EADSA.ComputationMode mode){
        EADSA.setComputationMode(mode);
    }
    static {
//        setCompMode(DynamicDTMC.ComputationMode.SEQUENTIAL);//Comment out this line when using a .sh script; otherwise, uncomment it. Control is performed here; parallelism is the default.
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

    public static Map<String, Service> RQ1_s1_SAQURE_ExpConfig(){
        double availabilityWeight = 0.3;
        double responseTimeWeight = 0.3;
        double vulnerabilityWeight = 0.4;
        try {
            converter = new ExcelToJsonConverter(FilePathConstants.configuration_rq1_path);
        } catch (Exception e) {
            throw new ExceptionInInitializerError("Failed to initialize Excel converter: " + e.getMessage());
        }
        String[] cveIds_s1_r0 = {"CVE-2024-38286", "CVE-2024-12798", "CVE-2024-38820", "CVE-2025-22228", "CVE-2023-44487", "CVE-2024-22243", "CVE-2024-34447", "CVE-2023-6378", "CVE-2022-40150", "CVE-2024-38816", "CVE-2022-1471", "CVE-2023-34055"};//(String[]) getValue("Sub-scenario1", "ORDERING-SERVICE", "vulnerabilityList");
        String[] cveIds_s1_r1 ={"CVE-2024-38286", "CVE-2024-12798", "CVE-2024-38820", "CVE-2024-22243", "CVE-2024-34447", "CVE-2023-6378", "CVE-2022-40150", "CVE-2024-38816", "CVE-2022-1471", "CVE-2023-34055"};
        String[] cveIds_s1_r2 ={"CVE-2024-38286", "CVE-2024-12798", "CVE-2024-38820", "CVE-2025-22228", "CVE-2023-44487", "CVE-2025-24813", "CVE-2024-22243", "CVE-2024-34447", "CVE-2023-6378", "CVE-2022-40150", "CVE-2024-38816", "CVE-2022-1471", "CVE-2023-34055"};

        String domainFile_s1_r0 = AED_process(FilePathConstants.AED_path_RQ1 + "S1_R0_O0_D0_P0.pddl", cveIds_s1_r0);
        String domainFile_s1_r1 = AED_process(FilePathConstants.AED_path_RQ1 + "S1_R1_O0_D0_P0.pddl", cveIds_s1_r1);
        String domainFile_s1_r2 = AED_process(FilePathConstants.AED_path_RQ1 + "S1_R2_O0_D0_P0.pddl", cveIds_s1_r2);

        final double costS1R0 = EADSA.planner_command_configuration_s1_r0(domainFile_s1_r0);
        final double costS1R1 = EADSA.planner_command_configuration_s1_r1(domainFile_s1_r1);
        final double costS1R2 = EADSA.planner_command_configuration_s1_r2(domainFile_s1_r2);
        double[] costValues = {costS1R0, costS1R1, costS1R2};
        DynamicNormalize costNormalizer = new DynamicNormalize();
        costNormalizer.preProcessing(costValues);
        final double aS1R0 = (double) converter.getValue("Sub-scenario1", "RESTAURANT-SERVICE", "Restaurant-1-service", "availability");
        final double aS1R1 = (double) converter.getValue("Sub-scenario1", "RESTAURANT-SERVICE", "Restaurant-2-service", "availability");
        final double aS1R2 = (double) converter.getValue("Sub-scenario1", "RESTAURANT-SERVICE", "Restaurant-3-service", "availability");
        final double aS1O0 = (double) converter.getValue("Sub-scenario1", "ORDERING-SERVICE", "Ordering-service", "availability");
        final double aS1D0 = (double) converter.getValue("Sub-scenario1", "DELIVERY-PROXY-SERVICE", "Delivery-proxy-1-service", "availability");
        final double aS1P0 = (double) converter.getValue("Sub-scenario1", "PAYMENT-PROXY-SERVICE", "Payment-proxy-1-service", "availability");
        double[] avalibilities = {aS1R0, aS1R1, aS1R2, aS1O0, aS1D0, aS1P0};
        DynamicNormalize availabilityNormalizer = new DynamicNormalize();
        availabilityNormalizer.preProcessing(avalibilities);
        final int tS1R0 = (int) converter.getValue("Sub-scenario1", "RESTAURANT-SERVICE", "Restaurant-1-service", "responseTime");
        final int tS1R1 = (int) converter.getValue("Sub-scenario1", "RESTAURANT-SERVICE", "Restaurant-2-service", "responseTime");
        final int tS1R2 = (int) converter.getValue("Sub-scenario1", "RESTAURANT-SERVICE", "Restaurant-3-service", "responseTime");
        final int tS1O0 = (int) converter.getValue("Sub-scenario1", "ORDERING-SERVICE", "Ordering-service", "responseTime");
        final int tS1D0 = (int) converter.getValue("Sub-scenario1", "DELIVERY-PROXY-SERVICE", "Delivery-proxy-1-service", "responseTime");
        final int tS1P0 = (int) converter.getValue("Sub-scenario1", "PAYMENT-PROXY-SERVICE", "Payment-proxy-1-service", "responseTime");
        int[] responseTimes = {tS1R0, tS1R1, tS1R2, tS1O0, tS1D0, tS1P0};
        double[] doubleResponseTimes = Arrays.stream(responseTimes).asDoubleStream().toArray();
        DynamicNormalize responseTimeNormalizer = new DynamicNormalize();
        responseTimeNormalizer.preProcessing(doubleResponseTimes);
        Map<String, List<String>> serviceImplementations = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> benchmarkForImplementation = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> currentQoSValues = new HashMap<>();

        // Restaurant //
        List<String> restaurantImplementations = List.of("restaurant-1-service","restaurant-2-service","restaurant-3-service");
        serviceImplementations.put("RESTAURANT-SERVICE", restaurantImplementations);

        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark1 = new HashMap<>();//option configuration
        restaurantBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS1R0));//0.766666667
        restaurantBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1R0));//0.165306122
        restaurantBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS1R0));//0.633333333
        benchmarkForImplementation.put("restaurant-1-service", restaurantBenchmark1);
        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark2 = new HashMap<>();
        restaurantBenchmark2.put(Availability.class, availabilityNormalizer.normalize(aS1R1));//0.92
        restaurantBenchmark2.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1R1));//0.132653061
        restaurantBenchmark2.put(Vulnerability.class, costNormalizer.normalize(costS1R1));//0.227891156
        benchmarkForImplementation.put("restaurant-2-service", restaurantBenchmark2);
        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark3 = new HashMap<>();
        restaurantBenchmark3.put(Availability.class, availabilityNormalizer.normalize(aS1R2));
        restaurantBenchmark3.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1R2));//0.1
        restaurantBenchmark3.put(Vulnerability.class, costNormalizer.normalize(costS1R2));//0.9
        benchmarkForImplementation.put("restaurant-3-service", restaurantBenchmark3);

        Map<Class<? extends QoSSpecification>, Double> restaurantCurrentQoS = new HashMap<>();//Initial configuration
        restaurantCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS1R0));
        restaurantCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1R0));
        currentQoSValues.put("RESTAURANT-SERVICE", restaurantCurrentQoS);

        // Ordering //
        List<String> orderingImplementations = List.of("ordering-service");
        serviceImplementations.put("ORDERING-SERVICE", orderingImplementations);

        Map<Class<? extends QoSSpecification>, Double> orderingBenchmark = new HashMap<>();
        orderingBenchmark.put(Availability.class, availabilityNormalizer.normalize(aS1O0));//0.8
        orderingBenchmark.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1O0));//0.655102041
        orderingBenchmark.put(Vulnerability.class, costNormalizer.normalize(costS1R0));
        benchmarkForImplementation.put("ordering-service", orderingBenchmark);

        Map<Class<? extends QoSSpecification>, Double> orderingCurrentQoS = new HashMap<>();
        orderingCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS1O0));
        orderingCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1O0));
        currentQoSValues.put("ORDERING-SERVICE", orderingCurrentQoS);

        // Delivery //
        List<String> deliveryProxyImplementations = List.of("delivery-proxy-1-service");
        serviceImplementations.put("DELIVERY-PROXY-SERVICE", deliveryProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyBenchmark1 = new HashMap<>();
        deliveryProxyBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS1D0));//0.683333333
        deliveryProxyBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1D0));//0.573469388
        deliveryProxyBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS1R0));
        benchmarkForImplementation.put("delivery-proxy-1-service", deliveryProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyCurrentQoS = new HashMap<>();
        deliveryProxyCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS1D0));
        deliveryProxyCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1D0));
        currentQoSValues.put("DELIVERY-PROXY-SERVICE", deliveryProxyCurrentQoS);

        // Payment //
        List<String> paymentProxyImplementations = List.of("payment-proxy-1-service");
        serviceImplementations.put("PAYMENT-PROXY-SERVICE", paymentProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyBenchmark1 = new HashMap<>();
        paymentProxyBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS1P0));//0.766666667
        paymentProxyBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1P0));//0.818367347
        paymentProxyBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS1R0));
        benchmarkForImplementation.put("payment-proxy-1-service", paymentProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyCurrentQoS = new HashMap<>();//Initial configuration
        paymentProxyCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS1P0));
        paymentProxyCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1P0));
        currentQoSValues.put("PAYMENT-PROXY-SERVICE", paymentProxyCurrentQoS);

        return createServiceMap(availabilityWeight,
                responseTimeWeight,
                vulnerabilityWeight,
                serviceImplementations,
                benchmarkForImplementation,
                currentQoSValues);
    }

    public static Map<String, Service> RQ1_s2_SAQURE_ExpConfig(){
        double availabilityWeight = 0.3;
        double responseTimeWeight = 0.3;
        double vulnerabilityWeight = 0.4;
        try {
            converter = new ExcelToJsonConverter(FilePathConstants.configuration_rq1_path);
        } catch (Exception e) {
            throw new ExceptionInInitializerError("Failed to initialize Excel converter: " + e.getMessage());
        }
        String[] cveIds_s2_r0 = {"CVE-2024-38286", "CVE-2024-12798", "CVE-2024-38820", "CVE-2025-22228", "CVE-2023-44487", "CVE-2024-22243", "CVE-2024-34447", "CVE-2023-6378", "CVE-2022-40150", "CVE-2024-38816", "CVE-2022-1471", "CVE-2023-34055"};
        String[] cveIds_s2_r1 = {"CVE-2024-38286", "CVE-2024-38820", "CVE-2024-22243", "CVE-2024-34447", "CVE-2023-6378", "CVE-2022-40150", "CVE-2024-38816", "CVE-2022-1471", "CVE-2023-34055"};
        String[] cveIds_s2_r2 = {"CVE-2024-38286", "CVE-2024-12798", "CVE-2025-24813", "CVE-2024-22243", "CVE-2024-34447", "CVE-2023-6378", "CVE-2024-38820", "CVE-2022-40150", "CVE-2024-38816", "CVE-2022-1471", "CVE-2023-34055"};

        String domainFile_s2_r0 = AED_process(FilePathConstants.AED_path_RQ1 + "S2_R0_O0_D0_P0.pddl", cveIds_s2_r0);
        String domainFile_s2_r1 = AED_process(FilePathConstants.AED_path_RQ1 + "S2_R1_O0_D0_P0.pddl", cveIds_s2_r1);
        String domainFile_s2_r2 = AED_process(FilePathConstants.AED_path_RQ1 + "S2_R2_O0_D0_P0.pddl", cveIds_s2_r2);

        final double costS2R0 = EADSA.planner_command_configuration_s2_r0(domainFile_s2_r0);
        final double costS2R1 = EADSA.planner_command_configuration_s2_r1(domainFile_s2_r1);
        final double costS2R2 = EADSA.planner_command_configuration_s2_r2(domainFile_s2_r2);
        double[] costValues = {costS2R0, costS2R1, costS2R2};
        DynamicNormalize costNormalizer = new DynamicNormalize();
        costNormalizer.preProcessing(costValues);
        final double aS2R0 = (double) converter.getValue("Sub-scenario2", "RESTAURANT-SERVICE", "Restaurant-1-service", "availability");
        final double aS2R1 = (double) converter.getValue("Sub-scenario2", "RESTAURANT-SERVICE", "Restaurant-2-service", "availability");
        final double aS2R2 = (double) converter.getValue("Sub-scenario2", "RESTAURANT-SERVICE", "Restaurant-3-service", "availability");
        final double aS2O0 = (double) converter.getValue("Sub-scenario2", "ORDERING-SERVICE", "Ordering-service", "availability");
        final double aS2D0 = (double) converter.getValue("Sub-scenario2", "DELIVERY-PROXY-SERVICE", "Delivery-proxy-1-service", "availability");
        final double aS2P0 = (double) converter.getValue("Sub-scenario2", "PAYMENT-PROXY-SERVICE", "Payment-proxy-1-service", "availability");
        double[] avalibilities = {aS2R0, aS2R1, aS2R2, aS2O0, aS2D0, aS2P0};
        DynamicNormalize availabilityNormalizer = new DynamicNormalize();
        availabilityNormalizer.preProcessing(avalibilities);
        final int tS2R0 = (int) converter.getValue("Sub-scenario2", "RESTAURANT-SERVICE", "Restaurant-1-service", "responseTime");
        final int tS2R1 = (int) converter.getValue("Sub-scenario2", "RESTAURANT-SERVICE", "Restaurant-2-service", "responseTime");
        final int tS2R2 = (int) converter.getValue("Sub-scenario2", "RESTAURANT-SERVICE", "Restaurant-3-service", "responseTime");
        final int tS2O0 = (int) converter.getValue("Sub-scenario2", "ORDERING-SERVICE", "Ordering-service", "responseTime");
        final int tS2D0 = (int) converter.getValue("Sub-scenario2", "DELIVERY-PROXY-SERVICE", "Delivery-proxy-1-service", "responseTime");
        final int tS2P0 = (int) converter.getValue("Sub-scenario2", "PAYMENT-PROXY-SERVICE", "Payment-proxy-1-service", "responseTime");
        int[] responseTimes = {tS2R0, tS2R1, tS2R2, tS2O0, tS2D0, tS2P0};
        double[] doubleResponseTimes = Arrays.stream(responseTimes).asDoubleStream().toArray();
        DynamicNormalize responseTimeNormalizer = new DynamicNormalize();
        responseTimeNormalizer.preProcessing(doubleResponseTimes);

        Map<String, List<String>> serviceImplementations = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> benchmarkForImplementation = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> currentQoSValues = new HashMap<>();

        // Restaurant //
        List<String> restaurantImplementations = List.of("restaurant-1-service","restaurant-2-service","restaurant-3-service");
        serviceImplementations.put("RESTAURANT-SERVICE", restaurantImplementations);

        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark1 = new HashMap<>();//option configuration
        restaurantBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS2R0));//0.766666667
        restaurantBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS2R0));//0.165306122
        restaurantBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS2R0));
        benchmarkForImplementation.put("restaurant-1-service", restaurantBenchmark1);
        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark2 = new HashMap<>();
        restaurantBenchmark2.put(Availability.class, availabilityNormalizer.normalize(aS2R1));//0.85
        restaurantBenchmark2.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS2R1));//0.148979592
        restaurantBenchmark2.put(Vulnerability.class, costNormalizer.normalize(costS2R1));
        benchmarkForImplementation.put("restaurant-2-service", restaurantBenchmark2);
        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark3 = new HashMap<>();
        restaurantBenchmark3.put(Availability.class, availabilityNormalizer.normalize(aS2R2));//0.9
        restaurantBenchmark3.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS2R2));//0.1
        restaurantBenchmark3.put(Vulnerability.class, costNormalizer.normalize(costS2R2));
        benchmarkForImplementation.put("restaurant-3-service", restaurantBenchmark3);

        Map<Class<? extends QoSSpecification>, Double> restaurantCurrentQoS = new HashMap<>();//Initial configuration
        restaurantCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS2R0));
        restaurantCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS2R0));
        currentQoSValues.put("RESTAURANT-SERVICE", restaurantCurrentQoS);

        // Ordering //
        List<String> orderingImplementations = List.of("ordering-service");
        serviceImplementations.put("ORDERING-SERVICE", orderingImplementations);

        Map<Class<? extends QoSSpecification>, Double> orderingBenchmark = new HashMap<>();
        orderingBenchmark.put(Availability.class, availabilityNormalizer.normalize(aS2O0));//0.8
        orderingBenchmark.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS2O0));//0.655102041
        orderingBenchmark.put(Vulnerability.class, costNormalizer.normalize(costS2R0));
        benchmarkForImplementation.put("ordering-service", orderingBenchmark);

        Map<Class<? extends QoSSpecification>, Double> orderingCurrentQoS = new HashMap<>();
        orderingCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS2O0));
        orderingCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS2O0));
        currentQoSValues.put("ORDERING-SERVICE", orderingCurrentQoS);

        // Delivery //
        List<String> deliveryProxyImplementations = List.of("delivery-proxy-1-service");
        serviceImplementations.put("DELIVERY-PROXY-SERVICE", deliveryProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyBenchmark1 = new HashMap<>();
        deliveryProxyBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS2D0));//0.683333333
        deliveryProxyBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS2D0));//0.573469388
        deliveryProxyBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS2R0));
        benchmarkForImplementation.put("delivery-proxy-1-service", deliveryProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyCurrentQoS = new HashMap<>();
        deliveryProxyCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS2D0));
        deliveryProxyCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS2D0));
        currentQoSValues.put("DELIVERY-PROXY-SERVICE", deliveryProxyCurrentQoS);

        // Payment //
        List<String> paymentProxyImplementations = List.of("payment-proxy-1-service");
        serviceImplementations.put("PAYMENT-PROXY-SERVICE", paymentProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyBenchmark1 = new HashMap<>();
        paymentProxyBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS2P0));//0.766666667
        paymentProxyBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS2P0));//0.818367347
        paymentProxyBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS2R0));
        benchmarkForImplementation.put("payment-proxy-1-service", paymentProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyCurrentQoS = new HashMap<>();//Initial configuration
        paymentProxyCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS2P0));
        paymentProxyCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS2P0));
        currentQoSValues.put("PAYMENT-PROXY-SERVICE", paymentProxyCurrentQoS);

        return createServiceMap(availabilityWeight,
                responseTimeWeight,
                vulnerabilityWeight,
                serviceImplementations,
                benchmarkForImplementation,
                currentQoSValues);
    }

    public static Map<String, Service> RQ1_s3_SAQURE_ExpConfig(){
        double availabilityWeight = 0.3;
        double responseTimeWeight = 0.3;
        double vulnerabilityWeight = 0.4;
        try {
            converter = new ExcelToJsonConverter(FilePathConstants.configuration_rq1_path);
        } catch (Exception e) {
            throw new ExceptionInInitializerError("Failed to initialize Excel converter: " + e.getMessage());
        }
        String[] cveIds_s3_o0 = {"CVE-2024-38286", "CVE-2024-12798", "CVE-2024-38820", "CVE-2025-22228", "CVE-2023-44487", "CVE-2024-22243", "CVE-2024-34447", "CVE-2023-6378", "CVE-2024-38820", "CVE-2022-40150", "CVE-2024-38816", "CVE-2022-1471", "CVE-2023-34055", "CVE-2024-34447", "CVE-2025-24813"};
        String[] cveIds_s3_o1 = {"CVE-2024-38286", "CVE-2024-12798", "CVE-2024-38820", "CVE-2025-22228", "CVE-2023-44487", "CVE-2024-22243", "CVE-2024-34447", "CVE-2023-6378", "CVE-2024-38820", "CVE-2022-40150", "CVE-2024-38816", "CVE-2022-1471", "CVE-2023-34055", "CVE-2024-34447", "CVE-2025-24813"};
        String[] cveIds_s3_o2 = {"CVE-2024-38286", "CVE-2024-12798", "CVE-2024-38820", "CVE-2025-22228", "CVE-2023-44487", "CVE-2024-22243", "CVE-2024-34447", "CVE-2023-6378", "CVE-2024-38820", "CVE-2022-40150", "CVE-2024-38816", "CVE-2022-1471", "CVE-2023-34055", "CVE-2024-34447", "CVE-2025-24813"};
        String[] cveIds_s3_o3 = {"CVE-2024-38286", "CVE-2024-12798", "CVE-2024-38820", "CVE-2025-22228", "CVE-2023-44487", "CVE-2023-34055", "CVE-2024-22243", "CVE-2024-38820", "CVE-2022-40150", "CVE-2024-38816", "CVE-2022-1471", "CVE-2023-34055", "CVE-2024-34447"};

        String domainFile_s3_o0 = AED_process(FilePathConstants.AED_path_RQ1 + "S3_R0_O0_D0_P0.pddl", cveIds_s3_o0);
        String domainFile_s3_o1 = AED_process(FilePathConstants.AED_path_RQ1 + "S3_R0_O1_D0_P0.pddl", cveIds_s3_o1);
        String domainFile_s3_o2 = AED_process(FilePathConstants.AED_path_RQ1 + "S3_R0_O2_D0_P0.pddl", cveIds_s3_o2);
        String domainFile_s3_o3 = AED_process(FilePathConstants.AED_path_RQ1 + "S3_R0_O3_D0_P0.pddl", cveIds_s3_o3);

        final double costS3O0 = EADSA.planner_command_configuration_s3_o0(domainFile_s3_o0);
        final double costS3O1 = EADSA.planner_command_configuration_s3_o1(domainFile_s3_o1);
        final double costS3O2 = EADSA.planner_command_configuration_s3_o2(domainFile_s3_o2);
        final double costS3O3 = EADSA.planner_command_configuration_s3_o3(domainFile_s3_o3);
        double[] costValues = {costS3O0, costS3O1, costS3O2, costS3O3};
        DynamicNormalize costNormalizer = new DynamicNormalize();
        costNormalizer.preProcessing(costValues);
        final double aS3R0 = (double) converter.getValue("Sub-scenario3", "RESTAURANT-SERVICE", "Restaurant-service", "availability");
        final double aS3O0 = (double) converter.getValue("Sub-scenario3", "ORDERING-SERVICE", "Ordering-1-service", "availability");
        final double aS3O1 = (double) converter.getValue("Sub-scenario3", "ORDERING-SERVICE", "Ordering-2-service", "availability");
        final double aS3O2 = (double) converter.getValue("Sub-scenario3", "ORDERING-SERVICE", "Ordering-3-service", "availability");
        final double aS3O3 = (double) converter.getValue("Sub-scenario3", "ORDERING-SERVICE", "Ordering-4-service", "availability");
        final double aS3D0 = (double) converter.getValue("Sub-scenario3", "DELIVERY-PROXY-SERVICE", "Delivery-proxy-1-service", "availability");
        final double aS3P0 = (double) converter.getValue("Sub-scenario3", "PAYMENT-PROXY-SERVICE", "Payment-proxy-1-service", "availability");
        double[] avalibilities = {aS3R0, aS3O0, aS3O1, aS3O2, aS3O3, aS3D0, aS3P0};
        DynamicNormalize availabilityNormalizer = new DynamicNormalize();
        availabilityNormalizer.preProcessing(avalibilities);
        final int tS3R0 = (int) converter.getValue("Sub-scenario3", "RESTAURANT-SERVICE", "Restaurant-service", "responseTime");
        final int tS3O0 = (int) converter.getValue("Sub-scenario3", "ORDERING-SERVICE", "Ordering-1-service", "responseTime");
        final int tS3O1 = (int) converter.getValue("Sub-scenario3", "ORDERING-SERVICE", "Ordering-2-service", "responseTime");
        final int tS3O2 = (int) converter.getValue("Sub-scenario3", "ORDERING-SERVICE", "Ordering-3-service", "responseTime");
        final int tS3O3 = (int) converter.getValue("Sub-scenario3", "ORDERING-SERVICE", "Ordering-4-service", "responseTime");
        final int tS3D0 = (int) converter.getValue("Sub-scenario3", "DELIVERY-PROXY-SERVICE", "Delivery-proxy-1-service", "responseTime");
        final int tS3P0 = (int) converter.getValue("Sub-scenario3", "PAYMENT-PROXY-SERVICE", "Payment-proxy-1-service", "responseTime");
        int[] responseTimes = {tS3R0, tS3O0, tS3O1, tS3O2, tS3O3, tS3D0, tS3P0};
        double[] doubleResponseTimes = Arrays.stream(responseTimes).asDoubleStream().toArray();
        DynamicNormalize responseTimeNormalizer = new DynamicNormalize();
        responseTimeNormalizer.preProcessing(doubleResponseTimes);
        Map<String, List<String>> serviceImplementations = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> benchmarkForImplementation = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> currentQoSValues = new HashMap<>();

        // Restaurant //
        List<String> restaurantImplementations = List.of("restaurant-1-service");
        serviceImplementations.put("RESTAURANT-SERVICE", restaurantImplementations);

        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark1 = new HashMap<>();//option configuration
        restaurantBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS3R0));//0.183333333
        restaurantBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS3R0));//0.9
        restaurantBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS3O0));
        benchmarkForImplementation.put("restaurant-1-service", restaurantBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> restaurantCurrentQoS = new HashMap<>();//Initial configuration
        restaurantCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS3R0));
        restaurantCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS3R0));
        currentQoSValues.put("RESTAURANT-SERVICE", restaurantCurrentQoS);

        // Ordering //
        List<String> orderingImplementations = List.of("ordering-1-service","ordering-2-service","ordering-3-service", "ordering-4-service");
        serviceImplementations.put("ORDERING-SERVICE", orderingImplementations);

        Map<Class<? extends QoSSpecification>, Double> orderingBenchmark1 = new HashMap<>();
        orderingBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS3O0));//0.6
        orderingBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS3O0));//0.655102041
        orderingBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS3O0));
        benchmarkForImplementation.put("ordering-1-service", orderingBenchmark1);
        Map<Class<? extends QoSSpecification>, Double> orderingBenchmark2 = new HashMap<>();
        orderingBenchmark2.put(Availability.class, availabilityNormalizer.normalize(aS3O1));//0.733333333
        orderingBenchmark2.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS3O1));//0.655102041
        orderingBenchmark2.put(Vulnerability.class, costNormalizer.normalize(costS3O1));
        benchmarkForImplementation.put("ordering-2-service", orderingBenchmark2);
        Map<Class<? extends QoSSpecification>, Double> orderingBenchmark3 = new HashMap<>();
        orderingBenchmark3.put(Availability.class, availabilityNormalizer.normalize(aS3O2));//0.6
        orderingBenchmark3.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS3O2));//0.491836735
        orderingBenchmark3.put(Vulnerability.class, costNormalizer.normalize(costS3O2));
        benchmarkForImplementation.put("ordering-3-service", orderingBenchmark3);
        Map<Class<? extends QoSSpecification>, Double> orderingBenchmark4 = new HashMap<>();
        orderingBenchmark4.put(Availability.class, availabilityNormalizer.normalize(aS3O3));//0.6
        orderingBenchmark4.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS3O3));//0.655102041
        orderingBenchmark4.put(Vulnerability.class, costNormalizer.normalize(costS3O3));
        benchmarkForImplementation.put("ordering-4-service", orderingBenchmark4);

        Map<Class<? extends QoSSpecification>, Double> orderingCurrentQoS = new HashMap<>();
        orderingCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS3O0));
        orderingCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS3O0));
        currentQoSValues.put("ORDERING-SERVICE", orderingCurrentQoS);

        // Delivery //
        List<String> deliveryProxyImplementations = List.of("delivery-proxy-1-service");
        serviceImplementations.put("DELIVERY-PROXY-SERVICE", deliveryProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyBenchmark1 = new HashMap<>();
        deliveryProxyBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS3D0));
        deliveryProxyBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS3D0));
        deliveryProxyBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS3O0));
        benchmarkForImplementation.put("delivery-proxy-1-service", deliveryProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyCurrentQoS = new HashMap<>();
        deliveryProxyCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS3D0));
        deliveryProxyCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS3D0));
        currentQoSValues.put("DELIVERY-PROXY-SERVICE", deliveryProxyCurrentQoS);

        // Payment //
        List<String> paymentProxyImplementations = List.of("payment-proxy-1-service");
        serviceImplementations.put("PAYMENT-PROXY-SERVICE", paymentProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyBenchmark1 = new HashMap<>();
        paymentProxyBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS3P0));//0.766666667
        paymentProxyBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS3P0));//0.818367347
        paymentProxyBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS3O0));
        benchmarkForImplementation.put("payment-proxy-1-service", paymentProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyCurrentQoS = new HashMap<>();//Initial configuration
        paymentProxyCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS3P0));
        paymentProxyCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS3P0));
        currentQoSValues.put("PAYMENT-PROXY-SERVICE", paymentProxyCurrentQoS);

        return createServiceMap(availabilityWeight,
                responseTimeWeight,
                vulnerabilityWeight,
                serviceImplementations,
                benchmarkForImplementation,
                currentQoSValues);
    }

    public static Map<String, Service> RQ1_s4_SAQURE_ExpConfig(){
        double availabilityWeight = 0.3;
        double responseTimeWeight = 0.3;
        double vulnerabilityWeight = 0.4;
        try {
            converter = new ExcelToJsonConverter(FilePathConstants.configuration_rq1_path);
        } catch (Exception e) {
            throw new ExceptionInInitializerError("Failed to initialize Excel converter: " + e.getMessage());
        }
        String[] cveIds_s4_d0 = {"CVE-2024-38286", "CVE-2024-12798", "CVE-2023-44487", "CVE-2023-6378", "CVE-2024-22243", "CVE-2024-34447", "CVE-2022-40149", "CVE-2024-38820", "CVE-2022-40150", "CVE-2024-38816", "CVE-2022-1471", "CVE-2023-34055", "CVE-2025-24813"};
        String[] cveIds_s4_d1 = {"CVE-2024-38286", "CVE-2024-12798", "CVE-2023-44487", "CVE-2023-6378", "CVE-2024-22243", "CVE-2024-34447", "CVE-2022-40149", "CVE-2024-38820", "CVE-2022-40150", "CVE-2024-38816", "CVE-2022-1471", "CVE-2023-34055", "CVE-2025-24813"};
        String[] cveIds_s4_d2 = {"CVE-2024-38286", "CVE-2024-12798", "CVE-2023-44487", "CVE-2023-6378", "CVE-2024-22243", "CVE-2024-34447", "CVE-2022-40149", "CVE-2024-38820", "CVE-2022-40150", "CVE-2024-38816", "CVE-2022-1471", "CVE-2023-34055", "CVE-2025-24813"};
        String[] cveIds_s4_d3 = {"CVE-2024-38286", "CVE-2024-12798", "CVE-2023-44487", "CVE-2023-6378", "CVE-2024-22243", "CVE-2024-34447", "CVE-2022-40149", "CVE-2024-38820", "CVE-2022-40150", "CVE-2023-34055"};

        String domainFile_s4_d0 = AED_process(FilePathConstants.AED_path_RQ1 + "S4_R0_O0_D0_P0.pddl", cveIds_s4_d0);
        String domainFile_s4_d1 = AED_process(FilePathConstants.AED_path_RQ1 + "S4_R0_O0_D1_P0.pddl", cveIds_s4_d1);
        String domainFile_s4_d2 = AED_process(FilePathConstants.AED_path_RQ1 + "S4_R0_O0_D2_P0.pddl", cveIds_s4_d2);
        String domainFile_s4_d3 = AED_process(FilePathConstants.AED_path_RQ1 + "S4_R0_O0_D3_P0.pddl", cveIds_s4_d3);

        final double costS4D0 = EADSA.planner_command_configuration_s4_d0(domainFile_s4_d0);
        final double costS4D1 = EADSA.planner_command_configuration_s4_d1(domainFile_s4_d1);
        final double costS4D2 = EADSA.planner_command_configuration_s4_d2(domainFile_s4_d2);
        final double costS4D3 = EADSA.planner_command_configuration_s4_d3(domainFile_s4_d3);
        double[] costValues = {costS4D0, costS4D1, costS4D2, costS4D3};
        DynamicNormalize costNormalizer = new DynamicNormalize();
        costNormalizer.preProcessing(costValues);
        final double aS4R0 = (double) converter.getValue("Sub-scenario4", "RESTAURANT-SERVICE", "Restaurant-service", "availability");
        final double aS4O0 = (double) converter.getValue("Sub-scenario4", "ORDERING-SERVICE", "Ordering-service", "availability");
        final double aS4D0 = (double) converter.getValue("Sub-scenario4", "DELIVERY-PROXY-SERVICE", "Delivery-proxy-1-service", "availability");
        final double aS4D1 = (double) converter.getValue("Sub-scenario4", "DELIVERY-PROXY-SERVICE", "Delivery-proxy-2-service", "availability");
        final double aS4D2 = (double) converter.getValue("Sub-scenario4", "DELIVERY-PROXY-SERVICE", "Delivery-proxy-3-service", "availability");
        final double aS4D3 = (double) converter.getValue("Sub-scenario4", "DELIVERY-PROXY-SERVICE", "Delivery-proxy-4-service", "availability");
        final double aS4P0 = (double) converter.getValue("Sub-scenario4", "PAYMENT-PROXY-SERVICE", "Payment-proxy-1-service", "availability");
        double[] avalibilities = {aS4R0, aS4O0, aS4D0, aS4D1, aS4D2, aS4D3, aS4P0};
        DynamicNormalize availabilityNormalizer = new DynamicNormalize();
        availabilityNormalizer.preProcessing(avalibilities);
        final int tS4R0 = (int) converter.getValue("Sub-scenario4", "RESTAURANT-SERVICE", "Restaurant-service", "responseTime");
        final int tS4O0 = (int) converter.getValue("Sub-scenario4", "ORDERING-SERVICE", "Ordering-service", "responseTime");
        final int tS4D0 = (int) converter.getValue("Sub-scenario4", "DELIVERY-PROXY-SERVICE", "Delivery-proxy-1-service", "responseTime");
        final int tS4D1 = (int) converter.getValue("Sub-scenario4", "DELIVERY-PROXY-SERVICE", "Delivery-proxy-2-service", "responseTime");
        final int tS4D2 = (int) converter.getValue("Sub-scenario4", "DELIVERY-PROXY-SERVICE", "Delivery-proxy-3-service", "responseTime");
        final int tS4D3 = (int) converter.getValue("Sub-scenario4", "DELIVERY-PROXY-SERVICE", "Delivery-proxy-4-service", "responseTime");
        final int tS4P0 = (int) converter.getValue("Sub-scenario4", "PAYMENT-PROXY-SERVICE", "Payment-proxy-1-service", "responseTime");
        int[] responseTimes = {tS4R0, tS4O0, tS4D0, tS4D1, tS4D2, tS4D3, tS4P0};
        double[] doubleResponseTimes = Arrays.stream(responseTimes).asDoubleStream().toArray();
        DynamicNormalize responseTimeNormalizer = new DynamicNormalize();
        responseTimeNormalizer.preProcessing(doubleResponseTimes);

        Map<String, List<String>> serviceImplementations = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> benchmarkForImplementation = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> currentQoSValues = new HashMap<>();

        // Restaurant //
        List<String> restaurantImplementations = List.of("restaurant-1-service");
        serviceImplementations.put("RESTAURANT-SERVICE", restaurantImplementations);

        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark1 = new HashMap<>();//option configuration
        restaurantBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS4R0));//0.766666667
        restaurantBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS4R0));//0.165306122
        restaurantBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS4D0));
        benchmarkForImplementation.put("restaurant-1-service", restaurantBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> restaurantCurrentQoS = new HashMap<>();//Initial configuration
        restaurantCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS4R0));
        restaurantCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS4R0));
        currentQoSValues.put("RESTAURANT-SERVICE", restaurantCurrentQoS);

        // Ordering //
        List<String> orderingImplementations = List.of("ordering-1-service");
        serviceImplementations.put("ORDERING-SERVICE", orderingImplementations);

        Map<Class<? extends QoSSpecification>, Double> orderingBenchmark1 = new HashMap<>();
        orderingBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS4O0));//0.266666667
        orderingBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS4O0));//0.655102041
        orderingBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS4D0));
        benchmarkForImplementation.put("ordering-1-service", orderingBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> orderingCurrentQoS = new HashMap<>();
        orderingCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS4O0));
        orderingCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS4O0));
        currentQoSValues.put("ORDERING-SERVICE", orderingCurrentQoS);

        // Delivery //
        List<String> deliveryProxyImplementations = List.of("delivery-proxy-1-service","delivery-proxy-2-service","delivery-proxy-3-service","delivery-proxy-4-service");
        serviceImplementations.put("DELIVERY-PROXY-SERVICE", deliveryProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyBenchmark1 = new HashMap<>();
        deliveryProxyBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS4D0));//0.683333333
        deliveryProxyBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS4D0));//0.573469388
        deliveryProxyBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS4D0));
        benchmarkForImplementation.put("delivery-proxy-1-service", deliveryProxyBenchmark1);
        Map<Class<? extends QoSSpecification>, Double> deliveryProxyBenchmark2 = new HashMap<>();
        deliveryProxyBenchmark2.put(Availability.class, availabilityNormalizer.normalize(aS4D1));//0.85
        deliveryProxyBenchmark2.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS4D1));//0.573469388
        deliveryProxyBenchmark2.put(Vulnerability.class, costNormalizer.normalize(costS4D1));
        benchmarkForImplementation.put("delivery-proxy-2-service", deliveryProxyBenchmark2);
        Map<Class<? extends QoSSpecification>, Double> deliveryProxyBenchmark3 = new HashMap<>();
        deliveryProxyBenchmark3.put(Availability.class, availabilityNormalizer.normalize(aS4D2));//0.683333333
        deliveryProxyBenchmark3.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS4D2));//0.410204082
        deliveryProxyBenchmark3.put(Vulnerability.class, costNormalizer.normalize(costS4D2));
        benchmarkForImplementation.put("delivery-proxy-3-service", deliveryProxyBenchmark3);
        Map<Class<? extends QoSSpecification>, Double> deliveryProxyBenchmark4 = new HashMap<>();
        deliveryProxyBenchmark4.put(Availability.class, availabilityNormalizer.normalize(aS4D3));//0.683333333
        deliveryProxyBenchmark4.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS4D3));//0.573469388
        deliveryProxyBenchmark4.put(Vulnerability.class, costNormalizer.normalize(costS4D3));
        benchmarkForImplementation.put("delivery-proxy-4-service", deliveryProxyBenchmark4);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyCurrentQoS = new HashMap<>();
        deliveryProxyCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS4D0));
        deliveryProxyCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS4D0));
        currentQoSValues.put("DELIVERY-PROXY-SERVICE", deliveryProxyCurrentQoS);

        // Payment //
        List<String> paymentProxyImplementations = List.of("payment-proxy-1-service");
        serviceImplementations.put("PAYMENT-PROXY-SERVICE", paymentProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyBenchmark1 = new HashMap<>();
        paymentProxyBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS4P0));//0.1
        paymentProxyBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS4P0));//0.736734694
        paymentProxyBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS4D0));
        benchmarkForImplementation.put("payment-proxy-1-service", paymentProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyCurrentQoS = new HashMap<>();//Initial configuration
        paymentProxyCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS4P0));
        paymentProxyCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS4P0));
        currentQoSValues.put("PAYMENT-PROXY-SERVICE", paymentProxyCurrentQoS);

        return createServiceMap(availabilityWeight,
                responseTimeWeight,
                vulnerabilityWeight,
                serviceImplementations,
                benchmarkForImplementation,
                currentQoSValues);
    }

    public static Map<String, Service> RQ1_s5_SAQURE_ExpConfig(){
        double availabilityWeight = 0.3;
        double responseTimeWeight = 0.3;
        double vulnerabilityWeight = 0.4;
        try {
            converter = new ExcelToJsonConverter(FilePathConstants.configuration_rq1_path);
        } catch (Exception e) {
            throw new ExceptionInInitializerError("Failed to initialize Excel converter: " + e.getMessage());
        }
        String[] cveIds_s5_p0 = {"CVE-2024-38286", "CVE-2024-12798", "CVE-2023-44487", "CVE-2024-22243", "CVE-2024-34447", "CVE-2023-6378", "CVE-2024-38820", "CVE-2022-40150", "CVE-2024-38816", "CVE-2023-34055", "CVE-2025-22228"};
        String[] cveIds_s5_p1 = {"CVE-2024-38286", "CVE-2024-12798", "CVE-2023-44487", "CVE-2024-22243", "CVE-2024-34447", "CVE-2023-6378", "CVE-2024-38820", "CVE-2022-40150", "CVE-2024-38816", "CVE-2023-34055", "CVE-2022-1471", "CVE-2025-24813", "CVE-2025-22228"};
        String[] cveIds_s5_p2 = {"CVE-2024-38286", "CVE-2024-12798", "CVE-2023-44487", "CVE-2024-22243", "CVE-2024-34447", "CVE-2023-6378", "CVE-2024-38820", "CVE-2022-40150", "CVE-2024-38816", "CVE-2023-34055", "CVE-2022-1471", "CVE-2025-24813", "CVE-2025-22228"};
        String[] cveIds_s5_p3 = {"CVE-2024-38286", "CVE-2024-12798", "CVE-2023-44487", "CVE-2024-22243", "CVE-2024-34447", "CVE-2023-6378", "CVE-2024-38820", "CVE-2022-40150", "CVE-2024-38816", "CVE-2023-34055"};

        String domainFile_s5_p0 = AED_process(FilePathConstants.AED_path_RQ1 + "S5_R0_O0_D0_P0.pddl", cveIds_s5_p0);
        String domainFile_s5_p1 = AED_process(FilePathConstants.AED_path_RQ1 + "S5_R0_O0_D0_P1.pddl", cveIds_s5_p1);
        String domainFile_s5_p2 = AED_process(FilePathConstants.AED_path_RQ1 + "S5_R0_O0_D0_P2.pddl", cveIds_s5_p2);
        String domainFile_s5_p3 = AED_process(FilePathConstants.AED_path_RQ1 + "S5_R0_O0_D0_P3.pddl", cveIds_s5_p3);

        final double costS5P0 = EADSA.planner_command_configuration_s5_p0(domainFile_s5_p0);
        final double costS5P1 = EADSA.planner_command_configuration_s5_p1(domainFile_s5_p1);
        final double costS5P2 = EADSA.planner_command_configuration_s5_p2(domainFile_s5_p2);
        final double costS5P3 = EADSA.planner_command_configuration_s5_p3(domainFile_s5_p3);
        double[] costValues = {costS5P0, costS5P1, costS5P2, costS5P3};
        DynamicNormalize costNormalizer = new DynamicNormalize();
        costNormalizer.preProcessing(costValues);
        final double aS5R0 = (double) converter.getValue("Sub-scenario5", "RESTAURANT-SERVICE", "Restaurant-service", "availability");
        final double aS5O0 = (double) converter.getValue("Sub-scenario5", "ORDERING-SERVICE", "Ordering-service", "availability");
        final double aS5D0 = (double) converter.getValue("Sub-scenario5", "DELIVERY-PROXY-SERVICE", "Delivery-proxy-1-service", "availability");
        final double aS5P0 = (double) converter.getValue("Sub-scenario5", "PAYMENT-PROXY-SERVICE", "Payment-proxy-1-service", "availability");
        final double aS5P1 = (double) converter.getValue("Sub-scenario5", "PAYMENT-PROXY-SERVICE", "Payment-proxy-2-service", "availability");
        final double aS5P2 = (double) converter.getValue("Sub-scenario5", "PAYMENT-PROXY-SERVICE", "Payment-proxy-3-service", "availability");
        final double aS5P3 = (double) converter.getValue("Sub-scenario5", "PAYMENT-PROXY-SERVICE", "Payment-proxy-4-service", "availability");
        double[] avalibilities = {aS5R0, aS5O0, aS5D0, aS5P0, aS5P1, aS5P2, aS5P3};
        DynamicNormalize availabilityNormalizer = new DynamicNormalize();
        availabilityNormalizer.preProcessing(avalibilities);
        final int tS5R0 = (int) converter.getValue("Sub-scenario5", "RESTAURANT-SERVICE", "Restaurant-service", "responseTime");
        final int tS5O0 = (int) converter.getValue("Sub-scenario5", "ORDERING-SERVICE", "Ordering-service", "responseTime");
        final int tS5D0 = (int) converter.getValue("Sub-scenario5", "DELIVERY-PROXY-SERVICE", "Delivery-proxy-1-service", "responseTime");
        final int tS5P0 = (int) converter.getValue("Sub-scenario5", "PAYMENT-PROXY-SERVICE", "Payment-proxy-1-service", "responseTime");
        final int tS5P1 = (int) converter.getValue("Sub-scenario5", "PAYMENT-PROXY-SERVICE", "Payment-proxy-2-service", "responseTime");
        final int tS5P2 = (int) converter.getValue("Sub-scenario5", "PAYMENT-PROXY-SERVICE", "Payment-proxy-3-service", "responseTime");
        final int tS5P3 = (int) converter.getValue("Sub-scenario5", "PAYMENT-PROXY-SERVICE", "Payment-proxy-4-service", "responseTime");
        int[] responseTimes = {tS5R0, tS5O0, tS5D0, tS5P0, tS5P1, tS5P2, tS5P3};
        double[] doubleResponseTimes = Arrays.stream(responseTimes).asDoubleStream().toArray();
        DynamicNormalize responseTimeNormalizer = new DynamicNormalize();
        responseTimeNormalizer.preProcessing(doubleResponseTimes);
        Map<String, List<String>> serviceImplementations = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> benchmarkForImplementation = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> currentQoSValues = new HashMap<>();

        // Restaurant //
        List<String> restaurantImplementations = List.of("restaurant-1-service");
        serviceImplementations.put("RESTAURANT-SERVICE", restaurantImplementations);

        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark1 = new HashMap<>();//option configuration
        restaurantBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS5R0));//0.766666667
        restaurantBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS5R0));//0.165306122
        restaurantBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS5P0));
        benchmarkForImplementation.put("restaurant-1-service", restaurantBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> restaurantCurrentQoS = new HashMap<>();//Initial configuration
        restaurantCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS5R0));
        restaurantCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS5R0));
        currentQoSValues.put("RESTAURANT-SERVICE", restaurantCurrentQoS);

        // Ordering //
        List<String> orderingImplementations = List.of("ordering-1-service");
        serviceImplementations.put("ORDERING-SERVICE", orderingImplementations);

        Map<Class<? extends QoSSpecification>, Double> orderingBenchmark1 = new HashMap<>();
        orderingBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS5O0));//0.8
        orderingBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS5O0));//0.655102041
        orderingBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS5P0));
        benchmarkForImplementation.put("ordering-1-service", orderingBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> orderingCurrentQoS = new HashMap<>();
        orderingCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS5O0));
        orderingCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS5O0));
        currentQoSValues.put("ORDERING-SERVICE", orderingCurrentQoS);

        // Delivery //
        List<String> deliveryProxyImplementations = List.of("delivery-proxy-1-service");
        serviceImplementations.put("DELIVERY-PROXY-SERVICE", deliveryProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyBenchmark1 = new HashMap<>();
        deliveryProxyBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS5D0));//0.683333333
        deliveryProxyBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS5D0));//0.655102041
        deliveryProxyBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS5P0));
        benchmarkForImplementation.put("delivery-proxy-1-service", deliveryProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyCurrentQoS = new HashMap<>();
        deliveryProxyCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS5D0));
        deliveryProxyCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS5D0));
        currentQoSValues.put("DELIVERY-PROXY-SERVICE", deliveryProxyCurrentQoS);

        // Payment //
        List<String> paymentProxyImplementations = List.of("payment-proxy-1-service","payment-proxy-2-service","payment-proxy-3-service","payment-proxy-4-service");
        serviceImplementations.put("PAYMENT-PROXY-SERVICE", paymentProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyBenchmark1 = new HashMap<>();
        paymentProxyBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS5P0));//0.766666667
        paymentProxyBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS5P0));//0.818367347
        paymentProxyBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS5P0));//
        benchmarkForImplementation.put("payment-proxy-1-service", paymentProxyBenchmark1);
        Map<Class<? extends QoSSpecification>, Double> paymentProxyBenchmark2 = new HashMap<>();
        paymentProxyBenchmark2.put(Availability.class, availabilityNormalizer.normalize(aS5P1));//0.8
        paymentProxyBenchmark2.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS5P1));//0.9
        paymentProxyBenchmark2.put(Vulnerability.class, costNormalizer.normalize(costS5P1));//
        benchmarkForImplementation.put("payment-proxy-2-service", paymentProxyBenchmark2);
        Map<Class<? extends QoSSpecification>, Double> paymentProxyBenchmark3 = new HashMap<>();
        paymentProxyBenchmark3.put(Availability.class, availabilityNormalizer.normalize(aS5P2));//0.433333333
        paymentProxyBenchmark3.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS5P2));//0.573469388
        paymentProxyBenchmark3.put(Vulnerability.class, costNormalizer.normalize(costS5P2));//
        benchmarkForImplementation.put("payment-proxy-3-service", paymentProxyBenchmark3);
        Map<Class<? extends QoSSpecification>, Double> paymentProxyBenchmark4 = new HashMap<>();
        paymentProxyBenchmark4.put(Availability.class, availabilityNormalizer.normalize(aS5P3));//0.433333333
        paymentProxyBenchmark4.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS5P3));//0.9
        paymentProxyBenchmark4.put(Vulnerability.class, costNormalizer.normalize(costS5P3));//
        benchmarkForImplementation.put("payment-proxy-4-service", paymentProxyBenchmark4);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyCurrentQoS = new HashMap<>();//Initial configuration
        paymentProxyCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS5P0));
        paymentProxyCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS5P0));
        currentQoSValues.put("PAYMENT-PROXY-SERVICE", paymentProxyCurrentQoS);

        return createServiceMap(availabilityWeight,
                responseTimeWeight,
                vulnerabilityWeight,
                serviceImplementations,
                benchmarkForImplementation,
                currentQoSValues);
    }

    public static Map<String, Service> RQ1_s1_Aqua_ExpConfig(){
        double availabilityWeight = 0.3;
        double responseTimeWeight = 0.3;
        double vulnerabilityWeight = 0.4;

        Map<String, List<String>> serviceImplementations = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> benchmarkForImplementation = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> currentQoSValues = new HashMap<>();

        // Restaurant //
        List<String> restaurantImplementations = List.of("restaurant-1-service","restaurant-2-service","restaurant-3-service");
        serviceImplementations.put("RESTAURANT-SERVICE", restaurantImplementations);

        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark1 = new HashMap<>();//option configuration
        restaurantBenchmark1.put(Availability.class, 0.9);
        restaurantBenchmark1.put(AverageResponseTime.class, 0.1);//50
        restaurantBenchmark1.put(Vulnerability.class, 0.56);//
        benchmarkForImplementation.put("restaurant-1-service", restaurantBenchmark1);
        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark2 = new HashMap<>();
        restaurantBenchmark2.put(Availability.class, 0.93);//0.92
        restaurantBenchmark2.put(AverageResponseTime.class, 0.06);//30
        restaurantBenchmark2.put(Vulnerability.class, 0.311666667);//
        benchmarkForImplementation.put("restaurant-2-service", restaurantBenchmark2);
        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark3 = new HashMap<>();
        restaurantBenchmark3.put(Availability.class, 0.96);
        restaurantBenchmark3.put(AverageResponseTime.class, 0.02);
        restaurantBenchmark3.put(Vulnerability.class, 0.723333333);//
        benchmarkForImplementation.put("restaurant-3-service", restaurantBenchmark3);

        Map<Class<? extends QoSSpecification>, Double> restaurantCurrentQoS = new HashMap<>();//Initial configuration
        restaurantCurrentQoS.put(Availability.class, 0.9);
        restaurantCurrentQoS.put(AverageResponseTime.class, 0.1);
        currentQoSValues.put("RESTAURANT-SERVICE", restaurantCurrentQoS);

        // Ordering //
        List<String> orderingImplementations = List.of("ordering-service");
        serviceImplementations.put("ORDERING-SERVICE", orderingImplementations);

        Map<Class<? extends QoSSpecification>, Double> orderingBenchmark = new HashMap<>();
        orderingBenchmark.put(Availability.class, 0.92);
        orderingBenchmark.put(AverageResponseTime.class, 0.7);
        orderingBenchmark.put(Vulnerability.class, 0.51);
        benchmarkForImplementation.put("ordering-service", orderingBenchmark);

        Map<Class<? extends QoSSpecification>, Double> orderingCurrentQoS = new HashMap<>();
        orderingCurrentQoS.put(Availability.class, 0.92);
        orderingCurrentQoS.put(AverageResponseTime.class, 0.7);
        currentQoSValues.put("ORDERING-SERVICE", orderingCurrentQoS);

        // Delivery //
        List<String> deliveryProxyImplementations = List.of("delivery-proxy-1-service");
        serviceImplementations.put("DELIVERY-PROXY-SERVICE", deliveryProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyBenchmark1 = new HashMap<>();
        deliveryProxyBenchmark1.put(Availability.class, 0.85);
        deliveryProxyBenchmark1.put(AverageResponseTime.class, 0.6);
        deliveryProxyBenchmark1.put(Vulnerability.class, 0.626666667);
        benchmarkForImplementation.put("delivery-proxy-1-service", deliveryProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyCurrentQoS = new HashMap<>();
        deliveryProxyCurrentQoS.put(Availability.class, 0.85);
        deliveryProxyCurrentQoS.put(AverageResponseTime.class, 0.6);
        currentQoSValues.put("DELIVERY-PROXY-SERVICE", deliveryProxyCurrentQoS);

        // Payment //
        List<String> paymentProxyImplementations = List.of("payment-proxy-1-service");
        serviceImplementations.put("PAYMENT-PROXY-SERVICE", paymentProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyBenchmark1 = new HashMap<>();
        paymentProxyBenchmark1.put(Availability.class, 0.9);
        paymentProxyBenchmark1.put(AverageResponseTime.class, 0.9);
        paymentProxyBenchmark1.put(Vulnerability.class, 0.358333333);
        benchmarkForImplementation.put("payment-proxy-1-service", paymentProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyCurrentQoS = new HashMap<>();//Initial configuration
        paymentProxyCurrentQoS.put(Availability.class, 0.9);
        paymentProxyCurrentQoS.put(AverageResponseTime.class, 0.9);
        currentQoSValues.put("PAYMENT-PROXY-SERVICE", paymentProxyCurrentQoS);

        return createServiceMap(availabilityWeight,
                responseTimeWeight,
                vulnerabilityWeight,
                serviceImplementations,
                benchmarkForImplementation,
                currentQoSValues);
    }
    public static Map<String, Service> RQ1_s2_Aqua_ExpConfig(){
        double availabilityWeight = 0.3;
        double responseTimeWeight = 0.3;
        double vulnerabilityWeight = 0.4;
        experiment_num = "rq2_s2-";

        Map<String, List<String>> serviceImplementations = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> benchmarkForImplementation = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> currentQoSValues = new HashMap<>();

        // Restaurant //
        List<String> restaurantImplementations = List.of("restaurant-1-service","restaurant-2-service","restaurant-3-service");
        serviceImplementations.put("RESTAURANT-SERVICE", restaurantImplementations);

        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark1 = new HashMap<>();//option configuration
        restaurantBenchmark1.put(Availability.class, 0.9);
        restaurantBenchmark1.put(AverageResponseTime.class, 0.1);
        restaurantBenchmark1.put(Vulnerability.class, 0.56);
        benchmarkForImplementation.put("restaurant-1-service", restaurantBenchmark1);
        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark2 = new HashMap<>();
        restaurantBenchmark2.put(Availability.class, 0.95);
        restaurantBenchmark2.put(AverageResponseTime.class, 0.08);
        restaurantBenchmark2.put(Vulnerability.class, 0.213333333);
        benchmarkForImplementation.put("restaurant-2-service", restaurantBenchmark2);
        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark3 = new HashMap<>();
        restaurantBenchmark3.put(Availability.class, 0.98);
        restaurantBenchmark3.put(AverageResponseTime.class, 0.02);
        restaurantBenchmark3.put(Vulnerability.class, 0.386666667);
        benchmarkForImplementation.put("restaurant-3-service", restaurantBenchmark3);

        Map<Class<? extends QoSSpecification>, Double> restaurantCurrentQoS = new HashMap<>();//Initial configuration
        restaurantCurrentQoS.put(Availability.class, 0.9);
        restaurantCurrentQoS.put(AverageResponseTime.class, 0.1);
        currentQoSValues.put("RESTAURANT-SERVICE", restaurantCurrentQoS);

        // Ordering //
        List<String> orderingImplementations = List.of("ordering-service");
        serviceImplementations.put("ORDERING-SERVICE", orderingImplementations);

        Map<Class<? extends QoSSpecification>, Double> orderingBenchmark = new HashMap<>();
        orderingBenchmark.put(Availability.class, 0.92);
        orderingBenchmark.put(AverageResponseTime.class, 0.7);
        orderingBenchmark.put(Vulnerability.class, 0.51);
        benchmarkForImplementation.put("ordering-service", orderingBenchmark);

        Map<Class<? extends QoSSpecification>, Double> orderingCurrentQoS = new HashMap<>();
        orderingCurrentQoS.put(Availability.class, 0.92);
        orderingCurrentQoS.put(AverageResponseTime.class, 0.7);
        currentQoSValues.put("ORDERING-SERVICE", orderingCurrentQoS);

        // Delivery //
        List<String> deliveryProxyImplementations = List.of("delivery-proxy-1-service");
        serviceImplementations.put("DELIVERY-PROXY-SERVICE", deliveryProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyBenchmark1 = new HashMap<>();
        deliveryProxyBenchmark1.put(Availability.class, 0.85);
        deliveryProxyBenchmark1.put(AverageResponseTime.class, 0.6);
        deliveryProxyBenchmark1.put(Vulnerability.class, 0.626666667);
        benchmarkForImplementation.put("delivery-proxy-1-service", deliveryProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyCurrentQoS = new HashMap<>();
        deliveryProxyCurrentQoS.put(Availability.class, 0.85);
        deliveryProxyCurrentQoS.put(AverageResponseTime.class, 0.6);
        currentQoSValues.put("DELIVERY-PROXY-SERVICE", deliveryProxyCurrentQoS);

        // Payment //
        List<String> paymentProxyImplementations = List.of("payment-proxy-1-service");
        serviceImplementations.put("PAYMENT-PROXY-SERVICE", paymentProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyBenchmark1 = new HashMap<>();
        paymentProxyBenchmark1.put(Availability.class, 0.9);
        paymentProxyBenchmark1.put(AverageResponseTime.class, 0.9);
        paymentProxyBenchmark1.put(Vulnerability.class, 0.358333333);
        benchmarkForImplementation.put("payment-proxy-1-service", paymentProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyCurrentQoS = new HashMap<>();//Initial configuration
        paymentProxyCurrentQoS.put(Availability.class, 0.9);
        paymentProxyCurrentQoS.put(AverageResponseTime.class, 0.9);
        currentQoSValues.put("PAYMENT-PROXY-SERVICE", paymentProxyCurrentQoS);

        return createServiceMap(availabilityWeight,
                responseTimeWeight,
                vulnerabilityWeight,
                serviceImplementations,
                benchmarkForImplementation,
                currentQoSValues);
    }
    public static Map<String, Service> RQ1_s3_Aqua_ExpConfig(){
        double availabilityWeight = 0.3;
        double responseTimeWeight = 0.3;
        double vulnerabilityWeight = 0.4;
        experiment_num = "rq2_s3-";

        Map<String, List<String>> serviceImplementations = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> benchmarkForImplementation = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> currentQoSValues = new HashMap<>();

        // Restaurant //
        List<String> restaurantImplementations = List.of("restaurant-1-service");
        serviceImplementations.put("RESTAURANT-SERVICE", restaurantImplementations);

        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark1 = new HashMap<>();//option configuration
        restaurantBenchmark1.put(Availability.class, 0.55);
        restaurantBenchmark1.put(AverageResponseTime.class, 1.0);
        restaurantBenchmark1.put(Vulnerability.class, 0.56);
        benchmarkForImplementation.put("restaurant-1-service", restaurantBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> restaurantCurrentQoS = new HashMap<>();//Initial configuration
        restaurantCurrentQoS.put(Availability.class, 0.55);
        restaurantCurrentQoS.put(AverageResponseTime.class, 1.0);
        currentQoSValues.put("RESTAURANT-SERVICE", restaurantCurrentQoS);

        // Ordering //
        List<String> orderingImplementations = List.of("ordering-1-service","ordering-2-service","ordering-3-service", "ordering-4-service");
        serviceImplementations.put("ORDERING-SERVICE", orderingImplementations);

        Map<Class<? extends QoSSpecification>, Double> orderingBenchmark1 = new HashMap<>();
        orderingBenchmark1.put(Availability.class, 0.8);
        orderingBenchmark1.put(AverageResponseTime.class, 0.7);
        orderingBenchmark1.put(Vulnerability.class, 0.673333333);
        benchmarkForImplementation.put("ordering-1-service", orderingBenchmark1);
        Map<Class<? extends QoSSpecification>, Double> orderingBenchmark2 = new HashMap<>();
        orderingBenchmark2.put(Availability.class, 0.88);
        orderingBenchmark2.put(AverageResponseTime.class, 0.7);
        orderingBenchmark2.put(Vulnerability.class, 0.673333333);
        benchmarkForImplementation.put("ordering-2-service", orderingBenchmark2);
        Map<Class<? extends QoSSpecification>, Double> orderingBenchmark3 = new HashMap<>();
        orderingBenchmark3.put(Availability.class, 0.8);
        orderingBenchmark3.put(AverageResponseTime.class, 0.5);
        orderingBenchmark3.put(Vulnerability.class, 0.673333333);
        benchmarkForImplementation.put("ordering-3-service", orderingBenchmark3);
        Map<Class<? extends QoSSpecification>, Double> orderingBenchmark4 = new HashMap<>();
        orderingBenchmark4.put(Availability.class, 0.8);
        orderingBenchmark4.put(AverageResponseTime.class, 0.7);
        orderingBenchmark4.put(Vulnerability.class, 0.368333333);
        benchmarkForImplementation.put("ordering-4-service", orderingBenchmark4);

        Map<Class<? extends QoSSpecification>, Double> orderingCurrentQoS = new HashMap<>();
        orderingCurrentQoS.put(Availability.class, 0.8);
        orderingCurrentQoS.put(AverageResponseTime.class, 0.7);
        currentQoSValues.put("ORDERING-SERVICE", orderingCurrentQoS);

        // Delivery //
        List<String> deliveryProxyImplementations = List.of("delivery-proxy-1-service");
        serviceImplementations.put("DELIVERY-PROXY-SERVICE", deliveryProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyBenchmark1 = new HashMap<>();
        deliveryProxyBenchmark1.put(Availability.class, 0.85);
        deliveryProxyBenchmark1.put(AverageResponseTime.class, 0.6);
        deliveryProxyBenchmark1.put(Vulnerability.class, 0.626666667);
        benchmarkForImplementation.put("delivery-proxy-1-service", deliveryProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyCurrentQoS = new HashMap<>();
        deliveryProxyCurrentQoS.put(Availability.class, 0.85);
        deliveryProxyCurrentQoS.put(AverageResponseTime.class, 0.6);
        currentQoSValues.put("DELIVERY-PROXY-SERVICE", deliveryProxyCurrentQoS);

        // Payment //
        List<String> paymentProxyImplementations = List.of("payment-proxy-1-service");
        serviceImplementations.put("PAYMENT-PROXY-SERVICE", paymentProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyBenchmark1 = new HashMap<>();
        paymentProxyBenchmark1.put(Availability.class, 0.9);
        paymentProxyBenchmark1.put(AverageResponseTime.class, 0.9);
        paymentProxyBenchmark1.put(Vulnerability.class, 0.358333333);
        benchmarkForImplementation.put("payment-proxy-1-service", paymentProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyCurrentQoS = new HashMap<>();//Initial configuration
        paymentProxyCurrentQoS.put(Availability.class, 0.9);
        paymentProxyCurrentQoS.put(AverageResponseTime.class, 0.9);
        currentQoSValues.put("PAYMENT-PROXY-SERVICE", paymentProxyCurrentQoS);

        return createServiceMap(availabilityWeight,
                responseTimeWeight,
                vulnerabilityWeight,
                serviceImplementations,
                benchmarkForImplementation,
                currentQoSValues);
    }
    public static Map<String, Service> RQ1_s4_Aqua_ExpConfig(){
        double availabilityWeight = 0.3;
        double responseTimeWeight = 0.3;
        double vulnerabilityWeight = 0.4;
        experiment_num = "rq2_s4-";

        Map<String, List<String>> serviceImplementations = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> benchmarkForImplementation = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> currentQoSValues = new HashMap<>();

        // Restaurant //
        List<String> restaurantImplementations = List.of("restaurant-1-service");
        serviceImplementations.put("RESTAURANT-SERVICE", restaurantImplementations);

        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark1 = new HashMap<>();//option configuration
        restaurantBenchmark1.put(Availability.class, 0.9);
        restaurantBenchmark1.put(AverageResponseTime.class, 0.1);
        restaurantBenchmark1.put(Vulnerability.class, 0.598333333);
        benchmarkForImplementation.put("restaurant-1-service", restaurantBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> restaurantCurrentQoS = new HashMap<>();//Initial configuration
        restaurantCurrentQoS.put(Availability.class, 0.9);
        restaurantCurrentQoS.put(AverageResponseTime.class, 0.1);
        currentQoSValues.put("RESTAURANT-SERVICE", restaurantCurrentQoS);

        // Ordering //
        List<String> orderingImplementations = List.of("ordering-1-service");
        serviceImplementations.put("ORDERING-SERVICE", orderingImplementations);

        Map<Class<? extends QoSSpecification>, Double> orderingBenchmark1 = new HashMap<>();
        orderingBenchmark1.put(Availability.class, 0.6);
        orderingBenchmark1.put(AverageResponseTime.class, 0.7);
        orderingBenchmark1.put(Vulnerability.class, 0.673333333);
        benchmarkForImplementation.put("ordering-1-service", orderingBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> orderingCurrentQoS = new HashMap<>();
        orderingCurrentQoS.put(Availability.class, 0.6);
        orderingCurrentQoS.put(AverageResponseTime.class, 0.7);
        currentQoSValues.put("ORDERING-SERVICE", orderingCurrentQoS);

        // Delivery //
        List<String> deliveryProxyImplementations = List.of("delivery-proxy-1-service","delivery-proxy-2-service","delivery-proxy-3-service","delivery-proxy-4-service");
        serviceImplementations.put("DELIVERY-PROXY-SERVICE", deliveryProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyBenchmark1 = new HashMap<>();
        deliveryProxyBenchmark1.put(Availability.class, 0.85);
        deliveryProxyBenchmark1.put(AverageResponseTime.class, 0.6);
        deliveryProxyBenchmark1.put(Vulnerability.class, 0.463333333);
        benchmarkForImplementation.put("delivery-proxy-1-service", deliveryProxyBenchmark1);
        Map<Class<? extends QoSSpecification>, Double> deliveryProxyBenchmark2 = new HashMap<>();
        deliveryProxyBenchmark2.put(Availability.class, 0.95);
        deliveryProxyBenchmark2.put(AverageResponseTime.class, 0.6);
        deliveryProxyBenchmark2.put(Vulnerability.class, 0.626666667);
        benchmarkForImplementation.put("delivery-proxy-2-service", deliveryProxyBenchmark2);
        Map<Class<? extends QoSSpecification>, Double> deliveryProxyBenchmark3 = new HashMap<>();
        deliveryProxyBenchmark3.put(Availability.class, 0.85);
        deliveryProxyBenchmark3.put(AverageResponseTime.class, 0.4);
        deliveryProxyBenchmark3.put(Vulnerability.class, 0.626666667);
        benchmarkForImplementation.put("delivery-proxy-3-service", deliveryProxyBenchmark3);
        Map<Class<? extends QoSSpecification>, Double> deliveryProxyBenchmark4 = new HashMap<>();
        deliveryProxyBenchmark4.put(Availability.class, 0.85);
        deliveryProxyBenchmark4.put(AverageResponseTime.class, 0.6);
        deliveryProxyBenchmark4.put(Vulnerability.class, 0.338333333);
        benchmarkForImplementation.put("delivery-proxy-4-service", deliveryProxyBenchmark4);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyCurrentQoS = new HashMap<>();
        deliveryProxyCurrentQoS.put(Availability.class, 0.85);
        deliveryProxyCurrentQoS.put(AverageResponseTime.class, 0.6);
        currentQoSValues.put("DELIVERY-PROXY-SERVICE", deliveryProxyCurrentQoS);

        // Payment //
        List<String> paymentProxyImplementations = List.of("payment-proxy-1-service");
        serviceImplementations.put("PAYMENT-PROXY-SERVICE", paymentProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyBenchmark1 = new HashMap<>();
        paymentProxyBenchmark1.put(Availability.class, 0.5);
        paymentProxyBenchmark1.put(AverageResponseTime.class, 0.8);
        paymentProxyBenchmark1.put(Vulnerability.class, 0.358333333);
        benchmarkForImplementation.put("payment-proxy-1-service", paymentProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyCurrentQoS = new HashMap<>();//Initial configuration
        paymentProxyCurrentQoS.put(Availability.class, 0.5);
        paymentProxyCurrentQoS.put(AverageResponseTime.class, 0.8);
        currentQoSValues.put("PAYMENT-PROXY-SERVICE", paymentProxyCurrentQoS);

        return createServiceMap(availabilityWeight,
                responseTimeWeight,
                vulnerabilityWeight,
                serviceImplementations,
                benchmarkForImplementation,
                currentQoSValues);
    }
    public static Map<String, Service> RQ1_s5_Aqua_ExpConfig(){
        double availabilityWeight = 0.3;
        double responseTimeWeight = 0.3;
        double vulnerabilityWeight = 0.4;
        experiment_num = "rq2_s5-";

        Map<String, List<String>> serviceImplementations = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> benchmarkForImplementation = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> currentQoSValues = new HashMap<>();

        // Restaurant //
        List<String> restaurantImplementations = List.of("restaurant-1-service");
        serviceImplementations.put("RESTAURANT-SERVICE", restaurantImplementations);

        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark1 = new HashMap<>();//option configuration
        restaurantBenchmark1.put(Availability.class, 0.9);
        restaurantBenchmark1.put(AverageResponseTime.class, 0.1);
        restaurantBenchmark1.put(Vulnerability.class, 0.348333333);
        benchmarkForImplementation.put("restaurant-1-service", restaurantBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> restaurantCurrentQoS = new HashMap<>();//Initial configuration
        restaurantCurrentQoS.put(Availability.class, 0.9);
        restaurantCurrentQoS.put(AverageResponseTime.class, 0.1);
        currentQoSValues.put("RESTAURANT-SERVICE", restaurantCurrentQoS);

        // Ordering //
        List<String> orderingImplementations = List.of("ordering-1-service");
        serviceImplementations.put("ORDERING-SERVICE", orderingImplementations);

        Map<Class<? extends QoSSpecification>, Double> orderingBenchmark1 = new HashMap<>();
        orderingBenchmark1.put(Availability.class, 0.92);
        orderingBenchmark1.put(AverageResponseTime.class, 0.7);
        orderingBenchmark1.put(Vulnerability.class, 0.51);
        benchmarkForImplementation.put("ordering-1-service", orderingBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> orderingCurrentQoS = new HashMap<>();
        orderingCurrentQoS.put(Availability.class, 0.92);
        orderingCurrentQoS.put(AverageResponseTime.class, 0.7);
        currentQoSValues.put("ORDERING-SERVICE", orderingCurrentQoS);

        // Delivery //
        List<String> deliveryProxyImplementations = List.of("delivery-proxy-1-service");
        serviceImplementations.put("DELIVERY-PROXY-SERVICE", deliveryProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyBenchmark1 = new HashMap<>();
        deliveryProxyBenchmark1.put(Availability.class, 0.85);
        deliveryProxyBenchmark1.put(AverageResponseTime.class, 0.6);
        deliveryProxyBenchmark1.put(Vulnerability.class, 0.626666667);
        benchmarkForImplementation.put("delivery-proxy-1-service", deliveryProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyCurrentQoS = new HashMap<>();
        deliveryProxyCurrentQoS.put(Availability.class, 0.85);
        deliveryProxyCurrentQoS.put(AverageResponseTime.class, 0.6);
        currentQoSValues.put("DELIVERY-PROXY-SERVICE", deliveryProxyCurrentQoS);

        // Payment //
        List<String> paymentProxyImplementations = List.of("payment-proxy-1-service","payment-proxy-2-service","payment-proxy-3-service","payment-proxy-4-service");
        serviceImplementations.put("PAYMENT-PROXY-SERVICE", paymentProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyBenchmark1 = new HashMap<>();
        paymentProxyBenchmark1.put(Availability.class, 0.9);
        paymentProxyBenchmark1.put(AverageResponseTime.class, 0.9);
        paymentProxyBenchmark1.put(Vulnerability.class, 0.358333333);//
        benchmarkForImplementation.put("payment-proxy-1-service", paymentProxyBenchmark1);
        Map<Class<? extends QoSSpecification>, Double> paymentProxyBenchmark2 = new HashMap<>();
        paymentProxyBenchmark2.put(Availability.class, 0.92);
        paymentProxyBenchmark2.put(AverageResponseTime.class, 1.0);
        paymentProxyBenchmark2.put(Vulnerability.class, 0.685);//
        benchmarkForImplementation.put("payment-proxy-2-service", paymentProxyBenchmark2);
        Map<Class<? extends QoSSpecification>, Double> paymentProxyBenchmark3 = new HashMap<>();
        paymentProxyBenchmark3.put(Availability.class, 0.7);
        paymentProxyBenchmark3.put(AverageResponseTime.class, 0.6);
        paymentProxyBenchmark3.put(Vulnerability.class, 0.685);//
        benchmarkForImplementation.put("payment-proxy-3-service", paymentProxyBenchmark3);
        Map<Class<? extends QoSSpecification>, Double> paymentProxyBenchmark4 = new HashMap<>();
        paymentProxyBenchmark4.put(Availability.class, 0.7);
        paymentProxyBenchmark4.put(AverageResponseTime.class, 1.0);
        paymentProxyBenchmark4.put(Vulnerability.class, 0.233333333);//
        benchmarkForImplementation.put("payment-proxy-4-service", paymentProxyBenchmark4);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyCurrentQoS = new HashMap<>();//Initial configuration
        paymentProxyCurrentQoS.put(Availability.class, 0.9);
        paymentProxyCurrentQoS.put(AverageResponseTime.class, 0.9);
        currentQoSValues.put("PAYMENT-PROXY-SERVICE", paymentProxyCurrentQoS);

        return createServiceMap(availabilityWeight,
                responseTimeWeight,
                vulnerabilityWeight,
                serviceImplementations,
                benchmarkForImplementation,
                currentQoSValues);
    }

    public static Map<String, Service> RQ1_s1_RAMSES_ExpConfig(){
        double availabilityWeight = 0.5;
        double responseTimeWeight = 0.5;
        double vulnerabilityWeight = 0.0;
        experiment_num = "rq2_s1-";

        Map<String, List<String>> serviceImplementations = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> benchmarkForImplementation = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> currentQoSValues = new HashMap<>();

        // Restaurant //
        List<String> restaurantImplementations = List.of("restaurant-1-service","restaurant-2-service","restaurant-3-service");
        serviceImplementations.put("RESTAURANT-SERVICE", restaurantImplementations);

        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark1 = new HashMap<>();//option configuration
        restaurantBenchmark1.put(Availability.class, 0.9);
        restaurantBenchmark1.put(AverageResponseTime.class, 0.1);//50
        restaurantBenchmark1.put(Vulnerability.class, 0.56);//
        benchmarkForImplementation.put("restaurant-1-service", restaurantBenchmark1);
        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark2 = new HashMap<>();
        restaurantBenchmark2.put(Availability.class, 0.93);//0.92
        restaurantBenchmark2.put(AverageResponseTime.class, 0.06);//30
        restaurantBenchmark2.put(Vulnerability.class, 0.311666667);//
        benchmarkForImplementation.put("restaurant-2-service", restaurantBenchmark2);
        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark3 = new HashMap<>();
        restaurantBenchmark3.put(Availability.class, 0.96);
        restaurantBenchmark3.put(AverageResponseTime.class, 0.02);
        restaurantBenchmark3.put(Vulnerability.class, 0.723333333);//
        benchmarkForImplementation.put("restaurant-3-service", restaurantBenchmark3);

        Map<Class<? extends QoSSpecification>, Double> restaurantCurrentQoS = new HashMap<>();//Initial configuration
        restaurantCurrentQoS.put(Availability.class, 0.9);
        restaurantCurrentQoS.put(AverageResponseTime.class, 0.1);
        currentQoSValues.put("RESTAURANT-SERVICE", restaurantCurrentQoS);

        // Ordering //
        List<String> orderingImplementations = List.of("ordering-service");
        serviceImplementations.put("ORDERING-SERVICE", orderingImplementations);

        Map<Class<? extends QoSSpecification>, Double> orderingBenchmark = new HashMap<>();
        orderingBenchmark.put(Availability.class, 0.92);
        orderingBenchmark.put(AverageResponseTime.class, 0.7);
        orderingBenchmark.put(Vulnerability.class, 0.51);
        benchmarkForImplementation.put("ordering-service", orderingBenchmark);

        Map<Class<? extends QoSSpecification>, Double> orderingCurrentQoS = new HashMap<>();
        orderingCurrentQoS.put(Availability.class, 0.92);
        orderingCurrentQoS.put(AverageResponseTime.class, 0.7);
        currentQoSValues.put("ORDERING-SERVICE", orderingCurrentQoS);

        // Delivery //
        List<String> deliveryProxyImplementations = List.of("delivery-proxy-1-service");
        serviceImplementations.put("DELIVERY-PROXY-SERVICE", deliveryProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyBenchmark1 = new HashMap<>();
        deliveryProxyBenchmark1.put(Availability.class, 0.85);
        deliveryProxyBenchmark1.put(AverageResponseTime.class, 0.6);
        deliveryProxyBenchmark1.put(Vulnerability.class, 0.626666667);
        benchmarkForImplementation.put("delivery-proxy-1-service", deliveryProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyCurrentQoS = new HashMap<>();
        deliveryProxyCurrentQoS.put(Availability.class, 0.85);
        deliveryProxyCurrentQoS.put(AverageResponseTime.class, 0.6);
        currentQoSValues.put("DELIVERY-PROXY-SERVICE", deliveryProxyCurrentQoS);

        // Payment //
        List<String> paymentProxyImplementations = List.of("payment-proxy-1-service");
        serviceImplementations.put("PAYMENT-PROXY-SERVICE", paymentProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyBenchmark1 = new HashMap<>();
        paymentProxyBenchmark1.put(Availability.class, 0.9);
        paymentProxyBenchmark1.put(AverageResponseTime.class, 0.9);
        paymentProxyBenchmark1.put(Vulnerability.class, 0.358333333);
        benchmarkForImplementation.put("payment-proxy-1-service", paymentProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyCurrentQoS = new HashMap<>();//Initial configuration
        paymentProxyCurrentQoS.put(Availability.class, 0.9);
        paymentProxyCurrentQoS.put(AverageResponseTime.class, 0.9);
        currentQoSValues.put("PAYMENT-PROXY-SERVICE", paymentProxyCurrentQoS);

        return createServiceMap(availabilityWeight,
                responseTimeWeight,
                vulnerabilityWeight,
                serviceImplementations,
                benchmarkForImplementation,
                currentQoSValues);
    }
    public static Map<String, Service> RQ1_s2_RAMSES_ExpConfig(){
        double availabilityWeight = 0.5;
        double responseTimeWeight = 0.5;
        double vulnerabilityWeight = 0.0;
        experiment_num = "rq2_s2-";

        Map<String, List<String>> serviceImplementations = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> benchmarkForImplementation = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> currentQoSValues = new HashMap<>();

        // Restaurant //
        List<String> restaurantImplementations = List.of("restaurant-1-service","restaurant-2-service","restaurant-3-service");
        serviceImplementations.put("RESTAURANT-SERVICE", restaurantImplementations);

        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark1 = new HashMap<>();//option configuration
        restaurantBenchmark1.put(Availability.class, 0.9);
        restaurantBenchmark1.put(AverageResponseTime.class, 0.1);
        restaurantBenchmark1.put(Vulnerability.class, 0.56);
        benchmarkForImplementation.put("restaurant-1-service", restaurantBenchmark1);
        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark2 = new HashMap<>();
        restaurantBenchmark2.put(Availability.class, 0.95);
        restaurantBenchmark2.put(AverageResponseTime.class, 0.08);
        restaurantBenchmark2.put(Vulnerability.class, 0.213333333);
        benchmarkForImplementation.put("restaurant-2-service", restaurantBenchmark2);
        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark3 = new HashMap<>();
        restaurantBenchmark3.put(Availability.class, 0.98);
        restaurantBenchmark3.put(AverageResponseTime.class, 0.02);
        restaurantBenchmark3.put(Vulnerability.class, 0.386666667);
        benchmarkForImplementation.put("restaurant-3-service", restaurantBenchmark3);

        Map<Class<? extends QoSSpecification>, Double> restaurantCurrentQoS = new HashMap<>();//Initial configuration
        restaurantCurrentQoS.put(Availability.class, 0.9);
        restaurantCurrentQoS.put(AverageResponseTime.class, 0.1);
        currentQoSValues.put("RESTAURANT-SERVICE", restaurantCurrentQoS);

        // Ordering //
        List<String> orderingImplementations = List.of("ordering-service");
        serviceImplementations.put("ORDERING-SERVICE", orderingImplementations);

        Map<Class<? extends QoSSpecification>, Double> orderingBenchmark = new HashMap<>();
        orderingBenchmark.put(Availability.class, 0.92);
        orderingBenchmark.put(AverageResponseTime.class, 0.7);
        orderingBenchmark.put(Vulnerability.class, 0.51);
        benchmarkForImplementation.put("ordering-service", orderingBenchmark);

        Map<Class<? extends QoSSpecification>, Double> orderingCurrentQoS = new HashMap<>();
        orderingCurrentQoS.put(Availability.class, 0.92);
        orderingCurrentQoS.put(AverageResponseTime.class, 0.7);
        currentQoSValues.put("ORDERING-SERVICE", orderingCurrentQoS);

        // Delivery //
        List<String> deliveryProxyImplementations = List.of("delivery-proxy-1-service");
        serviceImplementations.put("DELIVERY-PROXY-SERVICE", deliveryProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyBenchmark1 = new HashMap<>();
        deliveryProxyBenchmark1.put(Availability.class, 0.85);
        deliveryProxyBenchmark1.put(AverageResponseTime.class, 0.6);
        deliveryProxyBenchmark1.put(Vulnerability.class, 0.626666667);
        benchmarkForImplementation.put("delivery-proxy-1-service", deliveryProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyCurrentQoS = new HashMap<>();
        deliveryProxyCurrentQoS.put(Availability.class, 0.85);
        deliveryProxyCurrentQoS.put(AverageResponseTime.class, 0.6);
        currentQoSValues.put("DELIVERY-PROXY-SERVICE", deliveryProxyCurrentQoS);

        // Payment //
        List<String> paymentProxyImplementations = List.of("payment-proxy-1-service");
        serviceImplementations.put("PAYMENT-PROXY-SERVICE", paymentProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyBenchmark1 = new HashMap<>();
        paymentProxyBenchmark1.put(Availability.class, 0.9);
        paymentProxyBenchmark1.put(AverageResponseTime.class, 0.9);
        paymentProxyBenchmark1.put(Vulnerability.class, 0.358333333);
        benchmarkForImplementation.put("payment-proxy-1-service", paymentProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyCurrentQoS = new HashMap<>();//Initial configuration
        paymentProxyCurrentQoS.put(Availability.class, 0.9);
        paymentProxyCurrentQoS.put(AverageResponseTime.class, 0.9);
        currentQoSValues.put("PAYMENT-PROXY-SERVICE", paymentProxyCurrentQoS);

        return createServiceMap(availabilityWeight,
                responseTimeWeight,
                vulnerabilityWeight,
                serviceImplementations,
                benchmarkForImplementation,
                currentQoSValues);
    }
    public static Map<String, Service> RQ1_s3_RAMSES_ExpConfig(){
        double availabilityWeight = 0.5;
        double responseTimeWeight = 0.5;
        double vulnerabilityWeight = 0.0;
        experiment_num = "rq2_s3-";

        Map<String, List<String>> serviceImplementations = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> benchmarkForImplementation = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> currentQoSValues = new HashMap<>();

        // Restaurant //
        List<String> restaurantImplementations = List.of("restaurant-1-service");
        serviceImplementations.put("RESTAURANT-SERVICE", restaurantImplementations);

        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark1 = new HashMap<>();//option configuration
        restaurantBenchmark1.put(Availability.class, 0.55);
        restaurantBenchmark1.put(AverageResponseTime.class, 1.0);
        restaurantBenchmark1.put(Vulnerability.class, 0.56);
        benchmarkForImplementation.put("restaurant-1-service", restaurantBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> restaurantCurrentQoS = new HashMap<>();//Initial configuration
        restaurantCurrentQoS.put(Availability.class, 0.55);
        restaurantCurrentQoS.put(AverageResponseTime.class, 1.0);
        currentQoSValues.put("RESTAURANT-SERVICE", restaurantCurrentQoS);

        // Ordering //
        List<String> orderingImplementations = List.of("ordering-1-service","ordering-2-service","ordering-3-service", "ordering-4-service");
        serviceImplementations.put("ORDERING-SERVICE", orderingImplementations);

        Map<Class<? extends QoSSpecification>, Double> orderingBenchmark1 = new HashMap<>();
        orderingBenchmark1.put(Availability.class, 0.8);
        orderingBenchmark1.put(AverageResponseTime.class, 0.7);
        orderingBenchmark1.put(Vulnerability.class, 0.673333333);
        benchmarkForImplementation.put("ordering-1-service", orderingBenchmark1);
        Map<Class<? extends QoSSpecification>, Double> orderingBenchmark2 = new HashMap<>();
        orderingBenchmark2.put(Availability.class, 0.88);
        orderingBenchmark2.put(AverageResponseTime.class, 0.7);
        orderingBenchmark2.put(Vulnerability.class, 0.673333333);
        benchmarkForImplementation.put("ordering-2-service", orderingBenchmark2);
        Map<Class<? extends QoSSpecification>, Double> orderingBenchmark3 = new HashMap<>();
        orderingBenchmark3.put(Availability.class, 0.8);
        orderingBenchmark3.put(AverageResponseTime.class, 0.5);
        orderingBenchmark3.put(Vulnerability.class, 0.673333333);
        benchmarkForImplementation.put("ordering-3-service", orderingBenchmark3);
        Map<Class<? extends QoSSpecification>, Double> orderingBenchmark4 = new HashMap<>();
        orderingBenchmark4.put(Availability.class, 0.8);
        orderingBenchmark4.put(AverageResponseTime.class, 0.7);
        orderingBenchmark4.put(Vulnerability.class, 0.368333333);
        benchmarkForImplementation.put("ordering-4-service", orderingBenchmark4);

        Map<Class<? extends QoSSpecification>, Double> orderingCurrentQoS = new HashMap<>();
        orderingCurrentQoS.put(Availability.class, 0.8);
        orderingCurrentQoS.put(AverageResponseTime.class, 0.7);
        currentQoSValues.put("ORDERING-SERVICE", orderingCurrentQoS);

        // Delivery //
        List<String> deliveryProxyImplementations = List.of("delivery-proxy-1-service");
        serviceImplementations.put("DELIVERY-PROXY-SERVICE", deliveryProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyBenchmark1 = new HashMap<>();
        deliveryProxyBenchmark1.put(Availability.class, 0.85);
        deliveryProxyBenchmark1.put(AverageResponseTime.class, 0.6);
        deliveryProxyBenchmark1.put(Vulnerability.class, 0.626666667);
        benchmarkForImplementation.put("delivery-proxy-1-service", deliveryProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyCurrentQoS = new HashMap<>();
        deliveryProxyCurrentQoS.put(Availability.class, 0.85);
        deliveryProxyCurrentQoS.put(AverageResponseTime.class, 0.6);
        currentQoSValues.put("DELIVERY-PROXY-SERVICE", deliveryProxyCurrentQoS);

        // Payment //
        List<String> paymentProxyImplementations = List.of("payment-proxy-1-service");
        serviceImplementations.put("PAYMENT-PROXY-SERVICE", paymentProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyBenchmark1 = new HashMap<>();
        paymentProxyBenchmark1.put(Availability.class, 0.9);
        paymentProxyBenchmark1.put(AverageResponseTime.class, 0.9);
        paymentProxyBenchmark1.put(Vulnerability.class, 0.358333333);
        benchmarkForImplementation.put("payment-proxy-1-service", paymentProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyCurrentQoS = new HashMap<>();//Initial configuration
        paymentProxyCurrentQoS.put(Availability.class, 0.9);
        paymentProxyCurrentQoS.put(AverageResponseTime.class, 0.9);
        currentQoSValues.put("PAYMENT-PROXY-SERVICE", paymentProxyCurrentQoS);

        return createServiceMap(availabilityWeight,
                responseTimeWeight,
                vulnerabilityWeight,
                serviceImplementations,
                benchmarkForImplementation,
                currentQoSValues);
    }
    public static Map<String, Service> RQ1_s4_RAMSES_ExpConfig(){
        double availabilityWeight = 0.5;
        double responseTimeWeight = 0.5;
        double vulnerabilityWeight = 0.0;
        experiment_num = "rq2_s4-";

        Map<String, List<String>> serviceImplementations = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> benchmarkForImplementation = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> currentQoSValues = new HashMap<>();

        // Restaurant //
        List<String> restaurantImplementations = List.of("restaurant-1-service");
        serviceImplementations.put("RESTAURANT-SERVICE", restaurantImplementations);

        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark1 = new HashMap<>();//option configuration
        restaurantBenchmark1.put(Availability.class, 0.9);
        restaurantBenchmark1.put(AverageResponseTime.class, 0.1);
        restaurantBenchmark1.put(Vulnerability.class, 0.598333333);
        benchmarkForImplementation.put("restaurant-1-service", restaurantBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> restaurantCurrentQoS = new HashMap<>();//Initial configuration
        restaurantCurrentQoS.put(Availability.class, 0.9);
        restaurantCurrentQoS.put(AverageResponseTime.class, 0.1);
        currentQoSValues.put("RESTAURANT-SERVICE", restaurantCurrentQoS);

        // Ordering //
        List<String> orderingImplementations = List.of("ordering-1-service");
        serviceImplementations.put("ORDERING-SERVICE", orderingImplementations);

        Map<Class<? extends QoSSpecification>, Double> orderingBenchmark1 = new HashMap<>();
        orderingBenchmark1.put(Availability.class, 0.6);
        orderingBenchmark1.put(AverageResponseTime.class, 0.7);
        orderingBenchmark1.put(Vulnerability.class, 0.673333333);
        benchmarkForImplementation.put("ordering-1-service", orderingBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> orderingCurrentQoS = new HashMap<>();
        orderingCurrentQoS.put(Availability.class, 0.6);
        orderingCurrentQoS.put(AverageResponseTime.class, 0.7);
        currentQoSValues.put("ORDERING-SERVICE", orderingCurrentQoS);

        // Delivery //
        List<String> deliveryProxyImplementations = List.of("delivery-proxy-1-service","delivery-proxy-2-service","delivery-proxy-3-service","delivery-proxy-4-service");
        serviceImplementations.put("DELIVERY-PROXY-SERVICE", deliveryProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyBenchmark1 = new HashMap<>();
        deliveryProxyBenchmark1.put(Availability.class, 0.85);
        deliveryProxyBenchmark1.put(AverageResponseTime.class, 0.6);
        deliveryProxyBenchmark1.put(Vulnerability.class, 0.463333333);
        benchmarkForImplementation.put("delivery-proxy-1-service", deliveryProxyBenchmark1);
        Map<Class<? extends QoSSpecification>, Double> deliveryProxyBenchmark2 = new HashMap<>();
        deliveryProxyBenchmark2.put(Availability.class, 0.95);
        deliveryProxyBenchmark2.put(AverageResponseTime.class, 0.6);
        deliveryProxyBenchmark2.put(Vulnerability.class, 0.626666667);
        benchmarkForImplementation.put("delivery-proxy-2-service", deliveryProxyBenchmark2);
        Map<Class<? extends QoSSpecification>, Double> deliveryProxyBenchmark3 = new HashMap<>();
        deliveryProxyBenchmark3.put(Availability.class, 0.85);
        deliveryProxyBenchmark3.put(AverageResponseTime.class, 0.4);
        deliveryProxyBenchmark3.put(Vulnerability.class, 0.626666667);
        benchmarkForImplementation.put("delivery-proxy-3-service", deliveryProxyBenchmark3);
        Map<Class<? extends QoSSpecification>, Double> deliveryProxyBenchmark4 = new HashMap<>();
        deliveryProxyBenchmark4.put(Availability.class, 0.85);
        deliveryProxyBenchmark4.put(AverageResponseTime.class, 0.6);
        deliveryProxyBenchmark4.put(Vulnerability.class, 0.338333333);
        benchmarkForImplementation.put("delivery-proxy-4-service", deliveryProxyBenchmark4);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyCurrentQoS = new HashMap<>();
        deliveryProxyCurrentQoS.put(Availability.class, 0.85);
        deliveryProxyCurrentQoS.put(AverageResponseTime.class, 0.6);
        currentQoSValues.put("DELIVERY-PROXY-SERVICE", deliveryProxyCurrentQoS);

        // Payment //
        List<String> paymentProxyImplementations = List.of("payment-proxy-1-service");
        serviceImplementations.put("PAYMENT-PROXY-SERVICE", paymentProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyBenchmark1 = new HashMap<>();
        paymentProxyBenchmark1.put(Availability.class, 0.5);
        paymentProxyBenchmark1.put(AverageResponseTime.class, 0.8);
        paymentProxyBenchmark1.put(Vulnerability.class, 0.358333333);
        benchmarkForImplementation.put("payment-proxy-1-service", paymentProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyCurrentQoS = new HashMap<>();//Initial configuration
        paymentProxyCurrentQoS.put(Availability.class, 0.5);
        paymentProxyCurrentQoS.put(AverageResponseTime.class, 0.8);
        currentQoSValues.put("PAYMENT-PROXY-SERVICE", paymentProxyCurrentQoS);

        return createServiceMap(availabilityWeight,
                responseTimeWeight,
                vulnerabilityWeight,
                serviceImplementations,
                benchmarkForImplementation,
                currentQoSValues);
    }
    public static Map<String, Service> RQ1_s5_RAMSES_ExpConfig(){
        double availabilityWeight = 0.5;
        double responseTimeWeight = 0.5;
        double vulnerabilityWeight = 0.0;
        experiment_num = "rq2_s5-";

        Map<String, List<String>> serviceImplementations = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> benchmarkForImplementation = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> currentQoSValues = new HashMap<>();

        // Restaurant //
        List<String> restaurantImplementations = List.of("restaurant-1-service");
        serviceImplementations.put("RESTAURANT-SERVICE", restaurantImplementations);

        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark1 = new HashMap<>();//option configuration
        restaurantBenchmark1.put(Availability.class, 0.9);
        restaurantBenchmark1.put(AverageResponseTime.class, 0.1);
        restaurantBenchmark1.put(Vulnerability.class, 0.348333333);
        benchmarkForImplementation.put("restaurant-1-service", restaurantBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> restaurantCurrentQoS = new HashMap<>();//Initial configuration
        restaurantCurrentQoS.put(Availability.class, 0.9);
        restaurantCurrentQoS.put(AverageResponseTime.class, 0.1);
        currentQoSValues.put("RESTAURANT-SERVICE", restaurantCurrentQoS);

        // Ordering //
        List<String> orderingImplementations = List.of("ordering-1-service");
        serviceImplementations.put("ORDERING-SERVICE", orderingImplementations);

        Map<Class<? extends QoSSpecification>, Double> orderingBenchmark1 = new HashMap<>();
        orderingBenchmark1.put(Availability.class, 0.92);
        orderingBenchmark1.put(AverageResponseTime.class, 0.7);
        orderingBenchmark1.put(Vulnerability.class, 0.51);
        benchmarkForImplementation.put("ordering-1-service", orderingBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> orderingCurrentQoS = new HashMap<>();
        orderingCurrentQoS.put(Availability.class, 0.92);
        orderingCurrentQoS.put(AverageResponseTime.class, 0.7);
        currentQoSValues.put("ORDERING-SERVICE", orderingCurrentQoS);

        // Delivery //
        List<String> deliveryProxyImplementations = List.of("delivery-proxy-1-service");
        serviceImplementations.put("DELIVERY-PROXY-SERVICE", deliveryProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyBenchmark1 = new HashMap<>();
        deliveryProxyBenchmark1.put(Availability.class, 0.85);
        deliveryProxyBenchmark1.put(AverageResponseTime.class, 0.6);
        deliveryProxyBenchmark1.put(Vulnerability.class, 0.626666667);
        benchmarkForImplementation.put("delivery-proxy-1-service", deliveryProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyCurrentQoS = new HashMap<>();
        deliveryProxyCurrentQoS.put(Availability.class, 0.85);
        deliveryProxyCurrentQoS.put(AverageResponseTime.class, 0.6);
        currentQoSValues.put("DELIVERY-PROXY-SERVICE", deliveryProxyCurrentQoS);

        // Payment //
        List<String> paymentProxyImplementations = List.of("payment-proxy-1-service","payment-proxy-2-service","payment-proxy-3-service","payment-proxy-4-service");
        serviceImplementations.put("PAYMENT-PROXY-SERVICE", paymentProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyBenchmark1 = new HashMap<>();
        paymentProxyBenchmark1.put(Availability.class, 0.9);
        paymentProxyBenchmark1.put(AverageResponseTime.class, 0.9);
        paymentProxyBenchmark1.put(Vulnerability.class, 0.358333333);//
        benchmarkForImplementation.put("payment-proxy-1-service", paymentProxyBenchmark1);
        Map<Class<? extends QoSSpecification>, Double> paymentProxyBenchmark2 = new HashMap<>();
        paymentProxyBenchmark2.put(Availability.class, 0.92);
        paymentProxyBenchmark2.put(AverageResponseTime.class, 1.0);
        paymentProxyBenchmark2.put(Vulnerability.class, 0.685);//
        benchmarkForImplementation.put("payment-proxy-2-service", paymentProxyBenchmark2);
        Map<Class<? extends QoSSpecification>, Double> paymentProxyBenchmark3 = new HashMap<>();
        paymentProxyBenchmark3.put(Availability.class, 0.7);
        paymentProxyBenchmark3.put(AverageResponseTime.class, 0.6);
        paymentProxyBenchmark3.put(Vulnerability.class, 0.685);//
        benchmarkForImplementation.put("payment-proxy-3-service", paymentProxyBenchmark3);
        Map<Class<? extends QoSSpecification>, Double> paymentProxyBenchmark4 = new HashMap<>();
        paymentProxyBenchmark4.put(Availability.class, 0.7);
        paymentProxyBenchmark4.put(AverageResponseTime.class, 1.0);
        paymentProxyBenchmark4.put(Vulnerability.class, 0.233333333);//
        benchmarkForImplementation.put("payment-proxy-4-service", paymentProxyBenchmark4);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyCurrentQoS = new HashMap<>();//Initial configuration
        paymentProxyCurrentQoS.put(Availability.class, 0.9);
        paymentProxyCurrentQoS.put(AverageResponseTime.class, 0.9);
        currentQoSValues.put("PAYMENT-PROXY-SERVICE", paymentProxyCurrentQoS);

        return createServiceMap(availabilityWeight,
                responseTimeWeight,
                vulnerabilityWeight,
                serviceImplementations,
                benchmarkForImplementation,
                currentQoSValues);
    }

    public static Map<String, Service> RQ2_s1_SAQURE_ExpConfig(){
        double availabilityWeight = 0.3;
        double responseTimeWeight = 0.3;
        double vulnerabilityWeight = 0.4;
        try {
            converter = new ExcelToJsonConverter(FilePathConstants.configuration_rq2_path);
        } catch (Exception e) {
            throw new ExceptionInInitializerError("Failed to initialize Excel converter: " + e.getMessage());
        }
        List<String> cveList_o = (List<String>) converter.getValue("Sub-scenario1", "ORDERING-SERVICE", "Ordering-service", "vulnerabilitylist");
        List<String> cveList_d = (List<String>) converter.getValue("Sub-scenario1", "DELIVERY-PROXY-SERVICE", "Delivery-proxy-1-service", "vulnerabilitylist");
        List<String> cveList_p = (List<String>) converter.getValue("Sub-scenario1", "PAYMENT-PROXY-SERVICE", "Payment-proxy-1-service", "vulnerabilitylist");

        List<String> cveList0 = (List<String>) converter.getValue("Sub-scenario1", "RESTAURANT-SERVICE", "Restaurant-1-service", "vulnerabilitylist");
        cveList0 = Stream.of(cveList0, cveList_o, cveList_d, cveList_p).flatMap(List::stream).collect(Collectors.toList()) ;
        String[] cveIds_s1_r0 = cveList0.toArray(new String[0]);
        List<String> cveList1 = (List<String>) converter.getValue("Sub-scenario1", "RESTAURANT-SERVICE", "Restaurant-2-service", "vulnerabilitylist");
        cveList1 = Stream.of(cveList1, cveList_o, cveList_d, cveList_p).flatMap(List::stream).collect(Collectors.toList());
        String[] cveIds_s1_r1 = cveList1.toArray(new String[0]);
        List<String> cveList2 = (List<String>) converter.getValue("Sub-scenario1", "RESTAURANT-SERVICE", "Restaurant-3-service", "vulnerabilitylist");
        cveList2 = Stream.of(cveList2, cveList_o, cveList_d, cveList_p).flatMap(List::stream).collect(Collectors.toList());
        String[] cveIds_s1_r2 = cveList2.toArray(new String[0]);
        String domainFile_s1_r0 = AED_process(FilePathConstants.AED_path_RQ2 + "RQ2_S1_R0_O0_D0_P0.pddl", cveIds_s1_r0);
        String domainFile_s1_r1 = AED_process(FilePathConstants.AED_path_RQ2 + "RQ2_S1_R1_O0_D0_P0.pddl", cveIds_s1_r1);
        String domainFile_s1_r2 = AED_process(FilePathConstants.AED_path_RQ2 + "RQ2_S1_R2_O0_D0_P0.pddl", cveIds_s1_r2);
        log.info("cveList of Restaurant-1-service: "+ cveList0 + "cveList of Restaurant-2-service: "+ cveList1 + "cveList of Restaurant-3-service: "+ cveList2);

        final double costS1R0 = EADSA.planner_command_compute_RQ2_s1_r0(domainFile_s1_r0);
        final double costS1R1 = EADSA.planner_command_compute_RQ2_s1_r1(domainFile_s1_r1);
        final double costS1R2 = EADSA.planner_command_compute_RQ2_s1_r2(domainFile_s1_r2);
        double[] costValues = {costS1R0, costS1R1, costS1R2, 22.6675, 39.416};
        log.info("Risk of Restaurant-1-service: "+ costS1R0 + "; Risk of Restaurant-2-service: "+ costS1R1 + "; Risk of Restaurant-3-service: "+ costS1R2);
        DynamicNormalize costNormalizer = new DynamicNormalize();
        costNormalizer.preProcessing(costValues);
        final double aS1R0 = (double) converter.getValue("Sub-scenario1", "RESTAURANT-SERVICE", "Restaurant-1-service", "availability");
        final double aS1R1 = (double) converter.getValue("Sub-scenario1", "RESTAURANT-SERVICE", "Restaurant-2-service", "availability");
        final double aS1R2 = (double) converter.getValue("Sub-scenario1", "RESTAURANT-SERVICE", "Restaurant-3-service", "availability");
        final double aS1O0 = (double) converter.getValue("Sub-scenario1", "ORDERING-SERVICE", "Ordering-service", "availability");
        final double aS1D0 = (double) converter.getValue("Sub-scenario1", "DELIVERY-PROXY-SERVICE", "Delivery-proxy-1-service", "availability");
        final double aS1P0 = (double) converter.getValue("Sub-scenario1", "PAYMENT-PROXY-SERVICE", "Payment-proxy-1-service", "availability");
        double[] avalibilities = {aS1R0, aS1R1, aS1R2, aS1O0, aS1D0, aS1P0};
        DynamicNormalize availabilityNormalizer = new DynamicNormalize();
        availabilityNormalizer.preProcessing(avalibilities);
        final int tS1R0 = (int) converter.getValue("Sub-scenario1", "RESTAURANT-SERVICE", "Restaurant-1-service", "responseTime");
        final int tS1R1 = (int) converter.getValue("Sub-scenario1", "RESTAURANT-SERVICE", "Restaurant-2-service", "responseTime");
        final int tS1R2 = (int) converter.getValue("Sub-scenario1", "RESTAURANT-SERVICE", "Restaurant-3-service", "responseTime");
        final int tS1O0 = (int) converter.getValue("Sub-scenario1", "ORDERING-SERVICE", "Ordering-service", "responseTime");
        final int tS1D0 = (int) converter.getValue("Sub-scenario1", "DELIVERY-PROXY-SERVICE", "Delivery-proxy-1-service", "responseTime");
        final int tS1P0 = (int) converter.getValue("Sub-scenario1", "PAYMENT-PROXY-SERVICE", "Payment-proxy-1-service", "responseTime");
        int[] responseTimes = {tS1R0, tS1R1, tS1R2, tS1O0, tS1D0, tS1P0};
        double[] doubleResponseTimes = Arrays.stream(responseTimes).asDoubleStream().toArray();
        DynamicNormalize responseTimeNormalizer = new DynamicNormalize();
        responseTimeNormalizer.preProcessing(doubleResponseTimes);
//        System.out.printf(
//                "Availability (Normalized):\n" +
//                        "  aS1R0: %.2f, aS1R1: %.2f, aS1R2: %.2f," +
//                        "  aS1O0: %.2f, aS1D0: %.2f, aS1P0: %.2f\n" +
//                        "Response Time (Normalized):\n" +
//                        "  tS1R0: %.2f, tS1R1: %.2f, tS1R2: %.2f," +
//                        "  tS1O0: %.2f, tS1D0: %.2f, tS1P0: %.2f\n",
//                aS1R0,//availabilityNormalizer.normalize(aS1R0),
//                aS1R1,//availabilityNormalizer.normalize(aS1R1),
//                aS1R2,//availabilityNormalizer.normalize(aS1R2),
//                aS1O0,//availabilityNormalizer.normalize(aS1O0),
//                aS1D0,//availabilityNormalizer.normalize(aS1D0),
//                aS1P0,//availabilityNormalizer.normalize(aS1P0),
//                responseTimeNormalizer.normalize(tS1R0),
//                responseTimeNormalizer.normalize(tS1R1),
//                responseTimeNormalizer.normalize(tS1R2),
//                responseTimeNormalizer.normalize(tS1O0),
//                responseTimeNormalizer.normalize(tS1D0),
//                responseTimeNormalizer.normalize(tS1P0)
//        );
//        System.out.printf("Cost (Normalized):\n" + " vs1r0: %.2f, vs1r1: %.2f, vs1r2: %.2f ", costNormalizer.normalize(costS1R0), costNormalizer.normalize(costS1R1), costNormalizer.normalize(costS1R2));

        Map<String, List<String>> serviceImplementations = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> benchmarkForImplementation = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> currentQoSValues = new HashMap<>();

        // Restaurant //
        List<String> restaurantImplementations = List.of("restaurant-1-service","restaurant-2-service","restaurant-3-service");
        serviceImplementations.put("RESTAURANT-SERVICE", restaurantImplementations);

        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark1 = new HashMap<>();//option configuration
        restaurantBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS1R0));//0.766666667
        restaurantBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1R0));//0.165306122
        restaurantBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS1R0));//0.633333333
        benchmarkForImplementation.put("restaurant-1-service", restaurantBenchmark1);
        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark2 = new HashMap<>();
        restaurantBenchmark2.put(Availability.class, availabilityNormalizer.normalize(aS1R1));//0.92
        restaurantBenchmark2.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1R1));//0.132653061
        restaurantBenchmark2.put(Vulnerability.class, costNormalizer.normalize(costS1R1));//0.227891156
        benchmarkForImplementation.put("restaurant-2-service", restaurantBenchmark2);
        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark3 = new HashMap<>();
        restaurantBenchmark3.put(Availability.class, availabilityNormalizer.normalize(aS1R2));
        restaurantBenchmark3.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1R2));//0.1
        restaurantBenchmark3.put(Vulnerability.class, costNormalizer.normalize(costS1R2));//0.9
        benchmarkForImplementation.put("restaurant-3-service", restaurantBenchmark3);

        Map<Class<? extends QoSSpecification>, Double> restaurantCurrentQoS = new HashMap<>();//Initial configuration
        restaurantCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS1R0));
        restaurantCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1R0));
        currentQoSValues.put("RESTAURANT-SERVICE", restaurantCurrentQoS);

        // Ordering //
        List<String> orderingImplementations = List.of("ordering-service");
        serviceImplementations.put("ORDERING-SERVICE", orderingImplementations);

        Map<Class<? extends QoSSpecification>, Double> orderingBenchmark = new HashMap<>();
        orderingBenchmark.put(Availability.class, availabilityNormalizer.normalize(aS1O0));//0.8
        orderingBenchmark.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1O0));//0.655102041
        orderingBenchmark.put(Vulnerability.class, costNormalizer.normalize(costS1R0));
        benchmarkForImplementation.put("ordering-service", orderingBenchmark);

        Map<Class<? extends QoSSpecification>, Double> orderingCurrentQoS = new HashMap<>();
        orderingCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS1O0));
        orderingCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1O0));
        currentQoSValues.put("ORDERING-SERVICE", orderingCurrentQoS);

        // Delivery //
        List<String> deliveryProxyImplementations = List.of("delivery-proxy-1-service");
        serviceImplementations.put("DELIVERY-PROXY-SERVICE", deliveryProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyBenchmark1 = new HashMap<>();
        deliveryProxyBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS1D0));//0.683333333
        deliveryProxyBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1D0));//0.573469388
        deliveryProxyBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS1R0));
        benchmarkForImplementation.put("delivery-proxy-1-service", deliveryProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyCurrentQoS = new HashMap<>();
        deliveryProxyCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS1D0));
        deliveryProxyCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1D0));
        currentQoSValues.put("DELIVERY-PROXY-SERVICE", deliveryProxyCurrentQoS);

        // Payment //
        List<String> paymentProxyImplementations = List.of("payment-proxy-1-service");
        serviceImplementations.put("PAYMENT-PROXY-SERVICE", paymentProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyBenchmark1 = new HashMap<>();
        paymentProxyBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS1P0));//0.766666667
        paymentProxyBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1P0));//0.818367347
        paymentProxyBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS1R0));
        benchmarkForImplementation.put("payment-proxy-1-service", paymentProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyCurrentQoS = new HashMap<>();//Initial configuration
        paymentProxyCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS1P0));
        paymentProxyCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1P0));
        currentQoSValues.put("PAYMENT-PROXY-SERVICE", paymentProxyCurrentQoS);

        return createServiceMap(availabilityWeight,
                responseTimeWeight,
                vulnerabilityWeight,
                serviceImplementations,
                benchmarkForImplementation,
                currentQoSValues);
    }
    public static Map<String, Service> RQ2_s2_SAQURE_ExpConfig(){
        double availabilityWeight = 0.3;
        double responseTimeWeight = 0.3;
        double vulnerabilityWeight = 0.4;
        try {
            converter = new ExcelToJsonConverter(FilePathConstants.configuration_rq2_path);
        } catch (Exception e) {
            throw new ExceptionInInitializerError("Failed to initialize Excel converter: " + e.getMessage());
        }
        List<String> cveList_r = (List<String>) converter.getValue("Sub-scenario2", "RESTAURANT-SERVICE", "Restaurant-service", "vulnerabilitylist");
        List<String> cveList_o = (List<String>) converter.getValue("Sub-scenario2", "ORDERING-SERVICE", "Ordering-service", "vulnerabilitylist");
        List<String> cveList_d = (List<String>) converter.getValue("Sub-scenario2", "DELIVERY-PROXY-SERVICE", "Delivery-proxy-1-service", "vulnerabilitylist");

        List<String> cveList0 = (List<String>) converter.getValue("Sub-scenario2", "PAYMENT-PROXY-SERVICE", "Payment-proxy-1-service", "vulnerabilitylist");
        cveList0 = Stream.of(cveList0, cveList_r, cveList_o, cveList_d).flatMap(List::stream).collect(Collectors.toList()) ;
        String[] cveIds_s2_p0 = cveList0.toArray(new String[0]);
        List<String> cveList1 = (List<String>) converter.getValue("Sub-scenario2", "PAYMENT-PROXY-SERVICE", "Payment-proxy-2-service", "vulnerabilitylist");
        cveList1 = Stream.of(cveList1, cveList_r, cveList_o, cveList_d).flatMap(List::stream).collect(Collectors.toList()) ;
        String[] cveIds_s2_p1 = cveList1.toArray(new String[0]);
        List<String> cveList2 = (List<String>) converter.getValue("Sub-scenario2", "PAYMENT-PROXY-SERVICE", "Payment-proxy-3-service", "vulnerabilitylist");
        cveList2 = Stream.of(cveList2, cveList_r, cveList_o, cveList_d).flatMap(List::stream).collect(Collectors.toList()) ;
        String[] cveIds_s2_p2 = cveList2.toArray(new String[0]);
        String domainFile_s2_p0 = AED_process(FilePathConstants.AED_path_RQ2 + "RQ2_S2_R0_O0_D0_P0.pddl", cveIds_s2_p0);
        String domainFile_s2_p1 = AED_process(FilePathConstants.AED_path_RQ2 + "RQ2_S2_R0_O0_D0_P1.pddl", cveIds_s2_p1);
        String domainFile_s2_p2 = AED_process(FilePathConstants.AED_path_RQ2 + "RQ2_S2_R0_O0_D0_P2.pddl", cveIds_s2_p2);

        final double costS5P0 = EADSA.planner_command_compute_RQ2_s2_p0(domainFile_s2_p0);
        final double costS5P1 = EADSA.planner_command_compute_RQ2_s2_p1(domainFile_s2_p1);
        final double costS5P2 = EADSA.planner_command_compute_RQ2_s2_p2(domainFile_s2_p2); //改名：risk_value
        double[] costValues = {costS5P0, costS5P1, costS5P2, 27.632, 15.1675};
        log.info("Risk of Payment-proxy-1-service: "+ costS5P0 + "; Risk of Payment-proxy-2-service: "+ costS5P1 + "; Risk of Payment-proxy-3-service: "+ costS5P2);
        DynamicNormalize costNormalizer = new DynamicNormalize();
        costNormalizer.preProcessing(costValues);
        final double aS5R0 = (double) converter.getValue("Sub-scenario2", "RESTAURANT-SERVICE", "Restaurant-service", "availability");
        final double aS5O0 = (double) converter.getValue("Sub-scenario2", "ORDERING-SERVICE", "Ordering-service", "availability");
        final double aS5D0 = (double) converter.getValue("Sub-scenario2", "DELIVERY-PROXY-SERVICE", "Delivery-proxy-1-service", "availability");
        final double aS5P0 = (double) converter.getValue("Sub-scenario2", "PAYMENT-PROXY-SERVICE", "Payment-proxy-1-service", "availability");
        final double aS5P1 = (double) converter.getValue("Sub-scenario2", "PAYMENT-PROXY-SERVICE", "Payment-proxy-2-service", "availability");
        final double aS5P2 = (double) converter.getValue("Sub-scenario2", "PAYMENT-PROXY-SERVICE", "Payment-proxy-3-service", "availability");
        double[] avalibilities = {aS5R0, aS5O0, aS5D0, aS5P0, aS5P1, aS5P2};
        DynamicNormalize availabilityNormalizer = new DynamicNormalize();
        availabilityNormalizer.preProcessing(avalibilities);
        final int tS5R0 = (int) converter.getValue("Sub-scenario2", "RESTAURANT-SERVICE", "Restaurant-service", "responseTime");
        final int tS5O0 = (int) converter.getValue("Sub-scenario2", "ORDERING-SERVICE", "Ordering-service", "responseTime");
        final int tS5D0 = (int) converter.getValue("Sub-scenario2", "DELIVERY-PROXY-SERVICE", "Delivery-proxy-1-service", "responseTime");
        final int tS5P0 = (int) converter.getValue("Sub-scenario2", "PAYMENT-PROXY-SERVICE", "Payment-proxy-1-service", "responseTime");
        final int tS5P1 = (int) converter.getValue("Sub-scenario2", "PAYMENT-PROXY-SERVICE", "Payment-proxy-2-service", "responseTime");
        final int tS5P2 = (int) converter.getValue("Sub-scenario2", "PAYMENT-PROXY-SERVICE", "Payment-proxy-3-service", "responseTime");
        int[] responseTimes = {tS5R0, tS5O0, tS5D0, tS5P0, tS5P1, tS5P2};
        double[] doubleResponseTimes = Arrays.stream(responseTimes).asDoubleStream().toArray();
        DynamicNormalize responseTimeNormalizer = new DynamicNormalize();
        responseTimeNormalizer.preProcessing(doubleResponseTimes);

        Map<String, List<String>> serviceImplementations = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> benchmarkForImplementation = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> currentQoSValues = new HashMap<>();

        // Restaurant //
        List<String> restaurantImplementations = List.of("restaurant-1-service");
        serviceImplementations.put("RESTAURANT-SERVICE", restaurantImplementations);

        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark1 = new HashMap<>();//option configuration
        restaurantBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS5R0));//0.766666667
        restaurantBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS5R0));//0.165306122
        restaurantBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS5P0));
        benchmarkForImplementation.put("restaurant-1-service", restaurantBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> restaurantCurrentQoS = new HashMap<>();//Initial configuration
        restaurantCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS5R0));
        restaurantCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS5R0));
        currentQoSValues.put("RESTAURANT-SERVICE", restaurantCurrentQoS);

        // Ordering //
        List<String> orderingImplementations = List.of("ordering-1-service");
        serviceImplementations.put("ORDERING-SERVICE", orderingImplementations);

        Map<Class<? extends QoSSpecification>, Double> orderingBenchmark1 = new HashMap<>();
        orderingBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS5O0));//0.8
        orderingBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS5O0));//0.655102041
        orderingBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS5P0));
        benchmarkForImplementation.put("ordering-1-service", orderingBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> orderingCurrentQoS = new HashMap<>();
        orderingCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS5O0));
        orderingCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS5O0));
        currentQoSValues.put("ORDERING-SERVICE", orderingCurrentQoS);

        // Delivery //
        List<String> deliveryProxyImplementations = List.of("delivery-proxy-1-service");
        serviceImplementations.put("DELIVERY-PROXY-SERVICE", deliveryProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyBenchmark1 = new HashMap<>();
        deliveryProxyBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS5D0));//0.683333333
        deliveryProxyBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS5D0));//0.655102041
        deliveryProxyBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS5P0));
        benchmarkForImplementation.put("delivery-proxy-1-service", deliveryProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyCurrentQoS = new HashMap<>();
        deliveryProxyCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS5D0));
        deliveryProxyCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS5D0));
        currentQoSValues.put("DELIVERY-PROXY-SERVICE", deliveryProxyCurrentQoS);

        // Payment //
        List<String> paymentProxyImplementations = List.of("payment-proxy-1-service","payment-proxy-2-service","payment-proxy-3-service");
        serviceImplementations.put("PAYMENT-PROXY-SERVICE", paymentProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyBenchmark1 = new HashMap<>();
        paymentProxyBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS5P0));//0.766666667
        paymentProxyBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS5P0));//0.818367347
        paymentProxyBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS5P0));//
        benchmarkForImplementation.put("payment-proxy-1-service", paymentProxyBenchmark1);
        Map<Class<? extends QoSSpecification>, Double> paymentProxyBenchmark2 = new HashMap<>();
        paymentProxyBenchmark2.put(Availability.class, availabilityNormalizer.normalize(aS5P1));//0.8
        paymentProxyBenchmark2.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS5P1));//0.9
        paymentProxyBenchmark2.put(Vulnerability.class, costNormalizer.normalize(costS5P1));//
        benchmarkForImplementation.put("payment-proxy-2-service", paymentProxyBenchmark2);
        Map<Class<? extends QoSSpecification>, Double> paymentProxyBenchmark3 = new HashMap<>();
        paymentProxyBenchmark3.put(Availability.class, availabilityNormalizer.normalize(aS5P2));//0.433333333
        paymentProxyBenchmark3.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS5P2));//0.573469388
        paymentProxyBenchmark3.put(Vulnerability.class, costNormalizer.normalize(costS5P2));//
        benchmarkForImplementation.put("payment-proxy-3-service", paymentProxyBenchmark3);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyCurrentQoS = new HashMap<>();//Initial configuration
        paymentProxyCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS5P0));
        paymentProxyCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS5P0));
        currentQoSValues.put("PAYMENT-PROXY-SERVICE", paymentProxyCurrentQoS);

        return createServiceMap(availabilityWeight,
                responseTimeWeight,
                vulnerabilityWeight,
                serviceImplementations,
                benchmarkForImplementation,
                currentQoSValues);
    }
    public static Map<String, Service> RQ2_s3_SAQURE_ExpConfig(){
        double availabilityWeight = 0.3;
        double responseTimeWeight = 0.3;
        double vulnerabilityWeight = 0.4;
        try {
            converter = new ExcelToJsonConverter(FilePathConstants.configuration_rq2_path);
        } catch (Exception e) {
            throw new ExceptionInInitializerError("Failed to initialize Excel converter: " + e.getMessage());
        }
        List<String> cveList_r = (List<String>) converter.getValue("Sub-scenario3", "RESTAURANT-SERVICE", "Restaurant-service", "vulnerabilitylist");
        List<String> cveList_d = (List<String>) converter.getValue("Sub-scenario3", "DELIVERY-PROXY-SERVICE", "Delivery-proxy-1-service", "vulnerabilitylist");
        List<String> cveList_p = (List<String>) converter.getValue("Sub-scenario3", "PAYMENT-PROXY-SERVICE", "Payment-proxy-1-service", "vulnerabilitylist");

        List<String> cveList0 = (List<String>) converter.getValue("Sub-scenario3", "ORDERING-SERVICE", "Ordering-1-service", "vulnerabilitylist");
        cveList0 = Stream.of(cveList0, cveList_r, cveList_d, cveList_p).flatMap(List::stream).collect(Collectors.toList()) ;
        String[] cveIds_s3_O0 = cveList0.toArray(new String[0]);
        List<String> cveList1 = (List<String>) converter.getValue("Sub-scenario3", "ORDERING-SERVICE", "Ordering-2-service", "vulnerabilitylist");
        cveList1 = Stream.of(cveList1, cveList_r, cveList_d, cveList_p).flatMap(List::stream).collect(Collectors.toList()) ;
        String[] cveIds_s3_O1 = cveList1.toArray(new String[0]);
        List<String> cveList2 = (List<String>) converter.getValue("Sub-scenario3", "ORDERING-SERVICE", "Ordering-3-service", "vulnerabilitylist");
        cveList2 = Stream.of(cveList2, cveList_r, cveList_d, cveList_p).flatMap(List::stream).collect(Collectors.toList()) ;
        String[] cveIds_s3_O2 = cveList2.toArray(new String[0]);
        log.info("cve of ordering-1-service: "+ cveList0 + "; cve of ordering-2-service: "+ cveList1 + "; cve of ordering-3-service: "+ cveList2);

        String domainFile_s3_O0 = AED_process(FilePathConstants.AED_path_RQ2 + "RQ2_S3_R0_O0_D0_P0.pddl", cveIds_s3_O0);
        String domainFile_s3_O1 = AED_process(FilePathConstants.AED_path_RQ2 + "RQ2_S3_R0_O1_D0_P0.pddl", cveIds_s3_O1);
        String domainFile_s3_O2 = AED_process(FilePathConstants.AED_path_RQ2 + "RQ2_S3_R0_O2_D0_P0.pddl", cveIds_s3_O2);

        final double costS3O0 = EADSA.planner_command_compute_RQ2_s2_o0(domainFile_s3_O0);
        final double costS3O1 = EADSA.planner_command_compute_RQ2_s2_o1(domainFile_s3_O1);
        final double costS3O2 = EADSA.planner_command_compute_RQ2_s2_o2(domainFile_s3_O2);
        double[] costValues = {costS3O0, costS3O1, costS3O2, 22.6, 39.416}; // Add the MAX and MIN of both of the two sets at T1 and T2
        log.info("Risk of ordering-1-service: "+ costS3O0 + "; Risk of ordering-2-service: "+ costS3O1 + "; Risk of ordering-3-service: "+ costS3O2);
        DynamicNormalize costNormalizer = new DynamicNormalize();
        costNormalizer.preProcessing(costValues);
        final double aS3R0 = (double) converter.getValue("Sub-scenario3", "RESTAURANT-SERVICE", "Restaurant-service", "availability");
        final double aS3O0 = (double) converter.getValue("Sub-scenario3", "ORDERING-SERVICE", "Ordering-1-service", "availability");
        final double aS3O1 = (double) converter.getValue("Sub-scenario3", "ORDERING-SERVICE", "Ordering-2-service", "availability");
        final double aS3O2 = (double) converter.getValue("Sub-scenario3", "ORDERING-SERVICE", "Ordering-3-service", "availability");
        final double aS3D0 = (double) converter.getValue("Sub-scenario3", "DELIVERY-PROXY-SERVICE", "Delivery-proxy-1-service", "availability");
        final double aS3P0 = (double) converter.getValue("Sub-scenario3", "PAYMENT-PROXY-SERVICE", "Payment-proxy-1-service", "availability");
        double[] avalibilities = {aS3R0, aS3O0, aS3O1, aS3O2, aS3D0, aS3P0};
        DynamicNormalize availabilityNormalizer = new DynamicNormalize();
        availabilityNormalizer.preProcessing(avalibilities);
        final int tS3R0 = (int) converter.getValue("Sub-scenario3", "RESTAURANT-SERVICE", "Restaurant-service", "responseTime");
        final int tS3O0 = (int) converter.getValue("Sub-scenario3", "ORDERING-SERVICE", "Ordering-1-service", "responseTime");
        final int tS3O1 = (int) converter.getValue("Sub-scenario3", "ORDERING-SERVICE", "Ordering-2-service", "responseTime");
        final int tS3O2 = (int) converter.getValue("Sub-scenario3", "ORDERING-SERVICE", "Ordering-3-service", "responseTime");
        final int tS3D0 = (int) converter.getValue("Sub-scenario3", "DELIVERY-PROXY-SERVICE", "Delivery-proxy-1-service", "responseTime");
        final int tS3P0 = (int) converter.getValue("Sub-scenario3", "PAYMENT-PROXY-SERVICE", "Payment-proxy-1-service", "responseTime");
        int[] responseTimes = {tS3R0, tS3O0, tS3O1, tS3O2, tS3D0, tS3P0};
        double[] doubleResponseTimes = Arrays.stream(responseTimes).asDoubleStream().toArray();
        DynamicNormalize responseTimeNormalizer = new DynamicNormalize();
        responseTimeNormalizer.preProcessing(doubleResponseTimes);
        Map<String, List<String>> serviceImplementations = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> benchmarkForImplementation = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> currentQoSValues = new HashMap<>();

        // Restaurant //
        List<String> restaurantImplementations = List.of("restaurant-1-service");
        serviceImplementations.put("RESTAURANT-SERVICE", restaurantImplementations);

        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark1 = new HashMap<>();//option configuration
        restaurantBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS3R0));//0.183333333
        restaurantBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS3R0));//0.9
        restaurantBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS3O0));
        benchmarkForImplementation.put("restaurant-1-service", restaurantBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> restaurantCurrentQoS = new HashMap<>();//Initial configuration
        restaurantCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS3R0));
        restaurantCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS3R0));
        currentQoSValues.put("RESTAURANT-SERVICE", restaurantCurrentQoS);

        // Ordering //
        List<String> orderingImplementations = List.of("ordering-1-service","ordering-2-service","ordering-3-service");
        serviceImplementations.put("ORDERING-SERVICE", orderingImplementations);

        Map<Class<? extends QoSSpecification>, Double> orderingBenchmark1 = new HashMap<>();
        orderingBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS3O0));//0.6
        orderingBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS3O0));//0.655102041
        orderingBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS3O0));
        benchmarkForImplementation.put("ordering-1-service", orderingBenchmark1);
        Map<Class<? extends QoSSpecification>, Double> orderingBenchmark2 = new HashMap<>();
        orderingBenchmark2.put(Availability.class, availabilityNormalizer.normalize(aS3O1));//0.733333333
        orderingBenchmark2.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS3O1));//0.655102041
        orderingBenchmark2.put(Vulnerability.class, costNormalizer.normalize(costS3O1));
        benchmarkForImplementation.put("ordering-2-service", orderingBenchmark2);
        Map<Class<? extends QoSSpecification>, Double> orderingBenchmark3 = new HashMap<>();
        orderingBenchmark3.put(Availability.class, availabilityNormalizer.normalize(aS3O2));//0.6
        orderingBenchmark3.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS3O2));//0.491836735
        orderingBenchmark3.put(Vulnerability.class, costNormalizer.normalize(costS3O2));
        benchmarkForImplementation.put("ordering-3-service", orderingBenchmark3);

        Map<Class<? extends QoSSpecification>, Double> orderingCurrentQoS = new HashMap<>();
        orderingCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS3O0));
        orderingCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS3O0));
        currentQoSValues.put("ORDERING-SERVICE", orderingCurrentQoS);

        // Delivery //
        List<String> deliveryProxyImplementations = List.of("delivery-proxy-1-service");
        serviceImplementations.put("DELIVERY-PROXY-SERVICE", deliveryProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyBenchmark1 = new HashMap<>();
        deliveryProxyBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS3D0));
        deliveryProxyBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS3D0));
        deliveryProxyBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS3O0));
        benchmarkForImplementation.put("delivery-proxy-1-service", deliveryProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyCurrentQoS = new HashMap<>();
        deliveryProxyCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS3D0));
        deliveryProxyCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS3D0));
        currentQoSValues.put("DELIVERY-PROXY-SERVICE", deliveryProxyCurrentQoS);

        // Payment //
        List<String> paymentProxyImplementations = List.of("payment-proxy-1-service");
        serviceImplementations.put("PAYMENT-PROXY-SERVICE", paymentProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyBenchmark1 = new HashMap<>();
        paymentProxyBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS3P0));//0.766666667
        paymentProxyBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS3P0));//0.818367347
        paymentProxyBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS3O0));
        benchmarkForImplementation.put("payment-proxy-1-service", paymentProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyCurrentQoS = new HashMap<>();//Initial configuration
        paymentProxyCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS3P0));
        paymentProxyCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS3P0));
        currentQoSValues.put("PAYMENT-PROXY-SERVICE", paymentProxyCurrentQoS);

        return createServiceMap(availabilityWeight,
                responseTimeWeight,
                vulnerabilityWeight,
                serviceImplementations,
                benchmarkForImplementation,
                currentQoSValues);
    }

    public static Map<String, Service> RQ2_s1_SAQURE_nodyPa_ExpConfig(){
        EADSA.IS_DEFAULT = false;
        double availabilityWeight = 0.3;
        double responseTimeWeight = 0.3;
        double vulnerabilityWeight = 0.4;
        try {
            converter = new ExcelToJsonConverter(FilePathConstants.configuration_rq2_path);
        } catch (Exception e) {
            throw new ExceptionInInitializerError("Failed to initialize Excel converter: " + e.getMessage());
        }
        List<String> cveList_o = (List<String>) converter.getValue("Sub-scenario1", "ORDERING-SERVICE", "Ordering-service", "vulnerabilitylist");
        List<String> cveList_d = (List<String>) converter.getValue("Sub-scenario1", "DELIVERY-PROXY-SERVICE", "Delivery-proxy-1-service", "vulnerabilitylist");
        List<String> cveList_p = (List<String>) converter.getValue("Sub-scenario1", "PAYMENT-PROXY-SERVICE", "Payment-proxy-1-service", "vulnerabilitylist");

        List<String> cveList0 = (List<String>) converter.getValue("Sub-scenario1", "RESTAURANT-SERVICE", "Restaurant-1-service", "vulnerabilitylist");
        cveList0 = Stream.of(cveList0, cveList_o, cveList_d, cveList_p).flatMap(List::stream).collect(Collectors.toList()) ;
        String[] cveIds_s1_r0 = cveList0.toArray(new String[0]);
        List<String> cveList1 = (List<String>) converter.getValue("Sub-scenario1", "RESTAURANT-SERVICE", "Restaurant-2-service", "vulnerabilitylist");
        cveList1 = Stream.of(cveList1, cveList_o, cveList_d, cveList_p).flatMap(List::stream).collect(Collectors.toList());
        String[] cveIds_s1_r1 = cveList1.toArray(new String[0]);
        List<String> cveList2 = (List<String>) converter.getValue("Sub-scenario1", "RESTAURANT-SERVICE", "Restaurant-3-service", "vulnerabilitylist");
        cveList2 = Stream.of(cveList2, cveList_o, cveList_d, cveList_p).flatMap(List::stream).collect(Collectors.toList());
        String[] cveIds_s1_r2 = cveList2.toArray(new String[0]);
        String domainFile_s1_r0 = AED_process_nodyPa(FilePathConstants.AED_path_RQ2 + "RQ2_S1_R0_O0_D0_P0.pddl", cveIds_s1_r0);
        String domainFile_s1_r1 = AED_process_nodyPa(FilePathConstants.AED_path_RQ2 + "RQ2_S1_R1_O0_D0_P0.pddl", cveIds_s1_r1);
        String domainFile_s1_r2 = AED_process_nodyPa(FilePathConstants.AED_path_RQ2 + "RQ2_S1_R2_O0_D0_P0.pddl", cveIds_s1_r2);

        final double costS1R0 = EADSA.planner_command_compute_RQ2_s1_r0(domainFile_s1_r0);
        final double costS1R1 = EADSA.planner_command_compute_RQ2_s1_r1(domainFile_s1_r1);
        final double costS1R2 = EADSA.planner_command_compute_RQ2_s1_r2(domainFile_s1_r2);
        double[] costValues = {costS1R0, costS1R1, costS1R2, 37.400000000000006, 44.3};
        log.info("Risk of Restaurant-1-service: "+ costS1R0 + "; Risk of Restaurant-2-service: "+ costS1R1 + "; Risk of Restaurant-3-service: "+ costS1R2);
        DynamicNormalize costNormalizer = new DynamicNormalize();
        costNormalizer.preProcessing(costValues);
        final double aS1R0 = (double) converter.getValue("Sub-scenario1", "RESTAURANT-SERVICE", "Restaurant-1-service", "availability");
        final double aS1R1 = (double) converter.getValue("Sub-scenario1", "RESTAURANT-SERVICE", "Restaurant-2-service", "availability");
        final double aS1R2 = (double) converter.getValue("Sub-scenario1", "RESTAURANT-SERVICE", "Restaurant-3-service", "availability");
        final double aS1O0 = (double) converter.getValue("Sub-scenario1", "ORDERING-SERVICE", "Ordering-service", "availability");
        final double aS1D0 = (double) converter.getValue("Sub-scenario1", "DELIVERY-PROXY-SERVICE", "Delivery-proxy-1-service", "availability");
        final double aS1P0 = (double) converter.getValue("Sub-scenario1", "PAYMENT-PROXY-SERVICE", "Payment-proxy-1-service", "availability");
        double[] avalibilities = {aS1R0, aS1R1, aS1R2, aS1O0, aS1D0, aS1P0};
        DynamicNormalize availabilityNormalizer = new DynamicNormalize();
        availabilityNormalizer.preProcessing(avalibilities);
        final int tS1R0 = (int) converter.getValue("Sub-scenario1", "RESTAURANT-SERVICE", "Restaurant-1-service", "responseTime");
        final int tS1R1 = (int) converter.getValue("Sub-scenario1", "RESTAURANT-SERVICE", "Restaurant-2-service", "responseTime");
        final int tS1R2 = (int) converter.getValue("Sub-scenario1", "RESTAURANT-SERVICE", "Restaurant-3-service", "responseTime");
        final int tS1O0 = (int) converter.getValue("Sub-scenario1", "ORDERING-SERVICE", "Ordering-service", "responseTime");
        final int tS1D0 = (int) converter.getValue("Sub-scenario1", "DELIVERY-PROXY-SERVICE", "Delivery-proxy-1-service", "responseTime");
        final int tS1P0 = (int) converter.getValue("Sub-scenario1", "PAYMENT-PROXY-SERVICE", "Payment-proxy-1-service", "responseTime");
        int[] responseTimes = {tS1R0, tS1R1, tS1R2, tS1O0, tS1D0, tS1P0};
        double[] doubleResponseTimes = Arrays.stream(responseTimes).asDoubleStream().toArray();
        DynamicNormalize responseTimeNormalizer = new DynamicNormalize();
        responseTimeNormalizer.preProcessing(doubleResponseTimes);

        Map<String, List<String>> serviceImplementations = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> benchmarkForImplementation = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> currentQoSValues = new HashMap<>();

        // Restaurant //
        List<String> restaurantImplementations = List.of("restaurant-1-service","restaurant-2-service","restaurant-3-service");
        serviceImplementations.put("RESTAURANT-SERVICE", restaurantImplementations);

        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark1 = new HashMap<>();//option configuration
        restaurantBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS1R0));//0.766666667
        restaurantBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1R0));//0.165306122
        restaurantBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS1R0));//0.633333333
        benchmarkForImplementation.put("restaurant-1-service", restaurantBenchmark1);
        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark2 = new HashMap<>();
        restaurantBenchmark2.put(Availability.class, availabilityNormalizer.normalize(aS1R1));//0.92
        restaurantBenchmark2.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1R1));//0.132653061
        restaurantBenchmark2.put(Vulnerability.class, costNormalizer.normalize(costS1R1));//0.227891156
        benchmarkForImplementation.put("restaurant-2-service", restaurantBenchmark2);
        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark3 = new HashMap<>();
        restaurantBenchmark3.put(Availability.class, availabilityNormalizer.normalize(aS1R2));
        restaurantBenchmark3.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1R2));//0.1
        restaurantBenchmark3.put(Vulnerability.class, costNormalizer.normalize(costS1R2));//0.9
        benchmarkForImplementation.put("restaurant-3-service", restaurantBenchmark3);

        Map<Class<? extends QoSSpecification>, Double> restaurantCurrentQoS = new HashMap<>();//Initial configuration
        restaurantCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS1R0));
        restaurantCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1R0));
        currentQoSValues.put("RESTAURANT-SERVICE", restaurantCurrentQoS);

        // Ordering //
        List<String> orderingImplementations = List.of("ordering-service");
        serviceImplementations.put("ORDERING-SERVICE", orderingImplementations);

        Map<Class<? extends QoSSpecification>, Double> orderingBenchmark = new HashMap<>();
        orderingBenchmark.put(Availability.class, availabilityNormalizer.normalize(aS1O0));//0.8
        orderingBenchmark.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1O0));//0.655102041
        orderingBenchmark.put(Vulnerability.class, costNormalizer.normalize(costS1R0));
        benchmarkForImplementation.put("ordering-service", orderingBenchmark);

        Map<Class<? extends QoSSpecification>, Double> orderingCurrentQoS = new HashMap<>();
        orderingCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS1O0));
        orderingCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1O0));
        currentQoSValues.put("ORDERING-SERVICE", orderingCurrentQoS);

        // Delivery //
        List<String> deliveryProxyImplementations = List.of("delivery-proxy-1-service");
        serviceImplementations.put("DELIVERY-PROXY-SERVICE", deliveryProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyBenchmark1 = new HashMap<>();
        deliveryProxyBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS1D0));//0.683333333
        deliveryProxyBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1D0));//0.573469388
        deliveryProxyBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS1R0));
        benchmarkForImplementation.put("delivery-proxy-1-service", deliveryProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyCurrentQoS = new HashMap<>();
        deliveryProxyCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS1D0));
        deliveryProxyCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1D0));
        currentQoSValues.put("DELIVERY-PROXY-SERVICE", deliveryProxyCurrentQoS);

        // Payment //
        List<String> paymentProxyImplementations = List.of("payment-proxy-1-service");
        serviceImplementations.put("PAYMENT-PROXY-SERVICE", paymentProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyBenchmark1 = new HashMap<>();
        paymentProxyBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS1P0));//0.766666667
        paymentProxyBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1P0));//0.818367347
        paymentProxyBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS1R0));
        benchmarkForImplementation.put("payment-proxy-1-service", paymentProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyCurrentQoS = new HashMap<>();//Initial configuration
        paymentProxyCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS1P0));
        paymentProxyCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1P0));
        currentQoSValues.put("PAYMENT-PROXY-SERVICE", paymentProxyCurrentQoS);

        return createServiceMap(availabilityWeight,
                responseTimeWeight,
                vulnerabilityWeight,
                serviceImplementations,
                benchmarkForImplementation,
                currentQoSValues);
    }
    public static Map<String, Service> RQ2_s2_SAQURE_nodyPa_ExpConfig(){
        EADSA.IS_DEFAULT = false;
        log.info(" IS_DEFAULT = : "+ EADSA.IS_DEFAULT);
        double availabilityWeight = 0.3;
        double responseTimeWeight = 0.3;
        double vulnerabilityWeight = 0.4;
        try {
            converter = new ExcelToJsonConverter(FilePathConstants.configuration_rq2_path);
        } catch (Exception e) {
            throw new ExceptionInInitializerError("Failed to initialize Excel converter: " + e.getMessage());
        }
        List<String> cveList_r = (List<String>) converter.getValue("Sub-scenario2", "RESTAURANT-SERVICE", "Restaurant-service", "vulnerabilitylist");
        List<String> cveList_o = (List<String>) converter.getValue("Sub-scenario2", "ORDERING-SERVICE", "Ordering-service", "vulnerabilitylist");
        List<String> cveList_d = (List<String>) converter.getValue("Sub-scenario2", "DELIVERY-PROXY-SERVICE", "Delivery-proxy-1-service", "vulnerabilitylist");

        List<String> cveList0 = (List<String>) converter.getValue("Sub-scenario2", "PAYMENT-PROXY-SERVICE", "Payment-proxy-1-service", "vulnerabilitylist");
        cveList0 = Stream.of(cveList0, cveList_r, cveList_o, cveList_d).flatMap(List::stream).collect(Collectors.toList()) ;
        String[] cveIds_s2_p0 = cveList0.toArray(new String[0]);
        List<String> cveList1 = (List<String>) converter.getValue("Sub-scenario2", "PAYMENT-PROXY-SERVICE", "Payment-proxy-2-service", "vulnerabilitylist");
        cveList1 = Stream.of(cveList1, cveList_r, cveList_o, cveList_d).flatMap(List::stream).collect(Collectors.toList()) ;
        String[] cveIds_s2_p1 = cveList1.toArray(new String[0]);
        List<String> cveList2 = (List<String>) converter.getValue("Sub-scenario2", "PAYMENT-PROXY-SERVICE", "Payment-proxy-3-service", "vulnerabilitylist");
        cveList2 = Stream.of(cveList2, cveList_r, cveList_o, cveList_d).flatMap(List::stream).collect(Collectors.toList()) ;
        String[] cveIds_s2_p2 = cveList2.toArray(new String[0]);
        String domainFile_s2_p0 = AED_process_nodyPa(FilePathConstants.AED_path_RQ2 + "RQ2_S2_R0_O0_D0_P0.pddl", cveIds_s2_p0);
        String domainFile_s2_p1 = AED_process_nodyPa(FilePathConstants.AED_path_RQ2 + "RQ2_S2_R0_O0_D0_P1.pddl", cveIds_s2_p1);
        String domainFile_s2_p2 = AED_process_nodyPa(FilePathConstants.AED_path_RQ2 + "RQ2_S2_R0_O0_D0_P2.pddl", cveIds_s2_p2);

        final double costS5P0 = EADSA.planner_command_compute_RQ2_s2_p0(domainFile_s2_p0);
        final double costS5P1 = EADSA.planner_command_compute_RQ2_s2_p1(domainFile_s2_p1);
        final double costS5P2 = EADSA.planner_command_compute_RQ2_s2_p2(domainFile_s2_p2); //改名：risk_value
        double[] costValues = {costS5P0, costS5P1, costS5P2, 37.400000000000006, 29.900000000000002};
        log.info("Risk of Payment-1-service: "+ costS5P0 + "; Risk of Payment-2-service: "+ costS5P1 + "; Risk of Payment-3-service: "+ costS5P2);
        DynamicNormalize costNormalizer = new DynamicNormalize();
        costNormalizer.preProcessing(costValues);
        final double aS5R0 = (double) converter.getValue("Sub-scenario2", "RESTAURANT-SERVICE", "Restaurant-service", "availability");
        final double aS5O0 = (double) converter.getValue("Sub-scenario2", "ORDERING-SERVICE", "Ordering-service", "availability");
        final double aS5D0 = (double) converter.getValue("Sub-scenario2", "DELIVERY-PROXY-SERVICE", "Delivery-proxy-1-service", "availability");
        final double aS5P0 = (double) converter.getValue("Sub-scenario2", "PAYMENT-PROXY-SERVICE", "Payment-proxy-1-service", "availability");
        final double aS5P1 = (double) converter.getValue("Sub-scenario2", "PAYMENT-PROXY-SERVICE", "Payment-proxy-2-service", "availability");
        final double aS5P2 = (double) converter.getValue("Sub-scenario2", "PAYMENT-PROXY-SERVICE", "Payment-proxy-3-service", "availability");
        double[] avalibilities = {aS5R0, aS5O0, aS5D0, aS5P0, aS5P1, aS5P2};
        DynamicNormalize availabilityNormalizer = new DynamicNormalize();
        availabilityNormalizer.preProcessing(avalibilities);
        final int tS5R0 = (int) converter.getValue("Sub-scenario2", "RESTAURANT-SERVICE", "Restaurant-service", "responseTime");
        final int tS5O0 = (int) converter.getValue("Sub-scenario2", "ORDERING-SERVICE", "Ordering-service", "responseTime");
        final int tS5D0 = (int) converter.getValue("Sub-scenario2", "DELIVERY-PROXY-SERVICE", "Delivery-proxy-1-service", "responseTime");
        final int tS5P0 = (int) converter.getValue("Sub-scenario2", "PAYMENT-PROXY-SERVICE", "Payment-proxy-1-service", "responseTime");
        final int tS5P1 = (int) converter.getValue("Sub-scenario2", "PAYMENT-PROXY-SERVICE", "Payment-proxy-2-service", "responseTime");
        final int tS5P2 = (int) converter.getValue("Sub-scenario2", "PAYMENT-PROXY-SERVICE", "Payment-proxy-3-service", "responseTime");
        int[] responseTimes = {tS5R0, tS5O0, tS5D0, tS5P0, tS5P1, tS5P2};
        double[] doubleResponseTimes = Arrays.stream(responseTimes).asDoubleStream().toArray();
        DynamicNormalize responseTimeNormalizer = new DynamicNormalize();
        responseTimeNormalizer.preProcessing(doubleResponseTimes);

        Map<String, List<String>> serviceImplementations = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> benchmarkForImplementation = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> currentQoSValues = new HashMap<>();

        // Restaurant //
        List<String> restaurantImplementations = List.of("restaurant-1-service");
        serviceImplementations.put("RESTAURANT-SERVICE", restaurantImplementations);

        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark1 = new HashMap<>();//option configuration
        restaurantBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS5R0));//0.766666667
        restaurantBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS5R0));//0.165306122
        restaurantBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS5P0));
        benchmarkForImplementation.put("restaurant-1-service", restaurantBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> restaurantCurrentQoS = new HashMap<>();//Initial configuration
        restaurantCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS5R0));
        restaurantCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS5R0));
        currentQoSValues.put("RESTAURANT-SERVICE", restaurantCurrentQoS);

        // Ordering //
        List<String> orderingImplementations = List.of("ordering-1-service");
        serviceImplementations.put("ORDERING-SERVICE", orderingImplementations);

        Map<Class<? extends QoSSpecification>, Double> orderingBenchmark1 = new HashMap<>();
        orderingBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS5O0));//0.8
        orderingBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS5O0));//0.655102041
        orderingBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS5P0));
        benchmarkForImplementation.put("ordering-1-service", orderingBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> orderingCurrentQoS = new HashMap<>();
        orderingCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS5O0));
        orderingCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS5O0));
        currentQoSValues.put("ORDERING-SERVICE", orderingCurrentQoS);

        // Delivery //
        List<String> deliveryProxyImplementations = List.of("delivery-proxy-1-service");
        serviceImplementations.put("DELIVERY-PROXY-SERVICE", deliveryProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyBenchmark1 = new HashMap<>();
        deliveryProxyBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS5D0));//0.683333333
        deliveryProxyBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS5D0));//0.655102041
        deliveryProxyBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS5P0));
        benchmarkForImplementation.put("delivery-proxy-1-service", deliveryProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyCurrentQoS = new HashMap<>();
        deliveryProxyCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS5D0));
        deliveryProxyCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS5D0));
        currentQoSValues.put("DELIVERY-PROXY-SERVICE", deliveryProxyCurrentQoS);

        // Payment //
        List<String> paymentProxyImplementations = List.of("payment-proxy-1-service","payment-proxy-2-service","payment-proxy-3-service");
        serviceImplementations.put("PAYMENT-PROXY-SERVICE", paymentProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyBenchmark1 = new HashMap<>();
        paymentProxyBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS5P0));//0.766666667
        paymentProxyBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS5P0));//0.818367347
        paymentProxyBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS5P0));//
        benchmarkForImplementation.put("payment-proxy-1-service", paymentProxyBenchmark1);
        Map<Class<? extends QoSSpecification>, Double> paymentProxyBenchmark2 = new HashMap<>();
        paymentProxyBenchmark2.put(Availability.class, availabilityNormalizer.normalize(aS5P1));//0.8
        paymentProxyBenchmark2.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS5P1));//0.9
        paymentProxyBenchmark2.put(Vulnerability.class, costNormalizer.normalize(costS5P1));//
        benchmarkForImplementation.put("payment-proxy-2-service", paymentProxyBenchmark2);
        Map<Class<? extends QoSSpecification>, Double> paymentProxyBenchmark3 = new HashMap<>();
        paymentProxyBenchmark3.put(Availability.class, availabilityNormalizer.normalize(aS5P2));//0.433333333
        paymentProxyBenchmark3.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS5P2));//0.573469388
        paymentProxyBenchmark3.put(Vulnerability.class, costNormalizer.normalize(costS5P2));//
        benchmarkForImplementation.put("payment-proxy-3-service", paymentProxyBenchmark3);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyCurrentQoS = new HashMap<>();//Initial configuration
        paymentProxyCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS5P0));
        paymentProxyCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS5P0));
        currentQoSValues.put("PAYMENT-PROXY-SERVICE", paymentProxyCurrentQoS);

        return createServiceMap(availabilityWeight,
                responseTimeWeight,
                vulnerabilityWeight,
                serviceImplementations,
                benchmarkForImplementation,
                currentQoSValues);
    }
    public static Map<String, Service> RQ2_s3_SAQURE_nodyPa_ExpConfig(){
        EADSA.IS_DEFAULT = false;
        double availabilityWeight = 0.3;
        double responseTimeWeight = 0.3;
        double vulnerabilityWeight = 0.4;
        try {
            converter = new ExcelToJsonConverter(FilePathConstants.configuration_rq2_path);
        } catch (Exception e) {
            throw new ExceptionInInitializerError("Failed to initialize Excel converter: " + e.getMessage());
        }
        List<String> cveList_r = (List<String>) converter.getValue("Sub-scenario3", "RESTAURANT-SERVICE", "Restaurant-service", "vulnerabilitylist");
        List<String> cveList_d = (List<String>) converter.getValue("Sub-scenario3", "DELIVERY-PROXY-SERVICE", "Delivery-proxy-1-service", "vulnerabilitylist");
        List<String> cveList_p = (List<String>) converter.getValue("Sub-scenario3", "PAYMENT-PROXY-SERVICE", "Payment-proxy-1-service", "vulnerabilitylist");

        List<String> cveList0 = (List<String>) converter.getValue("Sub-scenario3", "ORDERING-SERVICE", "Ordering-1-service", "vulnerabilitylist");
        cveList0 = Stream.of(cveList0, cveList_r, cveList_d, cveList_p).flatMap(List::stream).collect(Collectors.toList()) ;
        String[] cveIds_s3_O0 = cveList0.toArray(new String[0]);
        List<String> cveList1 = (List<String>) converter.getValue("Sub-scenario3", "ORDERING-SERVICE", "Ordering-2-service", "vulnerabilitylist");
        cveList1 = Stream.of(cveList1, cveList_r, cveList_d, cveList_p).flatMap(List::stream).collect(Collectors.toList()) ;
        String[] cveIds_s3_O1 = cveList1.toArray(new String[0]);
        List<String> cveList2 = (List<String>) converter.getValue("Sub-scenario3", "ORDERING-SERVICE", "Ordering-3-service", "vulnerabilitylist");
        cveList2 = Stream.of(cveList2, cveList_r, cveList_d, cveList_p).flatMap(List::stream).collect(Collectors.toList()) ;
        String[] cveIds_s3_O2 = cveList2.toArray(new String[0]);

        String domainFile_s3_O0 = AED_process_nodyPa(FilePathConstants.AED_path_RQ2 + "RQ2_S3_R0_O0_D0_P0.pddl", cveIds_s3_O0);
        String domainFile_s3_O1 = AED_process_nodyPa(FilePathConstants.AED_path_RQ2 + "RQ2_S3_R0_O1_D0_P0.pddl", cveIds_s3_O1);
        String domainFile_s3_O2 = AED_process_nodyPa(FilePathConstants.AED_path_RQ2 + "RQ2_S3_R0_O2_D0_P0.pddl", cveIds_s3_O2);

        final double costS3O0 = EADSA.planner_command_compute_RQ2_s2_o0(domainFile_s3_O0);
        final double costS3O1 = EADSA.planner_command_compute_RQ2_s2_o1(domainFile_s3_O1);
        final double costS3O2 = EADSA.planner_command_compute_RQ2_s2_o2(domainFile_s3_O2);
        double[] costValues = {costS3O0, costS3O1, costS3O2, 37.400000000000006, 44.3}; // Add the MAX and MIN of both of the two sets at T1 and T2
        log.info("Risk of ordering-1-service: "+ costS3O0 + "; Risk of ordering-2-service: "+ costS3O1 + "; Risk of ordering-3-service: "+ costS3O2);
        DynamicNormalize costNormalizer = new DynamicNormalize();
        costNormalizer.preProcessing(costValues);
        final double aS3R0 = (double) converter.getValue("Sub-scenario3", "RESTAURANT-SERVICE", "Restaurant-service", "availability");
        final double aS3O0 = (double) converter.getValue("Sub-scenario3", "ORDERING-SERVICE", "Ordering-1-service", "availability");
        final double aS3O1 = (double) converter.getValue("Sub-scenario3", "ORDERING-SERVICE", "Ordering-2-service", "availability");
        final double aS3O2 = (double) converter.getValue("Sub-scenario3", "ORDERING-SERVICE", "Ordering-3-service", "availability");
        final double aS3D0 = (double) converter.getValue("Sub-scenario3", "DELIVERY-PROXY-SERVICE", "Delivery-proxy-1-service", "availability");
        final double aS3P0 = (double) converter.getValue("Sub-scenario3", "PAYMENT-PROXY-SERVICE", "Payment-proxy-1-service", "availability");
        double[] avalibilities = {aS3R0, aS3O0, aS3O1, aS3O2, aS3D0, aS3P0};
        DynamicNormalize availabilityNormalizer = new DynamicNormalize();
        availabilityNormalizer.preProcessing(avalibilities);
        final int tS3R0 = (int) converter.getValue("Sub-scenario3", "RESTAURANT-SERVICE", "Restaurant-service", "responseTime");
        final int tS3O0 = (int) converter.getValue("Sub-scenario3", "ORDERING-SERVICE", "Ordering-1-service", "responseTime");
        final int tS3O1 = (int) converter.getValue("Sub-scenario3", "ORDERING-SERVICE", "Ordering-2-service", "responseTime");
        final int tS3O2 = (int) converter.getValue("Sub-scenario3", "ORDERING-SERVICE", "Ordering-3-service", "responseTime");
        final int tS3D0 = (int) converter.getValue("Sub-scenario3", "DELIVERY-PROXY-SERVICE", "Delivery-proxy-1-service", "responseTime");
        final int tS3P0 = (int) converter.getValue("Sub-scenario3", "PAYMENT-PROXY-SERVICE", "Payment-proxy-1-service", "responseTime");
        int[] responseTimes = {tS3R0, tS3O0, tS3O1, tS3O2, tS3D0, tS3P0};
        double[] doubleResponseTimes = Arrays.stream(responseTimes).asDoubleStream().toArray();
        DynamicNormalize responseTimeNormalizer = new DynamicNormalize();
        responseTimeNormalizer.preProcessing(doubleResponseTimes);
        Map<String, List<String>> serviceImplementations = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> benchmarkForImplementation = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> currentQoSValues = new HashMap<>();

        // Restaurant //
        List<String> restaurantImplementations = List.of("restaurant-1-service");
        serviceImplementations.put("RESTAURANT-SERVICE", restaurantImplementations);

        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark1 = new HashMap<>();//option configuration
        restaurantBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS3R0));//0.183333333
        restaurantBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS3R0));//0.9
        restaurantBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS3O0));
        benchmarkForImplementation.put("restaurant-1-service", restaurantBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> restaurantCurrentQoS = new HashMap<>();//Initial configuration
        restaurantCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS3R0));
        restaurantCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS3R0));
        currentQoSValues.put("RESTAURANT-SERVICE", restaurantCurrentQoS);

        // Ordering //
        List<String> orderingImplementations = List.of("ordering-1-service","ordering-2-service","ordering-3-service");
        serviceImplementations.put("ORDERING-SERVICE", orderingImplementations);

        Map<Class<? extends QoSSpecification>, Double> orderingBenchmark1 = new HashMap<>();
        orderingBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS3O0));//0.6
        orderingBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS3O0));//0.655102041
        orderingBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS3O0));
        benchmarkForImplementation.put("ordering-1-service", orderingBenchmark1);
        Map<Class<? extends QoSSpecification>, Double> orderingBenchmark2 = new HashMap<>();
        orderingBenchmark2.put(Availability.class, availabilityNormalizer.normalize(aS3O1));//0.733333333
        orderingBenchmark2.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS3O1));//0.655102041
        orderingBenchmark2.put(Vulnerability.class, costNormalizer.normalize(costS3O1));
        benchmarkForImplementation.put("ordering-2-service", orderingBenchmark2);
        Map<Class<? extends QoSSpecification>, Double> orderingBenchmark3 = new HashMap<>();
        orderingBenchmark3.put(Availability.class, availabilityNormalizer.normalize(aS3O2));//0.6
        orderingBenchmark3.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS3O2));//0.491836735
        orderingBenchmark3.put(Vulnerability.class, costNormalizer.normalize(costS3O2));
        benchmarkForImplementation.put("ordering-3-service", orderingBenchmark3);

        Map<Class<? extends QoSSpecification>, Double> orderingCurrentQoS = new HashMap<>();
        orderingCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS3O0));
        orderingCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS3O0));
        currentQoSValues.put("ORDERING-SERVICE", orderingCurrentQoS);

        // Delivery //
        List<String> deliveryProxyImplementations = List.of("delivery-proxy-1-service");
        serviceImplementations.put("DELIVERY-PROXY-SERVICE", deliveryProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyBenchmark1 = new HashMap<>();
        deliveryProxyBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS3D0));
        deliveryProxyBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS3D0));
        deliveryProxyBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS3O0));
        benchmarkForImplementation.put("delivery-proxy-1-service", deliveryProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyCurrentQoS = new HashMap<>();
        deliveryProxyCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS3D0));
        deliveryProxyCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS3D0));
        currentQoSValues.put("DELIVERY-PROXY-SERVICE", deliveryProxyCurrentQoS);

        // Payment //
        List<String> paymentProxyImplementations = List.of("payment-proxy-1-service");
        serviceImplementations.put("PAYMENT-PROXY-SERVICE", paymentProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyBenchmark1 = new HashMap<>();
        paymentProxyBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS3P0));//0.766666667
        paymentProxyBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS3P0));//0.818367347
        paymentProxyBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS3O0));
        benchmarkForImplementation.put("payment-proxy-1-service", paymentProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyCurrentQoS = new HashMap<>();//Initial configuration
        paymentProxyCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS3P0));
        paymentProxyCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS3P0));
        currentQoSValues.put("PAYMENT-PROXY-SERVICE", paymentProxyCurrentQoS);

        return createServiceMap(availabilityWeight,
                responseTimeWeight,
                vulnerabilityWeight,
                serviceImplementations,
                benchmarkForImplementation,
                currentQoSValues);
    }


    public static Map<String, Service> RQ2_s1_Aqua_ExpConfig(){
        double availabilityWeight = 0.3;
        double responseTimeWeight = 0.3;
        double vulnerabilityWeight = 0.4;

        final double costS1R0 = 42.0; final double costS1R1 = 17.3; final double costS1R2 = 17.2;
        final double costS1O0 = 16.5; final double costS1D0 = 16.7; final double costS1P0 = 11.4;
        double[] costValues = {costS1R0, costS1R1, costS1R2, costS1O0, costS1D0, costS1P0};
        log.info("Risk of Restaurant-1-service: "+ costS1R0 + "; Risk of Restaurant-2-service: "+ costS1R1 + "; Risk of Restaurant-3-service: "+ costS1R2);
        DynamicNormalize costNormalizer = new DynamicNormalize();
        costNormalizer.preProcessing(costValues);
        final double aS1R0 = 0.75; final double aS1R1 = 0.75; final double aS1R2 = 0.75;
        final double aS1O0 = 0.9; final double aS1D0 = 0.85; final double aS1P0 = 0.95;
        double[] avalibilities = {aS1R0, aS1R1, aS1R2, aS1O0, aS1D0, aS1P0};
        DynamicNormalize availabilityNormalizer = new DynamicNormalize();
        availabilityNormalizer.preProcessing(avalibilities);
        final int tS1R0 = 200; final int tS1R1 = 200; final int tS1R2 = 200;
        final int tS1O0 = 150; final int tS1D0 = 100; final int tS1P0 = 50;
        int[] responseTimes = {tS1R0, tS1R1, tS1R2, tS1O0, tS1D0, tS1P0};
        double[] doubleResponseTimes = Arrays.stream(responseTimes).asDoubleStream().toArray();
        DynamicNormalize responseTimeNormalizer = new DynamicNormalize();
        responseTimeNormalizer.preProcessing(doubleResponseTimes);

        Map<String, List<String>> serviceImplementations = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> benchmarkForImplementation = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> currentQoSValues = new HashMap<>();

        // Restaurant //
        List<String> restaurantImplementations = List.of("restaurant-1-service","restaurant-2-service","restaurant-3-service");
        serviceImplementations.put("RESTAURANT-SERVICE", restaurantImplementations);

        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark1 = new HashMap<>();//option configuration
        restaurantBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS1R0));
        restaurantBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1R0));//50
        restaurantBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS1R0));//
        benchmarkForImplementation.put("restaurant-1-service", restaurantBenchmark1);
        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark2 = new HashMap<>();
        restaurantBenchmark2.put(Availability.class, availabilityNormalizer.normalize(aS1R1));//0.92
        restaurantBenchmark2.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1R1));//30
        restaurantBenchmark2.put(Vulnerability.class, costNormalizer.normalize(costS1R1));//
        benchmarkForImplementation.put("restaurant-2-service", restaurantBenchmark2);
        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark3 = new HashMap<>();
        restaurantBenchmark3.put(Availability.class, availabilityNormalizer.normalize(aS1R2));
        restaurantBenchmark3.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1R2));
        restaurantBenchmark3.put(Vulnerability.class, costNormalizer.normalize(costS1R2));//
        benchmarkForImplementation.put("restaurant-3-service", restaurantBenchmark3);

        Map<Class<? extends QoSSpecification>, Double> restaurantCurrentQoS = new HashMap<>();//Initial configuration
        restaurantCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS1R0));
        restaurantCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1R0));
        currentQoSValues.put("RESTAURANT-SERVICE", restaurantCurrentQoS);

        // Ordering //
        List<String> orderingImplementations = List.of("ordering-service");
        serviceImplementations.put("ORDERING-SERVICE", orderingImplementations);

        Map<Class<? extends QoSSpecification>, Double> orderingBenchmark = new HashMap<>();
        orderingBenchmark.put(Availability.class, availabilityNormalizer.normalize(aS1O0));
        orderingBenchmark.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1O0));
        orderingBenchmark.put(Vulnerability.class, costNormalizer.normalize(costS1O0));
        benchmarkForImplementation.put("ordering-service", orderingBenchmark);

        Map<Class<? extends QoSSpecification>, Double> orderingCurrentQoS = new HashMap<>();
        orderingCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS1O0));
        orderingCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1O0));
        currentQoSValues.put("ORDERING-SERVICE", orderingCurrentQoS);

        // Delivery //
        List<String> deliveryProxyImplementations = List.of("delivery-proxy-1-service");
        serviceImplementations.put("DELIVERY-PROXY-SERVICE", deliveryProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyBenchmark1 = new HashMap<>();
        deliveryProxyBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS1D0));
        deliveryProxyBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1D0));
        deliveryProxyBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS1D0));
        benchmarkForImplementation.put("delivery-proxy-1-service", deliveryProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyCurrentQoS = new HashMap<>();
        deliveryProxyCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS1D0));
        deliveryProxyCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1D0));
        currentQoSValues.put("DELIVERY-PROXY-SERVICE", deliveryProxyCurrentQoS);

        // Payment //
        List<String> paymentProxyImplementations = List.of("payment-proxy-1-service");
        serviceImplementations.put("PAYMENT-PROXY-SERVICE", paymentProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyBenchmark1 = new HashMap<>();
        paymentProxyBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS1P0));
        paymentProxyBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1P0));
        paymentProxyBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS1P0));
        benchmarkForImplementation.put("payment-proxy-1-service", paymentProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyCurrentQoS = new HashMap<>();//Initial configuration
        paymentProxyCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS1P0));
        paymentProxyCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1P0));
        currentQoSValues.put("PAYMENT-PROXY-SERVICE", paymentProxyCurrentQoS);

        return createServiceMap(availabilityWeight,
                responseTimeWeight,
                vulnerabilityWeight,
                serviceImplementations,
                benchmarkForImplementation,
                currentQoSValues);
    }
    public static Map<String, Service> RQ2_s2_Aqua_ExpConfig(){
        double availabilityWeight = 0.3;
        double responseTimeWeight = 0.3;
        double vulnerabilityWeight = 0.4;

        final double costS2R0 = 11.2; final double costS2O0 = 21.0; final double costS2D0 = 11.2;
        final double costS2P0 = 37.5; final double costS2P1 = 22.5; final double costS2P2 = 22.6;
        double[] costValues = {costS2R0, costS2O0, costS2D0, costS2P0, costS2P1, costS2P2};
        log.info("Risk of payment-proxy-1-service: "+ costS2P0 + "; Risk of payment-proxy-2-service: "+ costS2P1 + "; Risk of payment-proxy-3-service: "+ costS2P2);
        DynamicNormalize costNormalizer = new DynamicNormalize();
        costNormalizer.preProcessing(costValues);
        final double aS2R0 = 0.9; final double aS2O0 = 0.85; final double aS2D0 = 0.95;
        final double aS2P0 = 0.8; final double aS2P1 = 0.8; final double aS2P2 = 0.8;
        double[] avalibilities = {aS2R0, aS2O0, aS2D0, aS2P0, aS2P1, aS2P2};
        DynamicNormalize availabilityNormalizer = new DynamicNormalize();
        availabilityNormalizer.preProcessing(avalibilities);
        final int tS2R0 = 50; final int tS2O0 = 150; final int tS2D0 = 100;
        final int tS2P0 = 300; final int tS2P1 = 300; final int tS2P2 = 300;
        int[] responseTimes = {tS2R0, tS2O0, tS2D0, tS2P0, tS2P1, tS2P2};
        double[] doubleResponseTimes = Arrays.stream(responseTimes).asDoubleStream().toArray();
        DynamicNormalize responseTimeNormalizer = new DynamicNormalize();
        responseTimeNormalizer.preProcessing(doubleResponseTimes);

        Map<String, List<String>> serviceImplementations = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> benchmarkForImplementation = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> currentQoSValues = new HashMap<>();

        // Restaurant //
        List<String> restaurantImplementations = List.of("restaurant-1-service");
        serviceImplementations.put("RESTAURANT-SERVICE", restaurantImplementations);

        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark1 = new HashMap<>();//option configuration
        restaurantBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS2R0));
        restaurantBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS2R0));
        restaurantBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS2R0));
        benchmarkForImplementation.put("restaurant-1-service", restaurantBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> restaurantCurrentQoS = new HashMap<>();//Initial configuration
        restaurantCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS2R0));
        restaurantCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS2R0));
        currentQoSValues.put("RESTAURANT-SERVICE", restaurantCurrentQoS);

        // Ordering //
        List<String> orderingImplementations = List.of("ordering-1-service");
        serviceImplementations.put("ORDERING-SERVICE", orderingImplementations);

        Map<Class<? extends QoSSpecification>, Double> orderingBenchmark1 = new HashMap<>();
        orderingBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS2O0));
        orderingBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS2O0));
        orderingBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS2O0));
        benchmarkForImplementation.put("ordering-1-service", orderingBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> orderingCurrentQoS = new HashMap<>();
        orderingCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS2O0));
        orderingCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS2O0));
        currentQoSValues.put("ORDERING-SERVICE", orderingCurrentQoS);

        // Delivery //
        List<String> deliveryProxyImplementations = List.of("delivery-proxy-1-service");
        serviceImplementations.put("DELIVERY-PROXY-SERVICE", deliveryProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyBenchmark1 = new HashMap<>();
        deliveryProxyBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS2D0));
        deliveryProxyBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS2D0));
        deliveryProxyBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS2D0));
        benchmarkForImplementation.put("delivery-proxy-1-service", deliveryProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyCurrentQoS = new HashMap<>();
        deliveryProxyCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS2D0));
        deliveryProxyCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS2D0));
        currentQoSValues.put("DELIVERY-PROXY-SERVICE", deliveryProxyCurrentQoS);

        // Payment //
        List<String> paymentProxyImplementations = List.of("payment-proxy-1-service","payment-proxy-2-service","payment-proxy-3-service");
        serviceImplementations.put("PAYMENT-PROXY-SERVICE", paymentProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyBenchmark1 = new HashMap<>();
        paymentProxyBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS2P0));
        paymentProxyBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS2P0));
        paymentProxyBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS2P0));//
        benchmarkForImplementation.put("payment-proxy-1-service", paymentProxyBenchmark1);
        Map<Class<? extends QoSSpecification>, Double> paymentProxyBenchmark2 = new HashMap<>();
        paymentProxyBenchmark2.put(Availability.class, availabilityNormalizer.normalize(aS2P1));
        paymentProxyBenchmark2.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS2P1));
        paymentProxyBenchmark2.put(Vulnerability.class, costNormalizer.normalize(costS2P1));//
        benchmarkForImplementation.put("payment-proxy-2-service", paymentProxyBenchmark2);
        Map<Class<? extends QoSSpecification>, Double> paymentProxyBenchmark3 = new HashMap<>();
        paymentProxyBenchmark3.put(Availability.class, availabilityNormalizer.normalize(aS2P2));
        paymentProxyBenchmark3.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS2P2));
        paymentProxyBenchmark3.put(Vulnerability.class, costNormalizer.normalize(costS2P2));//
        benchmarkForImplementation.put("payment-proxy-3-service", paymentProxyBenchmark3);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyCurrentQoS = new HashMap<>();//Initial configuration
        paymentProxyCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS2P0));
        paymentProxyCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS2P0));
        currentQoSValues.put("PAYMENT-PROXY-SERVICE", paymentProxyCurrentQoS);

        return createServiceMap(availabilityWeight,
                responseTimeWeight,
                vulnerabilityWeight,
                serviceImplementations,
                benchmarkForImplementation,
                currentQoSValues);
    }
    public static Map<String, Service> RQ2_s3_Aqua_ExpConfig(){
        double availabilityWeight = 0.3;
        double responseTimeWeight = 0.3;
        double vulnerabilityWeight = 0.4;

        final double costS3R0 = 18.7; final double costS3O0 = 39.8; final double costS3O1 = 24.8;
        final double costS3O2 = 24.7; final double costS3D0 = 20.3; final double costS3P0 = 20.3;
        double[] costValues = {costS3R0, costS3O0, costS3O1, costS3O2, costS3D0, costS3P0};
        log.info("Risk of ordering-1-service: "+ costS3O0 + "; Risk of ordering-2-service: "+ costS3O1 + "; Risk of ordering-3-service: "+ costS3O2);
        DynamicNormalize costNormalizer = new DynamicNormalize();
        costNormalizer.preProcessing(costValues);
        final double aS3R0 = 0.95; final double aS3O0 = 0.85; final double aS3O1 = 0.85;
        final double aS3O2 = 0.85; final double aS3D0 = 0.9; final double aS3P0 = 0.9;
        double[] avalibilities = {aS3R0, aS3O0, aS3O1, aS3O2, aS3D0, aS3P0};
        DynamicNormalize availabilityNormalizer = new DynamicNormalize();
        availabilityNormalizer.preProcessing(avalibilities);
        final int tS3R0 = 100; final int tS3O0 = 100; final int tS3O1 = 100;
        final int tS3O2 = 100; final int tS3D0 = 50; final int tS3P0 = 150;
        int[] responseTimes = {tS3R0, tS3O0, tS3O1, tS3O2, tS3D0, tS3P0};
        double[] doubleResponseTimes = Arrays.stream(responseTimes).asDoubleStream().toArray();
        DynamicNormalize responseTimeNormalizer = new DynamicNormalize();
        responseTimeNormalizer.preProcessing(doubleResponseTimes);

        Map<String, List<String>> serviceImplementations = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> benchmarkForImplementation = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> currentQoSValues = new HashMap<>();

        // Restaurant //
        List<String> restaurantImplementations = List.of("restaurant-1-service");
        serviceImplementations.put("RESTAURANT-SERVICE", restaurantImplementations);

        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark1 = new HashMap<>();//option configuration
        restaurantBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS3R0));
        restaurantBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS3R0));
        restaurantBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS3R0));
        benchmarkForImplementation.put("restaurant-1-service", restaurantBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> restaurantCurrentQoS = new HashMap<>();//Initial configuration
        restaurantCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS3R0));
        restaurantCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS3R0));
        currentQoSValues.put("RESTAURANT-SERVICE", restaurantCurrentQoS);

        // Ordering //
        List<String> orderingImplementations = List.of("ordering-1-service","ordering-2-service","ordering-3-service");
        serviceImplementations.put("ORDERING-SERVICE", orderingImplementations);

        Map<Class<? extends QoSSpecification>, Double> orderingBenchmark1 = new HashMap<>();
        orderingBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS3O0));
        orderingBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS3O0));
        orderingBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS3O0));
        benchmarkForImplementation.put("ordering-1-service", orderingBenchmark1);
        Map<Class<? extends QoSSpecification>, Double> orderingBenchmark2 = new HashMap<>();
        orderingBenchmark2.put(Availability.class, availabilityNormalizer.normalize(aS3O1));
        orderingBenchmark2.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS3O1));
        orderingBenchmark2.put(Vulnerability.class, costNormalizer.normalize(costS3O1));
        benchmarkForImplementation.put("ordering-2-service", orderingBenchmark2);
        Map<Class<? extends QoSSpecification>, Double> orderingBenchmark3 = new HashMap<>();
        orderingBenchmark3.put(Availability.class, availabilityNormalizer.normalize(aS3O2));
        orderingBenchmark3.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS3O2));
        orderingBenchmark3.put(Vulnerability.class, costNormalizer.normalize(costS3O2));
        benchmarkForImplementation.put("ordering-3-service", orderingBenchmark3);

        Map<Class<? extends QoSSpecification>, Double> orderingCurrentQoS = new HashMap<>();
        orderingCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS3O0));
        orderingCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS3O0));
        currentQoSValues.put("ORDERING-SERVICE", orderingCurrentQoS);

        // Delivery //
        List<String> deliveryProxyImplementations = List.of("delivery-proxy-1-service");
        serviceImplementations.put("DELIVERY-PROXY-SERVICE", deliveryProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyBenchmark1 = new HashMap<>();
        deliveryProxyBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS3D0));
        deliveryProxyBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS3D0));
        deliveryProxyBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS3D0));
        benchmarkForImplementation.put("delivery-proxy-1-service", deliveryProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyCurrentQoS = new HashMap<>();
        deliveryProxyCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS3D0));
        deliveryProxyCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS3D0));
        currentQoSValues.put("DELIVERY-PROXY-SERVICE", deliveryProxyCurrentQoS);

        // Payment //
        List<String> paymentProxyImplementations = List.of("payment-proxy-1-service");
        serviceImplementations.put("PAYMENT-PROXY-SERVICE", paymentProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyBenchmark1 = new HashMap<>();
        paymentProxyBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS3P0));
        paymentProxyBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS3P0));
        paymentProxyBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS3P0));
        benchmarkForImplementation.put("payment-proxy-1-service", paymentProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyCurrentQoS = new HashMap<>();//Initial configuration
        paymentProxyCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS3P0));
        paymentProxyCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS3P0));
        currentQoSValues.put("PAYMENT-PROXY-SERVICE", paymentProxyCurrentQoS);

        return createServiceMap(availabilityWeight,
                responseTimeWeight,
                vulnerabilityWeight,
                serviceImplementations,
                benchmarkForImplementation,
                currentQoSValues);
    }

    public static Map<String, Service> RQ3_1_1_SAQURE_ExpConfig(int number){
        double availabilityWeight = 0.3;
        double responseTimeWeight = 0.3;
        double vulnerabilityWeight = 0.4;
        try {
            converter = new ExcelToJsonConverter(FilePathConstants.configuration_rq311_path);
        } catch (Exception e) {
            throw new ExceptionInInitializerError("Failed to initialize Excel converter: " + e.getMessage());
        }
        String path_plan = "RQ3/experiment1/S"+number;

        List<String> cveList_r0 = (List<String>) converter.getValue("Sub-scenario" + number, "RESTAURANT-SERVICE", "Restaurant-service", "vulnerabilitylist");
        List<String> cveList_o0 = (List<String>) converter.getValue("Sub-scenario" + number, "ORDERING-SERVICE", "Ordering-service", "vulnerabilitylist");
        List<String> cveList_d0 = (List<String>) converter.getValue("Sub-scenario" + number, "DELIVERY-PROXY-SERVICE", "Delivery-proxy-1-service", "vulnerabilitylist");
        List<Double> costValuesList = new ArrayList<>();
        final double aS1R0 = (double) converter.getValue("Sub-scenario" + number, "RESTAURANT-SERVICE", "Restaurant-service", "availability");
        final double aS1O0 = (double) converter.getValue("Sub-scenario" + number, "ORDERING-SERVICE", "Ordering-service", "availability");
        final double aS1D0 = (double) converter.getValue("Sub-scenario" + number, "DELIVERY-PROXY-SERVICE", "Delivery-proxy-1-service", "availability");
        List<Double> avalibilities = new ArrayList<>(List.of(aS1R0, aS1O0, aS1D0));
        final int tS1R0 = (int) converter.getValue("Sub-scenario" + number, "RESTAURANT-SERVICE", "Restaurant-service", "responseTime");
        final int tS1O0 = (int) converter.getValue("Sub-scenario" + number, "ORDERING-SERVICE", "Ordering-service", "responseTime");
        final int tS1D0 = (int) converter.getValue("Sub-scenario" + number, "DELIVERY-PROXY-SERVICE", "Delivery-proxy-1-service", "responseTime");
        List<Integer> responseTimes = new ArrayList<>(List.of(tS1R0, tS1O0, tS1D0));

        for (int i =0; i < number; i++){
            EADSA.outputPath planPath_p = new EADSA.outputPath(
                    "Plan/" + path_plan +"/spoofing_R0_O0_D0_P" + i + "_plan.pddl",
                    "Plan/" + path_plan +"/tampering_R0_O0_D0_P" + i + "_plan.pddl",
                    "Plan/" + path_plan +"/repudiation_R0_O0_D0_P" + i + "_plan.pddl",
                    "Plan/" + path_plan +"/information_disclosure_R0_O0_D0_P" + i + "_plan.pddl",
                    "Plan/" + path_plan +"/denial_of_service_R0_O0_D0_P" + i + "_plan.pddl",
                    "Plan/" + path_plan +"/elevation_of_privilege_R0_O0_D0_P" + i + "_plan.pddl");

            List<String> cveList = (List<String>) converter.getValue("Sub-scenario" + number, "PAYMENT-PROXY-SERVICE", "Payment-proxy-" + (i+1) + "-service", "vulnerabilitylist");
            cveList = Stream.of(cveList, cveList_o0, cveList_d0, cveList_r0).flatMap(List::stream).collect(Collectors.toList());
            String[] cveIds_p = cveList.toArray(new String[0]);

            String domainFile_p = AED_process(FilePathConstants.AED_path_RQ3 + "experiment1/S_"+ (i+1) +"R0_O0_D0_P" + i +".pddl", cveIds_p);
            final double cost_p = EADSA.computeScenario(domainFile_p, planPath_p);
            costValuesList.add(cost_p);
            final double aS1P = (double) converter.getValue("Sub-scenario" + number, "PAYMENT-PROXY-SERVICE", "Payment-proxy-" + (i+1) + "-service", "availability");
            avalibilities.add(aS1P);
            final int tS1P = (int) converter.getValue("Sub-scenario" + number, "PAYMENT-PROXY-SERVICE", "Payment-proxy-" + (i+1) + "-service", "responseTime");
            responseTimes.add(tS1P);
        }

        DynamicNormalize costNormalizer = new DynamicNormalize();
        costNormalizer.preProcessing(costValuesList.stream()
                .mapToDouble(Double::doubleValue)
                .toArray());
        DynamicNormalize availabilityNormalizer = new DynamicNormalize();
        availabilityNormalizer.preProcessing(avalibilities.stream()
                .mapToDouble(Double::doubleValue)
                .toArray());
        DynamicNormalize responseTimeNormalizer = new DynamicNormalize();
        responseTimeNormalizer.preProcessing(responseTimes.stream()
                .mapToDouble(Integer::doubleValue)
                .toArray());

        Map<String, List<String>> serviceImplementations = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> benchmarkForImplementation = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> currentQoSValues = new HashMap<>();

        // Restaurant //
        List<String> restaurantImplementations = List.of("restaurant-service");
        serviceImplementations.put("RESTAURANT-SERVICE", restaurantImplementations);

        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark1 = new HashMap<>();//option configuration
        restaurantBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS1R0));//0.766666667
        restaurantBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1R0));//0.165306122
        restaurantBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costValuesList.get(0)));//0.633333333
        benchmarkForImplementation.put("restaurant-service", restaurantBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> restaurantCurrentQoS = new HashMap<>();//Initial configuration
        restaurantCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS1R0));
        restaurantCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1R0));
        currentQoSValues.put("RESTAURANT-SERVICE", restaurantCurrentQoS);

        // Ordering //
        List<String> orderingImplementations = List.of("ordering-service");
        serviceImplementations.put("ORDERING-SERVICE", orderingImplementations);

        Map<Class<? extends QoSSpecification>, Double> orderingBenchmark = new HashMap<>();
        orderingBenchmark.put(Availability.class, availabilityNormalizer.normalize(aS1O0));//0.8
        orderingBenchmark.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1O0));//0.655102041
        orderingBenchmark.put(Vulnerability.class, costNormalizer.normalize(costValuesList.get(0)));
        benchmarkForImplementation.put("ordering-service", orderingBenchmark);

        Map<Class<? extends QoSSpecification>, Double> orderingCurrentQoS = new HashMap<>();
        orderingCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS1O0));
        orderingCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1O0));
        currentQoSValues.put("ORDERING-SERVICE", orderingCurrentQoS);

        // Delivery //
        List<String> deliveryProxyImplementations = List.of("delivery-proxy-1-service");
        serviceImplementations.put("DELIVERY-PROXY-SERVICE", deliveryProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyBenchmark1 = new HashMap<>();
        deliveryProxyBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS1D0));//0.683333333
        deliveryProxyBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1D0));//0.573469388
        deliveryProxyBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costValuesList.get(0)));
        benchmarkForImplementation.put("delivery-proxy-1-service", deliveryProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyCurrentQoS = new HashMap<>();
        deliveryProxyCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS1D0));
        deliveryProxyCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1D0));
        currentQoSValues.put("DELIVERY-PROXY-SERVICE", deliveryProxyCurrentQoS);

        // Payment //
        List<String> paymentProxyImplementations = new ArrayList<>(List.of());
        for (int i =1; i <= number; i++){
            paymentProxyImplementations.add("payment-proxy-" + i + "-service");
            serviceImplementations.put("PAYMENT-PROXY-SERVICE", paymentProxyImplementations);

            Map<Class<? extends QoSSpecification>, Double> paymentProxyBenchmark = new HashMap<>();
            paymentProxyBenchmark.put(Availability.class, availabilityNormalizer.normalize(avalibilities.get(i-1)));//0.766666667
            paymentProxyBenchmark.put(AverageResponseTime.class, responseTimeNormalizer.normalize(responseTimes.get(i-1)));//0.818367347
            paymentProxyBenchmark.put(Vulnerability.class, costNormalizer.normalize(costValuesList.get(i-1)));
            benchmarkForImplementation.put("payment-proxy-" + i + "-service", paymentProxyBenchmark);
        }

        Map<Class<? extends QoSSpecification>, Double> paymentProxyCurrentQoS = new HashMap<>();//Initial configuration
        paymentProxyCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(avalibilities.get(0)));
        paymentProxyCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(responseTimes.get(0)));
        currentQoSValues.put("PAYMENT-PROXY-SERVICE", paymentProxyCurrentQoS);

        return createServiceMap(availabilityWeight,
                responseTimeWeight,
                vulnerabilityWeight,
                serviceImplementations,
                benchmarkForImplementation,
                currentQoSValues);
    }
    public static Map<String, Service> RQ3_1_2_SAQURE_ExpConfig(int number){
        double availabilityWeight = 0.3;
        double responseTimeWeight = 0.3;
        double vulnerabilityWeight = 0.4;
        try {
            converter = new ExcelToJsonConverter(FilePathConstants.configuration_rq312_path);
        } catch (Exception e) {
            throw new ExceptionInInitializerError("Failed to initialize Excel converter: " + e.getMessage());
        }
        String path_R0_plan = "RQ3/experiment2/S"+number;
        String path_R1_plan = "RQ3/experiment2/S"+number;
        String path_R2_plan = "RQ3/experiment2/S"+number;
        EADSA.outputPath planPath_R0 = new EADSA.outputPath(
                "Plan/" + path_R0_plan +"/spoofing_R0_O0_D0_P0_plan.pddl",
                "Plan/" + path_R0_plan +"/tampering_R0_O0_D0_P0_plan.pddl",
                "Plan/" + path_R0_plan +"/repudiation_R0_O0_D0_P0_plan.pddl",
                "Plan/" + path_R0_plan +"/information_disclosure_R0_O0_D0_P0_plan.pddl",
                "Plan/" + path_R0_plan +"/denial_of_service_R0_O0_D0_P0_plan.pddl",
                "Plan/" + path_R0_plan +"/elevation_of_privilege_R0_O0_D0_P0_plan.pddl");
        EADSA.outputPath planPath_R1 = new EADSA.outputPath(
                "Plan/" + path_R1_plan +"/spoofing_R1_O0_D0_P0_plan.pddl",
                "Plan/" + path_R1_plan +"/tampering_R1_O0_D0_P0_plan.pddl",
                "Plan/" + path_R1_plan +"/repudiation_R1_O0_D0_P0_plan.pddl",
                "Plan/" + path_R1_plan +"/information_disclosure_R1_O0_D0_P0_plan.pddl",
                "Plan/" + path_R1_plan +"/denial_of_service_R1_O0_D0_P0_plan.pddl",
                "Plan/" + path_R1_plan +"/elevation_of_privilege_R1_O0_D0_P0_plan.pddl");
        EADSA.outputPath planPath_R2 = new EADSA.outputPath(
                "Plan/" + path_R2_plan +"/spoofing_R2_O0_D0_P0_plan.pddl",
                "Plan/" + path_R2_plan +"/tampering_R2_O0_D0_P0_plan.pddl",
                "Plan/" + path_R2_plan +"/repudiation_R2_O0_D0_P0_plan.pddl",
                "Plan/" + path_R2_plan +"/information_disclosure_R2_O0_D0_P0_plan.pddl",
                "Plan/" + path_R2_plan +"/denial_of_service_R2_O0_D0_P0_plan.pddl",
                "Plan/" + path_R2_plan +"/elevation_of_privilege_R2_O0_D0_P0_plan.pddl");

        List<String> cveList0 = (List<String>) converter.getValue("Sub-scenario" + number, "RESTAURANT-SERVICE", "Restaurant-1-service", "vulnerabilitylist");
        String[] cveIds_r0 = cveList0.toArray(new String[0]);
        List<String> cveList1 = (List<String>) converter.getValue("Sub-scenario" + number, "RESTAURANT-SERVICE", "Restaurant-2-service", "vulnerabilitylist");
        String[] cveIds_r1 = cveList1.toArray(new String[0]);
        List<String> cveList2 = (List<String>) converter.getValue("Sub-scenario" + number, "RESTAURANT-SERVICE", "Restaurant-3-service", "vulnerabilitylist");
        String[] cveIds_r2 = cveList2.toArray(new String[0]);

        // for RQ3.2
        Instant EADSAStart = Instant.now();
        String domainFile_r0 = AED_process(FilePathConstants.AED_path_RQ3 + "experiment1/S1_R0_O0_D0_P0.pddl", cveIds_r0);
        final double costS1R0 = EADSA.computeScenario(domainFile_r0, planPath_R0);
        Instant EADSAEnd = Instant.now();
        log.info("Time to implement EADSA for restaurant_0: {}ms", Duration.between(EADSAStart, EADSAEnd).toMillis());

        String domainFile_r1 = AED_process(FilePathConstants.AED_path_RQ3 + "experiment1/S2_R1_O0_D0_P0.pddl", cveIds_r1);
        final double costS1R1 = EADSA.computeScenario(domainFile_r1, planPath_R1);
        String domainFile_r2 = AED_process(FilePathConstants.AED_path_RQ3 + "experiment1/S3_R2_O0_D0_P0.pddl", cveIds_r2);
        final double costS1R2 = EADSA.computeScenario(domainFile_r2, planPath_R2);

        double[] costValues = {costS1R0, costS1R1, costS1R2};
        DynamicNormalize costNormalizer = new DynamicNormalize();
        costNormalizer.preProcessing(costValues);
        final double aS1R0 = (double) converter.getValue("Sub-scenario" + number, "RESTAURANT-SERVICE", "Restaurant-1-service", "availability");
        final double aS1R1 = (double) converter.getValue("Sub-scenario" + number, "RESTAURANT-SERVICE", "Restaurant-2-service", "availability");
        final double aS1R2 = (double) converter.getValue("Sub-scenario" + number, "RESTAURANT-SERVICE", "Restaurant-3-service", "availability");
        final double aS1O0 = (double) converter.getValue("Sub-scenario" + number, "ORDERING-SERVICE", "Ordering-service", "availability");
        final double aS1D0 = (double) converter.getValue("Sub-scenario" + number, "DELIVERY-PROXY-SERVICE", "Delivery-proxy-1-service", "availability");
        final double aS1P0 = (double) converter.getValue("Sub-scenario" + number, "PAYMENT-PROXY-SERVICE", "Payment-proxy-1-service", "availability");
        double[] avalibilities = {aS1R0, aS1R1, aS1R2, aS1O0, aS1D0, aS1P0};
        DynamicNormalize availabilityNormalizer = new DynamicNormalize();
        availabilityNormalizer.preProcessing(avalibilities);
        final int tS1R0 = (int) converter.getValue("Sub-scenario" + number, "RESTAURANT-SERVICE", "Restaurant-1-service", "responseTime");
        final int tS1R1 = (int) converter.getValue("Sub-scenario" + number, "RESTAURANT-SERVICE", "Restaurant-2-service", "responseTime");
        final int tS1R2 = (int) converter.getValue("Sub-scenario" + number, "RESTAURANT-SERVICE", "Restaurant-3-service", "responseTime");
        final int tS1O0 = (int) converter.getValue("Sub-scenario" + number, "ORDERING-SERVICE", "Ordering-service", "responseTime");
        final int tS1D0 = (int) converter.getValue("Sub-scenario" + number, "DELIVERY-PROXY-SERVICE", "Delivery-proxy-1-service", "responseTime");
        final int tS1P0 = (int) converter.getValue("Sub-scenario" + number, "PAYMENT-PROXY-SERVICE", "Payment-proxy-1-service", "responseTime");
        int[] responseTimes = {tS1R0, tS1R1, tS1R2, tS1O0, tS1D0, tS1P0};
        double[] doubleResponseTimes = Arrays.stream(responseTimes).asDoubleStream().toArray();
        DynamicNormalize responseTimeNormalizer = new DynamicNormalize();
        responseTimeNormalizer.preProcessing(doubleResponseTimes);
//        System.out.printf(
//                "Availability (Normalized):\n" +
//                        "  aS1R0: %.2f, aS1R1: %.2f, aS1R2: %.2f," +
//                        "  aS1O0: %.2f, aS1D0: %.2f, aS1P0: %.2f\n" +
//                        "Response Time (Normalized):\n" +
//                        "  tS1R0: %.2f, tS1R1: %.2f, tS1R2: %.2f," +
//                        "  tS1O0: %.2f, tS1D0: %.2f, tS1P0: %.2f\n",
//                aS1R0,//availabilityNormalizer.normalize(aS1R0),
//                aS1R1,//availabilityNormalizer.normalize(aS1R1),
//                aS1R2,//availabilityNormalizer.normalize(aS1R2),
//                aS1O0,//availabilityNormalizer.normalize(aS1O0),
//                aS1D0,//availabilityNormalizer.normalize(aS1D0),
//                aS1P0,//availabilityNormalizer.normalize(aS1P0),
//                responseTimeNormalizer.normalize(tS1R0),
//                responseTimeNormalizer.normalize(tS1R1),
//                responseTimeNormalizer.normalize(tS1R2),
//                responseTimeNormalizer.normalize(tS1O0),
//                responseTimeNormalizer.normalize(tS1D0),
//                responseTimeNormalizer.normalize(tS1P0)
//        );
//        System.out.printf("Cost (Normalized):\n" + " vs1r0: %.2f, vs1r1: %.2f, vs1r2: %.2f ", costNormalizer.normalize(costS1R0), costNormalizer.normalize(costS1R1), costNormalizer.normalize(costS1R2));

        Map<String, List<String>> serviceImplementations = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> benchmarkForImplementation = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> currentQoSValues = new HashMap<>();

        // Restaurant //
        List<String> restaurantImplementations = List.of("restaurant-1-service","restaurant-2-service","restaurant-3-service");
        serviceImplementations.put("RESTAURANT-SERVICE", restaurantImplementations);

        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark1 = new HashMap<>();//option configuration
        restaurantBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS1R0));//0.766666667
        restaurantBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1R0));//0.165306122
        restaurantBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS1R0));//0.633333333
        benchmarkForImplementation.put("restaurant-1-service", restaurantBenchmark1);
        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark2 = new HashMap<>();
        restaurantBenchmark2.put(Availability.class, availabilityNormalizer.normalize(aS1R1));//0.92
        restaurantBenchmark2.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1R1));//0.132653061
        restaurantBenchmark2.put(Vulnerability.class, costNormalizer.normalize(costS1R1));//0.227891156
        benchmarkForImplementation.put("restaurant-2-service", restaurantBenchmark2);
        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark3 = new HashMap<>();
        restaurantBenchmark3.put(Availability.class, availabilityNormalizer.normalize(aS1R2));
        restaurantBenchmark3.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1R2));//0.1
        restaurantBenchmark3.put(Vulnerability.class, costNormalizer.normalize(costS1R2));//0.9
        benchmarkForImplementation.put("restaurant-3-service", restaurantBenchmark3);

        Map<Class<? extends QoSSpecification>, Double> restaurantCurrentQoS = new HashMap<>();//Initial configuration
        restaurantCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS1R0));
        restaurantCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1R0));
        currentQoSValues.put("RESTAURANT-SERVICE", restaurantCurrentQoS);

        // Ordering //
        List<String> orderingImplementations = List.of("ordering-service");
        serviceImplementations.put("ORDERING-SERVICE", orderingImplementations);

        Map<Class<? extends QoSSpecification>, Double> orderingBenchmark = new HashMap<>();
        orderingBenchmark.put(Availability.class, availabilityNormalizer.normalize(aS1O0));//0.8
        orderingBenchmark.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1O0));//0.655102041
        orderingBenchmark.put(Vulnerability.class, costNormalizer.normalize(costS1R0));
        benchmarkForImplementation.put("ordering-service", orderingBenchmark);

        Map<Class<? extends QoSSpecification>, Double> orderingCurrentQoS = new HashMap<>();
        orderingCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS1O0));
        orderingCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1O0));
        currentQoSValues.put("ORDERING-SERVICE", orderingCurrentQoS);

        // Delivery //
        List<String> deliveryProxyImplementations = List.of("delivery-proxy-1-service");
        serviceImplementations.put("DELIVERY-PROXY-SERVICE", deliveryProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyBenchmark1 = new HashMap<>();
        deliveryProxyBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS1D0));//0.683333333
        deliveryProxyBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1D0));//0.573469388
        deliveryProxyBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS1R0));
        benchmarkForImplementation.put("delivery-proxy-1-service", deliveryProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyCurrentQoS = new HashMap<>();
        deliveryProxyCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS1D0));
        deliveryProxyCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1D0));
        currentQoSValues.put("DELIVERY-PROXY-SERVICE", deliveryProxyCurrentQoS);

        // Payment //
        List<String> paymentProxyImplementations = List.of("payment-proxy-1-service");
        serviceImplementations.put("PAYMENT-PROXY-SERVICE", paymentProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyBenchmark1 = new HashMap<>();
        paymentProxyBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS1P0));//0.766666667
        paymentProxyBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1P0));//0.818367347
        paymentProxyBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS1R0));
        benchmarkForImplementation.put("payment-proxy-1-service", paymentProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyCurrentQoS = new HashMap<>();//Initial configuration
        paymentProxyCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS1P0));
        paymentProxyCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1P0));
        currentQoSValues.put("PAYMENT-PROXY-SERVICE", paymentProxyCurrentQoS);

        return createServiceMap(availabilityWeight,
                responseTimeWeight,
                vulnerabilityWeight,
                serviceImplementations,
                benchmarkForImplementation,
                currentQoSValues);
    }

    public static Map<String, Service> RQ3_1_1_Aqua_ExpConfig(int number){
        double availabilityWeight = 0.3;
        double responseTimeWeight = 0.3;
        double vulnerabilityWeight = 0.4;

        Map<String, List<String>> serviceImplementations = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> benchmarkForImplementation = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> currentQoSValues = new HashMap<>();

        // Restaurant //
        List<String> restaurantImplementations = List.of("restaurant-service");
        serviceImplementations.put("RESTAURANT-SERVICE", restaurantImplementations);

        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark1 = new HashMap<>();//option configuration
        restaurantBenchmark1.put(Availability.class, 0.1);//0.766666667
        restaurantBenchmark1.put(AverageResponseTime.class, 0.9);//0.165306122
        restaurantBenchmark1.put(Vulnerability.class, 0.1);//0.633333333
        benchmarkForImplementation.put("restaurant-service", restaurantBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> restaurantCurrentQoS = new HashMap<>();//Initial configuration
        restaurantCurrentQoS.put(Availability.class, 0.1);
        restaurantCurrentQoS.put(AverageResponseTime.class, 0.9);
        currentQoSValues.put("RESTAURANT-SERVICE", restaurantCurrentQoS);

        // Ordering //
        List<String> orderingImplementations = List.of("ordering-service");
        serviceImplementations.put("ORDERING-SERVICE", orderingImplementations);

        Map<Class<? extends QoSSpecification>, Double> orderingBenchmark = new HashMap<>();
        orderingBenchmark.put(Availability.class, 0.9);//0.8
        orderingBenchmark.put(AverageResponseTime.class, 0.592307692);//0.655102041
        orderingBenchmark.put(Vulnerability.class, 0.1);
        benchmarkForImplementation.put("ordering-service", orderingBenchmark);

        Map<Class<? extends QoSSpecification>, Double> orderingCurrentQoS = new HashMap<>();
        orderingCurrentQoS.put(Availability.class, 0.9);
        orderingCurrentQoS.put(AverageResponseTime.class, 0.592307692);
        currentQoSValues.put("ORDERING-SERVICE", orderingCurrentQoS);

        // Delivery //
        List<String> deliveryProxyImplementations = List.of("delivery-proxy-1-service");
        serviceImplementations.put("DELIVERY-PROXY-SERVICE", deliveryProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyBenchmark1 = new HashMap<>();
        deliveryProxyBenchmark1.put(Availability.class, 0.633333333);//0.683333333
        deliveryProxyBenchmark1.put(AverageResponseTime.class, 0.1);//0.573469388
        deliveryProxyBenchmark1.put(Vulnerability.class, 0.1);
        benchmarkForImplementation.put("delivery-proxy-1-service", deliveryProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyCurrentQoS = new HashMap<>();
        deliveryProxyCurrentQoS.put(Availability.class, 0.633333333);
        deliveryProxyCurrentQoS.put(AverageResponseTime.class, 0.1);
        currentQoSValues.put("DELIVERY-PROXY-SERVICE", deliveryProxyCurrentQoS);

        // Payment //
        double[] vul_payment = {0.1,
                0.155414634,
                0.21395122,
                0.26,
                0.318536585,
                0.381756098,
                0.423121951,
                0.481658537,
                0.540195122,
                0.598731707,
                0.657268293,
                0.715804878,
                0.773560976,
                0.836780488,
                0.9};
        List<String> paymentProxyImplementations = new ArrayList<>(List.of());
        for (int i =1; i <= number; i++){
            paymentProxyImplementations.add("payment-proxy-" + i + "-service");
            serviceImplementations.put("PAYMENT-PROXY-SERVICE", paymentProxyImplementations);

            Map<Class<? extends QoSSpecification>, Double> paymentProxyBenchmark = new HashMap<>();
            paymentProxyBenchmark.put(Availability.class, 0.366666667);//0.766666667
            paymentProxyBenchmark.put(AverageResponseTime.class, 0.715384615);//0.818367347
            paymentProxyBenchmark.put(Vulnerability.class, vul_payment[i-1]);
            benchmarkForImplementation.put("payment-proxy-" + i + "-service", paymentProxyBenchmark);
        }

        Map<Class<? extends QoSSpecification>, Double> paymentProxyCurrentQoS = new HashMap<>();//Initial configuration
        paymentProxyCurrentQoS.put(Availability.class, 0.366666667);
        paymentProxyCurrentQoS.put(AverageResponseTime.class, 0.715384615);
        currentQoSValues.put("PAYMENT-PROXY-SERVICE", paymentProxyCurrentQoS);

        return createServiceMap(availabilityWeight,
                responseTimeWeight,
                vulnerabilityWeight,
                serviceImplementations,
                benchmarkForImplementation,
                currentQoSValues);
    }
    public static Map<String, Service> RQ3_1_2_Aqua_ExpConfig(int number){
        double availabilityWeight = 0.3;
        double responseTimeWeight = 0.3;
        double vulnerabilityWeight = 0.4;

        Map<String, List<String>> serviceImplementations = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> benchmarkForImplementation = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> currentQoSValues = new HashMap<>();

        // Restaurant //
        double[] vul_r0 = {0.1,
                0.15300879, 0.191413117, 0.231981068, 0.263894523, 0.304462475, 0.348275862, 0.376943881, 0.417511832, 0.458079784, 0.498647735, 0.539215686, 0.579783638, 0.619810683, 0.66362407, 0.707437458, 0.736105477, 0.776673428, 0.806423259, 0.84699121, 0.9};
        double[] vul_r1 = {0.117849899,
                0.170858688, 0.209263016, 0.249830967, 0.281744422, 0.322312373, 0.366125761, 0.39479378, 0.435361731, 0.475929682, 0.516497634, 0.557065585, 0.597633536, 0.637660581, 0.681473969, 0.725287356, 0.753955375, 0.794523327, 0.824273158, 0.864841109, 0.9};
        double[] vul_r2 = {0.117849899,
                0.156254226, 0.196822177, 0.228735632, 0.269303584, 0.313116971, 0.34178499, 0.382352941, 0.422920892, 0.463488844, 0.504056795, 0.544624746, 0.584651792, 0.628465179, 0.672278567, 0.700946586, 0.741514537, 0.771264368, 0.811832319, 0.864841109, 0.9};
        List<String> restaurantImplementations = List.of("restaurant-1-service","restaurant-2-service","restaurant-3-service");
        serviceImplementations.put("RESTAURANT-SERVICE", restaurantImplementations);

        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark1 = new HashMap<>();//option configuration
        restaurantBenchmark1.put(Availability.class, 0.1);//0.766666667
        restaurantBenchmark1.put(AverageResponseTime.class, 0.9);//0.165306122
        restaurantBenchmark1.put(Vulnerability.class, vul_r0[number-1]);//0.633333333
        benchmarkForImplementation.put("restaurant-1-service", restaurantBenchmark1);
        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark2 = new HashMap<>();
        restaurantBenchmark2.put(Availability.class, 0.1);//0.92
        restaurantBenchmark2.put(AverageResponseTime.class, 0.9);//0.132653061
        restaurantBenchmark2.put(Vulnerability.class, vul_r1[number-1]);//0.227891156
        benchmarkForImplementation.put("restaurant-2-service", restaurantBenchmark2);
        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark3 = new HashMap<>();
        restaurantBenchmark3.put(Availability.class, 0.1);
        restaurantBenchmark3.put(AverageResponseTime.class, 0.9);//0.1
        restaurantBenchmark3.put(Vulnerability.class, vul_r2[number-1]);//0.9
        benchmarkForImplementation.put("restaurant-3-service", restaurantBenchmark3);

        Map<Class<? extends QoSSpecification>, Double> restaurantCurrentQoS = new HashMap<>();//Initial configuration
        restaurantCurrentQoS.put(Availability.class, 0.1);
        restaurantCurrentQoS.put(AverageResponseTime.class, 0.9);
        currentQoSValues.put("RESTAURANT-SERVICE", restaurantCurrentQoS);

        // Ordering //
        List<String> orderingImplementations = List.of("ordering-service");
        serviceImplementations.put("ORDERING-SERVICE", orderingImplementations);

        Map<Class<? extends QoSSpecification>, Double> orderingBenchmark = new HashMap<>();
        orderingBenchmark.put(Availability.class, 0.9);//0.8
        orderingBenchmark.put(AverageResponseTime.class, 0.592307692);//0.655102041
        orderingBenchmark.put(Vulnerability.class, vul_r2[number-1]);
        benchmarkForImplementation.put("ordering-service", orderingBenchmark);

        Map<Class<? extends QoSSpecification>, Double> orderingCurrentQoS = new HashMap<>();
        orderingCurrentQoS.put(Availability.class, 0.9);
        orderingCurrentQoS.put(AverageResponseTime.class, 0.592307692);
        currentQoSValues.put("ORDERING-SERVICE", orderingCurrentQoS);

        // Delivery //
        List<String> deliveryProxyImplementations = List.of("delivery-proxy-1-service");
        serviceImplementations.put("DELIVERY-PROXY-SERVICE", deliveryProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyBenchmark1 = new HashMap<>();
        deliveryProxyBenchmark1.put(Availability.class, 0.633333333);//0.683333333
        deliveryProxyBenchmark1.put(AverageResponseTime.class, 0.1);//0.573469388
        deliveryProxyBenchmark1.put(Vulnerability.class, vul_r2[number-1]);
        benchmarkForImplementation.put("delivery-proxy-1-service", deliveryProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyCurrentQoS = new HashMap<>();
        deliveryProxyCurrentQoS.put(Availability.class, 0.633333333);
        deliveryProxyCurrentQoS.put(AverageResponseTime.class, 0.1);
        currentQoSValues.put("DELIVERY-PROXY-SERVICE", deliveryProxyCurrentQoS);

        // Payment //
        List<String> paymentProxyImplementations = List.of("payment-proxy-1-service");
        serviceImplementations.put("PAYMENT-PROXY-SERVICE", paymentProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyBenchmark1 = new HashMap<>();
        paymentProxyBenchmark1.put(Availability.class, 0.366666667);//0.766666667
        paymentProxyBenchmark1.put(AverageResponseTime.class, 0.715384615);//0.818367347
        paymentProxyBenchmark1.put(Vulnerability.class, vul_r2[number-1]);
        benchmarkForImplementation.put("payment-proxy-1-service", paymentProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyCurrentQoS = new HashMap<>();//Initial configuration
        paymentProxyCurrentQoS.put(Availability.class, 0.366666667);
        paymentProxyCurrentQoS.put(AverageResponseTime.class, 0.715384615);
        currentQoSValues.put("PAYMENT-PROXY-SERVICE", paymentProxyCurrentQoS);

        return createServiceMap(availabilityWeight,
                responseTimeWeight,
                vulnerabilityWeight,
                serviceImplementations,
                benchmarkForImplementation,
                currentQoSValues);
    }


    // RQ4 vulnerability axis: same scenario as RQ3_1_2 but the attack paths come from the
    // 136 independent domains via VulnAxisAP, so it is not capped at the 21 CVEs the
    // monolithic AED can switch on.
    // Measurement-only entry point for the managed-system size axis, so that RQ4.2's
    // two figures share one definition of risk assessment cost: the same independent
    // domains and the same critical-path timing as the vulnerability axis, instead of
    // EADSA on the monolithic AED. SizeAxisExperiment itself is left untouched; the
    // CVE set below is the one it fixes for the first implementation.
    private static final String[] SIZE_AXIS_CVES = {
            "CVE-2024-38286", "CVE-2024-12798", "CVE-2024-38820"
    };

    public static void RQ4_size_risk_profile(int scale) {
        for (int replica = 1; replica <= scale; replica++) {
            VulnAxisAPProfiler.profileReplica(replica, SIZE_AXIS_CVES);
        }
    }

    // Measurement-only entry point for the "risk assessment time vs number of
    // vulnerabilities" figure: it runs the attack-path sweep for the same
    // implementation the other RQ4 figures report (Restaurant-1-service) and stops
    // there, so no DTMC is built and PRISM is never called.
    public static void RQ4_vuln_risk_profile(int number) {
        ExcelToJsonConverter conv;
        try {
            conv = new ExcelToJsonConverter(FilePathConstants.configuration_rq4vuln_path);
        } catch (Exception e) {
            throw new ExceptionInInitializerError("Failed to initialize Excel converter: " + e.getMessage());
        }
        @SuppressWarnings("unchecked")
        List<String> cveList = (List<String>) conv.getValue(
                "Sub-scenario" + number, "RESTAURANT-SERVICE", "Restaurant-1-service", "vulnerabilitylist");
        VulnAxisAPProfiler.profile(number, cveList.toArray(new String[0]));
    }

    public static Map<String, Service> RQ4_vuln_SAQURE_ExpConfig(int number){
        double availabilityWeight = 0.3;
        double responseTimeWeight = 0.3;
        double vulnerabilityWeight = 0.4;
        try {
            converter = new ExcelToJsonConverter(FilePathConstants.configuration_rq4vuln_path);
        } catch (Exception e) {
            throw new ExceptionInInitializerError("Failed to initialize Excel converter: " + e.getMessage());
        }

        List<String> cveList0 = (List<String>) converter.getValue("Sub-scenario" + number, "RESTAURANT-SERVICE", "Restaurant-1-service", "vulnerabilitylist");
        String[] cveIds_r0 = cveList0.toArray(new String[0]);
        List<String> cveList1 = (List<String>) converter.getValue("Sub-scenario" + number, "RESTAURANT-SERVICE", "Restaurant-2-service", "vulnerabilitylist");
        String[] cveIds_r1 = cveList1.toArray(new String[0]);
        List<String> cveList2 = (List<String>) converter.getValue("Sub-scenario" + number, "RESTAURANT-SERVICE", "Restaurant-3-service", "vulnerabilitylist");
        String[] cveIds_r2 = cveList2.toArray(new String[0]);

        // for RQ3.2
        final double costS1R0 = VulnAxisAP.computeScenario(cveIds_r0);

        final double costS1R1 = VulnAxisAP.computeScenario(cveIds_r1);
        final double costS1R2 = VulnAxisAP.computeScenario(cveIds_r2);

        double[] costValues = {costS1R0, costS1R1, costS1R2};
        DynamicNormalize costNormalizer = new DynamicNormalize();
        costNormalizer.preProcessing(costValues);
        final double aS1R0 = (double) converter.getValue("Sub-scenario" + number, "RESTAURANT-SERVICE", "Restaurant-1-service", "availability");
        final double aS1R1 = (double) converter.getValue("Sub-scenario" + number, "RESTAURANT-SERVICE", "Restaurant-2-service", "availability");
        final double aS1R2 = (double) converter.getValue("Sub-scenario" + number, "RESTAURANT-SERVICE", "Restaurant-3-service", "availability");
        final double aS1O0 = (double) converter.getValue("Sub-scenario" + number, "ORDERING-SERVICE", "Ordering-service", "availability");
        final double aS1D0 = (double) converter.getValue("Sub-scenario" + number, "DELIVERY-PROXY-SERVICE", "Delivery-proxy-1-service", "availability");
        final double aS1P0 = (double) converter.getValue("Sub-scenario" + number, "PAYMENT-PROXY-SERVICE", "Payment-proxy-1-service", "availability");
        double[] avalibilities = {aS1R0, aS1R1, aS1R2, aS1O0, aS1D0, aS1P0};
        DynamicNormalize availabilityNormalizer = new DynamicNormalize();
        availabilityNormalizer.preProcessing(avalibilities);
        final int tS1R0 = (int) converter.getValue("Sub-scenario" + number, "RESTAURANT-SERVICE", "Restaurant-1-service", "responseTime");
        final int tS1R1 = (int) converter.getValue("Sub-scenario" + number, "RESTAURANT-SERVICE", "Restaurant-2-service", "responseTime");
        final int tS1R2 = (int) converter.getValue("Sub-scenario" + number, "RESTAURANT-SERVICE", "Restaurant-3-service", "responseTime");
        final int tS1O0 = (int) converter.getValue("Sub-scenario" + number, "ORDERING-SERVICE", "Ordering-service", "responseTime");
        final int tS1D0 = (int) converter.getValue("Sub-scenario" + number, "DELIVERY-PROXY-SERVICE", "Delivery-proxy-1-service", "responseTime");
        final int tS1P0 = (int) converter.getValue("Sub-scenario" + number, "PAYMENT-PROXY-SERVICE", "Payment-proxy-1-service", "responseTime");
        int[] responseTimes = {tS1R0, tS1R1, tS1R2, tS1O0, tS1D0, tS1P0};
        double[] doubleResponseTimes = Arrays.stream(responseTimes).asDoubleStream().toArray();
        DynamicNormalize responseTimeNormalizer = new DynamicNormalize();
        responseTimeNormalizer.preProcessing(doubleResponseTimes);
//        System.out.printf(
//                "Availability (Normalized):\n" +
//                        "  aS1R0: %.2f, aS1R1: %.2f, aS1R2: %.2f," +
//                        "  aS1O0: %.2f, aS1D0: %.2f, aS1P0: %.2f\n" +
//                        "Response Time (Normalized):\n" +
//                        "  tS1R0: %.2f, tS1R1: %.2f, tS1R2: %.2f," +
//                        "  tS1O0: %.2f, tS1D0: %.2f, tS1P0: %.2f\n",
//                aS1R0,//availabilityNormalizer.normalize(aS1R0),
//                aS1R1,//availabilityNormalizer.normalize(aS1R1),
//                aS1R2,//availabilityNormalizer.normalize(aS1R2),
//                aS1O0,//availabilityNormalizer.normalize(aS1O0),
//                aS1D0,//availabilityNormalizer.normalize(aS1D0),
//                aS1P0,//availabilityNormalizer.normalize(aS1P0),
//                responseTimeNormalizer.normalize(tS1R0),
//                responseTimeNormalizer.normalize(tS1R1),
//                responseTimeNormalizer.normalize(tS1R2),
//                responseTimeNormalizer.normalize(tS1O0),
//                responseTimeNormalizer.normalize(tS1D0),
//                responseTimeNormalizer.normalize(tS1P0)
//        );
//        System.out.printf("Cost (Normalized):\n" + " vs1r0: %.2f, vs1r1: %.2f, vs1r2: %.2f ", costNormalizer.normalize(costS1R0), costNormalizer.normalize(costS1R1), costNormalizer.normalize(costS1R2));

        Map<String, List<String>> serviceImplementations = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> benchmarkForImplementation = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> currentQoSValues = new HashMap<>();

        // Restaurant //
        List<String> restaurantImplementations = List.of("restaurant-1-service","restaurant-2-service","restaurant-3-service");
        serviceImplementations.put("RESTAURANT-SERVICE", restaurantImplementations);

        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark1 = new HashMap<>();//option configuration
        restaurantBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS1R0));//0.766666667
        restaurantBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1R0));//0.165306122
        restaurantBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS1R0));//0.633333333
        benchmarkForImplementation.put("restaurant-1-service", restaurantBenchmark1);
        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark2 = new HashMap<>();
        restaurantBenchmark2.put(Availability.class, availabilityNormalizer.normalize(aS1R1));//0.92
        restaurantBenchmark2.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1R1));//0.132653061
        restaurantBenchmark2.put(Vulnerability.class, costNormalizer.normalize(costS1R1));//0.227891156
        benchmarkForImplementation.put("restaurant-2-service", restaurantBenchmark2);
        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark3 = new HashMap<>();
        restaurantBenchmark3.put(Availability.class, availabilityNormalizer.normalize(aS1R2));
        restaurantBenchmark3.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1R2));//0.1
        restaurantBenchmark3.put(Vulnerability.class, costNormalizer.normalize(costS1R2));//0.9
        benchmarkForImplementation.put("restaurant-3-service", restaurantBenchmark3);

        Map<Class<? extends QoSSpecification>, Double> restaurantCurrentQoS = new HashMap<>();//Initial configuration
        restaurantCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS1R0));
        restaurantCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1R0));
        currentQoSValues.put("RESTAURANT-SERVICE", restaurantCurrentQoS);

        // Ordering //
        List<String> orderingImplementations = List.of("ordering-service");
        serviceImplementations.put("ORDERING-SERVICE", orderingImplementations);

        Map<Class<? extends QoSSpecification>, Double> orderingBenchmark = new HashMap<>();
        orderingBenchmark.put(Availability.class, availabilityNormalizer.normalize(aS1O0));//0.8
        orderingBenchmark.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1O0));//0.655102041
        orderingBenchmark.put(Vulnerability.class, costNormalizer.normalize(costS1R0));
        benchmarkForImplementation.put("ordering-service", orderingBenchmark);

        Map<Class<? extends QoSSpecification>, Double> orderingCurrentQoS = new HashMap<>();
        orderingCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS1O0));
        orderingCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1O0));
        currentQoSValues.put("ORDERING-SERVICE", orderingCurrentQoS);

        // Delivery //
        List<String> deliveryProxyImplementations = List.of("delivery-proxy-1-service");
        serviceImplementations.put("DELIVERY-PROXY-SERVICE", deliveryProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyBenchmark1 = new HashMap<>();
        deliveryProxyBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS1D0));//0.683333333
        deliveryProxyBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1D0));//0.573469388
        deliveryProxyBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS1R0));
        benchmarkForImplementation.put("delivery-proxy-1-service", deliveryProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyCurrentQoS = new HashMap<>();
        deliveryProxyCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS1D0));
        deliveryProxyCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1D0));
        currentQoSValues.put("DELIVERY-PROXY-SERVICE", deliveryProxyCurrentQoS);

        // Payment //
        List<String> paymentProxyImplementations = List.of("payment-proxy-1-service");
        serviceImplementations.put("PAYMENT-PROXY-SERVICE", paymentProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyBenchmark1 = new HashMap<>();
        paymentProxyBenchmark1.put(Availability.class, availabilityNormalizer.normalize(aS1P0));//0.766666667
        paymentProxyBenchmark1.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1P0));//0.818367347
        paymentProxyBenchmark1.put(Vulnerability.class, costNormalizer.normalize(costS1R0));
        benchmarkForImplementation.put("payment-proxy-1-service", paymentProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyCurrentQoS = new HashMap<>();//Initial configuration
        paymentProxyCurrentQoS.put(Availability.class, availabilityNormalizer.normalize(aS1P0));
        paymentProxyCurrentQoS.put(AverageResponseTime.class, responseTimeNormalizer.normalize(tS1P0));
        currentQoSValues.put("PAYMENT-PROXY-SERVICE", paymentProxyCurrentQoS);

        return createServiceMap(availabilityWeight,
                responseTimeWeight,
                vulnerabilityWeight,
                serviceImplementations,
                benchmarkForImplementation,
                currentQoSValues);
    }


    // RQ4 vulnerability axis, AQUA baseline: static vulnerability scores as in
    // RQ3_1_2_Aqua_ExpConfig, resampled from 21 to 100 points over the same 0.1-0.9 range.
    public static Map<String, Service> RQ4_vuln_Aqua_ExpConfig(int number){
        double availabilityWeight = 0.3;
        double responseTimeWeight = 0.3;
        double vulnerabilityWeight = 0.4;

        Map<String, List<String>> serviceImplementations = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> benchmarkForImplementation = new HashMap<>();
        Map<String, Map<Class<? extends QoSSpecification>, Double>> currentQoSValues = new HashMap<>();

        // Restaurant //
        double[] vul_r0 = {
                0.1, 0.110708846, 0.121417693, 0.132126539, 0.142835386, 0.153396712,
                0.161155162, 0.168913612, 0.176672062, 0.184430512, 0.192232672, 0.200428217,
                0.208623763, 0.216819309, 0.225014854, 0.232948142, 0.239395305, 0.245842468,
                0.25228963, 0.258736793, 0.265533632, 0.273729178, 0.281924724, 0.29012027,
                0.298315816, 0.306675272, 0.315526462, 0.324377651, 0.33322884, 0.342080029,
                0.350013318, 0.355804837, 0.361596356, 0.367387875, 0.373179394, 0.379812322,
                0.388007868, 0.396203413, 0.404398959, 0.412594505, 0.42079005, 0.428985596,
                0.437181142, 0.445376688, 0.453572234, 0.46176778, 0.469963325, 0.478158871,
                0.486354417, 0.494549962, 0.502745508, 0.510941053, 0.519136599, 0.527332145,
                0.53552769, 0.543723236, 0.551918782, 0.560114328, 0.568309874, 0.57650542,
                0.584635401, 0.592721673, 0.600807944, 0.608894216, 0.616980488, 0.625563956,
                0.634415145, 0.643266335, 0.652117524, 0.660968713, 0.669819903, 0.678671092,
                0.687522282, 0.696373471, 0.705224661, 0.711781097, 0.717572616, 0.723364135,
                0.729155654, 0.734947173, 0.742661914, 0.750857459, 0.759053005, 0.76724855,
                0.775444096, 0.781781985, 0.787792052, 0.793802119, 0.799812185, 0.805822252,
                0.81379925, 0.821994796, 0.830190341, 0.838385887, 0.846581433, 0.857164614,
                0.867873461, 0.878582307, 0.889291154, 0.9};
        double[] vul_r1 = {
                0.117849899, 0.128558745, 0.139267592, 0.149976438, 0.160685284, 0.171246611,
                0.179005061, 0.186763511, 0.194521961, 0.202280411, 0.210082571, 0.218278116,
                0.226473662, 0.234669208, 0.242864753, 0.250798041, 0.257245204, 0.263692367,
                0.270139529, 0.276586692, 0.283383531, 0.291579077, 0.299774622, 0.307970168,
                0.316165714, 0.32452517, 0.33337636, 0.342227549, 0.351078739, 0.359929928,
                0.367863217, 0.373654736, 0.379446255, 0.385237774, 0.391029293, 0.397662221,
                0.405857767, 0.414053312, 0.422248858, 0.430444404, 0.438639949, 0.446835495,
                0.455031041, 0.463226586, 0.471422132, 0.479617678, 0.487813223, 0.496008769,
                0.504204315, 0.512399861, 0.520595407, 0.528790952, 0.536986498, 0.545182044,
                0.553377589, 0.561573135, 0.569768681, 0.577964226, 0.586159772, 0.594355318,
                0.602485299, 0.610571571, 0.618657842, 0.626744114, 0.634830386, 0.643413854,
                0.652265044, 0.661116233, 0.669967423, 0.678818612, 0.687669802, 0.696520991,
                0.70537218, 0.714223369, 0.723074559, 0.729630995, 0.735422514, 0.741214033,
                0.747005552, 0.752797071, 0.760511812, 0.768707358, 0.776902903, 0.785098449,
                0.793293995, 0.799631884, 0.805641951, 0.811652018, 0.817662084, 0.823672151,
                0.831649149, 0.839844695, 0.84804024, 0.856235786, 0.864431332, 0.871588775,
                0.878691581, 0.885794387, 0.892897194, 0.9};
        double[] vul_r2 = {
                0.117849899, 0.125608349, 0.133366799, 0.141125249, 0.148883699, 0.156664003,
                0.164859549, 0.173055095, 0.18125064, 0.189446186, 0.197466893, 0.203914056,
                0.210361219, 0.216808381, 0.223255544, 0.229964964, 0.23816051, 0.246356056,
                0.254551601, 0.262747147, 0.271073822, 0.279925011, 0.2887762, 0.29762739,
                0.306478579, 0.314564851, 0.32035637, 0.326147889, 0.331939408, 0.337730927,
                0.344243654, 0.352439199, 0.360634745, 0.368830291, 0.377025836, 0.385221382,
                0.393416928, 0.401612473, 0.409808019, 0.418003565, 0.42619911, 0.434394656,
                0.442590202, 0.450785748, 0.458981294, 0.46717684, 0.475372385, 0.483567931,
                0.491763477, 0.499959022, 0.508154568, 0.516350113, 0.524545659, 0.532741205,
                0.54093675, 0.549072196, 0.557158467, 0.565244739, 0.573331011, 0.581417283,
                0.589962506, 0.598813695, 0.607664884, 0.616516073, 0.625367263, 0.634218452,
                0.643069642, 0.651920831, 0.660772021, 0.66962321, 0.67633263, 0.682124149,
                0.687915668, 0.693707187, 0.699498706, 0.707093245, 0.715288791, 0.723484337,
                0.731679882, 0.739875428, 0.74632259, 0.752332657, 0.758342724, 0.764352791,
                0.770362858, 0.778230582, 0.786426127, 0.794621673, 0.802817219, 0.811012764,
                0.821470281, 0.832179127, 0.842887974, 0.85359682, 0.864305667, 0.871588775,
                0.878691581, 0.885794387, 0.892897194, 0.9};
        List<String> restaurantImplementations = List.of("restaurant-1-service","restaurant-2-service","restaurant-3-service");
        serviceImplementations.put("RESTAURANT-SERVICE", restaurantImplementations);

        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark1 = new HashMap<>();//option configuration
        restaurantBenchmark1.put(Availability.class, 0.1);//0.766666667
        restaurantBenchmark1.put(AverageResponseTime.class, 0.9);//0.165306122
        restaurantBenchmark1.put(Vulnerability.class, vul_r0[number-1]);//0.633333333
        benchmarkForImplementation.put("restaurant-1-service", restaurantBenchmark1);
        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark2 = new HashMap<>();
        restaurantBenchmark2.put(Availability.class, 0.1);//0.92
        restaurantBenchmark2.put(AverageResponseTime.class, 0.9);//0.132653061
        restaurantBenchmark2.put(Vulnerability.class, vul_r1[number-1]);//0.227891156
        benchmarkForImplementation.put("restaurant-2-service", restaurantBenchmark2);
        Map<Class<? extends QoSSpecification>, Double> restaurantBenchmark3 = new HashMap<>();
        restaurantBenchmark3.put(Availability.class, 0.1);
        restaurantBenchmark3.put(AverageResponseTime.class, 0.9);//0.1
        restaurantBenchmark3.put(Vulnerability.class, vul_r2[number-1]);//0.9
        benchmarkForImplementation.put("restaurant-3-service", restaurantBenchmark3);

        Map<Class<? extends QoSSpecification>, Double> restaurantCurrentQoS = new HashMap<>();//Initial configuration
        restaurantCurrentQoS.put(Availability.class, 0.1);
        restaurantCurrentQoS.put(AverageResponseTime.class, 0.9);
        currentQoSValues.put("RESTAURANT-SERVICE", restaurantCurrentQoS);

        // Ordering //
        List<String> orderingImplementations = List.of("ordering-service");
        serviceImplementations.put("ORDERING-SERVICE", orderingImplementations);

        Map<Class<? extends QoSSpecification>, Double> orderingBenchmark = new HashMap<>();
        orderingBenchmark.put(Availability.class, 0.9);//0.8
        orderingBenchmark.put(AverageResponseTime.class, 0.592307692);//0.655102041
        orderingBenchmark.put(Vulnerability.class, vul_r2[number-1]);
        benchmarkForImplementation.put("ordering-service", orderingBenchmark);

        Map<Class<? extends QoSSpecification>, Double> orderingCurrentQoS = new HashMap<>();
        orderingCurrentQoS.put(Availability.class, 0.9);
        orderingCurrentQoS.put(AverageResponseTime.class, 0.592307692);
        currentQoSValues.put("ORDERING-SERVICE", orderingCurrentQoS);

        // Delivery //
        List<String> deliveryProxyImplementations = List.of("delivery-proxy-1-service");
        serviceImplementations.put("DELIVERY-PROXY-SERVICE", deliveryProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyBenchmark1 = new HashMap<>();
        deliveryProxyBenchmark1.put(Availability.class, 0.633333333);//0.683333333
        deliveryProxyBenchmark1.put(AverageResponseTime.class, 0.1);//0.573469388
        deliveryProxyBenchmark1.put(Vulnerability.class, vul_r2[number-1]);
        benchmarkForImplementation.put("delivery-proxy-1-service", deliveryProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> deliveryProxyCurrentQoS = new HashMap<>();
        deliveryProxyCurrentQoS.put(Availability.class, 0.633333333);
        deliveryProxyCurrentQoS.put(AverageResponseTime.class, 0.1);
        currentQoSValues.put("DELIVERY-PROXY-SERVICE", deliveryProxyCurrentQoS);

        // Payment //
        List<String> paymentProxyImplementations = List.of("payment-proxy-1-service");
        serviceImplementations.put("PAYMENT-PROXY-SERVICE", paymentProxyImplementations);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyBenchmark1 = new HashMap<>();
        paymentProxyBenchmark1.put(Availability.class, 0.366666667);//0.766666667
        paymentProxyBenchmark1.put(AverageResponseTime.class, 0.715384615);//0.818367347
        paymentProxyBenchmark1.put(Vulnerability.class, vul_r2[number-1]);
        benchmarkForImplementation.put("payment-proxy-1-service", paymentProxyBenchmark1);

        Map<Class<? extends QoSSpecification>, Double> paymentProxyCurrentQoS = new HashMap<>();//Initial configuration
        paymentProxyCurrentQoS.put(Availability.class, 0.366666667);
        paymentProxyCurrentQoS.put(AverageResponseTime.class, 0.715384615);
        currentQoSValues.put("PAYMENT-PROXY-SERVICE", paymentProxyCurrentQoS);

        return createServiceMap(availabilityWeight,
                responseTimeWeight,
                vulnerabilityWeight,
                serviceImplementations,
                benchmarkForImplementation,
                currentQoSValues);
    }

    public static Map<String, Service> createServiceMap(
            double availabilityWeight,
            double responseTimeWeight,
            double vulnerabilityWeight,
            Map<String, List<String>> serviceImplementations,
            Map<String, Map<Class<? extends QoSSpecification>, Double>> benchmarkForImplementation,
            Map<String, Map<Class<? extends QoSSpecification>, Double>> currentQoSValues) {
        //Set weights
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

