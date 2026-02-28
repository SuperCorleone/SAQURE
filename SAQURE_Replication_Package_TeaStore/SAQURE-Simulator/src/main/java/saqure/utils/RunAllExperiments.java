package saqure.utils;

import saqure.Planner.PlannerCommandComputing;
import saqure.SaqureSimulatorApplication;
import saqure.domain.adaptation.options.*;
import saqure.domain.adaptation.specifications.Availability;
import saqure.domain.adaptation.specifications.AverageResponseTime;
import saqure.domain.adaptation.specifications.QoSSpecification;
import saqure.domain.adaptation.specifications.Vulnerability;
import saqure.domain.architecture.Instance;
import saqure.domain.architecture.Service;
import saqure.domain.architecture.ServiceConfiguration;
import saqure.domain.architecture.ServiceImplementation;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;

import java.io.File;
import java.nio.file.Files;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

import static saqure.utils.PrismModelChecker.*;
import static saqure.utils.ServiceGraphUtils.*;
import static saqure.utils.SimulationsUtils.*;

@SpringBootApplication
@Slf4j
public class RunAllExperiments {

    public static void man(String[] args) {
        ConfigurableApplicationContext context = null;
        try {
            context = SpringApplication.run(SaqureSimulatorApplication.class, args);

            String RQ = readRQ();
            log.info("Start: {}", RQ);

            if ("RQ1".equals(RQ)) {
                runRQ1();
            } else if ("RQ2".equals(RQ)) {
                runRQ2();
            } else {
                log.error("unknown experiment: {}", RQ);
            }

            log.info("Experiment {} completed successfully", RQ);

        } catch (Exception e) {
            log.error("Experiment failed with error", e);
            System.exit(1);
        } finally {
            // Ensure the Spring context is properly closed.
            if (context != null && context.isActive()) {
                SpringApplication.exit(context, () -> 0);
            }
            System.exit(0);
        }
    }

    private static void runRQ1() {
        String commandName = readCmd();
        Map<String, RQ1_part1> commandMap1 = new HashMap<>();
        for (RQ1_part1 cmd : RQ1_part1.values()) {
            commandMap1.put(cmd.name(), cmd);
        }
        if (commandMap1.containsKey(commandName)) {
            RQ1_part1 selectedCmd = commandMap1.get(commandName);
            runRQ1Part1(selectedCmd);
        }
    }

    private static void runRQ1Part1(RQ1_part1 selectedCmd) {
        try {
            log.info("running experiment of: {}", selectedCmd.name());

            Map<String, Service> servicesMap = selectedCmd.excute();
            Service serviceToAdapt = servicesMap.get(selectedCmd.serviceName());

            Map<String, List<AdaptationOption>> proposedAdaptationOptions = new HashMap<>();
            proposedAdaptationOptions.put(serviceToAdapt.getServiceId(), List.of(
                    createChangeImplementationOption(serviceToAdapt, Availability.class),
                    createChangeImplementationOption(serviceToAdapt, AverageResponseTime.class),
                    createChangeImplementationOption(serviceToAdapt, Vulnerability.class)
            ));

            String currentGraph = jsonGraph(servicesMap, null);
            Instant ramsesV3Start = Instant.now();
            buildPossibleGraphs(servicesMap, filterOptions(proposedAdaptationOptions), currentGraph, 2000);
            Instant ramsesV3End = Instant.now();
            log.info("Time to extract best option RamsesV3: {}ms",
                    Duration.between(ramsesV3Start, ramsesV3End).toMillis());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static void runRQ2() {
        Map<String, RQ2> commandMap = new HashMap<>();
        for (RQ2 cmd : RQ2.values()) {
            commandMap.put(cmd.name(), cmd);
        }
        Map<String, ExternalChanges> extelnalMap = new HashMap<>();
        extelnalMap.put("RQ2_s1_SAQURE_ExpConfig", ExternalChanges.AEDI_CHANGE_VERSION_WEBUI);
        extelnalMap.put("RQ2_s2_SAQURE_ExpConfig", ExternalChanges.AEDI_CLOSE_SECURITY_CONTROL_AUTHENTICATION);
        extelnalMap.put("RQ2_s3_SAQURE_ExpConfig", ExternalChanges.AEDI_CHANGE_VERSION_PERSISTENCE);

        try {
            String commandName = readCmd();
            RQ2 selectedCmd = commandMap.get(commandName);
            log.info("running experiment of: {}", selectedCmd.name());

            update_AED_AEDI(extelnalMap.get(commandName));

            Map<String, Service> servicesMap = selectedCmd.excute();
            Service serviceToAdapt = servicesMap.get(selectedCmd.serviceName());

            Map<String, List<AdaptationOption>> proposedAdaptationOptions = new HashMap<>();
            proposedAdaptationOptions.put(serviceToAdapt.getServiceId(), List.of(
                    createChangeImplementationOption(serviceToAdapt, Availability.class),
                    createChangeImplementationOption(serviceToAdapt, AverageResponseTime.class),
                    createChangeImplementationOption(serviceToAdapt, Vulnerability.class)
            ));

            String currentGraph = jsonGraph(servicesMap, null);
            Instant ramsesV3Start = Instant.now();
            buildPossibleGraphs(servicesMap, filterOptions(proposedAdaptationOptions), currentGraph, 2000);
            Instant ramsesV3End = Instant.now();
            log.info("Time to extract best option RamsesV3: {}ms",
                    Duration.between(ramsesV3Start, ramsesV3End).toMillis());

            reverseUpdating(extelnalMap.get(commandName));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public interface Command {
        Map<String, Service> excute();

        void excute1();

        String serviceName();
    }

    public enum RQ1_part1 implements Command {
        RQ1_SAQURE_para_S1, RQ1_SAQURE_para_S2, RQ1_SAQURE_para_S3, RQ1_SAQURE_para_S4, RQ1_SAQURE_para_S5,
        RQ1_SAQURE_seq_S1, RQ1_SAQURE_seq_S2, RQ1_SAQURE_seq_S3, RQ1_SAQURE_seq_S4, RQ1_SAQURE_seq_S5,
        RQ1_Aqua_s1, RQ1_Aqua_s2, RQ1_Aqua_s3, RQ1_Aqua_s4, RQ1_Aqua_s5,
        RQ1_QoS_s1, RQ1_QoS_s2, RQ1_QoS_s3, RQ1_QoS_s4, RQ1_QoS_s5;

        @Override
        public Map<String, Service> excute() {
            switch (this) {
                case RQ1_SAQURE_para_S1:
                    return RQ1_SAQURE_s1_ExpConfig();
                case RQ1_SAQURE_para_S2:
                    return RQ1_SAQURE_s2_ExpConfig();
                case RQ1_SAQURE_para_S3:
                    return RQ1_SAQURE_s3_ExpConfig();
                case RQ1_SAQURE_para_S4:
                    return RQ1_SAQURE_s4_ExpConfig();
                case RQ1_SAQURE_para_S5:
                    return RQ1_SAQURE_s5_ExpConfig();

                case RQ1_SAQURE_seq_S1:
                    setCompMode(PlannerCommandComputing.ComputationMode.SEQUENTIAL);
                    return RQ1_SAQURE_s1_ExpConfig();
                case RQ1_SAQURE_seq_S2:
                    setCompMode(PlannerCommandComputing.ComputationMode.SEQUENTIAL);
                    return RQ1_SAQURE_s2_ExpConfig();
                case RQ1_SAQURE_seq_S3:
                    setCompMode(PlannerCommandComputing.ComputationMode.SEQUENTIAL);
                    return RQ1_SAQURE_s3_ExpConfig();
                case RQ1_SAQURE_seq_S4:
                    setCompMode(PlannerCommandComputing.ComputationMode.SEQUENTIAL);
                    return RQ1_SAQURE_s4_ExpConfig();
                case RQ1_SAQURE_seq_S5:
                    setCompMode(PlannerCommandComputing.ComputationMode.SEQUENTIAL);
                    return RQ1_SAQURE_s5_ExpConfig();

                case RQ1_Aqua_s1:
                    setCompMode(PlannerCommandComputing.ComputationMode.SEQUENTIAL);
                    return RQ1_Aqua_s1_ExpConfig();
                case RQ1_Aqua_s2:
                    setCompMode(PlannerCommandComputing.ComputationMode.SEQUENTIAL);
                    return RQ1_Aqua_s2_ExpConfig();
                case RQ1_Aqua_s3:
                    setCompMode(PlannerCommandComputing.ComputationMode.SEQUENTIAL);
                    return RQ1_Aqua_s3_ExpConfig();
                case RQ1_Aqua_s4:
                    setCompMode(PlannerCommandComputing.ComputationMode.SEQUENTIAL);
                    return RQ1_Aqua_s4_ExpConfig();
                case RQ1_Aqua_s5:
                    setCompMode(PlannerCommandComputing.ComputationMode.SEQUENTIAL);
                    return RQ1_Aqua_s5_ExpConfig();

                case RQ1_QoS_s1:
                    setCompMode(PlannerCommandComputing.ComputationMode.SEQUENTIAL);
                    return RQ1_Ramses_s1_ExpConfig();
                case RQ1_QoS_s2:
                    setCompMode(PlannerCommandComputing.ComputationMode.SEQUENTIAL);
                    return RQ1_Ramses_s2_ExpConfig();
                case RQ1_QoS_s3:
                    setCompMode(PlannerCommandComputing.ComputationMode.SEQUENTIAL);
                    return RQ1_Ramses_s3_ExpConfig();
                case RQ1_QoS_s4:
                    setCompMode(PlannerCommandComputing.ComputationMode.SEQUENTIAL);
                    return RQ1_Ramses_s4_ExpConfig();
                case RQ1_QoS_s5:
                    setCompMode(PlannerCommandComputing.ComputationMode.SEQUENTIAL);
                    return RQ1_Ramses_s5_ExpConfig();

                default:
                    log.warn("Default execution: RQ1_SAQURE_s1_ExpConfig");
                    return RQ1_SAQURE_s1_ExpConfig();
            }
        }

        @Override
        public String serviceName() {
            switch (this) {
                case RQ1_SAQURE_para_S1:
                case RQ1_QoS_s1:
                case RQ1_Aqua_s1:
                case RQ1_SAQURE_seq_S1:
                    return "WEBUI-SERVICE";
                case RQ1_SAQURE_para_S2:
                case RQ1_QoS_s2:
                case RQ1_Aqua_s2:
                case RQ1_SAQURE_seq_S2:
                    return "WEBUI-SERVICE";
                case RQ1_SAQURE_para_S3:
                case RQ1_QoS_s3:
                case RQ1_Aqua_s3:
                case RQ1_SAQURE_seq_S3:
                    return "AUTHENTICATION-SERVICE";
                case RQ1_SAQURE_para_S4:
                case RQ1_QoS_s4:
                case RQ1_Aqua_s4:
                case RQ1_SAQURE_seq_S4:
                    return "PERSISTENCE-SERVICE";
                case RQ1_SAQURE_para_S5:
                case RQ1_QoS_s5:
                case RQ1_Aqua_s5:
                case RQ1_SAQURE_seq_S5:
                    return "IMAGE-SERVICE"; // Adjust according to the actual situation.
                default:
                    return "WEBUI-SERVICE";
            }
        }

        @Override
        public void excute1() {
            // RQ1_part1: Do not implement this method
        }
    }

    public enum RQ2 implements Command {
        RQ2_SAQURE_s1, RQ2_SAQURE_s2, RQ2_SAQURE_s3;

        @Override
        public Map<String, Service> excute() {
            switch (this) {
                case RQ2_SAQURE_s1:
                    return RQ2_s1_SAQURE_ExpConfig();
                case RQ2_SAQURE_s2:
                    return RQ2_s2_SAQURE_ExpConfig();
                case RQ2_SAQURE_s3:
                    return RQ2_s3_SAQURE_ExpConfig();
                default:
                    log.warn("default: RQ2_s1_SAQURE_ExpConfig");
                    return RQ2_s1_SAQURE_ExpConfig();
            }
        }

        @Override
        public String serviceName() {
            switch (this) {
                case RQ2_SAQURE_s1:
                    return "WEBUI-SERVICE";
                case RQ2_SAQURE_s2:
                    return "AUTHENTICATION-SERVICE";
                case RQ2_SAQURE_s3:
                    return "PERSISTENCE-SERVICE";
                default:
                    return "WEBUI-SERVICE";
            }
        }

        @Override
        public void excute1() {
        }
    }

    private static final Map<String, Class<?>> COMMAND_RQ1 = Map.of(
            "RQ1_part1", RQ1_part1.class);

    private static String readRQ() {
        try {
            File paramFile = new File("/tmp/serviceName.txt");
            if (paramFile.exists()) {
                String content = new String(Files.readAllBytes(paramFile.toPath())).trim();
                return content;
            }
        } catch (Exception e) {
            log.warn("Unable to read parameter file, using default research question RQ1", e);
        }
        return "RQ1";
    }

    private static String readCmd() {
        try {
            File paramFile = new File("/tmp/cmd.txt");
            if (paramFile.exists()) {
                String content = new String(Files.readAllBytes(paramFile.toPath())).trim();
                return content;
            }
        } catch (Exception e) {
            log.warn("Unable to read cmd", e);
        }
        return "";
    }

    // Ensure that each service retains only one ChangeImplementationOption.
    private static Map<String, List<AdaptationOption>> filterOptions(Map<String, List<AdaptationOption>> proposedAdaptationOptions) {
        Map<String, List<AdaptationOption>> filteredOptions = new HashMap<>();
        proposedAdaptationOptions.forEach((s, adaptationOptions) -> {
            List<AdaptationOption> filtered = new LinkedList<>();
            for (AdaptationOption adaptationOption : adaptationOptions) {
                if (adaptationOption.getClass().equals(ChangeImplementationOption.class)) {
                    if (filtered.stream().noneMatch(ao -> ao.getClass().equals(ChangeImplementationOption.class)))
                        ((ChangeImplementationOption) adaptationOption).getPossibleImplementations().forEach(implementationId -> {
                            ChangeImplementationOption changeImplementationOption = new ChangeImplementationOption(adaptationOption.getServiceId(), adaptationOption.getServiceImplementationId(), ((ChangeImplementationOption) adaptationOption).getNumberOfInstances(), ((ChangeImplementationOption) adaptationOption).getPossibleImplementations(), null, null);
                            changeImplementationOption.setNewImplementationId(implementationId);
                            filtered.add(changeImplementationOption);
                        });
                } else {
                    filtered.add(adaptationOption);
                }
            }
            filteredOptions.put(s, filtered);
        });
        return filteredOptions;
    }

    private static AdaptationOption createChangeImplementationOption(Service service, Class<? extends QoSSpecification> goal) {
        List<String> possibleImplementations = new LinkedList<>();
        // collect Possible Implementations
        for (String possibleImplementationId : service.getPossibleImplementations().keySet())
            if (!possibleImplementationId.equals(service.getCurrentImplementationId()))
                possibleImplementations.add(possibleImplementationId);
        // create ChangeImplementationOption
        ChangeImplementationOption option = new ChangeImplementationOption(service.getServiceId(), service.getCurrentImplementationId(), service.getInstances().size(), possibleImplementations, goal, "Changing implementation");
        return handleChangeImplementation(option, service);
    }

    public static ChangeImplementationOption handleChangeImplementation(ChangeImplementationOption changeImplementationOption, Service service) {
        String bestImplementationId = null;
        double bestImplementationBenefit = 0;
        for (String implementationId : changeImplementationOption.getPossibleImplementations()) {
            // Get implementation details and QoS target type
            Class<? extends QoSSpecification> goal = changeImplementationOption.getQosGoal();
            ServiceImplementation implementation = service.getPossibleImplementations().get(implementationId);
            // Calculate benefit value based on target type
            if (Availability.class == goal) {
                double benchmark = implementation.getBenchmark(changeImplementationOption.getQosGoal());
                benchmark = benchmark * implementation.getPreference();
                if (bestImplementationId == null) {
                    bestImplementationId = implementationId;
                    bestImplementationBenefit = benchmark;
                }
                // filter maximum value
                if (benchmark > bestImplementationBenefit) {
                    bestImplementationId = implementationId;
                    bestImplementationBenefit = benchmark;
                }
            } else if (AverageResponseTime.class == goal) {
                double benchmark = implementation.getBenchmark(changeImplementationOption.getQosGoal());
                benchmark = benchmark / implementation.getPreference();
                if (bestImplementationId == null) {
                    bestImplementationId = implementationId;
                    bestImplementationBenefit = benchmark;
                }
                // filter minimum value
                if (benchmark < bestImplementationBenefit) {
                    bestImplementationId = implementationId;
                    bestImplementationBenefit = benchmark;
                }
            } else if (Vulnerability.class == goal) {
                double vulnerabilityScore = implementation.getVulnerabilityScore();
                if (bestImplementationId == null) {
                    bestImplementationId = implementationId;
                    bestImplementationBenefit = vulnerabilityScore;
                }
                // choose minimum value directly
                if (vulnerabilityScore < bestImplementationBenefit) {
                    bestImplementationId = implementationId;
                    bestImplementationBenefit = vulnerabilityScore;
                }
            }
        }
        changeImplementationOption.setNewImplementationId(bestImplementationId);

        return changeImplementationOption;
    }

    public static AddInstanceOption handleAddInstance(AddInstanceOption addInstanceOption, Service service) {
        if (service.getConfiguration().getLoadBalancerType() == ServiceConfiguration.LoadBalancerType.WEIGHTED_RANDOM) {
            double shutdownThreshold = service.getCurrentImplementation().getInstanceLoadShutdownThreshold() / (service.getInstances().size() + 1);
            Map<String, Double> weightsRedistributed = reduceWeightsForNewInstance(service.getLoadBalancerWeights(), 1);
            weightsRedistributed.put("NEWINSTANCE", 1 / (double) (weightsRedistributed.size() + 1));
            weightsRedistributed = recursivelyRemoveInstancesUnderThreshold(weightsRedistributed, shutdownThreshold);
            addInstanceOption.setNewInstanceWeight(weightsRedistributed.remove("NEWINSTANCE"));
            addInstanceOption.setOldInstancesNewWeights(weightsRedistributed);
            Map<String, Double> finalWeightsRedistributed = weightsRedistributed;
            addInstanceOption.setInstancesToShutdownIds(service.getLoadBalancerWeights().keySet().stream().filter(id -> !finalWeightsRedistributed.containsKey(id)).toList());
            if (!addInstanceOption.getInstancesToShutdownIds().isEmpty()) {
                log.warn("The Analyse module proposed to add an instance to service {} but also to shutdown some instances.", service.getServiceId());
                log.warn("New Instance weight: {}", addInstanceOption.getNewInstanceWeight());
                log.warn("Old instances new weights: {}", addInstanceOption.getOldInstancesNewWeights());
                log.warn("Instances to shutdown: {}", addInstanceOption.getInstancesToShutdownIds());
            }
        }
        return addInstanceOption;
    }

    private static Map<String, Double> recursivelyRemoveInstancesUnderThreshold(Map<String, Double> originalWeights, double threshold) {
        List<String> instancesToShutdownIds = originalWeights.entrySet().stream().filter(entry -> entry.getValue() < threshold).map(Map.Entry::getKey).toList();
        if (instancesToShutdownIds.isEmpty()) // Stop when no instances are under the threshold
            return originalWeights;
        double newThreshold = threshold * originalWeights.size() / (originalWeights.size() - instancesToShutdownIds.size());
        Map<String, Double> newWeights = redistributeWeight(originalWeights, instancesToShutdownIds);
        return recursivelyRemoveInstancesUnderThreshold(newWeights, newThreshold);
    }

    private static Map<String, Double> reduceWeightsForNewInstance(Map<String, Double> weights, int newNumberOfNewInstances) {
        Map<String, Double> newWeights = new HashMap<>();
        int oldNumberOfInstances = weights.size();
        for (String instanceId : weights.keySet()) {
            newWeights.put(instanceId, weights.get(instanceId) * (double) oldNumberOfInstances / (double) (oldNumberOfInstances + newNumberOfNewInstances));
        }
        return newWeights;
    }

    private static Map<String, Double> redistributeWeight(Map<String, Double> originalWeights, List<String> instancesToRemoveIds) {
        Map<String, Double> newWeights = new HashMap<>();
        double totalWeightToRemove = originalWeights.entrySet().stream().filter(entry -> instancesToRemoveIds.contains(entry.getKey())).mapToDouble(Map.Entry::getValue).sum();
        int newSizeOfActiveInstances = originalWeights.size() - instancesToRemoveIds.size();
        double weightToAdd = totalWeightToRemove / newSizeOfActiveInstances;
        for (String instanceId : originalWeights.keySet()) {
            if (!instancesToRemoveIds.contains(instanceId)) { // if the instance is not in the list of instances to shutdown
                double weight = originalWeights.get(instanceId) + weightToAdd; // increment the weight of the instance with 1/newSizeOfActiveInstances of the total weight to remove
                newWeights.put(instanceId, weight);
            }
        }
        return newWeights;
    }

    public static AdaptationOption extractBestOptionRamses(Service service, List<AdaptationOption> toCompare) {
        if (toCompare.isEmpty())
            return null;
        Map<Class<? extends QoSSpecification>, Double> benefits = new HashMap<>();
        Map<Class<? extends QoSSpecification>, AdaptationOption> bestOptionForGoal = new HashMap<>();
        log.info("{}: Extracting best option from {} options", service.getServiceId(), toCompare.size());

        for (AdaptationOption adaptationOption : toCompare) {
            List<Instance> instances = service.getInstances();
            if (adaptationOption.getQosGoal() == Availability.class) {
                double availabilityEstimation = 0.0;
                if (service.getConfiguration().getLoadBalancerType() == ServiceConfiguration.LoadBalancerType.WEIGHTED_RANDOM) {
                    if (ChangeLoadBalancerWeightsOption.class.equals(adaptationOption.getClass())) {
                        ChangeLoadBalancerWeightsOption changeLoadBalancerWeightsOption = (ChangeLoadBalancerWeightsOption) adaptationOption;
                        for (Instance instance : instances) {
                            if (!changeLoadBalancerWeightsOption.getInstancesToShutdownIds().contains(instance.getInstanceId()))
                                availabilityEstimation += changeLoadBalancerWeightsOption.getNewWeights().get(instance.getInstanceId()) * instance.getCurrentValueForQoS(Availability.class).getDoubleValue();
                        }
                    } else if (AddInstanceOption.class.equals(adaptationOption.getClass())) {
                        AddInstanceOption addInstanceOption = (AddInstanceOption) adaptationOption;
                        for (Instance instance : instances) {
                            if (!addInstanceOption.getInstancesToShutdownIds().contains(instance.getInstanceId()))
                                availabilityEstimation += addInstanceOption.getOldInstancesNewWeights().get(instance.getInstanceId()) * instance.getCurrentValueForQoS(Availability.class).getDoubleValue();
                        }
                        availabilityEstimation += addInstanceOption.getNewInstanceWeight() * service.getCurrentImplementation().getBenchmark(Availability.class);
                    } else if (ShutdownInstanceOption.class.equals(adaptationOption.getClass())) {
                        ShutdownInstanceOption shutdownInstanceOption = (ShutdownInstanceOption) adaptationOption;
                        for (Instance instance : instances) {
                            if (!instance.getInstanceId().equals(shutdownInstanceOption.getInstanceToShutdownId()))
                                availabilityEstimation += shutdownInstanceOption.getNewWeights().get(instance.getInstanceId()) * instance.getCurrentValueForQoS(Availability.class).getDoubleValue();
                        }
                    }
                } else {
                    if (AddInstanceOption.class.equals(adaptationOption.getClass())) {
                        for (Instance instance : instances) {
                            availabilityEstimation += instance.getCurrentValueForQoS(Availability.class).getDoubleValue();
                        }
                        availabilityEstimation += service.getCurrentImplementation().getBenchmark(Availability.class);
                        availabilityEstimation /= instances.size() + 1;
                    } else if (ShutdownInstanceOption.class.equals(adaptationOption.getClass())) {
                        ShutdownInstanceOption shutdownInstanceOption = (ShutdownInstanceOption) adaptationOption;
                        for (Instance instance : instances) {
                            if (!instance.getInstanceId().equals(shutdownInstanceOption.getInstanceToShutdownId()))
                                availabilityEstimation += instance.getCurrentValueForQoS(Availability.class).getDoubleValue();
                        }
                        availabilityEstimation /= instances.size() - 1;
                    }
                }
                if (ChangeImplementationOption.class.equals(adaptationOption.getClass())) {
                    ChangeImplementationOption changeImplementationOption = (ChangeImplementationOption) adaptationOption;
                    availabilityEstimation = service.getPossibleImplementations().get(changeImplementationOption.getNewImplementationId()).getBenchmark(Availability.class);
                }
                double newBenefit = availabilityEstimation / service.getCurrentValueForQoS(Availability.class).getDoubleValue();
                log.debug(service.getServiceId() + ": " + adaptationOption.getClass().getSimpleName() + " option for Availability. BENEFIT: " + newBenefit);

                if (newBenefit > 1 && (!benefits.containsKey(Availability.class) || newBenefit > benefits.get(Availability.class))) {
                    benefits.put(Availability.class, newBenefit);
                    bestOptionForGoal.put(Availability.class, adaptationOption);
                }
            } else if (adaptationOption.getQosGoal() == AverageResponseTime.class) {
                double avgResponseTimeEstimation = 0.0;
                if (service.getConfiguration().getLoadBalancerType() == ServiceConfiguration.LoadBalancerType.WEIGHTED_RANDOM) {
                    if (ChangeLoadBalancerWeightsOption.class.equals(adaptationOption.getClass())) {
                        ChangeLoadBalancerWeightsOption changeLoadBalancerWeightsOption = (ChangeLoadBalancerWeightsOption) adaptationOption;
                        for (Instance instance : instances) {
                            if (!changeLoadBalancerWeightsOption.getInstancesToShutdownIds().contains(instance.getInstanceId()))
                                avgResponseTimeEstimation += changeLoadBalancerWeightsOption.getNewWeights().get(instance.getInstanceId()) * instance.getCurrentValueForQoS(AverageResponseTime.class).getDoubleValue();
                        }
                    } else if (AddInstanceOption.class.equals(adaptationOption.getClass())) {
                        AddInstanceOption addInstanceOption = (AddInstanceOption) adaptationOption;
                        for (Instance instance : instances) {
                            if (!addInstanceOption.getInstancesToShutdownIds().contains(instance.getInstanceId()))
                                avgResponseTimeEstimation += addInstanceOption.getOldInstancesNewWeights().get(instance.getInstanceId()) * instance.getCurrentValueForQoS(AverageResponseTime.class).getDoubleValue();
                        }
                        avgResponseTimeEstimation += addInstanceOption.getNewInstanceWeight() * service.getCurrentImplementation().getBenchmark(AverageResponseTime.class);
                    } else if (ShutdownInstanceOption.class.equals(adaptationOption.getClass())) {
                        ShutdownInstanceOption shutdownInstanceOption = (ShutdownInstanceOption) adaptationOption;
                        for (Instance instance : instances) {
                            if (!instance.getInstanceId().equals(shutdownInstanceOption.getInstanceToShutdownId()))
                                avgResponseTimeEstimation += shutdownInstanceOption.getNewWeights().get(instance.getInstanceId()) * instance.getCurrentValueForQoS(AverageResponseTime.class).getDoubleValue();
                        }
                    }

                } else {
                    if (AddInstanceOption.class.equals(adaptationOption.getClass())) {
                        for (Instance instance : instances) {
                            avgResponseTimeEstimation += instance.getCurrentValueForQoS(AverageResponseTime.class).getDoubleValue();
                        }
                        avgResponseTimeEstimation += service.getCurrentImplementation().getBenchmark(AverageResponseTime.class);
                        avgResponseTimeEstimation /= instances.size() + 1;
                    } else if (ShutdownInstanceOption.class.equals(adaptationOption.getClass())) {
                        ShutdownInstanceOption shutdownInstanceOption = (ShutdownInstanceOption) adaptationOption;
                        for (Instance instance : instances) {
                            if (!instance.getInstanceId().equals(shutdownInstanceOption.getInstanceToShutdownId()))
                                avgResponseTimeEstimation += instance.getCurrentValueForQoS(AverageResponseTime.class).getDoubleValue();
                        }
                        avgResponseTimeEstimation /= instances.size() - 1;
                    }

                }
                if (ChangeImplementationOption.class.equals(adaptationOption.getClass())) {
                    ChangeImplementationOption changeImplementationOption = (ChangeImplementationOption) adaptationOption;
                    avgResponseTimeEstimation = service.getPossibleImplementations().get(changeImplementationOption.getNewImplementationId()).getBenchmark(AverageResponseTime.class);
                }
                double newBenefit = service.getCurrentValueForQoS(AverageResponseTime.class).getDoubleValue() / avgResponseTimeEstimation;
                log.debug(service.getServiceId() + ": " + adaptationOption.getClass().getSimpleName() + " option for AVG RT. BENEFIT: " + newBenefit);
                if (newBenefit > 1 && (!benefits.containsKey(AverageResponseTime.class) || newBenefit > benefits.get(AverageResponseTime.class))) {
                    benefits.put(AverageResponseTime.class, newBenefit);
                    bestOptionForGoal.put(AverageResponseTime.class, adaptationOption);
                }
            }
        }
        Class<? extends QoSSpecification> bestBenefitClass = null;

        for (Class<? extends QoSSpecification> qosSpecification : benefits.keySet()) {
            double newPreference = service.getQoSSpecifications().get(qosSpecification).getWeight();
            if (bestBenefitClass == null || benefits.get(qosSpecification) * newPreference > benefits.get(bestBenefitClass) * service.getQoSSpecifications().get(bestBenefitClass).getWeight())
                bestBenefitClass = qosSpecification;
        }
        if (bestBenefitClass == null) {
            log.warn("{}: No beneficial adaptation option", service.getServiceId());
            return null;
        }


        log.info("\n\t\t\t\t{}: Selected option {} for {} with benefit {}. \n\t\t\t\tDetails: {}", service.getServiceId(), bestOptionForGoal.get(bestBenefitClass).getClass().getSimpleName(), bestBenefitClass.getSimpleName(), benefits.get(bestBenefitClass), bestOptionForGoal.get(bestBenefitClass));
        return bestOptionForGoal.get(bestBenefitClass);
    }

    public static AdaptationOption extractBestOptionRamsesV2(Service service, List<AdaptationOption> toCompare) {
        if (toCompare.isEmpty())
            return null;
        Map<Class<? extends QoSSpecification>, Double> benefits = new HashMap<>();
        Map<Class<? extends QoSSpecification>, AdaptationOption> bestOptionForGoal = new HashMap<>();
        log.info("{}: Extracting best option from {} options", service.getServiceId(), toCompare.size());

        for (AdaptationOption adaptationOption : toCompare) {
            List<Instance> instances = service.getInstances();
            if (adaptationOption.getQosGoal() == Availability.class) {
                double availabilityEstimation = 0.0;
                if (service.getConfiguration().getLoadBalancerType() == ServiceConfiguration.LoadBalancerType.WEIGHTED_RANDOM) {
                    if (ChangeLoadBalancerWeightsOption.class.equals(adaptationOption.getClass())) {
                        ChangeLoadBalancerWeightsOption changeLoadBalancerWeightsOption = (ChangeLoadBalancerWeightsOption) adaptationOption;
                        for (Instance instance : instances) {
                            if (!changeLoadBalancerWeightsOption.getInstancesToShutdownIds().contains(instance.getInstanceId()))
                                availabilityEstimation += changeLoadBalancerWeightsOption.getNewWeights().get(instance.getInstanceId()) * instance.getCurrentValueForQoS(Availability.class).getDoubleValue();
                        }
                    } else if (AddInstanceOption.class.equals(adaptationOption.getClass())) {
                        AddInstanceOption addInstanceOption = (AddInstanceOption) adaptationOption;
                        for (Instance instance : instances) {
                            if (!addInstanceOption.getInstancesToShutdownIds().contains(instance.getInstanceId()))
                                availabilityEstimation += addInstanceOption.getOldInstancesNewWeights().get(instance.getInstanceId()) * instance.getCurrentValueForQoS(Availability.class).getDoubleValue();
                        }
                        availabilityEstimation += addInstanceOption.getNewInstanceWeight() * service.getCurrentImplementation().getBenchmark(Availability.class);
                    } else if (ShutdownInstanceOption.class.equals(adaptationOption.getClass())) {
                        ShutdownInstanceOption shutdownInstanceOption = (ShutdownInstanceOption) adaptationOption;
                        for (Instance instance : instances) {
                            if (!instance.getInstanceId().equals(shutdownInstanceOption.getInstanceToShutdownId()))
                                availabilityEstimation += shutdownInstanceOption.getNewWeights().get(instance.getInstanceId()) * instance.getCurrentValueForQoS(Availability.class).getDoubleValue();
                        }
                    }
                } else {
                    if (AddInstanceOption.class.equals(adaptationOption.getClass())) {
                        for (Instance instance : instances) {
                            availabilityEstimation += instance.getCurrentValueForQoS(Availability.class).getDoubleValue();
                        }
                        availabilityEstimation += service.getCurrentImplementation().getBenchmark(Availability.class);
                        availabilityEstimation /= instances.size() + 1;
                    } else if (ShutdownInstanceOption.class.equals(adaptationOption.getClass())) {
                        ShutdownInstanceOption shutdownInstanceOption = (ShutdownInstanceOption) adaptationOption;
                        for (Instance instance : instances) {
                            if (!instance.getInstanceId().equals(shutdownInstanceOption.getInstanceToShutdownId()))
                                availabilityEstimation += instance.getCurrentValueForQoS(Availability.class).getDoubleValue();
                        }
                        availabilityEstimation /= instances.size() - 1;
                    }
                }
                if (ChangeImplementationOption.class.equals(adaptationOption.getClass())) {
                    ChangeImplementationOption changeImplementationOption = (ChangeImplementationOption) adaptationOption;
                    availabilityEstimation = service.getPossibleImplementations().get(changeImplementationOption.getNewImplementationId()).getBenchmark(Availability.class);
                }
                double newBenefit = availabilityEstimation / service.getCurrentValueForQoS(Availability.class).getDoubleValue();
                log.debug(service.getServiceId() + ": " + adaptationOption.getClass().getSimpleName() + " option for Availability. BENEFIT: " + newBenefit);

                if (newBenefit > 1 && (!benefits.containsKey(Availability.class) || newBenefit > benefits.get(Availability.class))) {
                    benefits.put(Availability.class, newBenefit);
                    bestOptionForGoal.put(Availability.class, adaptationOption);
                }
            } else if (adaptationOption.getQosGoal() == AverageResponseTime.class) {
                double avgResponseTimeEstimation = 0.0;
                if (service.getConfiguration().getLoadBalancerType() == ServiceConfiguration.LoadBalancerType.WEIGHTED_RANDOM) {
                    if (ChangeLoadBalancerWeightsOption.class.equals(adaptationOption.getClass())) {
                        ChangeLoadBalancerWeightsOption changeLoadBalancerWeightsOption = (ChangeLoadBalancerWeightsOption) adaptationOption;
                        for (Instance instance : instances) {
                            if (!changeLoadBalancerWeightsOption.getInstancesToShutdownIds().contains(instance.getInstanceId()))
                                avgResponseTimeEstimation += changeLoadBalancerWeightsOption.getNewWeights().get(instance.getInstanceId()) * instance.getCurrentValueForQoS(AverageResponseTime.class).getDoubleValue();
                        }
                    } else if (AddInstanceOption.class.equals(adaptationOption.getClass())) {
                        AddInstanceOption addInstanceOption = (AddInstanceOption) adaptationOption;
                        for (Instance instance : instances) {
                            if (!addInstanceOption.getInstancesToShutdownIds().contains(instance.getInstanceId()))
                                avgResponseTimeEstimation += addInstanceOption.getOldInstancesNewWeights().get(instance.getInstanceId()) * instance.getCurrentValueForQoS(AverageResponseTime.class).getDoubleValue();
                        }
                        avgResponseTimeEstimation += addInstanceOption.getNewInstanceWeight() * service.getCurrentImplementation().getBenchmark(AverageResponseTime.class);
                    } else if (ShutdownInstanceOption.class.equals(adaptationOption.getClass())) {
                        ShutdownInstanceOption shutdownInstanceOption = (ShutdownInstanceOption) adaptationOption;
                        for (Instance instance : instances) {
                            if (!instance.getInstanceId().equals(shutdownInstanceOption.getInstanceToShutdownId()))
                                avgResponseTimeEstimation += shutdownInstanceOption.getNewWeights().get(instance.getInstanceId()) * instance.getCurrentValueForQoS(AverageResponseTime.class).getDoubleValue();
                        }
                    }

                } else {
                    if (AddInstanceOption.class.equals(adaptationOption.getClass())) {
                        for (Instance instance : instances) {
                            avgResponseTimeEstimation += instance.getCurrentValueForQoS(AverageResponseTime.class).getDoubleValue();
                        }
                        avgResponseTimeEstimation += service.getCurrentImplementation().getBenchmark(AverageResponseTime.class);
                        avgResponseTimeEstimation /= instances.size() + 1;
                    } else if (ShutdownInstanceOption.class.equals(adaptationOption.getClass())) {
                        ShutdownInstanceOption shutdownInstanceOption = (ShutdownInstanceOption) adaptationOption;
                        for (Instance instance : instances) {
                            if (!instance.getInstanceId().equals(shutdownInstanceOption.getInstanceToShutdownId()))
                                avgResponseTimeEstimation += instance.getCurrentValueForQoS(AverageResponseTime.class).getDoubleValue();
                        }
                        avgResponseTimeEstimation /= instances.size() - 1;
                    }

                }
                if (ChangeImplementationOption.class.equals(adaptationOption.getClass())) {
                    ChangeImplementationOption changeImplementationOption = (ChangeImplementationOption) adaptationOption;
                    avgResponseTimeEstimation = service.getPossibleImplementations().get(changeImplementationOption.getNewImplementationId()).getBenchmark(AverageResponseTime.class);
                }
                double newBenefit = service.getCurrentValueForQoS(AverageResponseTime.class).getDoubleValue() / avgResponseTimeEstimation;
                log.debug(service.getServiceId() + ": " + adaptationOption.getClass().getSimpleName() + " option for AVG RT. BENEFIT: " + newBenefit);
                if (newBenefit > 1 && (!benefits.containsKey(AverageResponseTime.class) || newBenefit > benefits.get(AverageResponseTime.class))) {
                    benefits.put(AverageResponseTime.class, newBenefit);
                    bestOptionForGoal.put(AverageResponseTime.class, adaptationOption);
                }
            } else if (adaptationOption.getQosGoal() == Vulnerability.class && (ChangeImplementationOption.class.equals(adaptationOption.getClass()))) {
                ChangeImplementationOption changeImplementationOption = (ChangeImplementationOption) adaptationOption;
                double vulnerabilityScore = service.getPossibleImplementations().get(changeImplementationOption.getNewImplementationId()).getVulnerabilityScore();
                double newBenefit = service.getCurrentVulnerabilityScore() / vulnerabilityScore;
                log.debug(service.getServiceId() + ": " + adaptationOption.getClass().getSimpleName() + " option for Vulnerability. BENEFIT: " + newBenefit);
                if (newBenefit > 1 && (!benefits.containsKey(Vulnerability.class) || newBenefit > benefits.get(Vulnerability.class))) {
                    benefits.put(Vulnerability.class, newBenefit);
                    bestOptionForGoal.put(Vulnerability.class, adaptationOption);
                }

            }
        }
        Class<? extends QoSSpecification> bestBenefitClass = null;

        for (Class<? extends QoSSpecification> qosSpecification : benefits.keySet()) {
            double newPreference = service.getQoSSpecifications().get(qosSpecification).getWeight();
            if (bestBenefitClass == null || benefits.get(qosSpecification) * newPreference > benefits.get(bestBenefitClass) * service.getQoSSpecifications().get(bestBenefitClass).getWeight())
                bestBenefitClass = qosSpecification;
        }
        if (bestBenefitClass == null) {
            log.warn("{}: No beneficial adaptation option", service.getServiceId());
            return null;
        }


        log.info("\n\t\t\t\t{}: Selected option {} for {} with benefit {}. \n\t\t\t\tDetails: {}", service.getServiceId(), bestOptionForGoal.get(bestBenefitClass).getClass().getSimpleName(), bestBenefitClass.getSimpleName(), benefits.get(bestBenefitClass), bestOptionForGoal.get(bestBenefitClass));
        return bestOptionForGoal.get(bestBenefitClass);
    }
}

