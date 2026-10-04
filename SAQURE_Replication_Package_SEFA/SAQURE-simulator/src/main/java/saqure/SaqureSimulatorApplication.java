package saqure;

import saqure.Analyzer.EADSA;
import saqure.utils.infrastructure.adaptation.options.*;
import saqure.utils.infrastructure.adaptation.specifications.Availability;
import saqure.utils.infrastructure.adaptation.specifications.AverageResponseTime;
import saqure.utils.infrastructure.adaptation.specifications.QoSSpecification;
import saqure.utils.infrastructure.adaptation.specifications.Vulnerability;
import saqure.utils.infrastructure.architecture.Instance;
import saqure.utils.infrastructure.architecture.Service;
import saqure.utils.infrastructure.architecture.ServiceConfiguration;
import saqure.utils.infrastructure.architecture.ServiceImplementation;
import saqure.utils.SizeAxisExperiment;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import saqure.Analyzer.RiskTiming;
import saqure.Analyzer.VulnAxisAP;
import saqure.Planner.PrismModelChecker;
import saqure.Planner.TransitionAvailability;
import saqure.utils.FilePathConstants;

import java.io.File;
import java.nio.file.Files;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static saqure.Planner.PrismModelChecker.reverseUpdating;
import static saqure.Planner.PrismModelChecker.update_AED_AEDI;
import static saqure.utils.ServiceGraphUtils.buildPossibleGraphs;
import static saqure.utils.ServiceGraphUtils.jsonGraph;
import static saqure.utils.SimulationsUtils.*;

@SpringBootApplication
@Slf4j
public class SaqureSimulatorApplication {

//    private static final Logger log = LoggerFactory.getLogger(RamsesPlannerSimulatorApplication.class);

    // SEFA scale factor used by all RQ1-RQ4 experiments: 500x SEFA = 4 * 500 = 2000 core structural states.
    private static final int DEFAULT_SEFA_SCALE = 1;

    public static void main(String[] args) {
        SpringApplication.run(SaqureSimulatorApplication.class, args);

        String caseName = "";
        String serviceOverride = "";
        String runtime = "";
        String dynamicParam = "";
        String scaleParam = "";

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-c":
                case "--config":
                    if (i + 1 < args.length) {
                        caseName = args[++i];
                    }
                    break;
                case "-s":
                case "--service":
                    if (i + 1 < args.length) {
                        serviceOverride = args[++i];
                    }
                    break;
                case "-t":
                case "--time":
                    if (i + 1 < args.length) {
                        runtime = args[++i]; // "T1" or "T2"
                    }
                    break;
                case "-d":
                case "--dynamic":
                    if (i + 1 < args.length) {
                        dynamicParam = args[++i];
                    }
                    break;
                case "-x":
                case "--scale":
                    if (i + 1 < args.length) {
                        scaleParam = args[++i]; // SEFA scale factor, e.g. 1, 25, 500
                    }
                    break;
                case "-h":
                case "--help":
                    printHelp();
                    return;
            }
        }

        if (caseName.isEmpty()) {
            System.err.println("Error: -c/--config is required. Use -h for help.");
            return;
        }

        // Determine service name: use override if provided, otherwise auto-detect from case name
        String serviceName = serviceOverride.isEmpty() ? getServiceNameByCase(caseName) : serviceOverride;
        if (serviceName == null) {
            System.err.println("Error: Unknown case name '" + caseName + "'. Use -h for help.");
            return;
        }

        // Parse dynamic parameter for RQ4 (from -d flag or file)
        int param = dynamicParam.isEmpty() ? readParam() : Integer.parseInt(dynamicParam);

        // Parse the SEFA scale factor (from -x flag, 500x by default)
        int sefaScale;
        try {
            sefaScale = scaleParam.isEmpty() ? DEFAULT_SEFA_SCALE : Integer.parseInt(scaleParam);
        } catch (NumberFormatException e) {
            System.err.println("Error: -x/--scale must be a positive integer, but was '" + scaleParam + "'");
            return;
        }
        if (sefaScale < 1) {
            System.err.println("Error: -x/--scale must be >= 1, but was " + sefaScale);
            return;
        }
        int sefaCoreStates = PrismModelChecker.coreStatesForScale(sefaScale);

        // RQ4 size axis: the managed system itself is scaled, so offline configuration, risk
        // assessment and decision are all measured against the same -x value.
        if (caseName.equals("RQ4_size_SAQURE") || caseName.equals("RQ4_size_AQUA")) {
            SizeAxisExperiment.run(sefaScale, caseName.endsWith("AQUA")
                    ? SizeAxisExperiment.Approach.AQUA
                    : SizeAxisExperiment.Approach.SAQURE);
            return;
        }

        // Measurement-only case for the vulnerability-axis risk assessment figure.
        if (caseName.equals("RQ4_vuln_risk_SAQURE")) {
            RQ4_vuln_risk_profile(param);
            return;
        }
        if (caseName.equals("RQ4_size_risk_SAQURE")) {
            RQ4_size_risk_profile(sefaScale);
            return;
        }

        // Simulate runtime change at T2, for RQ2 and RQ3
        PrismModelChecker.ExternalChanges externalChange = getExternalChangeForCase(caseName);
        boolean isT2 = runtime.equals("T2") && (caseName.startsWith("RQ2") || caseName.startsWith("RQ3")) && externalChange != null;
        if (isT2) {
            update_AED_AEDI(externalChange);
        }

        // Runtime decision time spans the Analyzer's risk assessment of every candidate
        // implementation and the Planner's search, so start accumulating before the
        // configuration is built -- that is where the assessments happen.
        loadTransitionAvailabilities(caseName);
        VulnAxisAP.warmUpLookup();
        RiskTiming.reset();

        // Experiment Configuration
        Map<String, Service> servicesMap = getServicesMapByConfigName(caseName, param);
        if (servicesMap == null) {
            System.err.println("Error: Unknown config case '" + caseName + "'");
            return;
        }
        Service serviceToAdapt = servicesMap.get(serviceName);

        if (serviceToAdapt == null) {
            System.err.println("Error: Service '" + serviceName + "' not found");
            System.err.println("Available services: " + servicesMap.keySet());
            return;
        }

        Map<String, List<AdaptationOption>> proposedAdaptationOptions = new HashMap<>();
        proposedAdaptationOptions.put(serviceToAdapt.getServiceId(), List.of(
                createChangeImplementationOption(serviceToAdapt, Availability.class),
                createChangeImplementationOption(serviceToAdapt, AverageResponseTime.class),
                createChangeImplementationOption(serviceToAdapt, Vulnerability.class)
        ));
        String currentGraph = jsonGraph(servicesMap, null);

        log.info("SEFA DTMC scale: {}x -> {} x {} = {} core structural states, plus START, success and failure = {} reachable states",
                sefaScale, PrismModelChecker.CORE_STATES_PER_SEFA_REPLICA, sefaScale, sefaCoreStates, sefaCoreStates + 3);

        Instant plannerStart = Instant.now();
        //Simulate SAQURE and calculate cost
        buildPossibleGraphs(servicesMap, filterOptions(proposedAdaptationOptions), currentGraph, sefaCoreStates);
        Instant plannerEnd = Instant.now();

        long riskAssessmentMillis = RiskTiming.totalMillis();
        long plannerMillis = Duration.between(plannerStart, plannerEnd).toMillis();
        log.debug("Risk assessment: {} implementations, {}ms; Planner: {}ms",
                RiskTiming.count(), riskAssessmentMillis, plannerMillis);
        log.info("Runtime decision time: {}ms", riskAssessmentMillis + plannerMillis);

        // Reverse simulate runtime change at T2
        if (isT2) {
            reverseUpdating(externalChange);
        }
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
                // Filter the maximum value
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
                // Filter the minimum value
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
                // Choose the minimum value directly
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

    // RQ1 reads Configuration_RQ1; RQ2 and RQ3 (which reuses RQ2's configurations) read
    // Configuration_RQ2. The sub-scenario is the case's trailing index, e.g. RQ3_SAQURE_s2_nodyPa.
    private static final Pattern RQ1_TO_RQ3_CASE = Pattern.compile("^RQ([123])_.*_[sS](\\d+)(_nodyPa)?$");

    // The DTMC transitions take the configuration sheet's availabilities (Fig. 8). Loaded before
    // the decision-time clock starts; other experiments keep the normalised availability.
    private static void loadTransitionAvailabilities(String caseName) {
        Matcher m = RQ1_TO_RQ3_CASE.matcher(caseName);
        if (!m.matches()) {
            TransitionAvailability.clear();
            return;
        }
        String sheet = m.group(1).equals("1") ? FilePathConstants.configuration_rq1_path : FilePathConstants.configuration_rq2_path;
        TransitionAvailability.load(sheet, "Sub-scenario" + m.group(2));
    }

    private static Map<String, Service> getServicesMapByConfigName(String caseName, int param) {
        switch (caseName) {
            // RQ1 SAQURE parallel (no SEQUENTIAL)
            case "RQ1_SAQURE_para_S1": return RQ1_s1_SAQURE_ExpConfig();
            case "RQ1_SAQURE_para_S2": return RQ1_s2_SAQURE_ExpConfig();
            case "RQ1_SAQURE_para_S3": return RQ1_s3_SAQURE_ExpConfig();
            case "RQ1_SAQURE_para_S4": return RQ1_s4_SAQURE_ExpConfig();
            case "RQ1_SAQURE_para_S5": return RQ1_s5_SAQURE_ExpConfig();

            // RQ1 SAQURE sequential
            case "RQ1_SAQURE_seq_S1": setCompMode(EADSA.ComputationMode.SEQUENTIAL); return RQ1_s1_SAQURE_ExpConfig();
            case "RQ1_SAQURE_seq_S2": setCompMode(EADSA.ComputationMode.SEQUENTIAL); return RQ1_s2_SAQURE_ExpConfig();
            case "RQ1_SAQURE_seq_S3": setCompMode(EADSA.ComputationMode.SEQUENTIAL); return RQ1_s3_SAQURE_ExpConfig();
            case "RQ1_SAQURE_seq_S4": setCompMode(EADSA.ComputationMode.SEQUENTIAL); return RQ1_s4_SAQURE_ExpConfig();
            case "RQ1_SAQURE_seq_S5": setCompMode(EADSA.ComputationMode.SEQUENTIAL); return RQ1_s5_SAQURE_ExpConfig();



            // RQ1 Aqua (all sequential)
            case "RQ1_Aqua_s1": setCompMode(EADSA.ComputationMode.SEQUENTIAL); return RQ1_s1_Aqua_ExpConfig();
            case "RQ1_Aqua_s2": setCompMode(EADSA.ComputationMode.SEQUENTIAL); return RQ1_s2_Aqua_ExpConfig();
            case "RQ1_Aqua_s3": setCompMode(EADSA.ComputationMode.SEQUENTIAL); return RQ1_s3_Aqua_ExpConfig();
            case "RQ1_Aqua_s4": setCompMode(EADSA.ComputationMode.SEQUENTIAL); return RQ1_s4_Aqua_ExpConfig();
            case "RQ1_Aqua_s5": setCompMode(EADSA.ComputationMode.SEQUENTIAL); return RQ1_s5_Aqua_ExpConfig();

            // RQ1 RAMSES (all sequential)
            case "RQ1_RAMSES_s1": setCompMode(EADSA.ComputationMode.SEQUENTIAL); return RQ1_s1_RAMSES_ExpConfig();
            case "RQ1_RAMSES_s2": setCompMode(EADSA.ComputationMode.SEQUENTIAL); return RQ1_s2_RAMSES_ExpConfig();
            case "RQ1_RAMSES_s3": setCompMode(EADSA.ComputationMode.SEQUENTIAL); return RQ1_s3_RAMSES_ExpConfig();
            case "RQ1_RAMSES_s4": setCompMode(EADSA.ComputationMode.SEQUENTIAL); return RQ1_s4_RAMSES_ExpConfig();
            case "RQ1_RAMSES_s5": setCompMode(EADSA.ComputationMode.SEQUENTIAL); return RQ1_s5_RAMSES_ExpConfig();

            // RQ2
            case "RQ2_SAQURE_s1": return RQ2_s1_SAQURE_ExpConfig();
            case "RQ2_AQUA_s1": setCompMode(EADSA.ComputationMode.SEQUENTIAL); return RQ2_s1_Aqua_ExpConfig();
            case "RQ2_SAQURE_s2": return RQ2_s2_SAQURE_ExpConfig();
            case "RQ2_AQUA_s2": setCompMode(EADSA.ComputationMode.SEQUENTIAL); return RQ2_s2_Aqua_ExpConfig();
            case "RQ2_SAQURE_s3": return RQ2_s3_SAQURE_ExpConfig();
            case "RQ2_AQUA_s3": setCompMode(EADSA.ComputationMode.SEQUENTIAL); return RQ2_s3_Aqua_ExpConfig();

            // RQ3
            case "RQ3_SAQURE_s1": return RQ2_s1_SAQURE_ExpConfig();
            case "RQ3_SAQURE_s1_nodyPa": return RQ2_s1_SAQURE_nodyPa_ExpConfig();
            case "RQ3_SAQURE_s2": return RQ2_s2_SAQURE_ExpConfig();
            case "RQ3_SAQURE_s2_nodyPa": return RQ2_s2_SAQURE_nodyPa_ExpConfig();
            case "RQ3_SAQURE_s3": return RQ2_s3_SAQURE_ExpConfig();
            case "RQ3_SAQURE_s3_nodyPa": return RQ2_s3_SAQURE_nodyPa_ExpConfig();

            // RQ4 (with dynamic parameter)
            case "RQ4_1_1_SAQURE": return RQ3_1_1_SAQURE_ExpConfig(param);
            case "RQ4_1_2_SAQURE": return RQ3_1_2_SAQURE_ExpConfig(param);
            case "RQ4_vuln_SAQURE": return RQ4_vuln_SAQURE_ExpConfig(param);
            case "RQ4_1_1_AQUA": return RQ3_1_1_Aqua_ExpConfig(param);
            case "RQ4_1_2_AQUA": return RQ3_1_2_Aqua_ExpConfig(param);
            case "RQ4_vuln_AQUA": return RQ4_vuln_Aqua_ExpConfig(param);

            default:
                System.err.println("Unknown config: " + caseName);
                return null;
        }
    }

    private static String getServiceNameByCase(String caseName) {
        switch (caseName) {
            // RQ4 size axis → RESTAURANT-SERVICE
            case "RQ4_size_SAQURE":
            case "RQ4_size_AQUA":
                return "RESTAURANT-SERVICE";
            // RQ1 S1 → RESTAURANT-SERVICE
            case "RQ1_SAQURE_para_S1":
            case "RQ1_SAQURE_seq_S1":
            case "RQ1_Aqua_s1":
            case "RQ1_RAMSES_s1":
                return "RESTAURANT-SERVICE";
            // RQ1 S2 → RESTAURANT-SERVICE
            case "RQ1_SAQURE_para_S2":
            case "RQ1_SAQURE_seq_S2":
            case "RQ1_Aqua_s2":
            case "RQ1_RAMSES_s2":
                return "RESTAURANT-SERVICE";
            // RQ1 S3 → ORDERING-SERVICE
            case "RQ1_SAQURE_para_S3":
            case "RQ1_SAQURE_seq_S3":
            case "RQ1_Aqua_s3":
            case "RQ1_RAMSES_s3":
                return "ORDERING-SERVICE";
            // RQ1 S4 → DELIVERY-PROXY-SERVICE
            case "RQ1_SAQURE_para_S4":
            case "RQ1_SAQURE_seq_S4":
            case "RQ1_Aqua_s4":
            case "RQ1_RAMSES_s4":
                return "DELIVERY-PROXY-SERVICE";
            // RQ1 S5 → PAYMENT-PROXY-SERVICE
            case "RQ1_SAQURE_para_S5":
            case "RQ1_SAQURE_seq_S5":
            case "RQ1_Aqua_s5":
            case "RQ1_RAMSES_s5":
                return "PAYMENT-PROXY-SERVICE";

            // RQ2 s1 → RESTAURANT-SERVICE
            case "RQ2_SAQURE_s1":
            case "RQ2_AQUA_s1":
                return "RESTAURANT-SERVICE";
            // RQ2 s2 → PAYMENT-PROXY-SERVICE
            case "RQ2_SAQURE_s2":
            case "RQ2_AQUA_s2":
                return "PAYMENT-PROXY-SERVICE";
            // RQ2 s3 → ORDERING-SERVICE
            case "RQ2_SAQURE_s3":
            case "RQ2_AQUA_s3":
                return "ORDERING-SERVICE";

            // RQ3 s1 → RESTAURANT-SERVICE
            case "RQ3_SAQURE_s1":
            case "RQ3_SAQURE_s1_nodyPa":
                return "RESTAURANT-SERVICE";
            // RQ3 s2 → PAYMENT-PROXY-SERVICE
            case "RQ3_SAQURE_s2":
            case "RQ3_SAQURE_s2_nodyPa":
                return "PAYMENT-PROXY-SERVICE";
            // RQ3 s3 → ORDERING-SERVICE
            case "RQ3_SAQURE_s3":
            case "RQ3_SAQURE_s3_nodyPa":
                return "ORDERING-SERVICE";

            // RQ4
            case "RQ4_1_1_SAQURE":
            case "RQ4_1_1_AQUA":
                return "PAYMENT-PROXY-SERVICE";
            case "RQ4_1_2_SAQURE":
            case "RQ4_1_2_AQUA":
            case "RQ4_vuln_SAQURE":
            case "RQ4_vuln_AQUA":
            case "RQ4_vuln_risk_SAQURE":
            case "RQ4_size_risk_SAQURE":
                return "RESTAURANT-SERVICE";

            default:
                return null;
        }
    }

    private static PrismModelChecker.ExternalChanges getExternalChangeForCase(String caseName) {
        if (caseName.contains("_s1")) {
            return PrismModelChecker.ExternalChanges.AEDI_REQUEST_BLOCK_RESTAURANT;
        } else if (caseName.contains("_s2")) {
            return PrismModelChecker.ExternalChanges.AEDI_CHANGE_VERSION_PAYMENT;
        } else if (caseName.contains("_s3")) {
            return PrismModelChecker.ExternalChanges.AED_ACTION_COST_ORDERING;
        }
        return null;
    }

    private static int readParam() {
        try {
            File paramFile = new File("SAQURE-simulator/tmp/param.txt");
            if (paramFile.exists()) {
                String content = new String(Files.readAllBytes(paramFile.toPath())).trim();
                return Integer.parseInt(content);
            }
        } catch (Exception e) {
            log.warn("Unable to read parameter file, using default parameter 1");
        }
        return 1;
    }

    private static void printHelp() {
        System.out.println("Usage: java -jar your-app.jar [options]");
        System.out.println("Options:");
        System.out.println("  -c, --config <case>       Experiment case name (required)");
        System.out.println("  -s, --service <name>      Service name override (auto-detected if omitted)");
        System.out.println("  -t, --time <T1|T2>        Runtime phase (T1 or T2, for RQ2/RQ3)");
        System.out.println("  -d, --dynamic <value>     Dynamic parameter value (for RQ4)");
        System.out.println("  -x, --scale <n>           SEFA scale factor (default 500, i.e. 4 x 500 = 2000 core structural states)");
        System.out.println("  -h, --help                Show this help message");
        System.out.println();
        System.out.println("RQ1 cases:");
        System.out.println("  RQ1_SAQURE_para_S1..S5    SAQURE parallel");
        System.out.println("  RQ1_SAQURE_seq_S1..S5     SAQURE sequential");
        System.out.println("  RQ1_Aqua_s1..s5           Aqua (sequential)");
        System.out.println("  RQ1_RAMSES_s1..s5          RAMSES (sequential)");
        System.out.println("RQ2 cases (use -t T1/T2):");
        System.out.println("  RQ2_SAQURE_s1..s3, RQ2_AQUA_s1..s3");
        System.out.println("RQ3 cases (use -t T1/T2):");
        System.out.println("  RQ3_SAQURE_s1..s3, RQ3_SAQURE_s1_nodyPa..s3_nodyPa");
        System.out.println("RQ4 cases (use -d <param>):");
        System.out.println("  RQ4_1_1_SAQURE, RQ4_1_2_SAQURE, RQ4_1_1_AQUA, RQ4_1_2_AQUA");
        System.out.println("  RQ4_vuln_SAQURE, RQ4_vuln_AQUA   (vulnerability axis, -d 1..100)");
        System.out.println("  RQ4_vuln_risk_SAQURE             (risk assessment only, no PRISM)");
        System.out.println("RQ4 size axis (use -x <scale>):");
        System.out.println("  RQ4_size_SAQURE, RQ4_size_AQUA   offline configuration, risk assessment and decision time");
        System.out.println();
        System.out.println("Services: RESTAURANT-SERVICE, ORDERING-SERVICE, DELIVERY-PROXY-SERVICE, PAYMENT-PROXY-SERVICE");
    }
}
