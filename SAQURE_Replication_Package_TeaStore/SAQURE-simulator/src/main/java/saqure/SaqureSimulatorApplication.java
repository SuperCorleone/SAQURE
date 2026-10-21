package saqure;

import saqure.Analyzer.EADSA;
import saqure.Analyzer.RiskTiming;
import saqure.utils.infrastructure.adaptation.options.*;
import saqure.utils.infrastructure.adaptation.specifications.Availability;
import saqure.utils.infrastructure.adaptation.specifications.AverageResponseTime;
import saqure.utils.infrastructure.adaptation.specifications.QoSSpecification;
import saqure.utils.infrastructure.adaptation.specifications.Vulnerability;
import saqure.utils.infrastructure.architecture.Instance;
import saqure.utils.infrastructure.architecture.Service;
import saqure.utils.infrastructure.architecture.ServiceConfiguration;
import saqure.utils.infrastructure.architecture.ServiceImplementation;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import saqure.Planner.PrismModelChecker;
import saqure.Planner.TransitionAvailability;
import saqure.utils.FilePathConstants;

import java.io.IOException;
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

    public static void main(String[] args) throws IOException {
        SpringApplication.run(SaqureSimulatorApplication.class, args);

        String caseName = "";
        String serviceOverride = "";
        String runtime = "";

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

        // Simulate runtime change at T2, for RQ2 and RQ3
        PrismModelChecker.ExternalChanges externalChange = getExternalChangeForCase(caseName);
        boolean isT2 = runtime.equals("T2") && (caseName.startsWith("RQ2") || caseName.startsWith("RQ3")) && externalChange != null;
        if (isT2) {
            update_AED_AEDI(externalChange);
        }

        // Experiment Configuration
        // Runtime decision time spans the Analyzer's risk assessment of every candidate
        // implementation and the Planner's search, so start accumulating before the
        // configuration is built -- that is where the assessments happen.
        loadTransitionAvailabilities(caseName);
        RiskTiming.reset();
        Map<String, Service> servicesMap = getServicesMapByConfigName(caseName);
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

        Instant ramsesV3Start = Instant.now();
        //Simulate SAQURE and calculate cost
        // 4 core structural states = one TeaStore replica (WebUI, Authentication,
        // Recommender+Image, Persistence) plus START, success and failure = 7 reachable states.
        // The previous 2000 (500 replicas) put PRISM past its convergence limit: at that size
        // Jacobi hits -maxiters instead of the epsilon test, so every option came back with the
        // same value regardless of its availability (s5's four options all returned
        // 405533.61720272724 while their availabilities ranged from 0.31 to 0.9).
        buildPossibleGraphs(servicesMap, filterOptions(proposedAdaptationOptions), currentGraph, 4);
        Instant ramsesV3End = Instant.now();

        long riskAssessmentMillis = RiskTiming.totalMillis();
        long plannerMillis = Duration.between(ramsesV3Start, ramsesV3End).toMillis();
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
    // Configuration_RQ2. The sub-scenario is the case's trailing index, e.g. RQ2_SAQURE_s2.
    private static final Pattern RQ1_TO_RQ3_CASE = Pattern.compile("^RQ([123])_.*_[sS](\\d+)(_nodyPa)?$");

    // The DTMC transitions take the configuration sheet's availabilities (Fig. 8). Loaded before
    // the decision-time clock starts; other experiments keep the normalised availability.
    private static void loadTransitionAvailabilities(String caseName) {
        Matcher m = RQ1_TO_RQ3_CASE.matcher(caseName);
        if (!m.matches()) {
            TransitionAvailability.clear();
            return;
        }
        String sheet = m.group(1).equals("1") ? FilePathConstants.configration_rq1_path : FilePathConstants.configration_rq2_path;
        TransitionAvailability.load(sheet, "Sub-scenario" + m.group(2));
    }

    private static Map<String, Service> getServicesMapByConfigName(String caseName) throws IOException {
        switch (caseName) {
            // RQ1-RQ3 SAQURE arms assess risk with ModularEADSA; the earlier
            // *_SAQURE_ExpConfig methods are superseded.
            // RQ1 SAQURE parallel (no SEQUENTIAL)
            case "RQ1_SAQURE_para_S1": return RQ1_s1_SAQURE_Modules_ExpConfig();
            case "RQ1_SAQURE_para_S2": return RQ1_s2_SAQURE_Modules_ExpConfig();
            case "RQ1_SAQURE_para_S3": return RQ1_s3_SAQURE_Modules_ExpConfig();
            case "RQ1_SAQURE_para_S4": return RQ1_s4_SAQURE_Modules_ExpConfig();
            case "RQ1_SAQURE_para_S5": return RQ1_s5_SAQURE_Modules_ExpConfig();

            // RQ1 SAQURE sequential
            case "RQ1_SAQURE_seq_S1": setCompMode(EADSA.ComputationMode.SEQUENTIAL); return RQ1_s1_SAQURE_Modules_ExpConfig();
            case "RQ1_SAQURE_seq_S2": setCompMode(EADSA.ComputationMode.SEQUENTIAL); return RQ1_s2_SAQURE_Modules_ExpConfig();
            case "RQ1_SAQURE_seq_S3": setCompMode(EADSA.ComputationMode.SEQUENTIAL); return RQ1_s3_SAQURE_Modules_ExpConfig();
            case "RQ1_SAQURE_seq_S4": setCompMode(EADSA.ComputationMode.SEQUENTIAL); return RQ1_s4_SAQURE_Modules_ExpConfig();
            case "RQ1_SAQURE_seq_S5": setCompMode(EADSA.ComputationMode.SEQUENTIAL); return RQ1_s5_SAQURE_Modules_ExpConfig();

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
            case "RQ2_SAQURE_s1": return RQ2_s1_SAQURE_Modules_ExpConfig();
            case "RQ2_AQUA_s1": return RQ2_s1_Aqua_ExpConfig();
            case "RQ2_SAQURE_s2": return RQ2_s2_SAQURE_Modules_ExpConfig();
            case "RQ2_AQUA_s2": return RQ2_s2_Aqua_ExpConfig();
            case "RQ2_SAQURE_s3": return RQ2_s3_SAQURE_Modules_ExpConfig();
            case "RQ2_AQUA_s3": return RQ2_s3_Aqua_ExpConfig();

            // RQ3
            case "RQ3_SAQURE_s1": return RQ2_s1_SAQURE_Modules_ExpConfig();
            case "RQ3_SAQURE_s1_nodyPa": return RQ2_s1_SAQURE_nodyPa_Modules_ExpConfig();
            case "RQ3_SAQURE_s2": return RQ2_s2_SAQURE_Modules_ExpConfig();
            case "RQ3_SAQURE_s2_nodyPa": return RQ2_s2_SAQURE_nodyPa_Modules_ExpConfig();
            case "RQ3_SAQURE_s3": return RQ2_s3_SAQURE_Modules_ExpConfig();
            case "RQ3_SAQURE_s3_nodyPa": return RQ2_s3_SAQURE_nodyPa_Modules_ExpConfig();

            default:
                System.err.println("Unknown config: " + caseName);
                return null;
        }
    }

    private static String getServiceNameByCase(String caseName) {
        switch (caseName) {
            // RQ1 S1 → WEBUI-SERVICE
            case "RQ1_SAQURE_para_S1":
            case "RQ1_SAQURE_seq_S1":
            case "RQ1_Aqua_s1":
            case "RQ1_RAMSES_s1":
                return "WEBUI-SERVICE";
            // RQ1 S2 → WEBUI-SERVICE
            case "RQ1_SAQURE_para_S2":
            case "RQ1_SAQURE_seq_S2":
            case "RQ1_Aqua_s2":
            case "RQ1_RAMSES_s2":
                return "WEBUI-SERVICE";
            // RQ1 S3 → AUTHENTICATION-SERVICE
            case "RQ1_SAQURE_para_S3":
            case "RQ1_SAQURE_seq_S3":
            case "RQ1_Aqua_s3":
            case "RQ1_RAMSES_s3":
                return "AUTHENTICATION-SERVICE";
            // RQ1 S4 → PERSISTENCE-SERVICE
            case "RQ1_SAQURE_para_S4":
            case "RQ1_SAQURE_seq_S4":
            case "RQ1_Aqua_s4":
            case "RQ1_RAMSES_s4":
                return "PERSISTENCE-SERVICE";
            // RQ1 S5 → IMAGE-SERVICE
            case "RQ1_SAQURE_para_S5":
            case "RQ1_SAQURE_seq_S5":
            case "RQ1_Aqua_s5":
            case "RQ1_RAMSES_s5":
                return "IMAGE-SERVICE";

            // RQ2 s1 → WEBUI-SERVICE
            case "RQ2_SAQURE_s1":
            case "RQ2_AQUA_s1":
                return "WEBUI-SERVICE";
            // RQ2 s2 → AUTHENTICATION-SERVICE
            case "RQ2_SAQURE_s2":
            case "RQ2_AQUA_s2":
                return "AUTHENTICATION-SERVICE";
            // RQ2 s3 → PERSISTENCE-SERVICE
            case "RQ2_SAQURE_s3":
            case "RQ2_AQUA_s3":
                return "PERSISTENCE-SERVICE";

            // RQ3 s1 → WEBUI-SERVICE
            case "RQ3_SAQURE_s1":
            case "RQ3_SAQURE_s1_nodyPa":
                return "WEBUI-SERVICE";
            // RQ3 s2 → AUTHENTICATION-SERVICE
            case "RQ3_SAQURE_s2":
            case "RQ3_SAQURE_s2_nodyPa":
                return "AUTHENTICATION-SERVICE";
            // RQ3 s3 → PERSISTENCE-SERVICE
            case "RQ3_SAQURE_s3":
            case "RQ3_SAQURE_s3_nodyPa":
                return "PERSISTENCE-SERVICE";

            default:
                return null;
        }
    }

    private static PrismModelChecker.ExternalChanges getExternalChangeForCase(String caseName) {
        if (caseName.contains("_s1")) {
            return PrismModelChecker.ExternalChanges.AEDI_CHANGE_VERSION_WEBUI;
        } else if (caseName.contains("_s2")) {
            return PrismModelChecker.ExternalChanges.AEDI_CLOSE_SECURITY_CONTROL_AUTHENTICATION;
        } else if (caseName.contains("_s3")) {
            return PrismModelChecker.ExternalChanges.AEDI_CHANGE_VERSION_PERSISTENCE;
        }
        return null;
    }

    private static void printHelp() {
        System.out.println("Usage: java -jar your-app.jar [options]");
        System.out.println("Options:");
        System.out.println("  -c, --config <case>       Experiment case name (required)");
        System.out.println("  -s, --service <name>      Service name override (auto-detected if omitted)");
        System.out.println("  -t, --time <T1|T2>        Runtime phase (T1 or T2, for RQ2/RQ3)");
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
        System.out.println();
        System.out.println("Services: WEBUI-SERVICE, AUTHENTICATION-SERVICE, PERSISTENCE-SERVICE, IMAGE-SERVICE");
    }
}
