package saqure;

import saqure.domain.adaptation.options.*;
import saqure.domain.adaptation.specifications.Availability;
import saqure.domain.adaptation.specifications.AverageResponseTime;
import saqure.domain.adaptation.specifications.QoSSpecification;
import saqure.domain.adaptation.specifications.Vulnerability;
import saqure.domain.architecture.Service;
import saqure.domain.architecture.ServiceConfiguration;
import saqure.domain.architecture.ServiceImplementation;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.io.File;
import java.nio.file.Files;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

import static saqure.utils.ServiceGraphUtils.buildPossibleGraphs;
import static saqure.utils.ServiceGraphUtils.jsonGraph;
import static saqure.utils.SimulationsUtils.*;

@SpringBootApplication
@Slf4j
public class SaqureSimulatorApplication {

    public static void main(String[] args) {
        SpringApplication.run(SaqureSimulatorApplication.class, args);
        int param = readRQ3Param();
        Instant planSimulationStart = Instant.now();
        //Simulate runtime change at T2, only for RQ2
//        update_AED_AEDI(PrismModelChecker.ExternalChanges.AEDI_CHANGE_VERSION_PERSISTENCE);

        // Experiment Configuration
        Map<String, Service> servicesMap = RQ1_SAQURE_s3_ExpConfig();
        Instant planSimulationEnd = Instant.now();
        log.info("Runtime risk assessment time: {}ms", Duration.between(planSimulationStart, planSimulationEnd).toMillis());
        Service serviceToAdapt = servicesMap.get("AUTHENTICATION-SERVICE");// WEBUI AUTHENTICATION PERSISTENCE IMAGE

        Map<String, List<AdaptationOption>> proposedAdaptationOptions = new HashMap<>();
        proposedAdaptationOptions.put(serviceToAdapt.getServiceId(), List.of(
                createChangeImplementationOption(serviceToAdapt, Availability.class),
                createChangeImplementationOption(serviceToAdapt, AverageResponseTime.class),
                createChangeImplementationOption(serviceToAdapt, Vulnerability.class)
        ));

        String currentGraph = jsonGraph(servicesMap, null);
        Instant ramsesV3Start = Instant.now();
        //Simulate SEFA and calculate cost
        buildPossibleGraphs(servicesMap, filterOptions(proposedAdaptationOptions), currentGraph, 2000);//, sceneria
        Instant ramsesV3End = Instant.now();
        log.info("Time to extract best option RamsesV3: {}ms", Duration.between(ramsesV3Start, ramsesV3End).toMillis());
        // Reverse simulate runtime change at T2
//        reverseUpdating(PrismModelChecker.ExternalChanges.AEDI_CHANGE_VERSION_PERSISTENCE);//Revert runtime external change, only for RQ2
    }

    private static int readRQ3Param() {
        try {
            File paramFile = new File("/tmp/rq3_param.txt");
            if (paramFile.exists()) {
                String content = new String(Files.readAllBytes(paramFile.toPath())).trim();
                return Integer.parseInt(content);
            }
        } catch (Exception e) {
            log.warn("Unable to read parameter file, using default parameter 1");
        }
        return 1;  // 默认值
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
}
