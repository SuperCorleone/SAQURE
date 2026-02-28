package saqure.utils;

import saqure.domain.adaptation.options.AdaptationOption;
import saqure.domain.adaptation.options.AddInstanceOption;
import saqure.domain.adaptation.options.ChangeImplementationOption;
import saqure.domain.adaptation.options.ShutdownInstanceOption;
import saqure.domain.adaptation.specifications.Availability;
import saqure.domain.adaptation.specifications.AverageResponseTime;
import saqure.domain.adaptation.specifications.QoSSpecification;
import saqure.domain.adaptation.specifications.Vulnerability;
import saqure.domain.architecture.Instance;
import saqure.domain.architecture.Service;
import saqure.domain.architecture.ServiceImplementation;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.Nullable;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static saqure.utils.PrismModelChecker.convertJsonToPrismCustomModel;

@Slf4j
public class ServiceGraphUtils {
//    private static final Logger log = LoggerFactory.getLogger(ServiceGraphUtils.class);

    private ServiceGraphUtils() {
        throw new IllegalStateException("Utility class");
    }

    public static void buildPossibleGraphs(Map<String, Service> servicesMap, Map<String, List<AdaptationOption>> proposedAdaptationOptions, String currentGraph, int numStates) {//, int sceneria
        log.info("Current graph: {}", currentGraph);
        Double currentValue = convertJsonToPrismCustomModel(currentGraph, currentGraph, numStates);//convertJsonToPrismEADSA(currentGraph, currentGraph, numStates);//计算当前reward //, sceneria
        AtomicReference<Double> best = new AtomicReference<>(currentValue);
        AtomicReference<AdaptationOption> bestOption = new AtomicReference<>(null);
        // For each AdaptationOption of each service
        proposedAdaptationOptions.forEach((s, adaptationOptions) ->
                adaptationOptions.forEach(adaptationOption -> {
                    Map<String, Service> serviceMapCopy = new HashMap<>(servicesMap);
                    //If it is an AdaptationOption of type Change, generate the graph.
                    if (adaptationOption.getClass().equals(ChangeImplementationOption.class)) {
                        ChangeImplementationOption changeImplementationOption = (ChangeImplementationOption) adaptationOption;
                        Service service = serviceMapCopy.get(changeImplementationOption.getServiceId());
                        String oldImplementationId = service.getCurrentImplementationId();
                        service.setCurrentImplementationId(changeImplementationOption.getNewImplementationId());
                        serviceMapCopy.put(service.getServiceId(), service);
                        Instant calculateGraphStart = Instant.now();
                        String graph = jsonGraph(serviceMapCopy, adaptationOption);
                        Instant calculateGraphEnd = Instant.now();
                        log.info("Time to generate the graph: {}ms", Duration.between(calculateGraphStart, calculateGraphEnd).toNanos() / 1_000_000.0);


                        log.info("Graph for option {}: {}", adaptationOption.getDescription(), graph);
                        //Calculate the reward of MC for the simulation of SEFA
                        Double value = convertJsonToPrismCustomModel(currentGraph, graph, numStates);//convertJsonToPrismEADSA(currentGraph, graph, numStates);//, sceneria
                        if (value != null && value < best.get()) {//If the reward is smaller, update the value and save the Option.
                            best.set(value);
                            bestOption.set(adaptationOption);
                        }
                        service.setCurrentImplementationId(oldImplementationId);
                    }
                    else {
                        String graph = jsonGraph(serviceMapCopy, adaptationOption);
                        log.info("Graph for option {}: {}", adaptationOption.getDescription(), graph);
                        Double value = convertJsonToPrismCustomModel(currentGraph, graph, numStates);//convertJsonToPrismEADSA(currentGraph, graph, numStates);//, sceneria
                        if (value != null && value < best.get()) {// <
                            best.set(value);
                            bestOption.set(adaptationOption);
                        }
                    }
                }));

        if (best.get() != null && best.get() < currentValue) {/// <
            log.info("Best option: {}", bestOption.get().getDescription());
            log.info("Best cost value: {}", best.get());
        }
        else {
            log.info("No better option found");
        }
    }

    public static String jsonGraph(Map<String, Service> servicesMap, @Nullable AdaptationOption adaptationOption) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        for (Service service : servicesMap.values()) {
            // Service ID as key
            sb.append("\"").append(service.getServiceId()).append("\":{");
            sb.append("\"currentImplementationId\":\"").append(service.getCurrentImplementationId()).append("\",");

            sb.append("\"values\":{");
//            log.info("class: {}", service.getServiceId());
            // Traverse all QoS specification types
            for (Class<? extends QoSSpecification> qosClass : service.getQoSSpecifications().keySet()) {
                sb.append("\"").append(qosClass.getSimpleName()).append("\":").append(getValue(service, adaptationOption, qosClass)).append(",");
//                log.info("test get value: {}", getValue(service, adaptationOption, qosClass));
            }
            sb.deleteCharAt(sb.length() - 1);
            sb.append("}},");
        }
        sb.deleteCharAt(sb.length() - 1);// Remove the last comma

        Service service = servicesMap.values().iterator().next();// Take the first service
        sb.append(",\"weights\":{");// Add weight object
        for (Class<? extends QoSSpecification> qosClass : service.getQoSSpecifications().keySet()) {
            sb.append("\"").append(qosClass.getSimpleName()).append("\":").append(service.getQoSSpecifications().get(qosClass).getWeight()).append(",");
        }
        sb.deleteCharAt(sb.length() - 1);
        sb.append("}}");
        return sb.toString();
    }

    private static Double getValue(Service service, AdaptationOption adaptationOption, Class<? extends QoSSpecification> qosClass) {
        // TODO handle change weights option

        if (adaptationOption == null || !adaptationOption.getServiceId().equals(service.getServiceId())) {
            if (qosClass.equals(Availability.class))
                return service.getCurrentValueForQoS(Availability.class).getDoubleValue();
            else if (qosClass.equals(AverageResponseTime.class))
                return service.getCurrentValueForQoS(AverageResponseTime.class).getDoubleValue();
            else if (qosClass.equals(Vulnerability.class))
                return service.getCurrentVulnerabilityScore();
            else return null;
        }

        if (adaptationOption.getClass().equals(ChangeImplementationOption.class)) {
            ServiceImplementation currentImplementation = service.getCurrentImplementation();
            if (qosClass.equals(Vulnerability.class))
                return currentImplementation.getVulnerabilityScore();
            else
                return currentImplementation.getBenchmark(qosClass);
        }

        if (adaptationOption.getClass().equals(AddInstanceOption.class)) {
            if (qosClass.equals(Availability.class)) {
                double newAvailability = 0;
                for (Instance instance : service.getInstances()) {
                    newAvailability += instance.getCurrentValueForQoS(Availability.class).getDoubleValue();
                }
                newAvailability += service.getCurrentImplementation().getBenchmark(Availability.class);
                newAvailability /= service.getInstances().size() + 1;
                return newAvailability;
            }
            else if (qosClass.equals(AverageResponseTime.class)) {
                double newAvgResponseTime = 0;
                for (Instance instance : service.getInstances()) {
                    newAvgResponseTime += instance.getCurrentValueForQoS(AverageResponseTime.class).getDoubleValue();
                }
                newAvgResponseTime += service.getCurrentImplementation().getBenchmark(AverageResponseTime.class);
                newAvgResponseTime /= service.getInstances().size() + 1;
                return newAvgResponseTime;
            }
            else if (qosClass.equals(Vulnerability.class))
                return service.getCurrentVulnerabilityScore();
        }

        if (adaptationOption.getClass().equals(ShutdownInstanceOption.class)) {
            if (qosClass.equals(Availability.class)) {
                double newAvailability = 0;
                for (Instance instance : service.getInstances()) {
                    newAvailability += instance.getCurrentValueForQoS(Availability.class).getDoubleValue();
                }
                newAvailability /= service.getInstances().size() - 1;
                return newAvailability;
            }
            else if (qosClass.equals(AverageResponseTime.class)) {
                double newAvgResponseTime = 0;
                for (Instance instance : service.getInstances()) {
                    newAvgResponseTime += instance.getCurrentValueForQoS(AverageResponseTime.class).getDoubleValue();
                }
                newAvgResponseTime /= service.getInstances().size() - 1;
                return newAvgResponseTime;
            }
            else if (qosClass.equals(Vulnerability.class))
                return service.getCurrentVulnerabilityScore();
        }

        return null;
    }
}
