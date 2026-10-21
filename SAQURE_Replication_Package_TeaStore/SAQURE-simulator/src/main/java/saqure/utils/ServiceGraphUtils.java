package saqure.utils;

import saqure.utils.infrastructure.adaptation.options.AdaptationOption;
import saqure.utils.infrastructure.adaptation.options.AddInstanceOption;
import saqure.utils.infrastructure.adaptation.options.ChangeImplementationOption;
import saqure.utils.infrastructure.adaptation.options.ShutdownInstanceOption;
import saqure.utils.infrastructure.adaptation.specifications.Availability;
import saqure.utils.infrastructure.adaptation.specifications.AverageResponseTime;
import saqure.utils.infrastructure.adaptation.specifications.QoSSpecification;
import saqure.utils.infrastructure.adaptation.specifications.Vulnerability;
import saqure.utils.infrastructure.architecture.Instance;
import saqure.utils.infrastructure.architecture.Service;
import saqure.utils.infrastructure.architecture.ServiceImplementation;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static saqure.Planner.PrismModelChecker.convertJsonToPrismCustomModel;

@Slf4j
public class ServiceGraphUtils {

    private ServiceGraphUtils() {
        throw new IllegalStateException("Utility class");
    }

    public static void buildPossibleGraphs(Map<String, Service> servicesMap, Map<String, List<AdaptationOption>> proposedAdaptationOptions, String currentGraph, int numStates) {//, int sceneria
        log.info("Current graph: {}", currentGraph);
        Double currentValue = convertJsonToPrismCustomModel(currentGraph, currentGraph, numStates);//convertJsonToPrismEADSA(currentGraph, currentGraph, numStates);//计算当前reward //, sceneria
        AtomicReference<Double> best = new AtomicReference<>(currentValue);
        AtomicReference<AdaptationOption> bestOption = new AtomicReference<>(null);
        proposedAdaptationOptions.forEach((s, adaptationOptions) ->
                adaptationOptions.forEach(adaptationOption -> {
                    Map<String, Service> serviceMapCopy = new HashMap<>(servicesMap);
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

                        Double value = convertJsonToPrismCustomModel(currentGraph, graph, numStates);//convertJsonToPrismEADSA(currentGraph, graph, numStates);//, sceneria
                        if (value != null && value < best.get()) {
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
            sb.append("\"").append(service.getServiceId()).append("\":{");
            sb.append("\"currentImplementationId\":\"").append(service.getCurrentImplementationId()).append("\",");

            sb.append("\"values\":{");
//            log.info("class: {}", service.getServiceId());
            for (Class<? extends QoSSpecification> qosClass : service.getQoSSpecifications().keySet()) {
                sb.append("\"").append(qosClass.getSimpleName()).append("\":").append(getValue(service, adaptationOption, qosClass)).append(",");
//                log.info("test get value: {}", getValue(service, adaptationOption, qosClass));
            }
            sb.deleteCharAt(sb.length() - 1);
            sb.append("}},");
        }
        sb.deleteCharAt(sb.length() - 1);

        Service service = servicesMap.values().iterator().next();
        sb.append(",\"weights\":{");
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
