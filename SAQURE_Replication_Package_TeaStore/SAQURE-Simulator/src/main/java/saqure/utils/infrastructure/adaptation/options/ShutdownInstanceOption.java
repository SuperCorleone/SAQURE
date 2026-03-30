package saqure.utils.infrastructure.adaptation.options;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import java.util.Map;

@Getter
@Setter
@NoArgsConstructor
public class ShutdownInstanceOption extends AdaptationOption {
    private String instanceToShutdownId;
    // <instanceId, newWeight>
    private Map<String, Double> newWeights;


    public ShutdownInstanceOption(String serviceId, String serviceImplementationId, String instanceToShutdownId, String comment) {
        super(serviceId, serviceImplementationId, comment);
        this.instanceToShutdownId = instanceToShutdownId;
    }

    public ShutdownInstanceOption(String serviceId, String serviceImplementationId, String instanceToShutdownId, String comment, boolean isForced) {
        super(serviceId, serviceImplementationId, comment);
        this.instanceToShutdownId = instanceToShutdownId;
        super.setForced(isForced);
    }

    @Override
    public String getDescription() {
        return (isForced() ? "FORCED" : ("Goal: " + getQosGoal().getSimpleName())) + " - Shutdown instance. Service:" + super.getServiceId() + ".\n\t\t\t\t\tInstances: " + instanceToShutdownId + "\n\t\t\t\t\t" + getComment();
    }
}

