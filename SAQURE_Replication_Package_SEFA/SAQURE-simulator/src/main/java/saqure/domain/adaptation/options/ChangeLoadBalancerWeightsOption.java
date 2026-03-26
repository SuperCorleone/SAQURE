package saqure.domain.adaptation.options;

import saqure.domain.adaptation.specifications.QoSSpecification;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

@Getter
@Setter
@NoArgsConstructor
public class ChangeLoadBalancerWeightsOption extends AdaptationOption {
    // <instanceId, newWeight>
    private Map<String, Double> newWeights; //Contains only the weights of the instances that will remain active
    private List<String> instancesToShutdownIds = new LinkedList<>();


    public ChangeLoadBalancerWeightsOption(String serviceId, String serviceImplementationId, Class<? extends QoSSpecification> goal, String comment) {
        super(serviceId, serviceImplementationId, comment);
        super.setQosGoal(goal);
    }

    @Override
    public String getDescription() {
        String base = "Goal: " + getQosGoal().getSimpleName() + " - Change LBW. Service: " + super.getServiceId();
        if (newWeights != null)
            base += "\n\t\t\t\t\tNew weights are: \n\t\t\t\t\t" + newWeights;
        return base + ".\n\t\t\t\t\t" + getComment();
    }
}
