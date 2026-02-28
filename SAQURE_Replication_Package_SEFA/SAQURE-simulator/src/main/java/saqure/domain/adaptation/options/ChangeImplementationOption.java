package saqure.domain.adaptation.options;
import static saqure.utils.SimulationsUtils.*;

import saqure.domain.adaptation.specifications.QoSSpecification;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@NoArgsConstructor
public class ChangeImplementationOption extends AdaptationOption {
    private List<String> possibleImplementations; //维护可用备选实现列表
    private String newImplementationId;
    private int numberOfInstances;

    //强制变更
    public ChangeImplementationOption(String serviceId, String serviceImplementationId, int numberOfInstances, List<String> possibleImplementations, boolean forced, String comment) {
        super(serviceId, serviceImplementationId, comment);
        super.setForced(forced);
        this.numberOfInstances = numberOfInstances;
        this.possibleImplementations = possibleImplementations;
    }
    //QoS驱动变更：绑定具体质量目标类
    public ChangeImplementationOption(String serviceId, String serviceImplementationId, int numberOfInstances, List<String> possibleImplementations, Class<? extends QoSSpecification> goal, String comment) {
        super(serviceId, serviceImplementationId, comment);
        super.setQosGoal(goal);
        this.numberOfInstances = numberOfInstances;
        this.possibleImplementations = possibleImplementations;
    }

    // 决策可追溯性
    @Override
    public String getDescription() {
        return (isForced() ? "FORCED" : getQosGoal() != null ? ("Goal: " + getQosGoal().getSimpleName()) : "") + " - Change "+super.getServiceId()+" implementation from "+super.getServiceImplementationId()+" to "+newImplementationId+". " + getComment();//+experiment_num+
    }
}
