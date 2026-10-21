package saqure.utils.infrastructure.adaptation.specifications;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
// 权重管理，约束条件验证，规范描述体系
public abstract class QoSSpecification {

    private Double weight;

    public abstract boolean isSatisfied(double value);

    // True if in the list of values the ones that satisfy the constraint are above a certain percentage
    public boolean isSatisfied(List<Double> values, double percentage) {
        if (values == null || values.size() == 0)
            return false;
        double count = 0;
        for (Double d : values) {
            if (isSatisfied(d))
                count += 1;
        }
        return (count / values.size()) >= percentage;
    }

    public abstract String getConstraintDescription();

    abstract void fromJson(String json);

    @Override
    public String toString() {
        return this.getClass().getSimpleName() + "(Weight: " + weight + ", Constraint: " + getConstraintDescription() + ")"; //+ ", priority: " + priority;
    }

}
