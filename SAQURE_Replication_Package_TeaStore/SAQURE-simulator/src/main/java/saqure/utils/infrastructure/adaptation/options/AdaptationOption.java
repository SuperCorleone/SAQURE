package saqure.utils.infrastructure.adaptation.options;

import saqure.utils.infrastructure.adaptation.specifications.QoSSpecification;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Date;


@Getter
@Setter
@NoArgsConstructor
public abstract class AdaptationOption {
    private long id;

    private String serviceId;
    private String serviceImplementationId;
    private String comment;
    private Class<? extends QoSSpecification> qosGoal;

    private boolean forced = false;

    // Timestamp of acceptance (it is NOT NULL ONLY IF the adaptation option has been accepted by the Plan)
    private Date timestamp;

    public abstract String getDescription();

    public void applyTimestamp() {
        this.timestamp = new Date();
    }

    public AdaptationOption(String serviceId, String serviceImplementationId, String comment) {
        this.serviceId = serviceId;
        this.serviceImplementationId = serviceImplementationId;
        this.comment = comment;
    }

    @Override
    public String toString() {
        return getDescription();
    }

}
