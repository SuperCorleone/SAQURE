package saqure.utils;

public final class FilePathConstants {
    // AED modules for RQ1-RQ3, generated from the two AEDs below by
    // SAQURE-simulator/AED/modules/build_modules.py (identical to SEFA's modules).
    public static String ModulesPath = "SAQURE-simulator/AED/modules/default/";
    public static String ModulesPath_nodyPa = "SAQURE-simulator/AED/modules/nodyPa/";

    public static String AED_path_RQ1 = "SAQURE-simulator/AED/RQ1/";
    public static String AED_path_RQ2 = "SAQURE-simulator/AED/RQ2/";

    public static String AP_path = "SAQURE-simulator/AP/";

    public static String AEDI_path = "SAQURE-simulator/AEDI/";

    public static String FFPath = "SAQURE-simulator/Metric-FF/ff";

    public static String AED_path = "SAQURE-simulator/src/main/java/saqure/Knowledge/AED:AEDI/Adversarial_Environment_Domain.pddl";
    public static String AED_path_nodyPa = "SAQURE-simulator/src/main/java/saqure/Knowledge/AED:AEDI/Adversarial_Environment_Domain_nodyPa.pddl";

    public static String LookupFilePath = "SAQURE-simulator/src/main/java/saqure/Analyzer/EADSA/Sv_Pa_lookupfiles/Sv_Pa_lookupfile.json";
    public static String LookupFilePath_nodyPa = "SAQURE-simulator/src/main/java/saqure/Analyzer/EADSA/Sv_Pa_lookupfiles/Sv_Pa_lookupfile_nodyPa.json";

    public static String configration_rq1_path = "experiments/experiment_config/Configuration_RQ1.xlsx";
    public static String configration_rq2_path = "experiments/experiment_config/Configuration_RQ2.xlsx";

    public static String model_prism_defination_path = "SAQURE-simulator/src/main/java/saqure/Knowledge/DTMC/model.prism";
    public static String model_props_defination_path = "SAQURE-simulator/src/main/java/saqure/Knowledge/DTMC/model.props";

    public enum Services {
        WEBUI("WEBUI-SERVICE"),
        AUTHENTICATION("AUTHENTICATION-SERVICE"),
        PERSISTENCE("PERSISTENCE-SERVICE"),
        IMAGE("IMAGE-SERVICE"),
        RECOMMENDER("RECOMMENDER-SERVICE");

        private final String serviceName;

        Services(String serviceName){
            this.serviceName = serviceName;
        }
        public String getServiceName() {
            return serviceName;
        }
    }
}
