package saqure.utils;

public final class FilePathConstants {
    public static String FFPath = "SAQURE-simulator/Metric-FF/ff";

    public static String LookupFilePath = "SAQURE-simulator/src/main/java/saqure/Analyzer/EADSA/Sv_Pa_lookupfiles/Sv_Pa_lookupfile.json";
    public static String LookupFilePathPath_nodyPa = "SAQURE-simulator/src/main/java/saqure/Analyzer/EADSA/Sv_Pa_lookupfiles/Sv_Pa_lookupfile_nodyPa.json";

    public static String AEDPath = "SAQURE-simulator/src/main/java/saqure/Knowledge/AED:AEDI/Adversarial_Environment_Domain.pddl";
    public static String AEDPath_nodyPa = "SAQURE-simulator/src/main/java/saqure/Knowledge/AED:AEDI/Adversarial_Environment_Domain_nodyPa.pddl";

    // AED modules for RQ1-RQ3, generated from the two AEDs above by
    // SAQURE-simulator/AED/modules/build_modules.py.
    public static String ModulesPath = "SAQURE-simulator/AED/modules/default/";
    public static String ModulesPath_nodyPa = "SAQURE-simulator/AED/modules/nodyPa/";

    public static String AED_path_RQ1 = "SAQURE-simulator/AED/RQ1/";
    public static String AED_path_RQ2 = "SAQURE-simulator/AED/RQ2/";
    public static String AED_path_RQ3 = "SAQURE-simulator/AED/RQ3/";

    public static String AP_path_RQ1 = "SAQURE-simulator/AP/RQ1/";
    public static String AP_path_RQ2 = "SAQURE-simulator/AP/RQ2/";

    public static String AEDI_path = "SAQURE-simulator/AEDI/";

    public static String configuration_rq1_path = "experiments/experiment_config/Configuration_RQ1.xlsx";
    public static String configuration_rq2_path = "experiments/experiment_config/Configuration_RQ2.xlsx";
    public static String configuration_rq311_path = "experiments/experiment_config/Configuration_RQ3.1.1.xlsx";
    // RQ4.1.1 options axis with the vulnerability count held fixed: every payment implementation
    // exposes the same two CVEs, so only the number of options varies.
    public static String configuration_rq4option_path = "experiments/experiment_config/Configuration_RQ4_option.xlsx";
    public static String configuration_rq312_path = "experiments/experiment_config/Configuration_RQ3.1.2.xlsx";

    // RQ4 vulnerability axis (1-100 CVEs) and its prepared attack-path problems.
    public static String configuration_rq4vuln_path = "experiments/experiment_config/Configuration_RQ4_vuln.xlsx";
    public static String LookupFilePathExtended = "SAQURE-simulator/src/main/java/saqure/Analyzer/EADSA/Sv_Pa_lookupfiles/Sv_Pa_lookupfile_extended.json";
    public static String PreparedAPPath = "SAQURE-vulnerability-scalability/prepared";

    public static String model_prism_defination_path = "SAQURE-simulator/src/main/java/saqure/Knowledge/DTMC/model.prism";
    public static String model_props_defination_path = "SAQURE-simulator/src/main/java/saqure/Knowledge/DTMC/model.props";

}
