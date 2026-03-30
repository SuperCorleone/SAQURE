package saqure.Analyzer;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import saqure.utils.FilePathConstants;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.concurrent.*;
import java.util.*;
import java.util.function.Supplier;

public class EADSA {
    private static final String cppProgram = FilePathConstants.FFPath;
    public static boolean IS_DEFAULT = true;
//    System.Logger(" IS_DEFAULT = : "+ DynamicDTMC.IS_DEFAULT);

    private static final ThreadPoolExecutor executor = new ThreadPoolExecutor(
            Runtime.getRuntime().availableProcessors(),
            Runtime.getRuntime().availableProcessors(),
            1, TimeUnit.SECONDS,
            new LinkedBlockingQueue<>());

    // main entry
    public static double computeScenario(String domainFile, outputPath path){
        return computationStrategy.compute(domainFile, path);
    }

    public static class outputPath {
        final String spoofingPath;
        final String tamperingPath;
        final String repudiationPath;
        final String infoDisclosurePath;
        final String denialOfServicePath;
        final String elevationOfPrivilegePath;

        public outputPath(String spoofingPath, String tamperingPath, String repudiationPath, String infoDisclosurePath, String denialOfServicePath, String elevationOfPrivilegePath){
            this.spoofingPath = spoofingPath;
            this.tamperingPath = tamperingPath;
            this.repudiationPath = repudiationPath;
            this.infoDisclosurePath = infoDisclosurePath;
            this.denialOfServicePath = denialOfServicePath;
            this.elevationOfPrivilegePath = elevationOfPrivilegePath;
        }
    }

    public enum ComputationMode{PARALLEL, SEQUENTIAL}

    public interface ScenarioComputation{
        double compute(String domainFile, outputPath path);
    }

    private static ScenarioComputation computationStrategy;

    static {
        executor.allowCoreThreadTimeOut(true);

        setComputationMode(ComputationMode.PARALLEL);
    }

    // Interface: External class calls control whether to use parallel or serial execution.
    public static void setComputationMode(ComputationMode mode) {
        switch (mode) {
            case PARALLEL:
                computationStrategy = new ParallelComputation(executor);
                break;
            case SEQUENTIAL:
                computationStrategy = new SequentialComputation();
                break;
            default: computationStrategy = new SequentialComputation();
                break;
        }
    }

    public static class ParallelComputation implements ScenarioComputation{
        private final ThreadPoolExecutor executor;
        public ParallelComputation(ThreadPoolExecutor executor){this.executor = executor;}

        @Override
        public double compute(String domainFile, outputPath path){
            return computeParallelSum(
                    () -> planner_command_AEDI_s(domainFile, path.spoofingPath),
                    () -> planner_command_AEDI_t(domainFile, path.tamperingPath),
                    () -> planner_command_AEDI_r(domainFile, path.repudiationPath),
                    () -> planner_command_AEDI_i(domainFile, path.infoDisclosurePath),
                    () -> planner_command_AEDI_d(domainFile, path.denialOfServicePath),
                    () -> planner_command_AEDI_e(domainFile, path.elevationOfPrivilegePath));
        }
    }

    private static double computeParallelSum(Supplier<Double>... tasks){
        List<CompletableFuture<Double>> futures = new ArrayList<>();

        for (Supplier<Double> task : tasks){
            futures.add(CompletableFuture.supplyAsync(task, executor));
        }

        CompletableFuture<Void> allFutrues = CompletableFuture.allOf(
                futures.toArray(new CompletableFuture[0]));

        return allFutrues.thenApply(
                v -> futures
                        .stream()
                        .mapToDouble(CompletableFuture::join)
                        .sum())
                .join();
    }

    public static class SequentialComputation implements ScenarioComputation{
        @Override
        public double compute(String domainFile, outputPath path){
            return planner_command_AEDI_s(domainFile, path.spoofingPath) +
                    planner_command_AEDI_t(domainFile, path.tamperingPath) +
                    planner_command_AEDI_r(domainFile, path.repudiationPath) +
                    planner_command_AEDI_i(domainFile, path.infoDisclosurePath) +
                    planner_command_AEDI_d(domainFile, path.denialOfServicePath) +
                    planner_command_AEDI_e(domainFile, path.elevationOfPrivilegePath);
        }
    }
    public static double planner_command_configuration_s1_r0(String domainFile){
        return computeScenario(domainFile, new outputPath(
                FilePathConstants.AP_path_RQ1 + "S1_R0_O0_D0_P0_plan/spoofing_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S1_R0_O0_D0_P0_plan/tampering_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S1_R0_O0_D0_P0_plan/repudiation_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S1_R0_O0_D0_P0_plan/information_disclosure_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S1_R0_O0_D0_P0_plan/denial_of_service_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S1_R0_O0_D0_P0_plan/elevation_of_privilege_plan.pddl"));
    }
    public static double planner_command_configuration_s1_r1(String domainFile){
        return computeScenario(domainFile, new outputPath(
                FilePathConstants.AP_path_RQ1 + "S1_R1_O0_D0_P0_plan/spoofing_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S1_R1_O0_D0_P0_plan/tampering_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S1_R1_O0_D0_P0_plan/repudiation_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S1_R1_O0_D0_P0_plan/information_disclosure_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S1_R1_O0_D0_P0_plan/denial_of_service_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S1_R1_O0_D0_P0_plan/elevation_of_privilege_plan.pddl"));
    }
    public static double planner_command_configuration_s1_r2(String domainFile){
        return computeScenario(domainFile, new outputPath(
                FilePathConstants.AP_path_RQ1 + "S1_R2_O0_D0_P0_plan/spoofing_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S1_R2_O0_D0_P0_plan/tampering_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S1_R2_O0_D0_P0_plan/repudiation_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S1_R2_O0_D0_P0_plan/information_disclosure_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S1_R2_O0_D0_P0_plan/denial_of_service_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S1_R2_O0_D0_P0_plan/elevation_of_privilege_plan.pddl"));
    }

    public static double planner_command_configuration_s2_r0(String domainFile){
        return computeScenario(domainFile, new outputPath(
                FilePathConstants.AP_path_RQ1 + "S2_R0_O0_D0_P0_plan/spoofing_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S2_R0_O0_D0_P0_plan/tampering_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S2_R0_O0_D0_P0_plan/repudiation_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S2_R0_O0_D0_P0_plan/information_disclosure_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S2_R0_O0_D0_P0_plan/denial_of_service_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S2_R0_O0_D0_P0_plan/elevation_of_privilege_plan.pddl"));
    }
    public static double planner_command_configuration_s2_r1(String domainFile){
        return computeScenario(domainFile, new outputPath(
                FilePathConstants.AP_path_RQ1 + "S2_R1_O0_D0_P0_plan/spoofing_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S2_R1_O0_D0_P0_plan/tampering_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S2_R1_O0_D0_P0_plan/repudiation_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S2_R1_O0_D0_P0_plan/information_disclosure_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S2_R1_O0_D0_P0_plan/denial_of_service_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S2_R1_O0_D0_P0_plan/elevation_of_privilege_plan.pddl"));
    }
    public static double planner_command_configuration_s2_r2(String domainFile){
        return computeScenario(domainFile, new outputPath(
                FilePathConstants.AP_path_RQ1 + "S2_R2_O0_D0_P0_plan/spoofing_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S2_R2_O0_D0_P0_plan/tampering_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S2_R2_O0_D0_P0_plan/repudiation_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S2_R2_O0_D0_P0_plan/information_disclosure_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S2_R2_O0_D0_P0_plan/denial_of_service_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S2_R2_O0_D0_P0_plan/elevation_of_privilege_plan.pddl"));
    }

    public static double planner_command_configuration_s3_o0(String domainFile){
        return computeScenario(domainFile, new outputPath(
                FilePathConstants.AP_path_RQ1 + "S3_R0_O0_D0_P0_plan/spoofing_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S3_R0_O0_D0_P0_plan/tampering_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S3_R0_O0_D0_P0_plan/repudiation_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S3_R0_O0_D0_P0_plan/information_disclosure_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S3_R0_O0_D0_P0_plan/denial_of_service_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S3_R0_O0_D0_P0_plan/elevation_of_privilege_plan.pddl"));
    }
    public static double planner_command_configuration_s3_o1(String domainFile){
        return computeScenario(domainFile, new outputPath(
                FilePathConstants.AP_path_RQ1 + "S3_R0_O1_D0_P0_plan/spoofing_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S3_R0_O1_D0_P0_plan/tampering_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S3_R0_O1_D0_P0_plan/repudiation_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S3_R0_O1_D0_P0_plan/information_disclosure_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S3_R0_O1_D0_P0_plan/denial_of_service_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S3_R0_O1_D0_P0_plan/elevation_of_privilege_plan.pddl"));
    }
    public static double planner_command_configuration_s3_o2(String domainFile){
        return computeScenario(domainFile, new outputPath(
                FilePathConstants.AP_path_RQ1 + "S3_R0_O2_D0_P0_plan/spoofing_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S3_R0_O2_D0_P0_plan/tampering_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S3_R0_O2_D0_P0_plan/repudiation_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S3_R0_O2_D0_P0_plan/information_disclosure_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S3_R0_O2_D0_P0_plan/denial_of_service_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S3_R0_O2_D0_P0_plan/elevation_of_privilege_plan.pddl"));
    }
    public static double planner_command_configuration_s3_o3(String domainFile){
        return computeScenario(domainFile, new outputPath(
                FilePathConstants.AP_path_RQ1 + "S3_R0_O3_D0_P0_plan/spoofing_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S3_R0_O3_D0_P0_plan/tampering_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S3_R0_O3_D0_P0_plan/repudiation_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S3_R0_O3_D0_P0_plan/information_disclosure_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S3_R0_O3_D0_P0_plan/denial_of_service_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S3_R0_O3_D0_P0_plan/elevation_of_privilege_plan.pddl"));
    }

    public static double planner_command_configuration_s4_d0(String domainFile){
        return computeScenario(domainFile, new outputPath(
                FilePathConstants.AP_path_RQ1 + "S4_R0_O0_D0_P0_plan/spoofing_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S4_R0_O0_D0_P0_plan/tampering_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S4_R0_O0_D0_P0_plan/repudiation_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S4_R0_O0_D0_P0_plan/information_disclosure_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S4_R0_O0_D0_P0_plan/denial_of_service_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S4_R0_O0_D0_P0_plan/elevation_of_privilege_plan.pddl"));
    }
    public static double planner_command_configuration_s4_d1(String domainFile){
        return computeScenario(domainFile, new outputPath(
                FilePathConstants.AP_path_RQ1 + "S4_R0_O0_D1_P0_plan/spoofing_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S4_R0_O0_D1_P0_plan/tampering_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S4_R0_O0_D1_P0_plan/repudiation_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S4_R0_O0_D1_P0_plan/information_disclosure_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S4_R0_O0_D1_P0_plan/denial_of_service_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S4_R0_O0_D1_P0_plan/elevation_of_privilege_plan.pddl"));
    }
    public static double planner_command_configuration_s4_d2(String domainFile){
        return computeScenario(domainFile, new outputPath(
                FilePathConstants.AP_path_RQ1 + "S4_R0_O0_D2_P0_plan/spoofing_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S4_R0_O0_D2_P0_plan/tampering_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S4_R0_O0_D2_P0_plan/repudiation_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S4_R0_O0_D2_P0_plan/information_disclosure_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S4_R0_O0_D2_P0_plan/denial_of_service_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S4_R0_O0_D2_P0_plan/elevation_of_privilege_plan.pddl"));
    }
    public static double planner_command_configuration_s4_d3(String domainFile){
        return computeScenario(domainFile, new outputPath(
                FilePathConstants.AP_path_RQ1 + "S4_R0_O0_D3_P0_plan/spoofing_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S4_R0_O0_D3_P0_plan/tampering_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S4_R0_O0_D3_P0_plan/repudiation_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S4_R0_O0_D3_P0_plan/information_disclosure_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S4_R0_O0_D3_P0_plan/denial_of_service_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S4_R0_O0_D3_P0_plan/elevation_of_privilege_plan.pddl"));
    }

    public static double planner_command_configuration_s5_p0(String domainFile){
        return computeScenario(domainFile, new outputPath(
                FilePathConstants.AP_path_RQ1 + "S5_R0_O0_D0_P0_plan/spoofing_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S5_R0_O0_D0_P0_plan/tampering_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S5_R0_O0_D0_P0_plan/repudiation_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S5_R0_O0_D0_P0_plan/information_disclosure_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S5_R0_O0_D0_P0_plan/denial_of_service_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S5_R0_O0_D0_P0_plan/elevation_of_privilege_plan.pddl"));
    }
    public static double planner_command_configuration_s5_p1(String domainFile){
        return computeScenario(domainFile, new outputPath(
                FilePathConstants.AP_path_RQ1 + "S5_R0_O0_D0_P1_plan/spoofing_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S5_R0_O0_D0_P1_plan/tampering_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S5_R0_O0_D0_P1_plan/repudiation_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S5_R0_O0_D0_P1_plan/information_disclosure_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S5_R0_O0_D0_P1_plan/denial_of_service_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S5_R0_O0_D0_P1_plan/elevation_of_privilege_plan.pddl"));
    }
    public static double planner_command_configuration_s5_p2(String domainFile){
        return computeScenario(domainFile, new outputPath(
                FilePathConstants.AP_path_RQ1 + "S5_R0_O0_D0_P2_plan/spoofing_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S5_R0_O0_D0_P2_plan/tampering_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S5_R0_O0_D0_P2_plan/repudiation_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S5_R0_O0_D0_P2_plan/information_disclosure_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S5_R0_O0_D0_P2_plan/denial_of_service_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S5_R0_O0_D0_P2_plan/elevation_of_privilege_plan.pddl"));
    }
    public static double planner_command_configuration_s5_p3(String domainFile){
        return computeScenario(domainFile, new outputPath(
                FilePathConstants.AP_path_RQ1 + "S5_R0_O0_D0_P3_plan/spoofing_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S5_R0_O0_D0_P3_plan/tampering_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S5_R0_O0_D0_P3_plan/repudiation_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S5_R0_O0_D0_P3_plan/information_disclosure_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S5_R0_O0_D0_P3_plan/denial_of_service_plan.pddl",
                FilePathConstants.AP_path_RQ1 + "S5_R0_O0_D0_P3_plan/elevation_of_privilege_plan.pddl"));
    }

    public static double planner_command_compute_RQ2_s1_r0(String domainFile){
        String outputPath = FilePathConstants.AP_path_RQ2 + "S1_R0/";
        String problemPath = FilePathConstants.AEDI_path + "RQ2/S1/Restaurant_1_service/";
        System.out.print("RO: \n spoofing_plan: "+ planner_command_AEDI(domainFile,outputPath+"spoofing.pddl",
                problemPath+"spoofing.pddl") + "\n tampering_plan: "+ planner_command_AEDI(domainFile,outputPath+"tampering.pddl",
                problemPath+"tampering.pddl") +
                "\nrepudiation_plan:"+ planner_command_AEDI(domainFile,outputPath+"repudiation.pddl",
                problemPath+"repudiation.pddl")+ "\n information_disclosure_plan: " + planner_command_AEDI(domainFile,outputPath+"information_disclosure.pddl",
                problemPath+"information_disclosure.pddl") + "\n denial_of_service:"+ planner_command_AEDI(domainFile,outputPath+"denial_of_service.pddl",
                problemPath+"denial_of_service.pddl") + "\n elevation_of_privilege_plan:" + planner_command_AEDI(domainFile,outputPath+"elevation_of_privilege.pddl",
                problemPath+"elevation_of_privilege.pddl")+"\n");
        return planner_command_AEDI(domainFile,outputPath+"spoofing.pddl",
                problemPath+"spoofing.pddl")+
                planner_command_AEDI(domainFile,outputPath+"tampering.pddl",
                        problemPath+"tampering.pddl")+
                planner_command_AEDI(domainFile,outputPath+"repudiation.pddl",
                        problemPath+"repudiation.pddl")+
                planner_command_AEDI(domainFile,outputPath+"information_disclosure.pddl",
                        problemPath+"information_disclosure.pddl")+
                planner_command_AEDI(domainFile,outputPath+"denial_of_service.pddl",
                        problemPath+"denial_of_service.pddl")+
                planner_command_AEDI(domainFile,outputPath+"elevation_of_privilege.pddl",
                        problemPath+"elevation_of_privilege.pddl");
    }
    public static double planner_command_compute_RQ2_s1_r1(String domainFile){
        String outputPath = FilePathConstants.AP_path_RQ2 + "S1_R1/";
        String problemPath = FilePathConstants.AEDI_path + "RQ2/S1/Restaurant_2_service/";
        System.out.print("R1: \n spoofing_plan: "+ planner_command_AEDI(domainFile,outputPath+"spoofing.pddl",
                problemPath+"spoofing.pddl") + "\n tampering_plan: "+ planner_command_AEDI(domainFile,outputPath+"tampering.pddl",
                problemPath+"tampering.pddl") +
                "\nrepudiation_plan:"+ planner_command_AEDI(domainFile,outputPath+"repudiation.pddl",
                problemPath+"repudiation.pddl")+ "\n information_disclosure_plan: " + planner_command_AEDI(domainFile,outputPath+"information_disclosure.pddl",
                problemPath+"information_disclosure.pddl") + "\n denial_of_service:"+ planner_command_AEDI(domainFile,outputPath+"denial_of_service.pddl",
                problemPath+"denial_of_service.pddl") + "\n elevation_of_privilege_plan:" + planner_command_AEDI(domainFile,outputPath+"elevation_of_privilege.pddl",
                problemPath+"elevation_of_privilege.pddl")+"\n");
        return planner_command_AEDI(domainFile,outputPath+"spoofing.pddl",
                problemPath+"spoofing.pddl")+
                planner_command_AEDI(domainFile,outputPath+"tampering.pddl",
                        problemPath+"tampering.pddl")+
                planner_command_AEDI(domainFile,outputPath+"repudiation.pddl",
                        problemPath+"repudiation.pddl")+
                planner_command_AEDI(domainFile,outputPath+"information_disclosure.pddl",
                        problemPath+"information_disclosure.pddl")+
                planner_command_AEDI(domainFile,outputPath+"denial_of_service.pddl",
                        problemPath+"denial_of_service.pddl")+
                planner_command_AEDI(domainFile,outputPath+"elevation_of_privilege.pddl",
                        problemPath+"elevation_of_privilege.pddl");
    }
    public static double planner_command_compute_RQ2_s1_r2(String domainFile){
        String outputPath = FilePathConstants.AP_path_RQ2 + "S1_R2/";
        String problemPath = FilePathConstants.AEDI_path + "RQ2/S1/Restaurant_3_service/";
        System.out.print("R2: \n spoofing_plan: "+ planner_command_AEDI(domainFile,outputPath+"spoofing.pddl",
                problemPath+"spoofing.pddl") + "\n tampering_plan: "+ planner_command_AEDI(domainFile,outputPath+"tampering.pddl",
                problemPath+"tampering.pddl") +
                "\nrepudiation_plan:"+ planner_command_AEDI(domainFile,outputPath+"repudiation.pddl",
                problemPath+"repudiation.pddl")+ "\n information_disclosure_plan: " + planner_command_AEDI(domainFile,outputPath+"information_disclosure.pddl",
                problemPath+"information_disclosure.pddl") + "\n denial_of_service:"+ planner_command_AEDI(domainFile,outputPath+"denial_of_service.pddl",
                problemPath+"denial_of_service.pddl") + "\n elevation_of_privilege_plan:" + planner_command_AEDI(domainFile,outputPath+"elevation_of_privilege.pddl",
                problemPath+"elevation_of_privilege.pddl")+"\n");
        return planner_command_AEDI(domainFile,outputPath+"spoofing.pddl",
                problemPath+"spoofing.pddl")+
                planner_command_AEDI(domainFile,outputPath+"tampering.pddl",
                        problemPath+"tampering.pddl")+
                planner_command_AEDI(domainFile,outputPath+"repudiation.pddl",
                        problemPath+"repudiation.pddl")+
                planner_command_AEDI(domainFile,outputPath+"information_disclosure.pddl",
                        problemPath+"information_disclosure.pddl")+
                planner_command_AEDI(domainFile,outputPath+"denial_of_service.pddl",
                        problemPath+"denial_of_service.pddl")+
                planner_command_AEDI(domainFile,outputPath+"elevation_of_privilege.pddl",
                        problemPath+"elevation_of_privilege.pddl");
    }

    public static double planner_command_compute_RQ2_s2_p0(String domainFile){
        String outputPath = FilePathConstants.AP_path_RQ2 + "S2_P0/";
        String problemPath = FilePathConstants.AEDI_path + "RQ2/S2/Payment_proxy_1_service/";
        System.out.print("spoofing_plan: "+ planner_command_AEDI(domainFile,outputPath+"spoofing_plan.pddl",
                problemPath+"spoofing.pddl") + "\n tampering_plan: "+ planner_command_AEDI(domainFile,outputPath+"tampering_plan.pddl",
                problemPath+"tampering.pddl") +
                "\nrepudiation_plan:"+ planner_command_AEDI(domainFile,outputPath+"repudiation_plan.pddl",
                problemPath+"repudiation.pddl")+ "\n information_disclosure_plan: " + planner_command_AEDI(domainFile,outputPath+"information_disclosure_plan.pddl",
                problemPath+"information_disclosure.pddl") + "\n denial_of_service:"+ planner_command_AEDI(domainFile,outputPath+"denial_of_service_plan.pddl",
                problemPath+"denial_of_service.pddl") + "\n elevation_of_privilege_plan:" + planner_command_AEDI(domainFile,outputPath+"elevation_of_privilege_plan.pddl",
                problemPath+"elevation_of_privilege.pddl")+"\n");
        return planner_command_AEDI(domainFile,outputPath+"spoofing.pddl",
                problemPath+"spoofing.pddl")+
                planner_command_AEDI(domainFile,outputPath+"tampering.pddl",
                        problemPath+"tampering.pddl")+
                planner_command_AEDI(domainFile,outputPath+"repudiation.pddl",
                        problemPath+"repudiation.pddl")+
                planner_command_AEDI(domainFile,outputPath+"information_disclosure.pddl",
                        problemPath+"information_disclosure.pddl")+
                planner_command_AEDI(domainFile,outputPath+"denial_of_service.pddl",
                        problemPath+"denial_of_service.pddl")+
                planner_command_AEDI(domainFile,outputPath+"elevation_of_privilege.pddl",
                        problemPath+"elevation_of_privilege.pddl");
    }
    public static double planner_command_compute_RQ2_s2_p1(String domainFile){
        String outputPath = FilePathConstants.AP_path_RQ2 + "S2_P1/";
        String problemPath = FilePathConstants.AEDI_path + "RQ2/S2/Payment_proxy_2_service/";
        System.out.print("spoofing_plan: "+ planner_command_AEDI(domainFile,outputPath+"spoofing_plan.pddl",
                problemPath+"spoofing.pddl") + "\n tampering_plan: "+ planner_command_AEDI(domainFile,outputPath+"tampering_plan.pddl",
                problemPath+"tampering.pddl") +
                "\nrepudiation_plan:"+ planner_command_AEDI(domainFile,outputPath+"repudiation_plan.pddl",
                problemPath+"repudiation.pddl")+ "\n information_disclosure_plan: " + planner_command_AEDI(domainFile,outputPath+"information_disclosure_plan.pddl",
                problemPath+"information_disclosure.pddl") + "\n denial_of_service:"+ planner_command_AEDI(domainFile,outputPath+"denial_of_service_plan.pddl",
                problemPath+"denial_of_service.pddl") + "\n elevation_of_privilege_plan:" + planner_command_AEDI(domainFile,outputPath+"elevation_of_privilege_plan.pddl",
                problemPath+"elevation_of_privilege.pddl")+"\n");
        return planner_command_AEDI(domainFile,outputPath+"spoofing.pddl",
                problemPath+"spoofing.pddl")+
                planner_command_AEDI(domainFile,outputPath+"tampering.pddl",
                        problemPath+"tampering.pddl")+
                planner_command_AEDI(domainFile,outputPath+"repudiation.pddl",
                        problemPath+"repudiation.pddl")+
                planner_command_AEDI(domainFile,outputPath+"information_disclosure.pddl",
                        problemPath+"information_disclosure.pddl")+
                planner_command_AEDI(domainFile,outputPath+"denial_of_service.pddl",
                        problemPath+"denial_of_service.pddl")+
                planner_command_AEDI(domainFile,outputPath+"elevation_of_privilege.pddl",
                        problemPath+"elevation_of_privilege.pddl");
    }
    public static double planner_command_compute_RQ2_s2_p2(String domainFile){
        String outputPath = FilePathConstants.AP_path_RQ2 + "S2_P2/";
        String problemPath = FilePathConstants.AEDI_path + "RQ2/S2/Payment_proxy_3_service/";
        System.out.print("spoofing_plan: "+ planner_command_AEDI(domainFile,outputPath+"spoofing_plan.pddl",
                problemPath+"spoofing.pddl") + "\n tampering_plan: "+ planner_command_AEDI(domainFile,outputPath+"tampering_plan.pddl",
                problemPath+"tampering.pddl") +
                "\nrepudiation_plan:"+ planner_command_AEDI(domainFile,outputPath+"repudiation_plan.pddl",
                problemPath+"repudiation.pddl")+ "\n information_disclosure_plan: " + planner_command_AEDI(domainFile,outputPath+"information_disclosure_plan.pddl",
                problemPath+"information_disclosure.pddl") + "\n denial_of_service:"+ planner_command_AEDI(domainFile,outputPath+"denial_of_service_plan.pddl",
                problemPath+"denial_of_service.pddl") + "\n elevation_of_privilege_plan:" + planner_command_AEDI(domainFile,outputPath+"elevation_of_privilege_plan.pddl",
                problemPath+"elevation_of_privilege.pddl")+"\n");
        return planner_command_AEDI(domainFile,outputPath+"spoofing.pddl",
                problemPath+"spoofing.pddl")+
                planner_command_AEDI(domainFile,outputPath+"tampering.pddl",
                        problemPath+"tampering.pddl")+
                planner_command_AEDI(domainFile,outputPath+"repudiation.pddl",
                        problemPath+"repudiation.pddl")+
                planner_command_AEDI(domainFile,outputPath+"information_disclosure.pddl",
                        problemPath+"information_disclosure.pddl")+
                planner_command_AEDI(domainFile,outputPath+"denial_of_service.pddl",
                        problemPath+"denial_of_service.pddl")+
                planner_command_AEDI(domainFile,outputPath+"elevation_of_privilege.pddl",
                        problemPath+"elevation_of_privilege.pddl");
    }

    public static double planner_command_compute_RQ2_s2_o0(String domainFile){
        String outputPath = FilePathConstants.AP_path_RQ2 + "S3_O0/";
        String problemPath = FilePathConstants.AEDI_path + "RQ2/S3/Ordering_1_service/";
        System.out.print("O0 \n O0--spoofing: "+ planner_command_AEDI(domainFile,outputPath+"spoofing.pddl",
                problemPath+"spoofing.pddl") +
                "\n tampering: "+
                planner_command_AEDI(domainFile,outputPath+"tampering.pddl",
                        problemPath+"tampering.pddl")+
                "\n repudiation: "+
                planner_command_AEDI(domainFile,outputPath+"repudiation.pddl",
                        problemPath+"repudiation.pddl")+
                "\n information_disclosure: "+
                planner_command_AEDI(domainFile,outputPath+"information_disclosure.pddl",
                        problemPath+"information_disclosure.pddl")+
                "\n denial_of_service: "+
                planner_command_AEDI(domainFile,outputPath+"denial_of_service.pddl",
                        problemPath+"denial_of_service.pddl")+
                "\n elevation_of_privilege: "+
                planner_command_AEDI(domainFile,outputPath+"elevation_of_privilege.pddl",
                        problemPath+"elevation_of_privilege.pddl"));
        return planner_command_AEDI(domainFile,outputPath+"spoofing.pddl",
                problemPath+"spoofing.pddl")+
                planner_command_AEDI(domainFile,outputPath+"tampering.pddl",
                        problemPath+"tampering.pddl")+
                planner_command_AEDI(domainFile,outputPath+"repudiation.pddl",
                        problemPath+"repudiation.pddl")+
                planner_command_AEDI(domainFile,outputPath+"information_disclosure.pddl",
                        problemPath+"information_disclosure.pddl")+
                planner_command_AEDI(domainFile,outputPath+"denial_of_service.pddl",
                        problemPath+"denial_of_service.pddl")+
                planner_command_AEDI(domainFile,outputPath+"elevation_of_privilege.pddl",
                        problemPath+"elevation_of_privilege.pddl");
    }
    public static double planner_command_compute_RQ2_s2_o1(String domainFile){
        String outputPath = FilePathConstants.AP_path_RQ2 + "S3_O1/";
        String problemPath = FilePathConstants.AEDI_path + "RQ2/S3/Ordering_2_service/";
        System.out.print("O1 \n O1--spoofing: "+ planner_command_AEDI(domainFile,outputPath+"spoofing.pddl",
                problemPath+"spoofing.pddl") +
                "\n tampering: "+
                planner_command_AEDI(domainFile,outputPath+"tampering.pddl",
                        problemPath+"tampering.pddl")+
                "\n repudiation: "+
                planner_command_AEDI(domainFile,outputPath+"repudiation.pddl",
                        problemPath+"repudiation.pddl")+
                "\n information_disclosure: "+
                planner_command_AEDI(domainFile,outputPath+"information_disclosure.pddl",
                        problemPath+"information_disclosure.pddl")+
                "\n denial_of_service: "+
                planner_command_AEDI(domainFile,outputPath+"denial_of_service.pddl",
                        problemPath+"denial_of_service.pddl")+
                "\n elevation_of_privilege: "+
                planner_command_AEDI(domainFile,outputPath+"elevation_of_privilege.pddl",
                        problemPath+"elevation_of_privilege.pddl"));
        return planner_command_AEDI(domainFile,outputPath+"spoofing.pddl",
                problemPath+"spoofing.pddl")+
                planner_command_AEDI(domainFile,outputPath+"tampering.pddl",
                        problemPath+"tampering.pddl")+
                planner_command_AEDI(domainFile,outputPath+"repudiation.pddl",
                        problemPath+"repudiation.pddl")+
                planner_command_AEDI(domainFile,outputPath+"information_disclosure.pddl",
                        problemPath+"information_disclosure.pddl")+
                planner_command_AEDI(domainFile,outputPath+"denial_of_service.pddl",
                        problemPath+"denial_of_service.pddl")+
                planner_command_AEDI(domainFile,outputPath+"elevation_of_privilege.pddl",
                        problemPath+"elevation_of_privilege.pddl");
    }
    public static double planner_command_compute_RQ2_s2_o2(String domainFile){
        String outputPath = FilePathConstants.AP_path_RQ2 + "S3_O2/";
        String problemPath = FilePathConstants.AEDI_path + "RQ2/S3/Ordering_3_service/";
        System.out.print("O2 \n O2--spoofing: "+ planner_command_AEDI(domainFile,outputPath+"spoofing.pddl",
                problemPath+"spoofing.pddl") +
                "\n tampering: "+
                planner_command_AEDI(domainFile,outputPath+"tampering.pddl",
                        problemPath+"tampering.pddl")+
                "\n repudiation: "+
                planner_command_AEDI(domainFile,outputPath+"repudiation.pddl",
                        problemPath+"repudiation.pddl")+
                "\n information_disclosure: "+
                planner_command_AEDI(domainFile,outputPath+"information_disclosure.pddl",
                        problemPath+"information_disclosure.pddl")+
                "\n denial_of_service: "+
                planner_command_AEDI(domainFile,outputPath+"denial_of_service.pddl",
                        problemPath+"denial_of_service.pddl")+
                "\n elevation_of_privilege: "+
                planner_command_AEDI(domainFile,outputPath+"elevation_of_privilege.pddl",
                        problemPath+"elevation_of_privilege.pddl"));
        return planner_command_AEDI(domainFile,outputPath+"spoofing.pddl",
                problemPath+"spoofing.pddl")+
                planner_command_AEDI(domainFile,outputPath+"tampering.pddl",
                        problemPath+"tampering.pddl")+
                planner_command_AEDI(domainFile,outputPath+"repudiation.pddl",
                        problemPath+"repudiation.pddl")+
                planner_command_AEDI(domainFile,outputPath+"information_disclosure.pddl",
                        problemPath+"information_disclosure.pddl")+
                planner_command_AEDI(domainFile,outputPath+"denial_of_service.pddl",
                        problemPath+"denial_of_service.pddl")+
                planner_command_AEDI(domainFile,outputPath+"elevation_of_privilege.pddl",
                        problemPath+"elevation_of_privilege.pddl");
    }

    private static double planner_command_AEDI(String domainFile, String outputFile, String AEDIFilepath) {
        ProcessBuilder pb = new ProcessBuilder(
                cppProgram,
                "-o", domainFile,
                "-f", AEDIFilepath,
                "-s", "4",
                "-w", "1"
        );

        pb.redirectErrorStream(true);

        double planRisk = -1; // default value

        try {
            Process process = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

            // Call the modified method, which processes the stream at once and returns all required results.
            ComputeResult result = attack_path_risk_compute_abstract(reader);

            // Get the risk and output content from the result object.
            planRisk = result.weightedRisk;
            String outputContent = result.fullOutput;

            // Write the full output content to the file.
            Files.write(Paths.get(outputFile), outputContent.getBytes());

            int exitCode = process.waitFor();
            if (exitCode != 0) {
//                System.err.println("Metric-FF exited with code " + exitCode);
            }

        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
        return planRisk;
    }
    private static double planner_command_AEDI_s(String domainFile, String outputFile) {
        String AEDIFile = FilePathConstants.AEDI_path + "spoofing.pddl";

        ProcessBuilder pb = new ProcessBuilder(
                cppProgram,
                "-o", domainFile,
                "-f", AEDIFile,
                "-s", "4",
                "-w", "1"
        );

        double planRisk = -1; // default value

        try {
            Process process = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

            // Call the modified method, which processes the stream at once and returns all required results.
            ComputeResult result = attack_path_risk_compute_abstract(reader);

            // Get the risk and output content from the result object.
            planRisk = result.weightedRisk;
            String outputContent = result.fullOutput;

            // Write the full output content to the file.
            Files.write(Paths.get(outputFile), outputContent.getBytes());

            int exitCode = process.waitFor();
            if (exitCode != 0) {
//                System.err.println("Metric-FF exited with code " + exitCode);
            }

        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
//        System.out.printf("s:"+ planRisk);
        return planRisk;
    }
    private static double planner_command_AEDI_t(String domainFile, String outputFile) {
        String AEDIFile = FilePathConstants.AEDI_path + "tampering.pddl";

        ProcessBuilder pb = new ProcessBuilder(
                cppProgram,
                "-o", domainFile,
                "-f", AEDIFile,
                "-s", "4",
                "-w", "1"
        );

        double planRisk = -1; // 默认值 (default value)

        try {
            Process process = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

            // Call the modified method, which processes the stream at once and returns all required results.
            ComputeResult result = attack_path_risk_compute_abstract(reader);

            // Get the risk and output content from the result object.
            planRisk = result.weightedRisk;
            String outputContent = result.fullOutput;

            // Write the full output content to the file.
            Files.write(Paths.get(outputFile), outputContent.getBytes());

            int exitCode = process.waitFor();
            if (exitCode != 0) {
//                System.err.println("Metric-FF exited with code " + exitCode);
            }

        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
//        System.out.printf("t:"+ planRisk);
        return planRisk;
    }
    private static double planner_command_AEDI_r(String domainFile, String outputFile) {
        String AEDIFile = FilePathConstants.AEDI_path + "repudiation.pddl";

        ProcessBuilder pb = new ProcessBuilder(
                cppProgram,
                "-o", domainFile,
                "-f", AEDIFile,
                "-s", "4",
                "-w", "1"
        );

        double planRisk = -1; // 默认值 (default value)

        try {
            Process process = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

            // Call the modified method, which processes the stream at once and returns all required results.
            ComputeResult result = attack_path_risk_compute_abstract(reader);

            // Get the risk and output content from the result object.
            planRisk = result.weightedRisk;
            String outputContent = result.fullOutput;

            // Write the full output content to the file.
            Files.write(Paths.get(outputFile), outputContent.getBytes());

            int exitCode = process.waitFor();
            if (exitCode != 0) {
//                System.err.println("Metric-FF exited with code " + exitCode);
            }

        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
//        System.out.printf("r:"+ planRisk);
        return planRisk;
    }
    private static double planner_command_AEDI_i(String domainFile, String outputFile) {
        String AEDIFile = FilePathConstants.AEDI_path + "information_disclosure.pddl";

        ProcessBuilder pb = new ProcessBuilder(
                cppProgram,
                "-o", domainFile,
                "-f", AEDIFile,
                "-s", "4",
                "-w", "1"
        );

        double planRisk = -1;

        try {
            Process process = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

            // Call the modified method, which processes the stream at once and returns all required results.
            ComputeResult result = attack_path_risk_compute_abstract(reader);

            // Get the risk and output content from the result object.
            planRisk = result.weightedRisk;
            String outputContent = result.fullOutput;

            // Write the full output content to the file.
            Files.write(Paths.get(outputFile), outputContent.getBytes());

            int exitCode = process.waitFor();
            if (exitCode != 0) {
//                System.err.println("Metric-FF exited with code " + exitCode);
            }

        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
//        System.out.printf("i:"+ planRisk);
        return planRisk;
    }
    private static double planner_command_AEDI_d(String domainFile, String outputFile) {
        String AEDIFile = FilePathConstants.AEDI_path + "denial_of_service.pddl";

        ProcessBuilder pb = new ProcessBuilder(
                cppProgram,
                "-o", domainFile,
                "-f", AEDIFile,
                "-s", "4",
                "-w", "1"
        );

        double planRisk = -1;

        try {
            Process process = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

            // Call the modified method, which processes the stream at once and returns all required results.
            ComputeResult result = attack_path_risk_compute_abstract(reader);

            // Get the risk and output content from the result object.
            planRisk = result.weightedRisk;
            String outputContent = result.fullOutput;

            // Write the full output content to the file.
            Files.write(Paths.get(outputFile), outputContent.getBytes());

            int exitCode = process.waitFor();
            if (exitCode != 0) {
//                System.err.println("Metric-FF exited with code " + exitCode);
            }

        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
//        System.out.printf("d:"+ planRisk);
        return planRisk;
    }
    private static double planner_command_AEDI_e(String domainFile, String outputFile) {
        String AEDIFile = FilePathConstants.AEDI_path + "elevation_of_privilege.pddl";

        ProcessBuilder pb = new ProcessBuilder(
                cppProgram,
                "-o", domainFile,
                "-f", AEDIFile,
                "-s", "4",
                "-w", "1"
        );

        double planRisk = -1; // default value

        try {
            Process process = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

            ComputeResult result = attack_path_risk_compute_abstract(reader);

            // Get the risk and output content from the result object.
            planRisk = result.weightedRisk;
            String outputContent = result.fullOutput;

            // Write the full output content to the file.
            Files.write(Paths.get(outputFile), outputContent.getBytes());

            int exitCode = process.waitFor();
            if (exitCode != 0) {
//                System.err.println("Metric-FF exited with code " + exitCode);
            }

        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
//        System.out.printf("e:"+ planRisk);
        return planRisk;
    }

    /**
     * A static inner class to hold the results from the attack_path_risk_compute method.
     */
    private static class ComputeResult {
        final double weightedRisk;
        final String fullOutput;

        ComputeResult(double risk, String output) {
            this.weightedRisk = risk;
            this.fullOutput = output;
        }
    }

    private static ComputeResult attack_path_risk_compute_abstract(BufferedReader outputStream) throws IOException {
        if (IS_DEFAULT){
            return attack_path_risk_compute(outputStream);
        }
        else {
            return attack_path_risk_compute_nodyPa(outputStream);
        }
    }
    /**
     * Reads the output stream, looks up probability and risk for each step, calculates the weighted risk,
     * and returns an encapsulated result including the full output.
     *
     * @param outputStream Output stream reader from external process
     * @return An ComputeResult object containing the weighted risk and the complete output string.
     * @throws IOException If an error occurs while reading a file or stream
     */
    private static ComputeResult attack_path_risk_compute(BufferedReader outputStream) throws IOException {

        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(com.fasterxml.jackson.core.JsonParser.Feature.ALLOW_NON_NUMERIC_NUMBERS, true);

        List<Map<String, Object>> actionList = mapper.readValue(
                new File(FilePathConstants.LookupFilePath),
                new TypeReference<List<Map<String, Object>>>() {}
        );

        Map<String, Double> probUcMap = new HashMap<>();
        Map<String, Double> probPreMap = new HashMap<>();
        Map<String, Double> cvssMap = new HashMap<>();
        //**addedd**//
        double prob_a = 1.0;
        //**addedd**//

        for (Map<String, Object> entry : actionList) {
            // Securely obtain the Action List string
            Object actionListObj = entry.get("Action List");
            String actionListStr = "";
            if (actionListObj instanceof String) {
                actionListStr = (String) actionListObj;
            } else if (actionListObj != null) {
                actionListStr = actionListObj.toString();
            }

            if (actionListStr.isEmpty()) {
                continue; // Skip invalid entries
            }

            // Handle possible NaN values safely
            Object probUc = entry.get("Puc");
            Object probPre = entry.get("Ppre");
            Object Cvss = entry.get("CVSS");

            double prob_uc = 1.0; // default value
            double prob_pre = 1.0; // default value
            double cvss = 0.0; // default value

            if (probUc instanceof Number) {
                double probValue = ((Number) probUc).doubleValue();
                prob_uc = Double.isNaN(probValue) ? 1.0 : probValue;
            }

            if (probPre instanceof Number) {
                double probValue = ((Number) probPre).doubleValue();
                prob_pre = Double.isNaN(probValue) ? 1.0 : probValue;
            }

            if (Cvss instanceof Number) {
                double riskValue = ((Number) Cvss).doubleValue();
                cvss = Double.isNaN(riskValue) ? 0.0 : riskValue;
            }

            String actionName = extractFirstToken(actionListStr);
            if (!actionName.isEmpty()) {
                String actionKey = actionName.toLowerCase();
                probUcMap.put(actionKey, prob_uc);
                probPreMap.put(actionKey, prob_pre);
                cvssMap.put(actionKey, cvss);
                // test output
//                System.out.println("DEBUG: Mapped " + actionName + " -> probuc=" + probuc + ", cvss=" + cvss);
            }
        }
        //    Traverse the plan stream and handle all logic in a single loop.
        StringBuilder outputContent = new StringBuilder();
        String line;
        boolean isFirstStep = true;

        Pattern p = Pattern.compile("(?:step\\s+)?\\d+:\\s+([A-Za-z0-9\\-]+)(?:\\s|$)");//"(?:step\\s+)?\\d+:\\s+([a-zA-Z0-9\\-]+)");
        Pattern enterPoint = Pattern.compile("(APPLICATION-EXPOSES-ATTACK[^\\s]*)");

        double weightedRisk = 1.0;

        while ((line = outputStream.readLine()) != null) {

            // Task 1: Cache the output content
            outputContent.append(line).append("\n");

            // Task 2: Match and calculate risk
            Matcher m = p.matcher(line);
            Matcher n = enterPoint.matcher(line);

            if (m.find()) {
                String actionInPlan = m.group(1);
//                System.out.print("actionInPlan: "+actionInPlan);
                String actionLower = actionInPlan.toLowerCase();
                double lookupProbUc = probUcMap.getOrDefault(actionLower, 1.0);
                double lookupProbPre = probPreMap.getOrDefault(actionLower, 1.0);
                double lookupCvss = cvssMap.getOrDefault(actionLower, 0.0);

                boolean isEnterPoint = n.find();
                if (isEnterPoint) {
//                    System.out.print("\n"+"expose line: "+line+"\n");
                    // CVSS
                    // weightedRisk = lookupCvss;
                    //**added**//
                    prob_a = lookupProbPre * lookupProbUc;
                    weightedRisk = lookupCvss * prob_a * weightedRisk;
                    //**added**//
                    // isFirstStep = false;
                   // System.out.printf("\n csot %s %s",weightedRisk, actionLower);
                    // System.out.printf("\n enterpoint"+line+"\n");
                }
                else {
                    prob_a = lookupProbPre * lookupProbUc;
                    weightedRisk =  prob_a * weightedRisk;
                    // System.out.printf("\n weightedRisk: "+ weightedRisk);
                    // System.out.printf("\n step:"+line+"\n");
                } // Multiply by the corresponding probability at each step
            }
//            else {System.out.println("failed");}
        }
        // If no available AP.
        if (weightedRisk == 1)
        {
            weightedRisk = 0;
        }

        // Return the encapsulated object containing both results.
        return new ComputeResult(weightedRisk, outputContent.toString());
    }
    private static ComputeResult attack_path_risk_compute_nodyPa(BufferedReader outputStream) throws IOException {

        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(com.fasterxml.jackson.core.JsonParser.Feature.ALLOW_NON_NUMERIC_NUMBERS, true);

        List<Map<String, Object>> actionList = mapper.readValue(
                new File(FilePathConstants.LookupFilePathPath_nodyPa),
                new TypeReference<List<Map<String, Object>>>() {}
        );

        Map<String, Double> probUcMap = new HashMap<>();
        Map<String, Double> probPreMap = new HashMap<>();
        Map<String, Double> cvssMap = new HashMap<>();
        //**addedd**//
        double prob_a = 1.0;
        //**addedd**//

        for (Map<String, Object> entry : actionList) {
            // Securely obtain the Action List string
            Object actionListObj = entry.get("Action List");
            String actionListStr = "";
            if (actionListObj instanceof String) {
                actionListStr = (String) actionListObj;
            } else if (actionListObj != null) {
                actionListStr = actionListObj.toString();
            }

            if (actionListStr.isEmpty()) {
                continue; // Skip invalid entries
            }

            // Handling possible NaN values safely
            Object probUc = entry.get("Puc");
            Object probPre = entry.get("Ppre");
            Object Cvss = entry.get("CVSS");

            double prob_uc = 1.0; // default value
            double prob_pre = 1.0; // default value
            double cvss = 0.0; // default value

            if (probUc instanceof Number) {
                double probValue = ((Number) probUc).doubleValue();
                prob_uc = Double.isNaN(probValue) ? 1.0 : probValue;
            }

            if (probPre instanceof Number) {
                double probValue = ((Number) probPre).doubleValue();
                prob_pre = Double.isNaN(probValue) ? 1.0 : probValue;
            }

            if (Cvss instanceof Number) {
                double riskValue = ((Number) Cvss).doubleValue();
                cvss = Double.isNaN(riskValue) ? 0.0 : riskValue;
            }

            String actionName = extractFirstToken(actionListStr);
            if (!actionName.isEmpty()) {
                String actionKey = actionName.toLowerCase();
                probUcMap.put(actionKey, prob_uc);
                probPreMap.put(actionKey, prob_pre);
                cvssMap.put(actionKey, cvss);
                // test output
//                System.out.println("DEBUG: Mapped " + actionName + " -> probuc=" + probuc + ", cvss=" + cvss);
            }
        }
        //  2.  Traverse the plan stream and handle all logic in a single loop.
        StringBuilder outputContent = new StringBuilder();
        String line;
        boolean isFirstStep = true;

        Pattern p = Pattern.compile("(?:step\\s+)?\\d+:\\s+([A-Za-z0-9\\-]+)(?:\\s|$)");//"(?:step\\s+)?\\d+:\\s+([a-zA-Z0-9\\-]+)");
        Pattern enterPoint = Pattern.compile("(APPLICATION-EXPOSES-ATTACK[^\\s]*)");

        double weightedRisk = 1.0;

        while ((line = outputStream.readLine()) != null) {

            // Task 1: Cache the output content
            outputContent.append(line).append("\n");

            // Task 2: Match and calculate risk
            Matcher m = p.matcher(line);
            Matcher n = enterPoint.matcher(line);

            if (m.find()) {
                String actionInPlan = m.group(1);
//                System.out.print("actionInPlan: "+actionInPlan);
                String actionLower = actionInPlan.toLowerCase();
                double lookupProbUc = probUcMap.getOrDefault(actionLower, 1.0);
                double lookupProbPre = probPreMap.getOrDefault(actionLower, 1.0);
                double lookupCvss = cvssMap.getOrDefault(actionLower, 0.0);

                boolean isEnterPoint = n.find();
                if (isEnterPoint) {
//                    System.out.print("\n"+"expose line: "+line+"\n");
                    // CVSS
                    // weightedRisk = lookupCvss;
                    //**added**//
                    prob_a = lookupProbPre * lookupProbUc;
                    weightedRisk = lookupCvss * prob_a * weightedRisk;
                    //**added**//
                    // isFirstStep = false;
                    // System.out.printf("\n csot %s %s",weightedRisk, actionLower);
                    // System.out.printf("\n enterpoint"+line+"\n");
                }
                else {
                    prob_a = lookupProbPre * lookupProbUc;
                    weightedRisk =  prob_a * weightedRisk;
                    // System.out.printf("\n weightedRisk: "+ weightedRisk);
                    // System.out.printf("\n step:"+line+"\n");
                } // Multiply by the corresponding probability at each step
            }
//            else {System.out.println("failed");}
        }
        // If no available AP.
        if (weightedRisk == 1)
        {
            weightedRisk = 0;
        }

        // Return the encapsulated object containing both results.
        return new ComputeResult(weightedRisk, outputContent.toString());
    }

    /**
     * Extract first token from Action List string
     */
    private static String extractFirstToken(String actionListStr) {
        // match (:action xxx ...
        Pattern pattern = Pattern.compile("\\(:action\\s+(\\S+)", Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(actionListStr);
        if (matcher.find()) {
//            System.out.printf("find: %s ", matcher.group(1));
            return matcher.group(1);
        } else {
            return "";
        }
    }

    public static void shutdown(){
            if (executor != null && !executor.isShutdown()){
                executor.shutdown();}
            try {
                if (!executor.awaitTermination(1, TimeUnit.SECONDS)) {
                    executor.shutdownNow();
                }
            } catch (InterruptedException e) {
                executor.shutdownNow();
                Thread.currentThread().interrupt();
            }
    }
}
