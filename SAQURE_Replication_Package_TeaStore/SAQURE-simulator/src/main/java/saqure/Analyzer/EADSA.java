package saqure.Analyzer;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import saqure.utils.FilePathConstants;

import java.io.*;
import java.time.Duration;
import java.time.Instant;
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

    // 6 = the number of STRIDE problems planned per implementation. Metric-FF is bound by
    // the ~758 MB of anonymous memory each invocation zero-fills, not by CPU, so the batch
    // saturates at about 4 concurrent processes on this host; handing it availableProcessors()
    // (12) is measurably slower than 6. Same setting as the SEFA package.
    private static final int POOL_SIZE =
            Math.max(1, Math.min(Runtime.getRuntime().availableProcessors(), 6));

    private static final ThreadPoolExecutor executor = new ThreadPoolExecutor(
            POOL_SIZE,
            POOL_SIZE,
            1, TimeUnit.SECONDS,
            new LinkedBlockingQueue<>());

    // Main computing entry point
    public static double computeScenario(String domainFile, outputPath path){
        // One call = the risk assessment of one implementation, which the runtime decision
        // time includes. See RiskTiming.
        Instant riskStart = Instant.now();
        try {
            return computationStrategy.compute(domainFile, path);
        } finally {
            RiskTiming.record(Duration.between(riskStart, Instant.now()));
        }
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
    public static class problemPath {
        final String spoofingPath;
        final String tamperingPath;
        final String repudiationPath;
        final String infoDisclosurePath;
        final String denialOfServicePath;
        final String elevationOfPrivilegePath;

        public problemPath(String spoofingPath, String tamperingPath, String repudiationPath, String infoDisclosurePath, String denialOfServicePath, String elevationOfPrivilegePath){
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

        setComputationMode(ComputationMode.PARALLEL); // default parallel
    }

    // Interface: external class calls control whether to use parallel or serial execution.
    public static void setComputationMode(ComputationMode mode) {
        switch (mode) {
            case PARALLEL:
                computationStrategy = new ParallelComputation(executor);
                break;
            case SEQUENTIAL:
                computationStrategy = new SequentialComputation();
                break;
        }
    }

    /** Worker count for attack-path planning; {@link ModularEADSA} uses the same. */
    public static int poolSize() {
        return POOL_SIZE;
    }

    /** Whether risk assessment runs in parallel; {@link ModularEADSA} follows the same setting. */
    public static boolean isParallel() {
        return computationStrategy instanceof ParallelComputation;
    }

    public static class ParallelComputation implements ScenarioComputation{
        private final ThreadPoolExecutor executor;
        public ParallelComputation(ThreadPoolExecutor executor){this.executor = executor;}

        @Override
        public double compute(String domainFile, outputPath path){
            return computeParallelSum(
                    () -> ff_planner_invocation_spoofing(domainFile, path.spoofingPath),
                    () -> ff_planner_invocation_tampering(domainFile, path.tamperingPath),
                    () -> ff_planner_invocation_repudiation(domainFile, path.repudiationPath),
                    () -> ff_planner_invocation_information_disclosure(domainFile, path.infoDisclosurePath),
                    () -> ff_planner_invocation_dos(domainFile, path.denialOfServicePath),
                    () -> ff_planner_invocation_elevation(domainFile, path.elevationOfPrivilegePath));
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
            return ff_planner_invocation_spoofing(domainFile, path.spoofingPath) +
                    ff_planner_invocation_tampering(domainFile, path.tamperingPath) +
                    ff_planner_invocation_repudiation(domainFile, path.repudiationPath) +
                    ff_planner_invocation_information_disclosure(domainFile, path.infoDisclosurePath) +
                    ff_planner_invocation_dos(domainFile, path.denialOfServicePath) +
                    ff_planner_invocation_elevation(domainFile, path.elevationOfPrivilegePath);
        }
    }

    /**
     * Risk of one implementation: the six STRIDE attack-path planning problems under
     * {@code problemPath}, scored against {@code domainFile}.
     *
     * <p>Goes through the configured {@link ScenarioComputation} so the parallel/sequential
     * ablation applies here too, and plans each problem once. The previous body invoked the
     * planner twice per problem -- once inside the {@code System.out.print} argument list and
     * once again in the {@code return} expression -- which doubled the work without changing
     * the result.
     */
    public static double planner_command_compute(String domainFile, String outputPath, String problemPath, String orderForDebug){
        List<Supplier<Double>> tasks = List.of(
                () -> ff_planner_invocation(domainFile, outputPath + "spoofing_plan.pddl", problemPath + "spoofing.pddl", orderForDebug),
                () -> ff_planner_invocation(domainFile, outputPath + "tampering_plan.pddl", problemPath + "tampering.pddl", orderForDebug),
                () -> ff_planner_invocation(domainFile, outputPath + "repudiation_plan.pddl", problemPath + "repudiation.pddl", orderForDebug),
                () -> ff_planner_invocation(domainFile, outputPath + "information_disclosure_plan.pddl", problemPath + "information_disclosure.pddl", orderForDebug),
                () -> ff_planner_invocation(domainFile, outputPath + "denial_of_service_plan.pddl", problemPath + "denial_of_service.pddl", orderForDebug),
                () -> ff_planner_invocation(domainFile, outputPath + "elevation_of_privilege_plan.pddl", problemPath + "elevation_of_privilege.pddl", orderForDebug));

        Instant riskStart = Instant.now();
        try {
            if (computationStrategy instanceof ParallelComputation) {
                return computeParallelSum(tasks.toArray(new Supplier[0]));
            }
            double sum = 0.0;
            for (Supplier<Double> task : tasks) {
                sum += task.get();
            }
            return sum;
        } finally {
            RiskTiming.record(Duration.between(riskStart, Instant.now()));
        }
    }

    private static double ff_planner_invocation(String domainFile, String outputFile, String problemFilepath, String order) {
        ProcessBuilder pb = new ProcessBuilder(
                cppProgram,
                "-o", domainFile,
                "-f", problemFilepath,
                "-s", "4",
                "-w", "1"
        );

        pb.redirectErrorStream(true);// Merging stderr into stdout avoids blocking.

        double planRisk = -1; // default value

        try {
            Process process = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

            // Call the modified method, which processes the stream at once and returns all required results.
            ComputeResult result = attack_path_risk_compute_abstract(reader);
//            System.out.print(order+": "+"weightedRisk: "+result.weightedRisk+"\n");

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

    private static double ff_planner_invocation_spoofing(String domainFile, String outputFile) {
        String problemFile = FilePathConstants.AEDI_path + "spoofing.pddl";

        ProcessBuilder pb = new ProcessBuilder(
                cppProgram,
                "-o", domainFile,
                "-f", problemFile,
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
    private static double ff_planner_invocation_tampering(String domainFile, String outputFile) {
        String problemFile = FilePathConstants.AEDI_path + "tampering.pddl";

        ProcessBuilder pb = new ProcessBuilder(
                cppProgram,
                "-o", domainFile,
                "-f", problemFile,
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
//        System.out.printf("t:"+ planRisk);
        return planRisk;
    }
    private static double ff_planner_invocation_repudiation(String domainFile, String outputFile) {
        String problemFile = FilePathConstants.AEDI_path + "repudiation.pddl";

        ProcessBuilder pb = new ProcessBuilder(
                cppProgram,
                "-o", domainFile,
                "-f", problemFile,
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
//        System.out.printf("r:"+ planRisk);
        return planRisk;
    }
    private static double ff_planner_invocation_information_disclosure(String domainFile, String outputFile) {
        String problemFile = FilePathConstants.AEDI_path + "information_disclosure.pddl";

        ProcessBuilder pb = new ProcessBuilder(
                cppProgram,
                "-o", domainFile,
                "-f", problemFile,
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
//        System.out.printf("i:"+ planRisk);
        return planRisk;
    }
    private static double ff_planner_invocation_dos(String domainFile, String outputFile) {
        String problemFile = FilePathConstants.AEDI_path + "denial_of_service.pddl";

        ProcessBuilder pb = new ProcessBuilder(
                cppProgram,
                "-o", domainFile,
                "-f", problemFile,
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
//        System.out.printf("d:"+ planRisk);
        return planRisk;
    }
    private static double ff_planner_invocation_elevation(String domainFile, String outputFile) {
        String problemFile = FilePathConstants.AEDI_path + "elevation_of_privilege.pddl";

        ProcessBuilder pb = new ProcessBuilder(
                cppProgram,
                "-o", domainFile,
                "-f", problemFile,
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

            double prob_uc = 1.0; //  default value
            double prob_pre = 1.0; //  default value
            double cvss = 0.0; //  default value

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
        // Eq.(1) multiplies the CVSS of *the* entry action once; a plan that mentions a second
        // APPLICATION-EXPOSES-ATTACK line must not multiply another CVSS on top of it.
        boolean entryCvssApplied = false;

        while ((line = outputStream.readLine()) != null) {

            // Task 1: Cache the output content
            outputContent.append(line).append("\n");

            // Task 2: Match and calculate risk
            Matcher m = p.matcher(line);
            Matcher n = enterPoint.matcher(line);

            if (m.find()) {
                String actionInPlan = m.group(1);
                String actionLower = actionInPlan.toLowerCase();
                double lookupProbUc = probUcMap.getOrDefault(actionLower, 1.0);
                double lookupProbPre = probPreMap.getOrDefault(actionLower, 1.0);
                double lookupCvss = cvssMap.getOrDefault(actionLower, 0.0);

//
                boolean isEnterPoint = n.find() && !entryCvssApplied;
                if (isEnterPoint) {
                    entryCvssApplied = true;
                    // CVSS
                    // weightedRisk = lookupCvss;
                    //**added**//
                    prob_a = lookupProbPre * lookupProbUc;
                    weightedRisk = lookupCvss * prob_a * weightedRisk;
                    //**added**//
                   // isFirstStep = false;
//                    System.out.printf("csot %s %s",weightedRisk, actionLower);
                }
                else {
                    prob_a = lookupProbPre * lookupProbUc;
                    weightedRisk =  prob_a * weightedRisk;
                } // Multiply by the corresponding probability at each step
//                System.out.printf("weightedRisk: "+ weightedRisk);
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
                new File(FilePathConstants.LookupFilePath_nodyPa),
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
        // Eq.(1) multiplies the CVSS of *the* entry action once; a plan that mentions a second
        // APPLICATION-EXPOSES-ATTACK line must not multiply another CVSS on top of it.
        boolean entryCvssApplied = false;

        while ((line = outputStream.readLine()) != null) {

            // Task 1: Cache the output content
            outputContent.append(line).append("\n");

            // Task 2: Match and calculate risk
            Matcher m = p.matcher(line);
            Matcher n = enterPoint.matcher(line);

            if (m.find()) {
                String actionInPlan = m.group(1);
                String actionLower = actionInPlan.toLowerCase();
                double lookupProbUc = probUcMap.getOrDefault(actionLower, 1.0);
                double lookupProbPre = probPreMap.getOrDefault(actionLower, 1.0);
                double lookupCvss = cvssMap.getOrDefault(actionLower, 0.0);

//
                boolean isEnterPoint = n.find() && !entryCvssApplied;
                if (isEnterPoint) {
                    entryCvssApplied = true;
                    // CVSS
                    // weightedRisk = lookupCvss;
                    //**added**//
                    prob_a = lookupProbPre * lookupProbUc;
                    weightedRisk = lookupCvss * prob_a * weightedRisk;
                    //**added**//
                    // isFirstStep = false;
//                    System.out.printf("csot %s %s",weightedRisk, actionLower);
                }
                else {
                    prob_a = lookupProbPre * lookupProbUc;
                    weightedRisk =  prob_a * weightedRisk;
                } // Multiply by the corresponding probability at each step
//                System.out.printf("weightedRisk: "+ weightedRisk);
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
