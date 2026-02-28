package saqure.Planner;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import saqure.utils.PathConstants;

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

public class PlannerCommandComputing {
    private static final String cppProgram = PathConstants.FFPath;
    public static boolean IS_DEFAULT = true;

    private static final ThreadPoolExecutor executor = new ThreadPoolExecutor(
            Runtime.getRuntime().availableProcessors(),
            Runtime.getRuntime().availableProcessors(),
            1, TimeUnit.SECONDS,
            new LinkedBlockingQueue<>());

    // Main computing entry point
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

    public static double planner_command_compute_RQ2(String domainFile, String outputPath, String problemPath, String orderForDebug){
        System.out.print("\n spoofing_plan: "+ planner_command_AEDI(domainFile,outputPath+"spoofing_plan.pddl",
                problemPath+"spoofing.pddl", orderForDebug) + "\n tampering_plan: "+ planner_command_AEDI(domainFile,outputPath+"tampering_plan.pddl",
                problemPath+"tampering.pddl", orderForDebug) +
                "\nrepudiation_plan:"+ planner_command_AEDI(domainFile,outputPath+"repudiation_plan.pddl",
                problemPath+"repudiation.pddl", orderForDebug)+ "\n information_disclosure_plan: " + planner_command_AEDI(domainFile,outputPath+"information_disclosure_plan.pddl",
                problemPath+"information_disclosure.pddl", orderForDebug) + "\n denial_of_service:"+ planner_command_AEDI(domainFile,outputPath+"denial_of_service_plan.pddl",
                problemPath+"denial_of_service.pddl", orderForDebug) + "\n elevation_of_privilege_plan:" + planner_command_AEDI(domainFile,outputPath+"elevation_of_privilege_plan.pddl",
                problemPath+"elevation_of_privilege.pddl", orderForDebug)+"\n");
        return planner_command_AEDI(domainFile,outputPath+"spoofing_plan.pddl",
                problemPath+"spoofing.pddl", orderForDebug)+
                planner_command_AEDI(domainFile,outputPath+"tampering_plan.pddl",
                        problemPath+"tampering.pddl", orderForDebug)+
                planner_command_AEDI(domainFile,outputPath+"repudiation_plan.pddl",
                        problemPath+"repudiation.pddl", orderForDebug)+
                planner_command_AEDI(domainFile,outputPath+"information_disclosure_plan.pddl",
                        problemPath+"information_disclosure.pddl", orderForDebug)+
                planner_command_AEDI(domainFile,outputPath+"denial_of_service_plan.pddl",
                        problemPath+"denial_of_service.pddl", orderForDebug)+
                planner_command_AEDI(domainFile,outputPath+"elevation_of_privilege_plan.pddl",
                        problemPath+"elevation_of_privilege.pddl", orderForDebug);
    }

    private static double planner_command_AEDI(String domainFile, String outputFile, String problemFilepath, String order) {
        ProcessBuilder pb = new ProcessBuilder(
                cppProgram,
                "-o", domainFile,
                "-f", problemFilepath,
                "-s", "4",
                "-w", "1"
        );

        pb.redirectErrorStream(true);// Merging stderr into stdout avoids blocking.

        double planCost = -1; // default value

        try {
            Process process = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

            // Call the modified method, which processes the stream at once and returns all required results.
            ActionResult result = ActionProbability_abstract(reader);
//            System.out.print(order+": "+"weightedCost: "+result.weightedCost+"\n");

            // Get the cost and output content from the result object.
            planCost = result.weightedCost;
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
//        System.out.printf("i:"+ planCost);
        return planCost;
    }

    private static double planner_command_AEDI_s(String domainFile, String outputFile) {
        String problemFile = PathConstants.AEDI_path + "spoofing.pddl";

        ProcessBuilder pb = new ProcessBuilder(
                cppProgram,
                "-o", domainFile,
                "-f", problemFile,
                "-s", "4",
                "-w", "1"
        );

        double planCost = -1; // default value

        try {
            Process process = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

            // Call the modified method, which processes the stream at once and returns all required results.
            ActionResult result = ActionProbability_abstract(reader);

            // Get the cost and output content from the result object.
            planCost = result.weightedCost;
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
//        System.out.printf("s:"+ planCost);
        return planCost;
    }
    private static double planner_command_AEDI_t(String domainFile, String outputFile) {
        String problemFile = PathConstants.AEDI_path + "tampering.pddl";

        ProcessBuilder pb = new ProcessBuilder(
                cppProgram,
                "-o", domainFile,
                "-f", problemFile,
                "-s", "4",
                "-w", "1"
        );

        double planCost = -1; // default value

        try {
            Process process = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

            // Call the modified method, which processes the stream at once and returns all required results.
            ActionResult result = ActionProbability_abstract(reader);

            // Get the cost and output content from the result object.
            planCost = result.weightedCost;
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
//        System.out.printf("t:"+ planCost);
        return planCost;
    }
    private static double planner_command_AEDI_r(String domainFile, String outputFile) {
        String problemFile = PathConstants.AEDI_path + "repudiation.pddl";

        ProcessBuilder pb = new ProcessBuilder(
                cppProgram,
                "-o", domainFile,
                "-f", problemFile,
                "-s", "4",
                "-w", "1"
        );

        double planCost = -1; // default value

        try {
            Process process = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

            // Call the modified method, which processes the stream at once and returns all required results.
            ActionResult result = ActionProbability_abstract(reader);

            // Get the cost and output content from the result object.
            planCost = result.weightedCost;
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
//        System.out.printf("r:"+ planCost);
        return planCost;
    }
    private static double planner_command_AEDI_i(String domainFile, String outputFile) {
        String problemFile = PathConstants.AEDI_path + "information_disclosure.pddl";

        ProcessBuilder pb = new ProcessBuilder(
                cppProgram,
                "-o", domainFile,
                "-f", problemFile,
                "-s", "4",
                "-w", "1"
        );

        double planCost = -1; // default value

        try {
            Process process = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

            // Call the modified method, which processes the stream at once and returns all required results.
            ActionResult result = ActionProbability_abstract(reader);

            // Get the cost and output content from the result object.
            planCost = result.weightedCost;
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
//        System.out.printf("i:"+ planCost);
        return planCost;
    }
    private static double planner_command_AEDI_d(String domainFile, String outputFile) {
        String problemFile = PathConstants.AEDI_path + "denial_of_service.pddl";

        ProcessBuilder pb = new ProcessBuilder(
                cppProgram,
                "-o", domainFile,
                "-f", problemFile,
                "-s", "4",
                "-w", "1"
        );

        double planCost = -1; // default value

        try {
            Process process = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

            // Call the modified method, which processes the stream at once and returns all required results.
            ActionResult result = ActionProbability_abstract(reader);

            // Get the cost and output content from the result object.
            planCost = result.weightedCost;
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
//        System.out.printf("d:"+ planCost);
        return planCost;
    }
    private static double planner_command_AEDI_e(String domainFile, String outputFile) {
        String problemFile = PathConstants.AEDI_path + "elevation_of_privilege.pddl";

        ProcessBuilder pb = new ProcessBuilder(
                cppProgram,
                "-o", domainFile,
                "-f", problemFile,
                "-s", "4",
                "-w", "1"
        );

        double planCost = -1; // default value

        try {
            Process process = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

            // Call the modified method, which processes the stream at once and returns all required results.
            ActionResult result = ActionProbability_abstract(reader);

            // Get the cost and output content from the result object.
            planCost = result.weightedCost;
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
//        System.out.printf("e:"+ planCost);
        return planCost;
    }

    /**
     * A static inner class to hold the results from the ActionProbabilityLookup method.
     */
    private static class ActionResult {
        final double weightedCost;
        final String fullOutput;

        ActionResult(double cost, String output) {
            this.weightedCost = cost;
            this.fullOutput = output;
        }
    }

    private static ActionResult ActionProbability_abstract(BufferedReader outputStream) throws IOException {
        if (IS_DEFAULT){
            return ActionProbabilityLookup(outputStream);
        }
        else {
            return ActionProbability_nodyPa(outputStream);
        }
    }
    /**
     * Reads the output stream, looks up probability and cost for each step, calculates the weighted cost,
     * and returns an encapsulated result including the full output.
     *
     * @param outputStream Output stream reader from external process
     * @return An ActionResult object containing the weighted cost and the complete output string.
     * @throws IOException If an error occurs while reading a file or stream
     */
    private static ActionResult ActionProbabilityLookup(BufferedReader outputStream) throws IOException {

        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(com.fasterxml.jackson.core.JsonParser.Feature.ALLOW_NON_NUMERIC_NUMBERS, true);

        List<Map<String, Object>> actionList = mapper.readValue(
                new File(PathConstants.LookupFilePath),
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
            Object costCvss = entry.get("CVSS");

            double prob_uc = 1.0; //  default value
            double prob_pre = 1.0; //  default value
            double cost_cvss = 0.0; //  default value

            if (probUc instanceof Number) {
                double probValue = ((Number) probUc).doubleValue();
                prob_uc = Double.isNaN(probValue) ? 1.0 : probValue;
            }

            if (probPre instanceof Number) {
                double probValue = ((Number) probPre).doubleValue();
                prob_pre = Double.isNaN(probValue) ? 1.0 : probValue;
            }

            if (costCvss instanceof Number) {
                double costValue = ((Number) costCvss).doubleValue();
                cost_cvss = Double.isNaN(costValue) ? 0.0 : costValue;
            }

            String actionName = extractFirstToken(actionListStr);
            if (!actionName.isEmpty()) {
                String actionKey = actionName.toLowerCase();
                probUcMap.put(actionKey, prob_uc);
                probPreMap.put(actionKey, prob_pre);
                cvssMap.put(actionKey, cost_cvss);
//                System.out.println("DEBUG: Mapped " + actionName + " -> probuc=" + probuc + ", cost_cvss=" + cost_cvss);
            }
        }
        //    Traverse the plan stream and handle all logic in a single loop.
        StringBuilder outputContent = new StringBuilder();
        String line;
        boolean isFirstStep = true;

        Pattern p = Pattern.compile("(?:step\\s+)?\\d+:\\s+([A-Za-z0-9\\-]+)(?:\\s|$)");//"(?:step\\s+)?\\d+:\\s+([a-zA-Z0-9\\-]+)");
        Pattern enterPoint = Pattern.compile("(APPLICATION-EXPOSES-ATTACK[^\\s]*)");

        double weightedCost = 1.0;

        while ((line = outputStream.readLine()) != null) {

            // Task 1: Cache the output content
            outputContent.append(line).append("\n");

            // Task 2: Match and calculate cost
            Matcher m = p.matcher(line);
            Matcher n = enterPoint.matcher(line);

            if (m.find()) {
                String actionInPlan = m.group(1);
                String actionLower = actionInPlan.toLowerCase();
                double lookupProbUc = probUcMap.getOrDefault(actionLower, 1.0);
                double lookupProbPre = probPreMap.getOrDefault(actionLower, 1.0);
                double lookupCvss = cvssMap.getOrDefault(actionLower, 0.0);

//                System.out.printf("Step action: %s\tprobability: %.3f\tcost: %.3f%n",
//                        actionLower, lookupProbUc, lookupCvss);
                boolean isEnterPoint = n.find();
                if (isEnterPoint) {
                    // CVSS
                    // weightedCost = lookupCvss;
                    //**added**//
                    prob_a = lookupProbPre * lookupProbUc;
                    weightedCost = lookupCvss * prob_a * weightedCost;
                    //**added**//
                   // isFirstStep = false;
//                    System.out.printf("csot %s %s",weightedCost, actionLower);
                }
                else {
                    prob_a = lookupProbPre * lookupProbUc;
                    weightedCost =  prob_a * weightedCost;
                } // Multiply by the corresponding probability at each step
//                System.out.printf("weightedCost: "+ weightedCost);
            }
//            else {System.out.println("failed");}
        }
        // If no available AP.
        if (weightedCost == 1)
        {
            weightedCost = 0;
        }

        // Return the encapsulated object containing both results.
        return new ActionResult(weightedCost, outputContent.toString());
    }
    private static ActionResult ActionProbability_nodyPa(BufferedReader outputStream) throws IOException {

        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(com.fasterxml.jackson.core.JsonParser.Feature.ALLOW_NON_NUMERIC_NUMBERS, true);

        List<Map<String, Object>> actionList = mapper.readValue(
                new File(PathConstants.LookupFilePath_nodyPa),
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
            Object costCvss = entry.get("CVSS");

            double prob_uc = 1.0; // default value
            double prob_pre = 1.0; // default value
            double cost_cvss = 0.0; // default value

            if (probUc instanceof Number) {
                double probValue = ((Number) probUc).doubleValue();
                prob_uc = Double.isNaN(probValue) ? 1.0 : probValue;
            }

            if (probPre instanceof Number) {
                double probValue = ((Number) probPre).doubleValue();
                prob_pre = Double.isNaN(probValue) ? 1.0 : probValue;
            }

            if (costCvss instanceof Number) {
                double costValue = ((Number) costCvss).doubleValue();
                cost_cvss = Double.isNaN(costValue) ? 0.0 : costValue;
            }

            String actionName = extractFirstToken(actionListStr);
            if (!actionName.isEmpty()) {
                String actionKey = actionName.toLowerCase();
                probUcMap.put(actionKey, prob_uc);
                probPreMap.put(actionKey, prob_pre);
                cvssMap.put(actionKey, cost_cvss);
//                System.out.println("DEBUG: Mapped " + actionName + " -> probuc=" + probuc + ", cost_cvss=" + cost_cvss);
            }
        }
        //    Traverse the plan stream and handle all logic in a single loop.
        StringBuilder outputContent = new StringBuilder();
        String line;
        boolean isFirstStep = true;

        Pattern p = Pattern.compile("(?:step\\s+)?\\d+:\\s+([A-Za-z0-9\\-]+)(?:\\s|$)");//"(?:step\\s+)?\\d+:\\s+([a-zA-Z0-9\\-]+)");
        Pattern enterPoint = Pattern.compile("(APPLICATION-EXPOSES-ATTACK[^\\s]*)");

        double weightedCost = 1.0;

        while ((line = outputStream.readLine()) != null) {

            // Task 1: Cache the output content
            outputContent.append(line).append("\n");

            // Task 2: Match and calculate cost
            Matcher m = p.matcher(line);
            Matcher n = enterPoint.matcher(line);

            if (m.find()) {
                String actionInPlan = m.group(1);
                String actionLower = actionInPlan.toLowerCase();
                double lookupProbUc = probUcMap.getOrDefault(actionLower, 1.0);
                double lookupProbPre = probPreMap.getOrDefault(actionLower, 1.0);
                double lookupCvss = cvssMap.getOrDefault(actionLower, 0.0);

//                System.out.printf("Step action: %s\tprobability: %.3f\tcost: %.3f%n",
//                        actionLower, lookupProbUc, lookupCvss);
                boolean isEnterPoint = n.find();
                if (isEnterPoint) {
                    // CVSS
                    // weightedCost = lookupCvss;
                    //**added**//
                    prob_a = lookupProbPre * lookupProbUc;
                    weightedCost = lookupCvss * prob_a * weightedCost;
                    //**added**//
                    // isFirstStep = false;
//                    System.out.printf("csot %s %s",weightedCost, actionLower);
                }
                else {
                    prob_a = lookupProbPre * lookupProbUc;
                    weightedCost =  prob_a * weightedCost;
                } // Multiply by the corresponding probability at each step
//                System.out.printf("weightedCost: "+ weightedCost);
            }
//            else {System.out.println("failed");}
        }
        // If no available AP.
        if (weightedCost == 1)
        {
            weightedCost = 0;
        }

        // Return the encapsulated object containing both results.
        return new ActionResult(weightedCost, outputContent.toString());
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
