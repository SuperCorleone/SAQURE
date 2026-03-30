package saqure.Planner;

import com.fasterxml.jackson.core.json.JsonReadFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import lombok.extern.slf4j.Slf4j;
import saqure.utils.FilePathConstants;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Slf4j
public class PrismModelChecker {
    private PrismModelChecker() {
        throw new IllegalStateException("Utility class");
    }

    public enum ExternalChanges{
        AEDI_CHANGE_VERSION_PERSISTENCE,
        AEDI_CLOSE_SECURITY_CONTROL_AUTHENTICATION,
        AEDI_CHANGE_VERSION_WEBUI;
    }

    public static void update_AED_AEDI(ExternalChanges changes){
        switch (changes){
            case AEDI_CHANGE_VERSION_WEBUI -> changeVersion_AEDI_RQ2_S1_W2("1.4.10.9", "1.4.21.0", "version XStreamLibrary_TeaStore");
            case AEDI_CLOSE_SECURITY_CONTROL_AUTHENTICATION -> closeSecurityControl_AEDI_RQ2_S2_A3("(endpoint-has-asn1-sanity-checks TeaStore pem-endpoint_TeaStore)", ";(not (endpoint-has-asn1-sanity-checks TeaStore pem-endpoint_TeaStore))");
            case AEDI_CHANGE_VERSION_PERSISTENCE -> changeVersion_AEDI_RQ2_S3_P2("31.1.1.0", "31.1.0.0", "version guava-library_TeaStore");
            default -> System.out.print("No Runtime External Changes");
        }
    }
    public static void reverseUpdating(ExternalChanges changes){
        switch (changes){
            case AEDI_CHANGE_VERSION_WEBUI -> changeVersion_AEDI_RQ2_S1_W2("1.4.21.0", "1.4.10.9", "version XStreamLibrary_TeaStore");
            case AEDI_CLOSE_SECURITY_CONTROL_AUTHENTICATION -> closeSecurityControl_AEDI_RQ2_S2_A3(";(not (endpoint-has-asn1-sanity-checks TeaStore pem-endpoint_TeaStore))", "(endpoint-has-asn1-sanity-checks TeaStore pem-endpoint_TeaStore)");
            case AEDI_CHANGE_VERSION_PERSISTENCE -> changeVersion_AEDI_RQ2_S3_P2("31.1.0.0", "31.1.1.0", "version guava-library_TeaStore");
            default -> System.out.print("No Runtime External Changes");
        }
    }

    private static void changeActionCost_AED(String key1, String key2, double original_p_uc, double new_p_uc){
        String checkTablePath = FilePathConstants.LookupFilePath;
        Path AED_path = Path.of(FilePathConstants.AED_path);
        // modify AED
        int originalCost = (int) Math.ceil(Math.max(1.0, -100.0 * Math.log(Math.max(1e-6, 1.0 * original_p_uc))));
        int newCost = (int) Math.ceil(Math.max(1.0, -100.0 * Math.log(Math.max(1e-6, 1.0 * new_p_uc))));//向上取整
        try {
            List<String> lines = Files.readAllLines(AED_path);
            for (int i=0; i<lines.size(); i++){
                if(lines.get(i).toLowerCase().contains(key1.toLowerCase())){
                    for (int j = i; j<lines.size(); j++){
                        if(lines.get(j).toLowerCase().contains(key2.toLowerCase())){
                            lines.set(j, lines.get(j).replace("" + originalCost, "" + newCost));
                            break;
                        }
                    }
                }
            }
            Files.write(AED_path, lines, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);
        } catch (IOException e) {
            System.err.println("error when dealing with file: " + e.getMessage() + " " + AED_path);
            e.printStackTrace();}
        // modify CheckTable.Json
        class JosnModifier{
            void modifyJosn() throws IOException {
                ObjectMapper mapper = new ObjectMapper();
                mapper.enable(JsonReadFeature.ALLOW_NON_NUMERIC_NUMBERS.mappedFeature());

                File file = new File(checkTablePath);
                JsonNode root = mapper.readTree(file);

                for (JsonNode node : root){
                    String action = node.get("Action List").asText();
                    if(action.toUpperCase().contains(key1)){
                        ((ObjectNode) node).put("Initial Successful probability", new_p_uc);
                    }
                }
                mapper.writerWithDefaultPrettyPrinter().writeValue(file, root);
            }
        }
        JosnModifier modify = new JosnModifier();
        try{
            modify.modifyJosn();
        } catch (IOException e) {
            throw new RuntimeException(e + " " + checkTablePath);
        }
    }

    private static void closeSecurityControl_AEDI_RQ2_S2_A3(String keyword, String replacement){
        List<String> PathList = new ArrayList<>();
        PathList.add(FilePathConstants.AEDI_path + "RQ2/S2/authentication_3_service/denial_of_service.pddl");
        PathList.add(FilePathConstants.AEDI_path + "RQ2/S2/authentication_3_service/elevation_of_privilege.pddl");
        PathList.add(FilePathConstants.AEDI_path + "RQ2/S2/authentication_3_service/information_disclosure.pddl");
        PathList.add(FilePathConstants.AEDI_path + "RQ2/S2/authentication_3_service/repudiation.pddl");
        PathList.add(FilePathConstants.AEDI_path + "RQ2/S2/authentication_3_service/spoofing.pddl");
        PathList.add(FilePathConstants.AEDI_path + "RQ2/S2/authentication_3_service/tampering.pddl");
        for(String path : PathList){
            Path AEDI_path = Path.of(path);
            try {
                List<String> lines = Files.readAllLines(AEDI_path);
                for (int i=0; i<lines.size(); i++){
                    if(lines.get(i).contains(keyword)){
                        lines.set(i, lines.get(i).replace(keyword, replacement));
                    }
                }
                Files.write(AEDI_path, lines, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);
            } catch (IOException e) {
                System.err.println("error when dealing with file: " + e.getMessage() + " " + AEDI_path);
                e.printStackTrace();}
        }
    }

    private static void changeVersion_AEDI_RQ2_S1_W2(String oldVersion, String newVersion, String keyword){// input format using XX.XX.XX.XX
        class Helper{
            long convertVersiontoInt(String version){
                String[] versions = version.split("\\.");
                long major = Integer.parseInt(versions[0]);
                long minor = Integer.parseInt(versions[1]);
                long patch = Integer.parseInt(versions[2]);
                long build = Integer.parseInt(versions[3]);
                return major * (long) Math.pow(10, 9)
                        + minor * (long) Math.pow(10, 6)
                        + patch * (long) Math.pow(10, 3)
                        + build * (long) Math.pow(10, 0);
            }
        }
        List<String> PathList = new ArrayList<>();
        PathList.add(FilePathConstants.AEDI_path + "RQ2/S1/webui_2_service/denial_of_service.pddl");
        PathList.add(FilePathConstants.AEDI_path + "RQ2/S1/webui_2_service/elevation_of_privilege.pddl");
        PathList.add(FilePathConstants.AEDI_path + "RQ2/S1/webui_2_service/information_disclosure.pddl");
        PathList.add(FilePathConstants.AEDI_path + "RQ2/S1/webui_2_service/repudiation.pddl");
        PathList.add(FilePathConstants.AEDI_path + "RQ2/S1/webui_2_service/spoofing.pddl");
        PathList.add(FilePathConstants.AEDI_path + "RQ2/S1/webui_2_service/tampering.pddl");
        for(String path : PathList){
            Path AEDI_path = Path.of(path);
            try {
                Helper converter = new Helper();
                String oldV = "" + converter.convertVersiontoInt(oldVersion);
                String newV = "" + converter.convertVersiontoInt(newVersion);
                List<String> lines = Files.readAllLines(AEDI_path);
                for (int i=0; i<lines.size(); i++){
                    if(lines.get(i).contains(oldV) && lines.get(i).contains(keyword)){
                        lines.set(i, lines.get(i).replace(oldV, newV));
                    }
                }
                Files.write(AEDI_path, lines, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);
            } catch (IOException e) {
                System.err.println("error when dealing with file: " + e.getMessage() + " " + AEDI_path);
                e.printStackTrace();}
        }
    }

    private static void changeVersion_AEDI_RQ2_S3_P2(String oldVersion, String newVersion, String keyword){// input format using XX.XX.XX.XX
        class Helper{
            long convertVersiontoInt(String version){
                String[] versions = version.split("\\.");
                long major = Integer.parseInt(versions[0]);
                long minor = Integer.parseInt(versions[1]);
                long patch = Integer.parseInt(versions[2]);
                long build = Integer.parseInt(versions[3]);
                return major * (long) Math.pow(10, 9)
                        + minor * (long) Math.pow(10, 6)
                        + patch * (long) Math.pow(10, 3)
                        + build * (long) Math.pow(10, 0);
            }
        }
        List<String> PathList = new ArrayList<>();
        PathList.add(FilePathConstants.AEDI_path + "RQ2/S3/persistence_2_service/denial_of_service.pddl");
        PathList.add(FilePathConstants.AEDI_path + "RQ2/S3/persistence_2_service/elevation_of_privilege.pddl");
        PathList.add(FilePathConstants.AEDI_path + "RQ2/S3/persistence_2_service/information_disclosure.pddl");
        PathList.add(FilePathConstants.AEDI_path + "RQ2/S3/persistence_2_service/repudiation.pddl");
        PathList.add(FilePathConstants.AEDI_path + "RQ2/S3/persistence_2_service/spoofing.pddl");
        PathList.add(FilePathConstants.AEDI_path + "RQ2/S3/persistence_2_service/tampering.pddl");
        for(String path : PathList){
            Path AEDI_path = Path.of(path);
            try {
                Helper converter = new Helper();
                String oldV = "" + converter.convertVersiontoInt(oldVersion);
//                System.out.print("Old: "+oldV+"\n");
                String newV = "" + converter.convertVersiontoInt(newVersion);
//                System.out.print("New: "+newV+"\n");
                List<String> lines = Files.readAllLines(AEDI_path);
                for (int i=0; i<lines.size(); i++){
                    if(lines.get(i).contains(oldV) && lines.get(i).contains(keyword)){
                        lines.set(i, lines.get(i).replace(oldV, newV));
                    }
                }
                Files.write(AEDI_path, lines, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);
            } catch (IOException e) {
                System.err.println("error when dealing with file: " + e.getMessage() + " " + AEDI_path);
                e.printStackTrace();}
        }
    }

    public static Double convertJsonToPrismCustomModel(String currentGraph, String destinationGraph, int numStates) {
        int cycles = numStates / 4;
        Instant generatePrismStart = Instant.now();
        Gson gson = new Gson();
        JsonObject currentJson = gson.fromJson(currentGraph, JsonObject.class);
        JsonObject destinationJson = gson.fromJson(destinationGraph, JsonObject.class);

        // The following are values without normalization, using standardized values.
        double weightAvailability = currentJson.getAsJsonObject("weights").getAsJsonPrimitive("Availability").getAsDouble();
        double weightResponseTime = currentJson.getAsJsonObject("weights").getAsJsonPrimitive("AverageResponseTime").getAsDouble();
        double weightVulnerability = currentJson.getAsJsonObject("weights").getAsJsonPrimitive("Vulnerability").getAsDouble();

        double oldPersistenceAvailability = currentJson.getAsJsonObject("PERSISTENCE-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("Availability").getAsDouble();
        double oldPersistenceResponseTime = currentJson.getAsJsonObject("PERSISTENCE-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("AverageResponseTime").getAsDouble();
        double oldPersistenceVulnerability = currentJson.getAsJsonObject("PERSISTENCE-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("Vulnerability").getAsDouble();

        double oldRecommenderAvailability = currentJson.getAsJsonObject("RECOMMENDER-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("Availability").getAsDouble();
        double oldRecommenderResponseTime = currentJson.getAsJsonObject("RECOMMENDER-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("AverageResponseTime").getAsDouble();
        double oldRecommenderVulnerability = currentJson.getAsJsonObject("RECOMMENDER-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("Vulnerability").getAsDouble();

        double oldImageAvailability = currentJson.getAsJsonObject("IMAGE-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("Availability").getAsDouble();
        double oldImageResponseTime = currentJson.getAsJsonObject("IMAGE-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("AverageResponseTime").getAsDouble();
        double oldImageVulnerability = currentJson.getAsJsonObject("IMAGE-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("Vulnerability").getAsDouble();

        double oldAuthenticationAvailability = currentJson.getAsJsonObject("AUTHENTICATION-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("Availability").getAsDouble();
        double oldAuthenticationResponseTime = currentJson.getAsJsonObject("AUTHENTICATION-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("AverageResponseTime").getAsDouble();
        double oldAuthenticationVulnerability = currentJson.getAsJsonObject("AUTHENTICATION-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("Vulnerability").getAsDouble();

        double oldWebuiAvailability = currentJson.getAsJsonObject("WEBUI-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("Availability").getAsDouble();
        double oldWebuiResponseTime = currentJson.getAsJsonObject("WEBUI-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("AverageResponseTime").getAsDouble();
        double oldWebuiVulnerability = currentJson.getAsJsonObject("WEBUI-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("Vulnerability").getAsDouble();

        double persistenceAvailability = destinationJson.getAsJsonObject("PERSISTENCE-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("Availability").getAsDouble();
        double persistenceResponseTime = destinationJson.getAsJsonObject("PERSISTENCE-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("AverageResponseTime").getAsDouble();
        double persistenceVulnerability = destinationJson.getAsJsonObject("PERSISTENCE-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("Vulnerability").getAsDouble();

        double recommenderAvailability = destinationJson.getAsJsonObject("RECOMMENDER-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("Availability").getAsDouble();
        double recommenderResponseTime = destinationJson.getAsJsonObject("RECOMMENDER-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("AverageResponseTime").getAsDouble();
        double recommenderVulnerability = destinationJson.getAsJsonObject("RECOMMENDER-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("Vulnerability").getAsDouble();

        double ImageAvailability = currentJson.getAsJsonObject("IMAGE-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("Availability").getAsDouble();
        double ImageResponseTime = currentJson.getAsJsonObject("IMAGE-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("AverageResponseTime").getAsDouble();
        double ImageVulnerability = currentJson.getAsJsonObject("IMAGE-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("Vulnerability").getAsDouble();

        double authenticationAvailability = destinationJson.getAsJsonObject("AUTHENTICATION-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("Availability").getAsDouble();
        double authenticationResponseTime = destinationJson.getAsJsonObject("AUTHENTICATION-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("AverageResponseTime").getAsDouble();
        double authenticationVulnerability = destinationJson.getAsJsonObject("AUTHENTICATION-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("Vulnerability").getAsDouble();

        double webuiAvailability = destinationJson.getAsJsonObject("WEBUI-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("Availability").getAsDouble();
        double webuiResponseTime = destinationJson.getAsJsonObject("WEBUI-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("AverageResponseTime").getAsDouble();
        double webuiVulnerability = destinationJson.getAsJsonObject("WEBUI-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("Vulnerability").getAsDouble();


        StringBuilder prismModel = new StringBuilder();
        prismModel.append("dtmc\n\n");

        // availabilities
        prismModel.append("// availabilities\n");
        prismModel.append("const double w_a = ").append(weightAvailability).append(";\n");
        prismModel.append("const double old_a_recommender = ").append(oldRecommenderAvailability).append(";\n");
        prismModel.append("const double old_a_image = ").append(oldImageAvailability).append(";\n"); // added
        prismModel.append("const double old_a_authentication = ").append(oldAuthenticationAvailability).append(";\n");
        prismModel.append("const double old_a_persistence = ").append(oldPersistenceAvailability).append(";\n");
        prismModel.append("const double old_a_webui = ").append(oldWebuiAvailability).append(";\n");
        prismModel.append("const double a_recommender = ").append(recommenderAvailability).append(";\n");
        prismModel.append("const double a_image = ").append(ImageAvailability).append(";\n"); // added
        prismModel.append("const double a_authentication = ").append(authenticationAvailability).append(";\n");
        prismModel.append("const double a_persistence = ").append(persistenceAvailability).append(";\n");
        prismModel.append("const double a_webui = ").append(webuiAvailability).append(";\n\n");

        // response times
        prismModel.append("// response times\n");
        prismModel.append("const double w_rt = ").append(weightResponseTime).append(";\n");
        prismModel.append("const double old_rt_recommender = ").append(oldRecommenderResponseTime).append(";\n");
        prismModel.append("const double old_rt_image = ").append(oldImageResponseTime).append(";\n");
        prismModel.append("const double old_rt_authentication = ").append(oldAuthenticationResponseTime).append(";\n");
        prismModel.append("const double old_rt_persistence = ").append(oldPersistenceResponseTime).append(";\n");
        prismModel.append("const double old_rt_webui = ").append(oldWebuiResponseTime).append(";\n");
        prismModel.append("const double rt_recommender = ").append(recommenderResponseTime).append(";\n");
        prismModel.append("const double rt_image = ").append(ImageResponseTime).append(";\n");
        prismModel.append("const double rt_authentication = ").append(authenticationResponseTime).append(";\n");
        prismModel.append("const double rt_persistence = ").append(persistenceResponseTime).append(";\n");
        prismModel.append("const double rt_webui = ").append(webuiResponseTime).append(";\n\n");

        // vulnerabilities
        prismModel.append("// vulnerabilities\n");
        prismModel.append("const double w_v = ").append(weightVulnerability).append(";\n");
        prismModel.append("const double old_v_recommender = ").append(oldRecommenderVulnerability).append(";\n");
        prismModel.append("const double old_v_image = ").append(oldImageVulnerability).append(";\n");
        prismModel.append("const double old_v_authentication = ").append(oldAuthenticationVulnerability).append(";\n");
        prismModel.append("const double old_v_persistence = ").append(oldPersistenceVulnerability).append(";\n");
        prismModel.append("const double old_v_webui = ").append(oldWebuiVulnerability).append(";\n");
        prismModel.append("const double v_recommender = ").append(recommenderVulnerability).append(";\n");
        prismModel.append("const double v_image = ").append(ImageVulnerability).append(";\n\n");
        prismModel.append("const double v_authentication = ").append(authenticationVulnerability).append(";\n");
        prismModel.append("const double v_persistence = ").append(persistenceVulnerability).append(";\n");
        prismModel.append("const double v_webui = ").append(webuiVulnerability).append(";\n\n");

        // cost
        prismModel.append("rewards\n");
        prismModel.append("s=1 : (w_a * (1 - a_webui) + w_rt * rt_webui + w_v * v_webui) / (w_a * (1 - old_a_webui) + w_rt * old_rt_webui + w_v * old_v_webui);\n");
        prismModel.append("s=2 : (w_a * (1 - a_authentication) + w_rt * rt_authentication + w_v * v_authentication) / (w_a * (1 - old_a_authentication) + w_rt * old_rt_authentication + w_v * old_v_authentication);\n");
        prismModel.append("s=3 : (w_a * (1 - a_recommender) + w_rt * rt_recommender + w_v * v_recommender) / (w_a * (1 - old_a_recommender) + w_rt * old_rt_recommender + w_v * old_v_recommender) * (w_a * (1 - a_image) + w_rt * rt_image + w_v * v_image) / (w_a * (1 - old_a_image) + w_rt * old_rt_image + w_v * old_v_image);\n");
        prismModel.append("s=4 : (w_a * (1 - a_persistence) + w_rt * rt_persistence + w_v * v_persistence) / (w_a * (1 - old_a_persistence) + w_rt * old_rt_persistence + w_v * old_v_persistence);\n\n");
        prismModel.append("endrewards\n\n");

        // module teaStore
        prismModel.append("module teaStore\n");
        prismModel.append("\ts : [0.." + (4*cycles + 3) + "] init 0;\n\n");

        prismModel.append("\t[] s=0 -> 1 : (s'=1);\n");

        for (int i = 0; i < cycles; i++) {
            prismModel.append("\t[] s=" + (i*4+1) + " -> a_webui : (s'=" + (i*4+2) + ") + (1-a_webui) : (s'=" + (4*cycles+2) + ");\n");
            prismModel.append("\t[] s=" + (i*4+2) + " -> a_authentication : (s'=" + (i*4+3) + ") + (1-a_authentication) : (s'=" + (i*4+1) + ");\n");
            prismModel.append("\t[] s=" + (i*4+3) + " -> (a_recommender * a_image) + (1-a_recommender) * a_image + a_recommender * (1-a_image) : (s'=" + (i*4+4) + ") + (1-a_recommender) * (1-a_image) : (s'=" + (i*4+1) + ");\n");
            prismModel.append("\t[] s=" + (i*4+4) + " -> a_persistence : (s'=" + (i*4 + 5) + ") + (1-a_persistence) : (s'=" + (4*cycles+2) + ");\n");
        }

        prismModel.append("\t[] s=" + (4*cycles + 1) + " -> 1 : (s'=" + (4*cycles + 1) + ");\n");
        prismModel.append("\t[] s=" + (4*cycles + 2) + " -> 1 : (s'=0);\n");
        prismModel.append("endmodule\n\n");

        // Write the PRISM model to a file
        try {
            Files.write(Paths.get(FilePathConstants.model_prism_defination_path), prismModel.toString().getBytes());
        } catch (IOException e) {
            log.debug("I was serching in this directory: {}", Paths.get("").toAbsolutePath());
            log.error("Error writing PRISM model to file: {}", e.getMessage());
        }

        // Create "model.props" file
        try {
            Files.write(Paths.get(FilePathConstants.model_props_defination_path), "Rmin = ? [ C ]".getBytes());
        } catch (IOException e) {
            log.error("Error writing model.props file: {}", e.getMessage());
        }
        Instant generatePrismEnd = Instant.now();
        log.info("Time to generate and save PRISM model: {}ms", Duration.between(generatePrismStart, generatePrismEnd).toNanos() / 1000000.0);


        Instant obtainCostStart = Instant.now();
        // Execute the PRISM command: prism model.prism model.props -prop 2
        try {
            Process process = Runtime.getRuntime().exec("./SAQURE-simulator/prism/bin/prism SAQURE-simulator/src/main/java/saqure/Knowledge/DTMC/model.prism SAQURE-simulator/src/main/java/saqure/Knowledge/DTMC/model.props -maxiters 2000000"); // -maxiters 1000000000 -gs -power
            int exitCode = process.waitFor();

            if (exitCode == 0) {
                InputStream inputStream = process.getInputStream();
                String result = parsePrismOutput(inputStream);

                log.info("Cost Value: " + result);
                Instant obtainCostEnd = Instant.now();
                log.info("Time to obtain the cost: {}ms", Duration.between(obtainCostStart, obtainCostEnd).toMillis());

                return result == null ? null : Double.parseDouble(result);
            } else {
                log.error("Error executing PRISM command. Exit code: {}", exitCode);
                InputStream inputStream = process.getInputStream();
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        log.error(line);
                    }
                }
            }
        } catch (IOException | InterruptedException e) {
            log.error("Error executing PRISM command: {}", e.getMessage());
        }

        return null;
    }

    // Analysis of PRISM Model Checker Output
    private static String parsePrismOutput(InputStream inputStream) throws IOException {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("Value in the initial state")) {//Find lines containing the specific identifier string "Value in the initial state".
                    String[] tokens = line.split(":");
                    if (tokens.length > 1) {
                        return tokens[1].trim();
                    }
                }
            }
        }
        return null;
    }
}
