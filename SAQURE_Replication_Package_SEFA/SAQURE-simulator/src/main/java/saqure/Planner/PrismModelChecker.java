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
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.nio.file.StandardOpenOption;

@Slf4j
public class PrismModelChecker {
    private PrismModelChecker() {
        throw new IllegalStateException("Utility class");
    }

    public enum ExternalChanges{
        AEDI_REQUEST_BLOCK_RESTAURANT,
        AED_ACTION_COST_ORDERING,
        AEDI_CHANGE_VERSION_PAYMENT;
    }

    public static void update_AED_AEDI(ExternalChanges changes){
        switch (changes){
            case AED_ACTION_COST_ORDERING -> changeActionCost_AED("USER-INPUTS-SENSITIVE-INFORMATION-IN-THE-WEBPAGE", "total-cost", 0.005, 0.0);
            case AEDI_REQUEST_BLOCK_RESTAURANT -> requestBlock_AEDI_RQ2_S1_R2("(WAF-malicious-request-block SEFA)", "; (not (WAF-malicious-request-block SEFA))");
            case AEDI_CHANGE_VERSION_PAYMENT -> changeVersion_AEDI_RQ2_S2_P3("2.7.18.1", "2.7.10.1", "version springboot_SEFA");
            default -> System.out.print("No Runtime External Changes");
        }
    }
    public static void reverseUpdating(ExternalChanges changes){
        switch (changes){
            case AED_ACTION_COST_ORDERING -> changeActionCost_AED("USER-INPUTS-SENSITIVE-INFORMATION-IN-THE-WEBPAGE", "total-cost", 0.0, 0.005);
            case AEDI_REQUEST_BLOCK_RESTAURANT -> requestBlock_AEDI_RQ2_S1_R2("; (not (WAF-malicious-request-block SEFA))", "(WAF-malicious-request-block SEFA)");
            case AEDI_CHANGE_VERSION_PAYMENT -> changeVersion_AEDI_RQ2_S2_P3("2.7.10.1", "2.7.18.1", "version springboot_SEFA");
            default -> System.out.print("No Runtime External Changes");
        }
    }

    private static void changeActionCost_AED(String key1, String key2, double original_p_uc, double new_p_uc){
        String checkTablePath = FilePathConstants.LookupFilePath;
        Path AED_path = Path.of(FilePathConstants.AEDPath);
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
                        ((ObjectNode) node).put("Puc", new_p_uc);
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

    private static void requestBlock_AEDI_RQ2_S1_R2(String keyword, String replacement){
        List<String> PathList = new ArrayList<>();
        PathList.add(FilePathConstants.AEDI_path + "RQ2/S1/Restaurant_2_service/denial_of_service.pddl");
        PathList.add(FilePathConstants.AEDI_path + "RQ2/S1/Restaurant_2_service/elevation_of_privilege.pddl");
        PathList.add(FilePathConstants.AEDI_path + "RQ2/S1/Restaurant_2_service/information_disclosure.pddl");
        PathList.add(FilePathConstants.AEDI_path + "RQ2/S1/Restaurant_2_service/repudiation.pddl");
        PathList.add(FilePathConstants.AEDI_path + "RQ2/S1/Restaurant_2_service/spoofing.pddl");
        PathList.add(FilePathConstants.AEDI_path + "RQ2/S1/Restaurant_2_service/tampering.pddl");
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

    private static void changeVersion_AEDI_RQ2_S2_P3(String oldVersion, String newVersion, String keyword){// input format using XX.XX.XX.XX
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
        PathList.add(FilePathConstants.AEDI_path + "RQ2/S2/Payment_proxy_3_service/denial_of_service.pddl");
        PathList.add(FilePathConstants.AEDI_path + "RQ2/S2/Payment_proxy_3_service/elevation_of_privilege.pddl");
        PathList.add(FilePathConstants.AEDI_path + "RQ2/S2/Payment_proxy_3_service/information_disclosure.pddl");
        PathList.add(FilePathConstants.AEDI_path + "RQ2/S2/Payment_proxy_3_service/repudiation.pddl");
        PathList.add(FilePathConstants.AEDI_path + "RQ2/S2/Payment_proxy_3_service/spoofing.pddl");
        PathList.add(FilePathConstants.AEDI_path + "RQ2/S2/Payment_proxy_3_service/tampering.pddl");
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

    // Core structural states of one SEFA replica: ordering, payment + delivery, delivery retry, restaurant.
    public static final int CORE_STATES_PER_SEFA_REPLICA = 4;

    // Core structural states of an n-times scaled SEFA model, e.g. 500x -> 4 * 500 = 2000.
    public static int coreStatesForScale(int scaleFactor) {
        if (scaleFactor < 1) {
            throw new IllegalArgumentException("SEFA scale factor must be >= 1, but was " + scaleFactor);
        }
        return CORE_STATES_PER_SEFA_REPLICA * scaleFactor;
    }

    public static Double convertJsonToPrismCustomModel(String currentGraph, String destinationGraph, int numStates) {
        if (numStates < CORE_STATES_PER_SEFA_REPLICA || numStates % CORE_STATES_PER_SEFA_REPLICA != 0) {
            throw new IllegalArgumentException("numStates must be a positive multiple of " + CORE_STATES_PER_SEFA_REPLICA
                    + " (one SEFA replica = " + CORE_STATES_PER_SEFA_REPLICA + " core structural states), but was " + numStates);
        }
        // cycles is the SEFA scale factor: numStates = 4 * cycles, e.g. 2000 core states = 500x SEFA.
        int cycles = numStates / CORE_STATES_PER_SEFA_REPLICA;
        Instant generatePrismStart = Instant.now();
        Gson gson = new Gson();
        JsonObject currentJson = gson.fromJson(currentGraph, JsonObject.class);
        JsonObject destinationJson = gson.fromJson(destinationGraph, JsonObject.class);

        double weightAvailability = currentJson.getAsJsonObject("weights").getAsJsonPrimitive("Availability").getAsDouble();
        double weightResponseTime = currentJson.getAsJsonObject("weights").getAsJsonPrimitive("AverageResponseTime").getAsDouble();
        double weightVulnerability = currentJson.getAsJsonObject("weights").getAsJsonPrimitive("Vulnerability").getAsDouble();

        double oldRestaurantAvailability = currentJson.getAsJsonObject("RESTAURANT-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("Availability").getAsDouble();
        double oldRestaurantResponseTime = currentJson.getAsJsonObject("RESTAURANT-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("AverageResponseTime").getAsDouble();
        double oldRestaurantVulnerability = currentJson.getAsJsonObject("RESTAURANT-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("Vulnerability").getAsDouble();

        double oldDeliveryAvailability = currentJson.getAsJsonObject("DELIVERY-PROXY-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("Availability").getAsDouble();
        double oldDeliveryResponseTime = currentJson.getAsJsonObject("DELIVERY-PROXY-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("AverageResponseTime").getAsDouble();
        double oldDeliveryVulnerability = currentJson.getAsJsonObject("DELIVERY-PROXY-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("Vulnerability").getAsDouble();

        double oldPaymentAvailability = currentJson.getAsJsonObject("PAYMENT-PROXY-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("Availability").getAsDouble();
        double oldPaymentResponseTime = currentJson.getAsJsonObject("PAYMENT-PROXY-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("AverageResponseTime").getAsDouble();
        double oldPaymentVulnerability = currentJson.getAsJsonObject("PAYMENT-PROXY-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("Vulnerability").getAsDouble();

        double oldOrderingAvailability = currentJson.getAsJsonObject("ORDERING-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("Availability").getAsDouble();
        double oldOrderingResponseTime = currentJson.getAsJsonObject("ORDERING-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("AverageResponseTime").getAsDouble();
        double oldOrderingVulnerability = currentJson.getAsJsonObject("ORDERING-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("Vulnerability").getAsDouble();

        double restaurantAvailablity = destinationJson.getAsJsonObject("RESTAURANT-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("Availability").getAsDouble();
        double restaurantResponseTime = destinationJson.getAsJsonObject("RESTAURANT-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("AverageResponseTime").getAsDouble();
        double restaurantVulnerability = destinationJson.getAsJsonObject("RESTAURANT-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("Vulnerability").getAsDouble();

        double deliveryAvailability = destinationJson.getAsJsonObject("DELIVERY-PROXY-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("Availability").getAsDouble();
        double deliveryResponseTime = destinationJson.getAsJsonObject("DELIVERY-PROXY-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("AverageResponseTime").getAsDouble();
        double deliveryVulnerability = destinationJson.getAsJsonObject("DELIVERY-PROXY-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("Vulnerability").getAsDouble();

        double paymentAvailability = destinationJson.getAsJsonObject("PAYMENT-PROXY-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("Availability").getAsDouble();
        double paymentResponseTime = destinationJson.getAsJsonObject("PAYMENT-PROXY-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("AverageResponseTime").getAsDouble();
        double paymentVulnerability = destinationJson.getAsJsonObject("PAYMENT-PROXY-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("Vulnerability").getAsDouble();

        double orderingAvailability = destinationJson.getAsJsonObject("ORDERING-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("Availability").getAsDouble();
        double orderingResponseTime = destinationJson.getAsJsonObject("ORDERING-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("AverageResponseTime").getAsDouble();
        double orderingVulnerability = destinationJson.getAsJsonObject("ORDERING-SERVICE").getAsJsonObject("values").getAsJsonPrimitive("Vulnerability").getAsDouble();

        // Transition probabilities take each service's own availability (Fig. 8); the normalised
        // "Availability" above feeds the instant cost (Eq. 5) only. See TransitionAvailability.
        double restaurantTransition = TransitionAvailability.of(destinationJson, "RESTAURANT-SERVICE");
        double deliveryTransition = TransitionAvailability.of(destinationJson, "DELIVERY-PROXY-SERVICE");
        double paymentTransition = TransitionAvailability.of(destinationJson, "PAYMENT-PROXY-SERVICE");
        double orderingTransition = TransitionAvailability.of(destinationJson, "ORDERING-SERVICE");


        StringBuilder prismModel = new StringBuilder();
        prismModel.append("dtmc\n\n");

        // scale of the generated model
        prismModel.append("// SEFA scale: " + cycles + "x -> " + CORE_STATES_PER_SEFA_REPLICA + " core structural states x "
                + cycles + " replicas = " + numStates + " core structural states\n");
        prismModel.append("// plus START (s=0), success (s=" + (4*cycles + 1) + ") and failure (s=" + (4*cycles + 2) + ")"
                + " => " + (numStates + 3) + " reachable states\n\n");

        // availabilities
        prismModel.append("// availabilities\n");
        prismModel.append("const double w_a = ").append(weightAvailability).append(";\n");
        prismModel.append("const double old_a_delivery = ").append(oldDeliveryAvailability).append(";\n");
        prismModel.append("const double old_a_payment = ").append(oldPaymentAvailability).append(";\n");
        prismModel.append("const double old_a_restaurant = ").append(oldRestaurantAvailability).append(";\n");
        prismModel.append("const double old_a_ordering = ").append(oldOrderingAvailability).append(";\n");
        prismModel.append("const double a_delivery = ").append(deliveryAvailability).append(";\n");
        prismModel.append("const double a_payment = ").append(paymentAvailability).append(";\n");
        prismModel.append("const double a_restaurant = ").append(restaurantAvailablity).append(";\n");
        prismModel.append("const double a_ordering = ").append(orderingAvailability).append(";\n");
        prismModel.append("const double p_delivery = ").append(deliveryTransition).append(";\n");
        prismModel.append("const double p_payment = ").append(paymentTransition).append(";\n");
        prismModel.append("const double p_restaurant = ").append(restaurantTransition).append(";\n");
        prismModel.append("const double p_ordering = ").append(orderingTransition).append(";\n");
        prismModel.append("const double denom = (p_payment * p_delivery * p_delivery) - (2 * p_payment * p_delivery) - p_delivery + 3;\n\n");

        // response times
        prismModel.append("// response times\n");
        prismModel.append("const double w_rt = ").append(weightResponseTime).append(";\n");
        prismModel.append("const double old_rt_delivery = ").append(oldDeliveryResponseTime).append(";\n");
        prismModel.append("const double old_rt_payment = ").append(oldPaymentResponseTime).append(";\n");
        prismModel.append("const double old_rt_restaurant = ").append(oldRestaurantResponseTime).append(";\n");
        prismModel.append("const double old_rt_ordering = ").append(oldOrderingResponseTime).append(";\n");
        prismModel.append("const double rt_delivery = ").append(deliveryResponseTime).append(";\n");
        prismModel.append("const double rt_payment = ").append(paymentResponseTime).append(";\n");
        prismModel.append("const double rt_restaurant = ").append(restaurantResponseTime).append(";\n");
        prismModel.append("const double rt_ordering = ").append(orderingResponseTime).append(";\n\n");

        // vulnerabilities
        prismModel.append("// vulnerabilities\n");
        prismModel.append("const double w_v = ").append(weightVulnerability).append(";\n");
        prismModel.append("const double old_v_delivery = ").append(oldDeliveryVulnerability).append(";\n");
        prismModel.append("const double old_v_payment = ").append(oldPaymentVulnerability).append(";\n");
        prismModel.append("const double old_v_restaurant = ").append(oldRestaurantVulnerability).append(";\n");
        prismModel.append("const double old_v_ordering = ").append(oldOrderingVulnerability).append(";\n");
        prismModel.append("const double v_delivery = ").append(deliveryVulnerability).append(";\n");
        prismModel.append("const double v_payment = ").append(paymentVulnerability).append(";\n");
        prismModel.append("const double v_restaurant = ").append(restaurantVulnerability).append(";\n");
        prismModel.append("const double v_ordering = ").append(orderingVulnerability).append(";\n\n");

        // cost
        // Every one of the "cycles" SEFA replicas carries the same four core structural rewards,
        // so the whole 4 * cycles core states contribute to the cumulative cost.
        // Availability reaches the cost through two channels: w_a*(1-A) in the reward, which the
        // weights govern, and the transition probabilities, which do not. The chain restarts on
        // failure, so a cumulative reward is (reward of one pass) / P(pass succeeds); that second
        // factor scales the cost by 1/P regardless of w_a. Measured elasticity of the cumulative
        // cost w.r.t. a_restaurant was -1.07 even at w_a = 0.1, i.e. almost entirely ungoverned.
        // The planner nevertheless ranks options by this cumulative cost, as the paper specifies.
        // The cost per service invocation (the "cost" reward divided by the "visits" reward) cancels
        // the 1/P factor, leaving an elasticity of exactly the w_a response (-0.067 at w_a = 0.1,
        // -0.27 at 0.3, -0.65 at 0.5); it is logged alongside for reference.
        // w_a*(1-A) stays: dropping it collapses the RAMSES baseline (w_v = 0) to
        // (w_rt*rt)/(w_rt*old_rt), i.e. a pure response-time baseline.
        String orderingReward = "(w_a * (1 - a_ordering) + w_rt * rt_ordering + w_v * v_ordering) / (w_a * (1 - old_a_ordering) + w_rt * old_rt_ordering + w_v * old_v_ordering)";
        String paymentDeliveryReward = "(w_a * (1 - a_delivery) + w_rt * rt_delivery + w_v * v_delivery) / (w_a * (1 - old_a_delivery) + w_rt * old_rt_delivery + w_v * old_v_delivery) * (w_a * (1 - a_payment) + w_rt * rt_payment + w_v * v_payment) / (w_a * (1 - old_a_payment) + w_rt * old_rt_payment + w_v * old_v_payment)";
        String deliveryReward = "(w_a * (1 - a_delivery) + w_rt * rt_delivery + w_v * v_delivery) / (w_a * (1 - old_a_delivery) + w_rt * old_rt_delivery + w_v * old_v_delivery)";
        String restaurantReward = "(w_a * (1 - a_restaurant) + w_rt * rt_restaurant + w_v * v_restaurant) / (w_a * (1 - old_a_restaurant) + w_rt * old_rt_restaurant + w_v * old_v_restaurant)";

        prismModel.append("rewards \"cost\"\n");
        for (int i = 0; i < cycles; i++) {
            prismModel.append("s=" + (i*4 + 1) + " : " + orderingReward + ";\n");
            prismModel.append("s=" + (i*4 + 2) + " : " + paymentDeliveryReward + ";\n");
            prismModel.append("s=" + (i*4 + 3) + " : " + deliveryReward + ";\n");
            prismModel.append("s=" + (i*4 + 4) + " : " + restaurantReward + ";\n");
        }
        prismModel.append("\n");
        prismModel.append("endrewards\n\n");

        // Counts the service invocations the "cost" reward is accumulated over, so the property
        // can divide by it. Same state set, weight 1 each.
        prismModel.append("rewards \"visits\"\n");
        prismModel.append("s>=1 & s<=" + (4*cycles) + " : 1;\n");
        prismModel.append("endrewards\n\n");

        // module sefa
//        0	intial state
//        i*4 + 1	Order Decision
//        i*4 + 2 Payment Processing
//        i*4 + 3 Delivery Processing
//        i*4 + 4 Restaurant Processing
//        4*cycles + 1 Successful Termination (Self-Loop)
//        4*cycles + 2 Failure Reset (Returns to initial state 0 with probability 1)
        prismModel.append("module sefa\n");
        prismModel.append("\ts : [0.." + (4*cycles + 3) + "] init 0;\n\n");

        prismModel.append("\t[] s=0 -> 1 : (s'=1);\n");

        for (int i = 0; i < cycles; i++) {
            prismModel.append("\t[] s=" + (i*4 + 1) + " -> (p_ordering / denom) : (s'=" + (i*4 + 2) + ") + (p_ordering * (1 - p_payment * p_delivery) / denom) : (s'=" + (i*4 + 3) + ") + (p_ordering * (1 - p_payment * p_delivery) * (1 - p_delivery) / denom) : (s'=" + (i*4 + 4) + ") + (1 - p_ordering) : (s'=" + (4*cycles + 2) + ");\n");
            prismModel.append("\t[] s=" + (i*4 + 2) + " -> p_payment * p_delivery : (s'=" + (i*4 + 4) + ") + (1 - p_payment * p_delivery) : (s'=" + (i*4 + 1) + ");\n");
            prismModel.append("\t[] s=" + (i*4 + 3) + " -> p_delivery : (s'=" + (i*4 + 4) + ") + (1 - p_delivery) : (s'=" + (i*4 + 1) + ");\n");
            prismModel.append("\t[] s=" + (i*4 + 4) + " -> p_restaurant : (s'=" + (i*4 + 5) + ") + (1 - p_restaurant) : (s'=" + (4*cycles + 2) + ");\n");
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
            Files.write(Paths.get(FilePathConstants.model_props_defination_path),
                    "R{\"cost\"}min = ? [ C ]\nR{\"visits\"}min = ? [ C ]\n".getBytes());
        } catch (IOException e) {
            log.error("Error writing model.props file: {}", e.getMessage());
        }
        Instant generatePrismEnd = Instant.now();
        // RQ4.3.2 (initial model generation vs. size of the managed system) reads this line out
        // of the Size_vs_RuntimeDeTime logs, so it has to stay at info: at the default level a
        // debug line is dropped and that sub-question has no data source at all.
        log.info("Time to generate and save PRISM model: {}ms", Duration.between(generatePrismStart, generatePrismEnd).toNanos() / 1000000.0);


        Instant obtainCostStart = Instant.now();
        // Execute the PRISM command: prism model.prism model.props -prop 2
        try {
            Process process = Runtime.getRuntime().exec("./SAQURE-simulator/prism/bin/prism SAQURE-simulator/src/main/java/saqure/Knowledge/DTMC/model.prism SAQURE-simulator/src/main/java/saqure/Knowledge/DTMC/model.props -maxiters 2000000"); // -maxiters 1000000000 -gs -power
            int exitCode = process.waitFor();

            if (exitCode == 0) {
                InputStream inputStream = process.getInputStream();
                List<Double> values = parsePrismOutput(inputStream);

                if (values.size() < 2) {
                    log.error("PRISM returned {} value(s), expected cost and visits", values.size());
                    return null;
                }
                // Options are ranked by the paper's metric, the expected long-term cumulative cost per
                // request, R{"cost"}=?[C]. The per-invocation cost (cumulative / expected invocations)
                // is logged next to it for reference. See the comment on the reward structures.
                double result = values.get(0);

                log.info("Cost Value: " + result);
                log.info("Per-invocation cost: " + (values.get(0) / values.get(1))
                        + " (expected service invocations: " + values.get(1) + ")");
                Instant obtainCostEnd = Instant.now();
                log.debug("Time to obtain the cost: {}ms (cumulative {} over {} visits)",
                        Duration.between(obtainCostStart, obtainCostEnd).toMillis(), values.get(0), values.get(1));

                return result;
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
    private static List<Double> parsePrismOutput(InputStream inputStream) throws IOException {
        List<Double> values = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("Value in the initial state")) {//Find lines containing the specific identifier string "Value in the initial state".
                    String[] tokens = line.split(":");
                    if (tokens.length > 1) {
                        values.add(Double.parseDouble(tokens[1].trim()));
                    }
                }
            }
        }
        return values;
    }
}
