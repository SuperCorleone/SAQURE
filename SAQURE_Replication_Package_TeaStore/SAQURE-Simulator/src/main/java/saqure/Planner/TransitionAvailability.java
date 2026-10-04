package saqure.Planner;

import com.google.gson.JsonObject;
import lombok.extern.slf4j.Slf4j;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.CellType;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;

import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Availabilities used as DTMC transition probabilities.
 *
 * The instant cost (Eq. 5) works on standardised and normalised metrics, but the DTMC (Fig. 8) is
 * parameterised by the services' availabilities themselves. Feeding the normalised value into the
 * transitions maps each sub-scenario's lowest availability to a 0.1 success probability and its
 * highest to 0.9, so a 0.70 vs 0.72 availability became 0.10 vs 0.18; the cumulative cost then
 * amplifies that through the expected number of retries and overrides the cost terms.
 *
 * The table is loaded per run from the experiment's configuration sheet, keyed by implementation.
 * When nothing is loaded (experiments without a configuration sheet) the normalised value is used,
 * as before.
 */
@Slf4j
public final class TransitionAvailability {

    private static Map<String, Double> byImplementation;
    // A service with a single implementation is listed without its "-1" index ("Restaurant-service")
    // while the graph calls it "restaurant-1-service".
    private static Map<String, Double> singleImplementationByService;
    private static String source;

    private TransitionAvailability() {
    }

    public static void load(String xlsxPath, String subScenario) {
        Map<String, Double> implementations = new HashMap<>();
        Map<String, List<Double>> perService = new HashMap<>();
        try (FileInputStream in = new FileInputStream(xlsxPath); Workbook workbook = new XSSFWorkbook(in)) {
            Sheet sheet = workbook.getSheetAt(0);
            String scenario = null;
            for (Row row : sheet) {
                if (row.getRowNum() == 0) continue;
                String scenarioCell = text(row.getCell(0));
                if (scenarioCell != null && !scenarioCell.isEmpty()) scenario = scenarioCell;
                String service = text(row.getCell(1));
                String implementation = text(row.getCell(2));
                Cell availability = row.getCell(3);
                if (!subScenario.equals(scenario) || service == null || implementation == null || !numeric(availability)) continue;
                double value = availability.getNumericCellValue();
                implementations.put(implementation.toLowerCase(), value);
                perService.computeIfAbsent(service.toUpperCase(), k -> new ArrayList<>()).add(value);
            }
        } catch (Exception e) {
            throw new IllegalStateException("Cannot read availabilities from " + xlsxPath, e);
        }
        if (implementations.isEmpty()) {
            throw new IllegalStateException("No availabilities for " + subScenario + " in " + xlsxPath);
        }
        Map<String, Double> single = new HashMap<>();
        perService.forEach((service, values) -> {
            if (values.size() == 1) single.put(service, values.get(0));
        });
        byImplementation = implementations;
        singleImplementationByService = single;
        source = xlsxPath + " / " + subScenario;
        log.info("Transition availabilities from {}: {}", source, new TreeMap<>(implementations));
    }

    public static void clear() {
        byImplementation = null;
        singleImplementationByService = null;
        source = null;
    }

    /** Transition availability of the implementation the graph assigns to the service. */
    public static double of(JsonObject graph, String service) {
        JsonObject node = graph.getAsJsonObject(service);
        double normalised = node.getAsJsonObject("values").getAsJsonPrimitive("Availability").getAsDouble();
        if (byImplementation == null) {
            return normalised;
        }
        String implementation = node.getAsJsonPrimitive("currentImplementationId").getAsString();
        Double value = byImplementation.get(implementation.toLowerCase());
        if (value == null) {
            value = singleImplementationByService.get(service.toUpperCase());
        }
        if (value == null) {
            throw new IllegalStateException("No availability for " + implementation + " (" + service + ") in " + source);
        }
        return value;
    }

    private static boolean numeric(Cell cell) {
        if (cell == null) return false;
        if (cell.getCellType() == CellType.NUMERIC) return true;
        return cell.getCellType() == CellType.FORMULA && cell.getCachedFormulaResultType() == CellType.NUMERIC;
    }

    private static String text(Cell cell) {
        if (cell == null || cell.getCellType() != CellType.STRING) return null;
        return cell.getStringCellValue().trim();
    }
}
