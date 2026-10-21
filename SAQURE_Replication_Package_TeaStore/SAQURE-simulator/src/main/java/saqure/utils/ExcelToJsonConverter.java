package saqure.utils;

import org.apache.poi.ss.usermodel.*;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class ExcelToJsonConverter {
    private List<Map<String, Object>> processedData;

    private static final Pattern VULN_SCORE_PATTERN = Pattern.compile("Vulnerabilities\\s*Scores", Pattern.CASE_INSENSITIVE);
    private static final Pattern VULN_LIST_PATTERN = Pattern.compile("Vulnerabilities\\s*lists", Pattern.CASE_INSENSITIVE);

    // Column index (will be dynamically determined based on the column header)
    private int subScenarioCol = -1;
    private int microserviceCol = -1;
    private int implementationsCol = -1;
    private int availabilityCol = -1;
    private int responseTimeCol = -1;
    private List<Integer> vulnScoresCols = new ArrayList<>();
    private List<Integer> vulnListsCols = new ArrayList<>();

    public ExcelToJsonConverter(String filePath) throws Exception {
        this.processedData = processExcel(filePath);
    }

    public Object getValue(String scenarioName, String serviceName,
                           String implementation, String valueType) {
        return queryValue(scenarioName, serviceName, implementation, valueType);
    }

    private List<Map<String, Object>> processExcel(String filePath) throws Exception {
        List<Map<String, Object>> allScenarios = new ArrayList<>();
        Map<String, Map<String, Object>> scenarioMap = new LinkedHashMap<>();
        Map<String, Map<String, List<Map<String, Object>>>> serviceMap = new HashMap<>();

        try (FileInputStream fis = new FileInputStream(filePath);
             Workbook workbook = new XSSFWorkbook(fis)) {

            Sheet sheet = workbook.getSheetAt(0);
            Iterator<Row> rowIterator = sheet.iterator();

            // Process header row
            if (!rowIterator.hasNext()) {
                throw new RuntimeException("Excel sheet is empty");
            }

            Row headerRow = rowIterator.next();
            detectColumnIndexes(headerRow);

            while (rowIterator.hasNext()) {
                Row row = rowIterator.next();
                if (isEmptyRow(row)) continue;

                // Get Scene Name
                String scenarioName = getCellStringValue(row.getCell(subScenarioCol));
                if (scenarioName == null || !scenarioName.startsWith("Sub-scenario")) {
                    if (!scenarioMap.isEmpty()) {
                        scenarioName = scenarioMap.keySet().iterator().next();
//                        System.out.print("scenarioName: "+scenarioName+"\n");
                    } else {
                        continue;
                    }
                }

                // Initialize scene data structure
                if (!scenarioMap.containsKey(scenarioName)) {
                    Map<String, Object> scenario = new LinkedHashMap<>();
                    scenario.put("scenario_name", scenarioName);
                    scenarioMap.put(scenarioName, scenario);

                    Map<String, List<Map<String, Object>>> services = new LinkedHashMap<>();
                    services.put(FilePathConstants.Services.WEBUI.getServiceName(), new ArrayList<>());
                    services.put(FilePathConstants.Services.AUTHENTICATION.getServiceName(), new ArrayList<>());
                    services.put(FilePathConstants.Services.PERSISTENCE.getServiceName(), new ArrayList<>());
                    services.put(FilePathConstants.Services.IMAGE.getServiceName(), new ArrayList<>());
                    services.put(FilePathConstants.Services.RECOMMENDER.getServiceName(), new ArrayList<>());
                    serviceMap.put(scenarioName, services);
                }

                // Processing service data lines
                String microservice = getCellStringValue(row.getCell(microserviceCol));
                if (microservice == null || microservice.isEmpty()) continue;

                String serviceType = classifyService(microservice);
                if (serviceType == null) continue;

                // Create implementation data and add it to the scene.
                Map<String, Object> implementationData = createComponentData(row);
                serviceMap.get(scenarioName).get(serviceType).add(implementationData);
            }

            // Add service implementation to the scene
            for (Map.Entry<String, Map<String, Object>> entry : scenarioMap.entrySet()) {
                String scenarioName = entry.getKey();
                Map<String, Object> scenario = entry.getValue();
                Map<String, List<Map<String, Object>>> services = serviceMap.get(scenarioName);

                services.forEach((serviceType, implementations) -> {
                    if (!implementations.isEmpty()) {
                        scenario.put(serviceType, implementations);
                    }
                });

                allScenarios.add(scenario);
            }
        }

        return allScenarios;
    }

    // The position of each column is automatically detected based on the column header.

    private void detectColumnIndexes(Row headerRow) {
        // Clear previous indexes
        vulnScoresCols.clear();
        vulnListsCols.clear();

        // Traverse all cells in the header row
        for (Cell cell : headerRow) {
            String headerValue = getCellStringValue(cell);
            if (headerValue == null) continue;

            headerValue = headerValue.trim().toLowerCase();

            // Detect key columns
            if (headerValue.contains("sub-scenario") || headerValue.contains("scenario")) {
                subScenarioCol = cell.getColumnIndex();
            } else if (headerValue.contains("microservice")) {
                microserviceCol = cell.getColumnIndex();
            } else if (headerValue.contains("implementation")) {
                implementationsCol = cell.getColumnIndex();
            } else if (headerValue.contains("availability")) {
                availabilityCol = cell.getColumnIndex();
            } else if (headerValue.contains("response time")) {
                responseTimeCol = cell.getColumnIndex();
            } else if (VULN_SCORE_PATTERN.matcher(headerValue).find()) {
                vulnScoresCols.add(cell.getColumnIndex());
            } else if (VULN_LIST_PATTERN.matcher(headerValue).find()) {
                vulnListsCols.add(cell.getColumnIndex());
            }
        }

        // Validate whether the required columns are found
        if (subScenarioCol == -1) throw new RuntimeException("Sub-scenario column not found");
        if (microserviceCol == -1) throw new RuntimeException("Microservice column not found");
        if (implementationsCol == -1) throw new RuntimeException("Implementations column not found");
        if (availabilityCol == -1) throw new RuntimeException("Availability column not found");
        if (responseTimeCol == -1) throw new RuntimeException("Response Time column not found");

//        System.out.println("Detected columns:");
//        System.out.println("  Sub-scenario: " + subScenarioCol);
//        System.out.println("  Microservice: " + microserviceCol);
//        System.out.println("  Implementations: " + implementationsCol);
//        System.out.println("  Availability: " + availabilityCol);
//        System.out.println("  Response Time: " + responseTimeCol);
//        System.out.println("  Vulnerability Scores: " + vulnScoresCols);
//        System.out.println("  Vulnerability Lists: " + vulnListsCols);
    }

    private String classifyService(String microservice) {
        String ms = microservice.toUpperCase();
        if (ms.contains("WEBUI")) return FilePathConstants.Services.WEBUI.getServiceName();
        if (ms.contains("AUTHENTICATION")) return FilePathConstants.Services.AUTHENTICATION.getServiceName();
        if (ms.contains("PERSISTENCE")) return FilePathConstants.Services.PERSISTENCE.getServiceName();
        if (ms.contains("IMAGE")) return FilePathConstants.Services.IMAGE.getServiceName();
        if (ms.contains("RECOMMENDER")) return FilePathConstants.Services.RECOMMENDER.getServiceName();
        return null;
    }

    private Map<String, Object> createComponentData(Row row) {
        Map<String, Object> componentData = new LinkedHashMap<>();

        componentData.put("implementation", getCellStringValue(row.getCell(implementationsCol)));
        componentData.put("availability", getCellNumericValue(row.getCell(availabilityCol)));
        componentData.put("response_time", (int) getCellNumericValue(row.getCell(responseTimeCol)));

        // Extracting vulnerabilities
        List<Double> vulnScores = new ArrayList<>();
        for (int col : vulnScoresCols) {
            Cell cell = row.getCell(col);
            if (cell != null && cell.getCellType() != CellType.BLANK) {
                double value = getCellNumericValue(cell);
                if (value > 0) {
                    vulnScores.add(value);
                }
            }
        }
        componentData.put("vulnerability_scores", vulnScores);

        // Extract vulnerability list
        Set<String> vulnLists = new HashSet<>();
        for (int col : vulnListsCols) {
            Cell cell = row.getCell(col);
            if (cell != null && cell.getCellType() != CellType.BLANK) {
                String cve = cleanCve(getCellStringValue(cell));
                if (cve != null) {
                    vulnLists.add(cve);
//                    System.out.print("cve: "+cve+"\n");
                }
            }
        }
        componentData.put("vulnerability_lists", new ArrayList<>(vulnLists));

        return componentData;
    }

    private String cleanCve(String cveStr) {
        if (cveStr == null || cveStr.isEmpty()) return null;

        // Handling line breaks and extra spaces
        cveStr = cveStr.replaceAll("\\s+", " ").trim();

        // Matching standard CVE format
        Pattern pattern = Pattern.compile("(CVE-\\d{4}-\\d{4,})", Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(cveStr);
        if (matcher.find()) {
            return matcher.group(1).toUpperCase();
        }
        return null;
    }

    private Object queryValue(String scenarioName, String serviceName,
                              String implementation, String valueType) {
        try {
            // Search Scene
            Map<String, Object> scenario = processedData.stream()
                    .filter(s -> scenarioName.equals(s.get("scenario_name")))
                    .findFirst()
                    .orElseThrow(() -> {
                        List<String> availableScenarios = processedData.stream()
                                .map(s -> (String) s.get("scenario_name"))
                                .distinct()
                                .collect(Collectors.toList());
                        return new RuntimeException("Scenario not found: " + scenarioName +
                                ". Available scenarios: " + availableScenarios);
                    });

            // 获取服务列表
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> services = (List<Map<String, Object>>) scenario.get(serviceName);
            if (services == null || services.isEmpty()) {
                Set<String> availableServices = scenario.keySet().stream()
                        .filter(k -> !k.equals("scenario_name") && scenario.get(k) instanceof List)
                        .collect(Collectors.toSet());
                throw new RuntimeException("Service not found: " + serviceName +
                        ". Available services: " + availableServices);
            }

            // Search implementation
            Map<String, Object> impl = services.stream()
                    .filter(s -> implementation.equals(s.get("implementation")))
                    .findFirst()
                    .orElseThrow(() -> {
                        List<String> availableImpls = services.stream()
                                .map(s -> (String) s.get("implementation"))
                                .collect(Collectors.toList());
                        return new RuntimeException("Implementation not found: " + implementation +
                                ". Available implementations: " + availableImpls);
                    });

            // Return value based on type
            switch (valueType.toLowerCase()) {
                case "availability":
                    return impl.get("availability");
                case "responsetime":
                    return impl.get("response_time");
                case "avgvulnerabilityscore":
                    @SuppressWarnings("unchecked")
                    List<Double> scores = (List<Double>) impl.get("vulnerability_scores");
                    return scores.stream().mapToDouble(Double::doubleValue).average().orElse(0.0);
                case "sumvulnerabilityscore":
                    @SuppressWarnings("unchecked")
                    List<Double> sumScores = (List<Double>) impl.get("vulnerability_scores");
                    return sumScores.stream().mapToDouble(Double::doubleValue).sum();
                case "vulnerabilitylist":
                    @SuppressWarnings("unchecked")
                    List<String> vulnList = (List<String>) impl.get("vulnerability_lists");
                    return vulnList;
                default:
                    throw new IllegalArgumentException("Unsupported value type: " + valueType);
            }
        } catch (Exception e) {
            throw new RuntimeException(String.format(
                    "Error getting value [scenario=%s, service=%s, impl=%s, type=%s]: %s",
                    scenarioName, serviceName, implementation, valueType, e.getMessage()), e);
        }
    }

    // Auxiliary methods
    private boolean isEmptyRow(Row row) {
        if (row == null) return true;
        for (int c = row.getFirstCellNum(); c < row.getLastCellNum(); c++) {
            Cell cell = row.getCell(c);
            if (cell != null && cell.getCellType() != CellType.BLANK) {
                return false;
            }
        }
        return true;
    }

    private String getCellStringValue(Cell cell) {
        if (cell == null) return null;
        switch (cell.getCellType()) {
            case STRING: return cell.getStringCellValue().trim();
            case NUMERIC: return String.valueOf(cell.getNumericCellValue());
            default: return null;
        }
    }

    private double getCellNumericValue(Cell cell) {
        if (cell == null) return 0.0;
        switch (cell.getCellType()) {
            case NUMERIC: return cell.getNumericCellValue();
            case STRING:
                try {
                    return Double.parseDouble(cell.getStringCellValue());
                } catch (NumberFormatException e) {
                    return 0.0;
                }
            default: return 0.0;
        }
    }

    public void saveToJson(String filePath) throws IOException {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        try (FileWriter writer = new FileWriter(filePath)) {
            gson.toJson(processedData, writer);
        }
    }
}

