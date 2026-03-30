package saqure.utils;

import java.io.*;
import java.nio.file.*;
import java.util.*;

import static saqure.utils.SimulationsUtils.log;

public class AED_Processor {
    private static final String START_MARKER = ";;@start vulnerability expose@;;";
    private static final String END_MARKER = ";;@end vulnerability expose@;;";

    public static String AED_process(String outputFile, String[] cveIds) {
        String inputFile = FilePathConstants.AED_path;

        try {
            // read file
            List<String> lines = Files.readAllLines(Paths.get(inputFile));

            // Comment out all vulnerability sections
            List<String> commentedLines = commentAllVulnerabilitySections(lines);
            // Decommenting target vulnerabilities
            List<String> processedLines = uncommentTargetVulnerabilitySections(commentedLines, cveIds);

            // Write to output file
            Files.write(Paths.get(outputFile), processedLines);
            log.info("pddl line 1: " + lines.get(0));
//            System.out.println("Processing complete. Output file: " + outputFile);

        } catch (IOException e) {
            System.err.println("Error processing file: " + e.getMessage());
            e.printStackTrace();
        }
        return outputFile;
    }

    public static String AED_process_nodyPa(String outputFile, String[] cveIds) throws IOException {
        String inputFile = FilePathConstants.AED_path_nodyPa;

        try {
            // read file
            List<String> lines = Files.readAllLines(Paths.get(inputFile));

            // Comment out all vulnerability sections
            List<String> commentedLines = commentAllVulnerabilitySections(lines);
            // Decommenting target vulnerabilities
            List<String> processedLines = uncommentTargetVulnerabilitySections(commentedLines, cveIds);

            // Write to output file
            Files.write(Paths.get(outputFile), processedLines);

//            System.out.println("Processing complete. Output file: " + outputFile);

        } catch (IOException e) {
            System.err.println("Error processing file1: " + e.getMessage());
            e.printStackTrace();
        }
        return outputFile;
    }

    private static List<String> commentAllVulnerabilitySections(List<String> lines) {
        List<String> commentedLines = new ArrayList<>();
        boolean inVulnerabilitySection = false;

        for (String line : lines) {
            String trimmedLine = line.trim();

            if (trimmedLine.contains(START_MARKER)) {
                inVulnerabilitySection = true;
            }

            if (inVulnerabilitySection) {
                commentedLines.add(line.startsWith(";") ? line : ";" + line);
            } else {
                commentedLines.add(line);
            }

            if (trimmedLine.contains(END_MARKER)) {
                inVulnerabilitySection = false;
            }
        }

        return commentedLines;
    }

    private static List<String> uncommentTargetVulnerabilitySections(List<String> lines, String[] cveIds) {
        List<String> modifiedLines = new ArrayList<>();
        Set<String> targetCves = new HashSet<>(Arrays.asList(cveIds));
        Set<String> foundCves = new HashSet<>();
        boolean inTargetSection = false;
        String currentCve = null;

        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            String trimmedLine = line.trim();

            if (trimmedLine.contains(START_MARKER)) {
                // Forward search for associated CVEs
                currentCve = findAssociatedCve(lines, i, targetCves);
                inTargetSection = currentCve != null;
                if (inTargetSection) {
                    foundCves.add(currentCve);
                }
            }

            if (inTargetSection) {
                // Uncomment line
                modifiedLines.add(line.equals(START_MARKER)
                        ? line
                        : line.startsWith(";")
                            ? (line.length() > 1 ? line.substring(1) : "")
                            : line);

                // Check the end marker
                if (trimmedLine.contains(END_MARKER)) {
                    inTargetSection = false;
                    currentCve = null;
                }
            } else {
                modifiedLines.add(line);
            }
        }

        // Output report
        if (foundCves.size() < targetCves.size()) {
            targetCves.removeAll(foundCves);
        }

        return modifiedLines;
    }

    private static String findAssociatedCve(List<String> lines, int currentIndex, Set<String> targetCves) {
        for (int j = currentIndex + 1; j >= 0 && j <= currentIndex + 5; j++) {
            String prevLine = lines.get(j).trim();
            if (prevLine.matches(";?\\(:action.*")) {
//                System.out.println("prevLine: " + prevLine);
//                System.out.println("targetCves: " + targetCves);
                return targetCves.stream()
                        .filter(prevLine::contains)
                        .findFirst()
                        .orElse(null);
            }
        }
//        System.out.println("null");
        return null;
    }
}