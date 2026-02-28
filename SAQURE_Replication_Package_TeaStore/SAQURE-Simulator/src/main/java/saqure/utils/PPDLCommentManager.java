package saqure.utils;

import java.io.*;
import java.nio.file.*;
import java.util.*;

public class PPDLCommentManager {
    private static final String START_MARKER = ";;@start vulnerability expose@;;";
    private static final String END_MARKER = ";;@end vulnerability expose@;;";

    public static String ppdl_commentManager(String outputFile, String[] cveIds) {
        String inputFile = PathConstants.AED_path;

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
            System.err.println("Error processing file: " + e.getMessage());
            e.printStackTrace();
        }
        return outputFile;
    }

    public static String ppdl_commentManager_nodyPa(String outputFile, String[] cveIds) {
        String inputFile = PathConstants.AED_path_nodyPa;

        try {
            // read file
            List<String> lines = Files.readAllLines(Paths.get(inputFile));

            // Comment out all vulnerability sections
            List<String> commentedLines = commentAllVulnerabilitySections(lines);
            // 解注释目标漏洞
            List<String> processedLines = uncommentTargetVulnerabilitySections(commentedLines, cveIds);

            // 写入输出文件
            Files.write(Paths.get(outputFile), processedLines);

//            System.out.println("处理完成。输出文件: " + outputFile);

        } catch (IOException e) {
            System.err.println("处理文件时出错: " + e.getMessage());
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

            // 在漏洞部分内，确保每行都被注释
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
                // 向前查找关联的CVE
                currentCve = findAssociatedCve(lines, i, targetCves);
                inTargetSection = currentCve != null;
                if (inTargetSection) {
                    foundCves.add(currentCve);
                }
            }

            if (inTargetSection) {
                // 解注释行
                modifiedLines.add(line.equals(START_MARKER)
                        ? line
                        : line.startsWith(";")
                            ? (line.length() > 1 ? line.substring(1) : "")
                            : line);

                // 检查结束标记
                if (trimmedLine.contains(END_MARKER)) {
                    inTargetSection = false;
                    currentCve = null;
                }
            } else {
                modifiedLines.add(line);
            }
        }

        // 输出报告
//        System.out.println("找到并解注释了 " + foundCves.size() + " 个漏洞部分");
        if (foundCves.size() < targetCves.size()) {
//            System.out.println("未找到的CVE:");
            targetCves.removeAll(foundCves);
//            targetCves.forEach(System.out::println);
        }

        return modifiedLines;
    }

    private static String findAssociatedCve(List<String> lines, int currentIndex, Set<String> targetCves) {
        // 向下查找最多5行，寻找action定义
        for (int j = currentIndex + 1; j >= 0 && j <= currentIndex + 5; j++) {
            String prevLine = lines.get(j).trim();
            if (prevLine.matches(";?\\(:action.*")) {
                // 检查是否包含目标CVE
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