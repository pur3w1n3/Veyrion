package com.aq.jvmsentinel.analysis;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * P0-17: harvest candidate application HTTP ports from Boot config lines / manifest text.
 * Dependency ports (3306/6379/5432/…) are never returned as application candidates.
 */
public final class BootPortCandidateHarvester {
    private static final Set<Integer> DEPENDENCY_PORTS = Set.of(
            3306, 6379, 5432, 27017, 11211, 9200, 5672, 2181, 9092);
    private static final Pattern PROPERTIES_PORT = Pattern.compile(
            "(?i)^\\s*server\\.port\\s*[=:]\\s*(\\d{2,5})\\s*$");
    private static final Pattern YAML_PORT = Pattern.compile(
            "(?i)^\\s*port\\s*:\\s*(\\d{2,5})\\s*$");
    private static final Pattern INLINE_SERVER_PORT = Pattern.compile(
            "(?i)server\\.port\\s*[=:]\\s*(\\d{2,5})");
    private static final Pattern MANIFEST_MAIN = Pattern.compile(
            "(?i)Start-Class:\\s*(\\S+)");

    private BootPortCandidateHarvester() {
    }

    public record Harvest(
            List<Integer> candidateHttpPorts,
            List<Integer> rejectedDependencyPorts,
            String startClass,
            String provenance
    ) {
        public Harvest {
            candidateHttpPorts = List.copyOf(candidateHttpPorts == null ? List.of() : candidateHttpPorts);
            rejectedDependencyPorts = List.copyOf(
                    rejectedDependencyPorts == null ? List.of() : rejectedDependencyPorts);
            startClass = startClass == null ? "" : startClass;
            provenance = provenance == null ? "" : provenance;
        }
    }

    public static Harvest harvest(List<String> configurationLines) {
        return harvest(configurationLines, List.of());
    }

    public static Harvest harvest(List<String> configurationLines, List<String> manifestLines) {
        LinkedHashSet<Integer> candidates = new LinkedHashSet<>();
        LinkedHashSet<Integer> rejected = new LinkedHashSet<>();
        List<String> config = configurationLines == null ? List.of() : configurationLines;
        boolean inServerBlock = false;
        for (String raw : config) {
            if (raw == null || raw.isBlank()) continue;
            boolean indented = !raw.isEmpty() && (raw.charAt(0) == ' ' || raw.charAt(0) == '\t');
            String line = raw.strip();
            Matcher props = PROPERTIES_PORT.matcher(line);
            if (props.find()) {
                classify(parsePort(props.group(1)), candidates, rejected);
                continue;
            }
            Matcher inline = INLINE_SERVER_PORT.matcher(line);
            if (inline.find()) {
                classify(parsePort(inline.group(1)), candidates, rejected);
            }
            if (line.toLowerCase(Locale.ROOT).matches("server\\s*:\\s*")) {
                inServerBlock = true;
                continue;
            }
            if (inServerBlock) {
                if (!indented && line.contains(":")) {
                    inServerBlock = line.toLowerCase(Locale.ROOT).startsWith("server");
                }
                Matcher yaml = YAML_PORT.matcher(line);
                if (inServerBlock && yaml.find()) {
                    classify(parsePort(yaml.group(1)), candidates, rejected);
                }
            }
        }
        String startClass = "";
        List<String> manifests = manifestLines == null ? List.of() : manifestLines;
        for (String raw : manifests) {
            if (raw == null) continue;
            Matcher matcher = MANIFEST_MAIN.matcher(raw);
            if (matcher.find()) {
                startClass = matcher.group(1).trim();
                break;
            }
        }
        if (candidates.isEmpty()) {
            // Common Boot default remains a soft candidate for readiness ordering only.
            candidates.add(8080);
        }
        return new Harvest(new ArrayList<>(candidates), new ArrayList<>(rejected), startClass,
                "BOOT_CONFIG_HARVEST");
    }

    public static boolean isDependencyPort(int port) {
        return DEPENDENCY_PORTS.contains(port);
    }

    private static void classify(int port, Set<Integer> candidates, Set<Integer> rejected) {
        if (port < 1 || port > 65535) return;
        if (DEPENDENCY_PORTS.contains(port)) {
            rejected.add(port);
            return;
        }
        candidates.add(port);
    }

    private static int parsePort(String text) {
        try {
            return Integer.parseInt(Objects.requireNonNullElse(text, "").trim());
        } catch (NumberFormatException ignored) {
            return -1;
        }
    }
}
