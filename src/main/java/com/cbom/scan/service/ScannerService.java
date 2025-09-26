package com.cbom.scan.service;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.springframework.stereotype.Service;

import com.cbom.scan.repo.ScanJobRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.scheduling.annotation.Async;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class ScannerService {
    private static final Logger log = LoggerFactory.getLogger(ScannerService.class);
    private final ScanJobRepository repo;

    public ScannerService(ScanJobRepository repo) {
        this.repo = repo;
    }

    @Async
    public void run(UUID jobId) {
        Path workspace = null;
        var job = repo.findById(jobId).orElseThrow();
        log.info("[Scanner] Running job: {}", jobId);
        try {
            job.setStatus("RUNNING");
            repo.save(job);

            workspace = Files.createTempDirectory("scan-" + jobId);
            String ref = job.getRef();

            try {
                log.info("[Scanner] Cloning {} (ref={}) to {}", job.getRepoUrl(), ref, workspace);
                if (ref != null && !ref.isBlank()) {
                    // Try cloning a specific branch/tag with shallow history
                    exec(new String[] { "git", "clone", "--depth", "1", "--branch", ref, job.getRepoUrl(),
                            workspace.toString() });
                } else {
                    exec(new String[] { "git", "clone", "--depth", "1", job.getRepoUrl(), workspace.toString() });
                }
            } catch (Exception cloneEx) {
                // Fallback: clone default branch, then checkout ref (works for commit SHA too)
                exec(new String[] { "git", "clone", "--depth", "1", job.getRepoUrl(), workspace.toString() });
                if (ref != null && !ref.isBlank()) {
                    // fetch the ref (branch/tag/commit) and checkout
                    try {
                        exec(new String[] { "git", "-C", workspace.toString(), "fetch", "--depth", "1", "origin",
                                ref });
                    } catch (Exception ignored) {
                        /* might be a commit SHA; continue */ }
                    exec(new String[] { "git", "-C", workspace.toString(), "checkout", ref });
                }

            }
            String detectedLanguage = null;

            // Detect primary language using 'github-linguist' if available, else fallback
            // to file extension heuristics
            try {
                ProcessBuilder pb = new ProcessBuilder("github-linguist", workspace.toString());
                pb.redirectErrorStream(true);
                Process p = pb.start();
                StringBuilder sb = new StringBuilder();
                try (BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                    String line;
                    while ((line = br.readLine()) != null) {
                        sb.append(line).append("\n");
                    }
                }
                int rc = p.waitFor();
                if (rc == 0) {
                    // Parse output, e.g. "Java 80.0%" -> "Java"
                    String output = sb.toString();
                    if (!output.isBlank()) {
                        detectedLanguage = output.split("\\s")[0];
                    }
                }
            } catch (Exception ignored) {
                // Fallback: simple heuristic based on file extensions

            }
            if (detectedLanguage == null || detectedLanguage.isBlank()) {
                String lang = "generic";
                try {
                    List<String> files = new ArrayList<>();
                    Files.walk(workspace).filter(Files::isRegularFile).forEach(f -> files.add(f.toString()));
                    int javaCount = 0, jsCount = 0, pyCount = 0, goCount = 0, rsCount = 0;
                    for (String f : files) {
                        if (f.endsWith(".java"))
                            javaCount++;
                        else if (f.endsWith(".js") || f.endsWith(".jsx") || f.endsWith(".ts") || f.endsWith(".tsx"))
                            jsCount++;
                        else if (f.endsWith(".py"))
                            pyCount++;
                        else if (f.endsWith(".go"))
                            goCount++;
                        else if (f.endsWith(".rs"))
                            rsCount++;
                    }
                    int max = Math.max(javaCount, Math.max(jsCount, Math.max(pyCount, Math.max(goCount, rsCount))));
                    if (max == javaCount && max > 0)
                        lang = "Java";
                    else if (max == jsCount && max > 0)
                        lang = "JavaScript";
                    else if (max == pyCount && max > 0)
                        lang = "Python";
                    else if (max == goCount && max > 0)
                        lang = "Go";
                    else if (max == rsCount && max > 0)
                        lang = "Rust";
                } catch (Exception ignored) {
                }
                detectedLanguage = lang;
            }
            log.info("[Scanner] Detected language for {}: {}", ref, detectedLanguage);
            if (detectedLanguage != null) {
                job.setDetectedLanguage(detectedLanguage);
            }
            // exec(new String[] { "git", "clone", "--depth", "1", job.getRepoUrl(),
            // workspace.toString() });

            // if (!"cbomkit".equalsIgnoreCase(job.getTool())) {
            log.info("[Scanner] Running Semgrep scan...");
            String lang = job.getDetectedLanguage() != null ? job.getDetectedLanguage().toLowerCase() : "generic";
            String semgrepConfig = "/app/scanner-scripts/rules/" + lang + ".yml";
            String semgrepScript = System.getProperty("user.dir") + "/scanner-scripts/run-semgrep.sh";
            String semOut = runScript(semgrepScript, workspace.toString(), semgrepConfig, lang);
            job.setSemgrepOutput(semOut);
            // Build a compliant CBOM from Semgrep results
            try {
                ObjectMapper mapper = new ObjectMapper();
                JsonNode sem = mapper.readTree(semOut);
                String cbom = new CbomBuilder().fromSemgrep(job, sem, semgrepConfig);
                job.setCbomkitOutput(cbom);
            } catch (Exception e) {
                log.error("[Scanner] Failed to transform Semgrep results to CBOM: {}", e.getMessage());
                e.printStackTrace();
                // leave cbomkitOutput as-is if transform fails
            }
            // }
            /*
             * if (!"semgrep".equalsIgnoreCase(job.getTool())) {
             * System.out.println("[Scanner] Running CBOMKit scan...");
             * String cbomOut = runScript("/app/scanner-scripts/run-cbomkit.sh",
             * workspace.toString());
             * job.setCbomkitOutput(cbomOut);
             * }
             */

            int score = 100;
            try {
                ObjectMapper mapper = new ObjectMapper();
                if (job.getSemgrepOutput() != null) {
                    JsonNode node = mapper.readTree(job.getSemgrepOutput());
                    int cnt = node.has("results") ? node.get("results").size() : 0;
                    score = Math.max(0, 100 - cnt * 5);
                }
            } catch (Exception ignored) {
                log.error("[Scanner] Failed to calculate PQC score: {}", ignored.getMessage());
                ignored.printStackTrace();
            }
            job.setPqcScore(score);

            job.setStatus("COMPLETED");
            job.setUpdatedAt(Instant.now());
            // Validate cbomkitOutput and semgrepOutput as JSON before saving
            boolean validCbom = true, validSemgrep = true;
            try {
                ObjectMapper mapper = new ObjectMapper();
                if (job.getCbomkitOutput() != null && !job.getCbomkitOutput().isBlank()) {
                    log.info("cbomkitOutput before save: {}", job.getCbomkitOutput());
                    mapper.readTree(job.getCbomkitOutput());
                }
            } catch (Exception jsonEx) {
                log.error("[Scanner] Invalid JSON in cbomkitOutput: {}", jsonEx.getMessage());
                job.setCbomkitOutput(null);
                validCbom = false;
            }
            try {
                ObjectMapper mapper = new ObjectMapper();
                if (job.getSemgrepOutput() != null && !job.getSemgrepOutput().isBlank()) {
                    log.info("semgrepOutput before save: {}", job.getSemgrepOutput());
                    mapper.readTree(job.getSemgrepOutput());
                }
            } catch (Exception jsonEx) {
                log.error("[Scanner] Invalid JSON in semgrepOutput: {}", jsonEx.getMessage());
                job.setSemgrepOutput(null);
                validSemgrep = false;
            }
            if (!validCbom || !validSemgrep) {
                job.setStatus("FAILED");
                job.setErrorMessage("Invalid JSON output detected. See logs for details.");
            }
            repo.save(job);
            log.info("[Scanner] Job completed: {}", jobId);
        } catch (Exception e) {
            log.error("[Scanner] Job failed: {}: {}", jobId, e.getMessage());
            e.printStackTrace();
            // mark job as FAILED
            job.setStatus("FAILED");
            job.setErrorMessage(e.getMessage());
            repo.save(job);
        } finally {
            if (workspace != null) {
                try {
                    java.nio.file.Files.walk(workspace)
                            .sorted(java.util.Comparator.reverseOrder())
                            .map(java.nio.file.Path::toFile)
                            .forEach(java.io.File::delete);
                    log.info("Deleted workspace: {}", workspace);
                } catch (Exception cleanupEx) {
                    log.warn("Failed to delete workspace {}: {}", workspace, cleanupEx.getMessage());
                }
            }
        }
    }

    private String runScript(String scriptPath, String... args) throws Exception {
        List<String> cmd = new ArrayList<>();
        log.info("[Scanner] Executing script: {} {}", scriptPath,
                String.join(" ", args != null ? args : new String[] {}));
        cmd.add("sh");
        cmd.add(scriptPath);
        if (args != null) {
            for (String arg : args) {
                cmd.add(arg);
            }
        }
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.directory(new File(System.getProperty("user.dir")));
        pb.redirectErrorStream(true);
        Process p = pb.start();
        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
            String line;
            while ((line = br.readLine()) != null)
                sb.append(line).append("\n");
        }
        int rc = p.waitFor();
        log.info("Return code: {}", rc);
        log.info("Script output:\n{}", sb.toString());
        if (rc != 0) {
            log.error("[Scanner] Job failed: {}: Script failed: {}\nOutput:\n{}", args.length > 0 ? args[0] : "",
                    scriptPath, sb.toString());
            throw new RuntimeException("Script failed: " + scriptPath);
        }
        return sb.toString();
    }

    private void exec(String[] cmd) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
            while (br.readLine() != null) {
            }
        }
        int rc = p.waitFor();
        if (rc != 0)
            throw new RuntimeException("Command failed: " + String.join(" ", cmd));
    }
}
