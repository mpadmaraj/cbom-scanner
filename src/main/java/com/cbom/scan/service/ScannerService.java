package com.cbom.scan.service;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.UUID;

import org.springframework.stereotype.Service;

import com.cbom.scan.repo.ScanJobRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.scheduling.annotation.Async;

@Service
public class ScannerService {
    private final ScanJobRepository repo;

    public ScannerService(ScanJobRepository repo) {
        this.repo = repo;
    }

    @Async
    public void run(UUID jobId) {
        var job = repo.findById(jobId).orElseThrow();
        System.out.println("[Scanner] Running job: " + jobId);
        try {
            job.setStatus("RUNNING");
            repo.save(job);

            Path workspace = Files.createTempDirectory("scan-" + jobId);
            String ref = job.getRef();

            try {
                System.out.println("[Scanner] Cloning " + job.getRepoUrl() + " (ref=" + ref + ") to " + workspace);
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
            // exec(new String[] { "git", "clone", "--depth", "1", job.getRepoUrl(),
            // workspace.toString() });

            if (!"cbomkit".equalsIgnoreCase(job.getTool())) {
                System.out.println("[Scanner] Running Semgrep scan...");
                String semOut = runScript("/app/scanner-scripts/run-semgrep.sh", workspace.toString());
                job.setSemgrepOutput(semOut);
                // Build a compliant CBOM from Semgrep results
                try {
                    ObjectMapper mapper = new ObjectMapper();
                    JsonNode sem = mapper.readTree(semOut);
                    String cbom = new CbomBuilder().fromSemgrep(job.getRepoUrl(), job.getRef(), sem);
                    job.setCbomkitOutput(cbom);
                } catch (Exception e) {
                    // leave cbomkitOutput as-is if transform fails
                }
            }
            if (!"semgrep".equalsIgnoreCase(job.getTool())) {
                System.out.println("[Scanner] Running CBOMKit scan...");
                String cbomOut = runScript("/app/scanner-scripts/run-cbomkit.sh", workspace.toString());
                job.setCbomkitOutput(cbomOut);
            }

            int score = 100;
            try {
                ObjectMapper mapper = new ObjectMapper();
                if (job.getSemgrepOutput() != null) {
                    JsonNode node = mapper.readTree(job.getSemgrepOutput());
                    int cnt = node.has("results") ? node.get("results").size() : 0;
                    score = Math.max(0, 100 - cnt * 5);
                }
            } catch (Exception ignored) {
            }
            job.setPqcScore(score);

            job.setStatus("COMPLETED");
            job.setUpdatedAt(Instant.now());
            repo.save(job);
            System.out.println("[Scanner] Job completed: " + jobId);
        } catch (Exception e) {
            job.setStatus("FAILED");
            job.setErrorMessage(e.getMessage());
            repo.save(job);
        }
    }

    private String runScript(String scriptPath, String workspace) throws Exception {
        ProcessBuilder pb = new ProcessBuilder("sh", scriptPath, workspace);
        pb.directory(new File("/app"));
        pb.redirectErrorStream(true);
        Process p = pb.start();
        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
            String line;
            while ((line = br.readLine()) != null)
                sb.append(line).append("\n");
        }
        int rc = p.waitFor();
        if (rc != 0)
            throw new RuntimeException("Script failed: " + scriptPath);
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
