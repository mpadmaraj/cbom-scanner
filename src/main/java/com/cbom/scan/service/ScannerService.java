package com.cbom.scan.service;

import com.cbom.scan.model.ScanJob;
import com.cbom.scan.repo.ScanJobRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.UUID;

@Service
public class ScannerService {
    private final ScanJobRepository repo;

    public ScannerService(ScanJobRepository repo) { this.repo = repo; }

    public void run(UUID jobId) {
        var job = repo.findById(jobId).orElseThrow();
        try {
            job.setStatus("RUNNING"); repo.save(job);

            Path workspace = Files.createTempDirectory("scan-" + jobId);
            exec(new String[]{"git","clone","--depth","1", job.getRepoUrl(), workspace.toString()});

            if (!"cbomkit".equalsIgnoreCase(job.getTool())) {
                String semOut = runScript("/app/scanner-scripts/run-semgrep.sh", workspace.toString());
                job.setSemgrepOutput(semOut);
            }
            if (!"semgrep".equalsIgnoreCase(job.getTool())) {
                String cbomOut = runScript("/app/scanner-scripts/run-cbomkit.sh", workspace.toString());
                job.setCbomkitOutput(cbomOut);
            }

            int score = 100;
            try {
                var mapper = new ObjectMapper();
                if (job.getSemgrepOutput()!=null) {
                    var node = mapper.readTree(job.getSemgrepOutput());
                    int cnt = node.has("results") ? node.get("results").size() : 0;
                    score = Math.max(0, 100 - cnt*5);
                }
            } catch (Exception ignored){}
            job.setPqcScore(score);

            job.setStatus("COMPLETED"); job.setUpdatedAt(Instant.now()); repo.save(job);
        } catch (Exception e) {
            job.setStatus("FAILED"); job.setErrorMessage(e.getMessage()); repo.save(job);
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
            while ((line = br.readLine()) != null) sb.append(line).append("\n");
        }
        int rc = p.waitFor();
        if (rc != 0) throw new RuntimeException("Script failed: " + scriptPath);
        return sb.toString();
    }

    private void exec(String[] cmd) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
            while (br.readLine() != null) {}
        }
        int rc = p.waitFor();
        if (rc != 0) throw new RuntimeException("Command failed: " + String.join(" ", cmd));
    }
}
