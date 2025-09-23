package com.cbom.scan.api;

import com.cbom.scan.model.ScanJob;
import com.cbom.scan.repo.ScanJobRepository;
import com.cbom.scan.service.ReportService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/scans")
public class ScanController {

    private final ScanJobRepository repo;
    private final JdbcTemplate jdbc;
    private final ReportService reportService;

    public ScanController(ScanJobRepository repo, JdbcTemplate jdbc, ReportService reportService) {
        this.repo = repo;
        this.jdbc = jdbc;
        this.reportService = reportService;
    }

    @PostMapping
    public ResponseEntity<?> create(@RequestBody CreateScan req) {
        ScanJob job = new ScanJob();
        job.setId(UUID.randomUUID());
        job.setRepoUrl(req.repoUrl());
        // Prefer branch; fallback to ref (tag/sha)
        String resolvedRef = (req.branch() != null && !req.branch().isBlank())
                ? req.branch()
                : req.ref();
        job.setRef(resolvedRef);
        job.setTool(req.tool() == null ? "semgrep" : req.tool());
        job.setStatus("QUEUED");
        job.setCreatedAt(Instant.now());
        job.setUpdatedAt(Instant.now());
        repo.save(job);
        jdbc.execute(String.format("SELECT pg_notify('scan_jobs','%s')", job.getId().toString()));
        return ResponseEntity.accepted().body(Map.of("id", job.getId(), "status", job.getStatus()));
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> status(@PathVariable("id") UUID id) {
        Optional<ScanJob> job = repo.findById(id);
        return job.<ResponseEntity<?>>map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
    }

    @GetMapping("/{id}/json")
    public ResponseEntity<String> mergedJson(@PathVariable("id") UUID id) {
        return repo.findById(id)
                .map(job -> ResponseEntity.ok(reportService.buildMergedJson(job)))
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/{id}/report.pdf")
    public ResponseEntity<byte[]> pdf(@PathVariable("id") UUID id) {
        return repo.findById(id)
                .map(job -> {
                    byte[] pdf = reportService.generatePdf(job);
                    return ResponseEntity.ok()
                            .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=scan-" + id + ".pdf")
                            .contentType(MediaType.APPLICATION_PDF)
                            .body(pdf);
                })
                .orElse(ResponseEntity.notFound().build());
    }

    public record CreateScan(String repoUrl, String branch, String ref, String tool) {
    }

    @GetMapping("/{id}/cbom")
    public ResponseEntity<?> cbom(@PathVariable("id") UUID id) {
        return repo.findById(id)
                .map(job -> {
                    String cbom = job.getCbomkitOutput();
                    if (cbom == null || cbom.isBlank()) {
                        return ResponseEntity.noContent().build(); // 204
                    }
                    return ResponseEntity.ok()
                            .contentType(MediaType.APPLICATION_JSON)
                            .body(cbom);
                })
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

}
