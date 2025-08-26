package com.cbom.scan.model;

import jakarta.persistence.*;
import org.hibernate.annotations.Type;
import java.time.Instant;
import java.util.UUID;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

@Entity
@Table(name = "scan_job")
public class ScanJob {
    @Id
    private UUID id;

    @Column(name = "repo_url", nullable = false)
    private String repoUrl;
    private String ref;
    private String tool;
    private String status;
    @Column(name = "created_at")
    private Instant createdAt = Instant.now();
    @Column(name = "updated_at")
    private Instant updatedAt = Instant.now();

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb", name = "semgrep_output")
    private String semgrepOutput;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb", name = "cbomkit_output")
    private String cbomkitOutput;

    private Integer pqcScore;
    private String errorMessage;

    // getters/setters
    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getRepoUrl() {
        return repoUrl;
    }

    public void setRepoUrl(String repoUrl) {
        this.repoUrl = repoUrl;
    }

    public String getRef() {
        return ref;
    }

    public void setRef(String ref) {
        this.ref = ref;
    }

    public String getTool() {
        return tool;
    }

    public void setTool(String tool) {
        this.tool = tool;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Instant updatedAt) {
        this.updatedAt = updatedAt;
    }

    public String getSemgrepOutput() {
        return semgrepOutput;
    }

    public void setSemgrepOutput(String semgrepOutput) {
        this.semgrepOutput = semgrepOutput;
    }

    public String getCbomkitOutput() {
        return cbomkitOutput;
    }

    public void setCbomkitOutput(String cbomkitOutput) {
        this.cbomkitOutput = cbomkitOutput;
    }

    public Integer getPqcScore() {
        return pqcScore;
    }

    public void setPqcScore(Integer pqcScore) {
        this.pqcScore = pqcScore;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }
}
