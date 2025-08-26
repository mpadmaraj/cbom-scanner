package com.cbom.scan.repo;

import com.cbom.scan.model.ScanJob;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.UUID;

public interface ScanJobRepository extends JpaRepository<ScanJob, UUID> { }
