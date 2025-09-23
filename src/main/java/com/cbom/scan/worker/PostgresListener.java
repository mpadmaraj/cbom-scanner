package com.cbom.scan.worker;

import java.sql.Connection;
import java.sql.Statement;
import java.util.UUID;

import javax.sql.DataSource;

import org.postgresql.PGConnection;
import org.postgresql.PGNotification;
import org.springframework.core.task.TaskExecutor;
import org.springframework.stereotype.Component;

import com.cbom.scan.service.ScannerService;

import jakarta.annotation.PostConstruct;

@Component
public class PostgresListener {
    private final DataSource dataSource;
    private final ScannerService scannerService;
    private final TaskExecutor taskExecutor;

    public PostgresListener(DataSource dataSource, ScannerService scannerService, TaskExecutor taskExecutor) {
        this.dataSource = dataSource;
        this.scannerService = scannerService;
        this.taskExecutor = taskExecutor;
    }

    @PostConstruct
    public void start() {
        taskExecutor.execute(this::loop);
    }

    }

    private void loop() {
        try (Connection conn = dataSource.getConnection();
                Statement st = conn.createStatement()) {
            conn.setAutoCommit(true);
            st.execute("LISTEN scan_jobs");
            PGConnection pg = conn.unwrap(PGConnection.class);
            System.out.println("[Worker] Listening on channel 'scan_jobs'...");
            while (true) {
                PGNotification[] notifications = pg.getNotifications(5000);
                if (notifications != null) {
                    for (PGNotification n : notifications) {
                        try {
                            UUID jobId = UUID.fromString(n.getParameter());
                            System.out.println("[Worker] Received job: " + jobId);
                            scannerService.run(jobId);
                        } catch (Exception ex) {
                            ex.printStackTrace();
                        }
                    }
                }
                Thread.sleep(200);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
