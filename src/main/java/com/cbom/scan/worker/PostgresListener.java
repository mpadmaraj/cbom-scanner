package com.cbom.scan.worker;

import com.cbom.scan.service.ScannerService;
import org.postgresql.PGConnection;
import org.postgresql.PGNotification;
import org.springframework.stereotype.Component;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.Statement;
import java.util.UUID;
import org.postgresql.PGConnection;
import org.postgresql.PGNotification;

@Component
public class PostgresListener {

    private final DataSource dataSource;
    private final ScannerService scannerService;

    public PostgresListener(DataSource dataSource, ScannerService scannerService) {
        this.dataSource = dataSource;
        this.scannerService = scannerService;
    }

    public void start() {
        new Thread(this::loop, "pg-listener").start();
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
