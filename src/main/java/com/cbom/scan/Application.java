package com.cbom.scan;

import com.cbom.scan.worker.PostgresListener;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;
import java.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SpringBootApplication
public class Application {
    private static final Logger log = LoggerFactory.getLogger(Application.class);

    public static void main(String[] args) {
        boolean workerMode = Arrays.asList(args).contains("--worker");
        ConfigurableApplicationContext ctx = SpringApplication.run(Application.class, args);
        if (workerMode) {
            log.info("[Worker] Starting LISTEN/NOTIFY worker...");
            ctx.getBean(PostgresListener.class).start();
        } else {
            log.info("[API] Starting REST API...");
        }
    }
}
