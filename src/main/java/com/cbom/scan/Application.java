package com.cbom.scan;

import com.cbom.scan.worker.PostgresListener;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;
import java.util.Arrays;

@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        boolean workerMode = Arrays.asList(args).contains("--worker");
        ConfigurableApplicationContext ctx = SpringApplication.run(Application.class, args);
        if (workerMode) {
            System.out.println("[Worker] Starting LISTEN/NOTIFY worker...");
            ctx.getBean(PostgresListener.class).start();
        } else {
            System.out.println("[API] Starting REST API...");
        }
    }
}
