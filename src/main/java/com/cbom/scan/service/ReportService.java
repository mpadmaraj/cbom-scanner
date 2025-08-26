package com.cbom.scan.service;

import com.cbom.scan.model.ScanJob;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.openhtmltopdf.pdfboxout.PdfRendererBuilder;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;

@Service
public class ReportService {
    private final ObjectMapper mapper = new ObjectMapper();

    public String buildMergedJson(ScanJob job) {
        try {
            var root = mapper.createObjectNode();
            if (job.getSemgrepOutput()!=null) root.set("semgrep", mapper.readTree(job.getSemgrepOutput()));
            if (job.getCbomkitOutput()!=null) root.set("cbomkit", mapper.readTree(job.getCbomkitOutput()));
            root.put("pqc_score", job.getPqcScore()==null?0:job.getPqcScore());
            return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(root);
        } catch(Exception e) { throw new RuntimeException(e); }
    }

    public byte[] generatePdf(ScanJob job) {
        String json = buildMergedJson(job);
        String html = "<html><body><h1>CBOM Scan Report</h1><pre>" +
                json.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;") +
                "</pre></body></html>";
        try (ByteArrayOutputStream os = new ByteArrayOutputStream()) {
            PdfRendererBuilder b = new PdfRendererBuilder();
            b.withHtmlContent(html, null);
            b.toStream(os);
            b.run();
            return os.toByteArray();
        } catch (Exception e) { throw new RuntimeException(e); }
    }
}
