package com.cbom.scan.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.*;

import java.time.Instant;
import java.util.Iterator;

public class CbomBuilder {
    private final ObjectMapper mapper = new ObjectMapper();

    /**
     * Convert Semgrep JSON to a minimal CycloneDX 1.6 CBOM-like doc with
     * "cryptographic-asset" components.
     */
    public String fromSemgrep(String repoUrl, JsonNode semgrepJson) {
        ObjectNode root = mapper.createObjectNode();
        root.put("bomFormat", "CycloneDX");
        root.put("specVersion", "1.6");
        root.put("version", 1);

        ObjectNode metadata = root.putObject("metadata");
        metadata.put("timestamp", Instant.now().toString());
        ArrayNode props = metadata.putArray("properties");
        props.add(prop("gitUrl", repoUrl));

        ArrayNode components = root.putArray("components");

        // Walk semgrep results and project into coarse crypto assets
        if (semgrepJson != null && semgrepJson.has("results")) {
            for (JsonNode r : semgrepJson.get("results")) {
                String ruleId = get(r, "check_id");
                String path = get(r.path("path"), "path");
                int line = r.path("start").path("line").asInt(-1);

                String snippet = get(r.path("extra"), "lines");
                String lang = get(r.path("extra"), "language");

                // naive classification
                String name = classifyName(ruleId, snippet);
                String primitive = classifyPrimitive(ruleId, snippet);

                ObjectNode comp = components.addObject();
                comp.put("type", "cryptographic-asset");
                comp.put("bom-ref", ruleId + "@" + path + ":" + line);
                comp.put("group", "detected-in-" + fileBase(path));
                comp.put("name", name);
                comp.put("version", "line-" + (line > 0 ? line : 0));
                comp.put("description", snippet != null ? snippet.trim() : ruleId);
                comp.put("scope", "required");

                ArrayNode cprops = comp.putArray("properties");
                cprops.add(prop("detectionMethod", "static-analysis"));
                if (!lang.isEmpty())
                    cprops.add(prop("language", lang));
                cprops.add(prop("toolName", "Semgrep"));

                ObjectNode evidence = comp.putObject("evidence");
                ArrayNode occ = evidence.putArray("occurrences");
                ObjectNode o = occ.addObject();
                o.put("line", line);
                o.put("location", path);
                o.put("additionalContext", snippet);

                ObjectNode cryptoProps = comp.putObject("cryptoProperties");
                ObjectNode algProps = cryptoProps.putObject("algorithmProperties");
                algProps.put("primitive", primitive);
            }
        }
        return root.toString();
    }

    private ObjectNode prop(String k, String v) {
        ObjectNode n = new ObjectMapper().createObjectNode();
        n.put("name", k);
        n.put("value", v);
        return n;
    }

    private String get(JsonNode n, String k) {
        return n.has(k) ? n.get(k).asText("") : "";
    }

    private String fileBase(String p) {
        int i = p == null ? -1 : p.lastIndexOf('/');
        return i >= 0 ? p.substring(i + 1) : String.valueOf(p);
    }

    private String classifyName(String ruleId, String code) {
        String s = (ruleId + " " + code).toLowerCase();
        if (s.contains("sha-512") || s.contains("sha512") || s.contains("sha_512"))
            return "SHA-512";
        if (s.contains("sha-256") || s.contains("sha256") || s.contains("sha_256"))
            return "SHA-256";
        if (s.contains("aes-cbc"))
            return "AES-CBC";
        if (s.contains("aes-ecb"))
            return "AES-ECB";
        if (s.contains("aes-gcm"))
            return "AES-GCM";
        if (s.contains("publicencrypt") || s.contains("\"rsa-oaep") || s.contains("rsa-oaep"))
            return "RSA";
        if (s.contains("randombytes") || s.contains("forge.random"))
            return "PRNG";
        if (s.contains("aes-128"))
            return "AES-128";
        return "CRYPTO";
    }

    private String classifyPrimitive(String ruleId, String code) {
        String s = (ruleId + " " + code).toLowerCase();
        if (s.contains("sha"))
            return "hash";
        if (s.contains("aes"))
            return "block-cipher";
        if (s.contains("rsa") || s.contains("publicencrypt"))
            return "pke";
        if (s.contains("random"))
            return "drbg";
        return "other";
    }
}
