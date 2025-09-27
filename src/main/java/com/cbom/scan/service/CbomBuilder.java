package com.cbom.scan.service;

import java.io.File;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.yaml.snakeyaml.Yaml;

import com.cbom.scan.model.ScanJob;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * Build a CycloneDX 1.6 CBOM (JSON) from Semgrep results.
 * - bomFormat: CycloneDX
 * - specVersion: 1.6
 * - components[].type = "cryptographic-asset"
 * - components[].cryptoProperties.assetType = "algorithm" | "protocol" |
 * "certificate" | "relatedCryptoMaterial"
 * - components[].cryptoProperties.algorithmProperties.{primitive, mode,
 * parameterSetIdentifier}
 * - evidence.occurrences with file + line + snippet
 * - metadata.tools includes "Semgrep"
 */
public class CbomBuilder {
  private static final ObjectMapper M = new ObjectMapper();

  public String fromSemgrep(ScanJob job, JsonNode semgrepJson, String semgrepConfig) {
    ObjectNode bom = M.createObjectNode();
    bom.put("bomFormat", "CycloneDX");
    bom.put("specVersion", "1.6");
    bom.put("version", 1);

    // --- metadata
    ObjectNode metadata = bom.putObject("metadata");
    metadata.put("timestamp", Instant.now().toString());
    if (job != null && job.getRepoUrl() != null) {
      metadata.put("supplier", job.getRepoUrl());
    }
    ArrayNode tools = metadata.putArray("tools");
    ObjectNode t = tools.addObject();
    t.put("vendor", "Semgrep");
    t.put("name", "Semgrep");

    ArrayNode properties = metadata.putArray("properties");
    addProp(properties, "repoUrl", job != null ? nvl(job.getRepoUrl(), "") : "");
    addProp(properties, "ref", job != null ? nvl(job.getRef(), "") : "");
    addProp(properties, "semgrepConfig", nvl(semgrepConfig, ""));

    // --- Load Semgrep config YAML for rule metadata enrichment ---
    Map<String, Map<String, Object>> ruleMeta = new HashMap<>();
    try {
      File yamlFile = new File(semgrepConfig);
      if (yamlFile.exists()) {
        Yaml yaml = new Yaml();
        Map<String, Object> yamlObj = yaml.load(new java.io.FileInputStream(yamlFile));
        if (yamlObj != null && yamlObj.containsKey("rules")) {
          List<?> rules = (List<?>) yamlObj.get("rules");
          for (Object ruleObj : rules) {
            if (ruleObj instanceof Map) {
              Map<String, Object> rule = (Map<String, Object>) ruleObj;
              String id = rule.getOrDefault("id", "").toString();
              ruleMeta.put(id, rule);
            }
          }
        }
      }
    } catch (Exception e) {
      // ignore YAML errors, fallback to Semgrep results only
    }

    // --- components (cryptographic-asset)
    ArrayNode components = bom.putArray("components");
    if (semgrepJson != null && semgrepJson.has("results")) {
      for (JsonNode r : semgrepJson.get("results")) {
        String ruleId = txt(r, "check_id");
        String path = txt(r.path("path"), "path");
        int line = r.path("start").path("line").asInt(-1);
        String lang = txt(r.path("extra"), "language");
        String code = txt(r.path("extra"), "lines");

        // classify algorithm info
        String assetType = classifyAssetType(ruleId, code); // most detections are "algorithm"
        String primitive = classifyPrimitive(ruleId, code); // e.g., hash | block-cipher | pke | drbg
        String mode = classifyMode(ruleId, code); // gcm | cbc | ecb | ""
        String bits = classifyBits(ruleId, code); // "128"|"256"|"" (parameterSetIdentifier)
        String name = buildDisplayName(primitive, mode, bits); // "AES-128-GCM" etc.

        ObjectNode comp = components.addObject();
        comp.put("type", "cryptographic-asset");
        comp.put("bom-ref", ruleId + "@" + path + ":" + Math.max(line, 0));
        comp.put("name", name);
        comp.put("scope", "required");
        if (code != null && !code.isBlank())
          comp.put("description", code.trim());

        // optional grouping by file
        comp.put("group", baseName(path));

        // evidence
        ObjectNode evidence = comp.putObject("evidence");
        ArrayNode occ = evidence.putArray("occurrences");
        ObjectNode o = occ.addObject();
        o.put("location", nvl(path, ""));
        if (line > 0)
          o.put("line", line);
        if (code != null && !code.isBlank())
          o.put("additionalContext", code);

        // cryptoProperties (CBOM)
        ObjectNode cryptoProps = comp.putObject("cryptoProperties");
        cryptoProps.put("assetType", assetType); // "algorithm" most commonly for Semgrep hits

        ObjectNode algProps = cryptoProps.putObject("algorithmProperties");
        if (!primitive.isBlank())
          algProps.put("primitive", primitive);
        if (!mode.isBlank())
          algProps.put("mode", mode);
        if (!bits.isBlank())
          algProps.put("parameterSetIdentifier", bits);

        // extra properties (not required, but useful)
        ArrayNode cprops = comp.putArray("properties");
        addProp(cprops, "language", nvl(lang, ""));
        addProp(cprops, "detectionMethod", "static-analysis");
        addProp(cprops, "ruleId", ruleId);

        // --- Enrich with rule metadata from YAML config ---
        if (ruleMeta.containsKey(ruleId)) {
          Map<String, Object> meta = ruleMeta.get(ruleId);
          if (meta.containsKey("severity")) {
            addProp(cprops, "severity", meta.get("severity").toString());
          }
          if (meta.containsKey("message")) {
            addProp(cprops, "message", meta.get("message").toString());
          }
          if (meta.containsKey("patterns")) {
            addProp(cprops, "patterns", meta.get("patterns").toString());
          }
          if (meta.containsKey("languages")) {
            addProp(cprops, "languages", meta.get("languages").toString());
          }
          if (meta.containsKey("id")) {
            addProp(cprops, "ruleConfigId", meta.get("id").toString());
          }
        }
      }
    }

    return bom.toString();
  }

  // ---------- helpers ----------

  private static void addProp(ArrayNode props, String k, String v) {
    if (v == null)
      v = "";
    ObjectNode p = props.addObject();
    p.put("name", k);
    p.put("value", v);
  }

  private static String txt(JsonNode node, String key) {
    return node.has(key) ? node.get(key).asText("") : "";
  }

  private static String nvl(String s, String d) {
    return s == null ? d : s;
  }

  private static String baseName(String path) {
    if (path == null)
      return "";
    int i = path.lastIndexOf('/');
    return i >= 0 ? path.substring(i + 1) : path;
  }

  /**
   * "algorithm" for primitives we detect; you can extend to "protocol" for TLS,
   * etc.
   */
  private static String classifyAssetType(String ruleId, String code) {
    String s = (ruleId + " " + nvl(code, "")).toLowerCase(Locale.ROOT);
    if (s.contains("tls") || s.contains("https") || s.contains("pkcs"))
      return "protocol";
    // certificates/keys could be "relatedCryptoMaterial" if you add detectors.
    return "algorithm";
  }

  private static String classifyPrimitive(String ruleId, String code) {
    String s = (ruleId + " " + nvl(code, "")).toLowerCase(Locale.ROOT);
    if (s.contains("sha"))
      return "hash";
    if (s.contains("aes")) {
      if (s.contains("gcm"))
        return "ae"; // authenticated encryption (common CBOM shorthand)
      return "block-cipher";
    }
    if (s.contains("rsa") || s.contains("publicencrypt") || s.contains("oaep"))
      return "pke";
    if (s.contains("randombytes") || s.contains("forge.random") || s.contains("drbg"))
      return "drbg";
    return "other";
  }

  private static String classifyMode(String ruleId, String code) {
    String s = (ruleId + " " + nvl(code, "")).toLowerCase(Locale.ROOT);
    if (s.contains("gcm"))
      return "gcm";
    if (s.contains("cbc"))
      return "cbc";
    if (s.contains("ecb"))
      return "ecb";
    if (s.contains("ctr"))
      return "ctr";
    return "";
  }

  private static String classifyBits(String ruleId, String code) {
    String s = (ruleId + " " + nvl(code, ""));
    // find 128/192/256 in rule/code; very permissive
    Matcher m = Pattern.compile("\\b(128|192|256)\\b").matcher(s);
    if (m.find())
      return m.group(1);
    // Node ciphers like 'aes-128-ecb'
    m = Pattern.compile("aes[-_]?((128|192|256))", Pattern.CASE_INSENSITIVE).matcher(s);
    if (m.find())
      return m.group(1);
    return "";
  }

  private static String buildDisplayName(String primitive, String mode, String bits) {
    // Pretty label e.g., AES-128-GCM, SHA-256, RSA-OAEP
    if ("hash".equals(primitive)) {
      if ("".equals(bits)) {
        // try pulling from mode/misc but hashes don't have modes; fallback:
        return "Hash";
      }
      return "SHA-" + bits;
    }
    if ("pke".equals(primitive)) {
      if ("".equals(mode))
        return "RSA";
      // we often get "oaep"
      return "RSA-" + mode.toUpperCase(Locale.ROOT);
    }
    if ("ae".equals(primitive) || "block-cipher".equals(primitive)) {
      String b = bits.isBlank() ? "" : (bits + "-");
      String m = mode.isBlank() ? "" : mode.toUpperCase(Locale.ROOT);
      if (m.isBlank())
        return "AES-" + b + "BLOCK";
      return "AES-" + b + m;
    }
    if ("drbg".equals(primitive))
      return "Random-Bytes";
    return "CRYPTO";
  }
}
