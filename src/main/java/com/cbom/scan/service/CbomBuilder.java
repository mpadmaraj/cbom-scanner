package com.cbom.scan.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.*;

import java.time.Instant;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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

  public String fromSemgrep(String repoUrl, String ref, JsonNode semgrepJson) {
    ObjectNode bom = M.createObjectNode();
    bom.put("bomFormat", "CycloneDX");
    bom.put("specVersion", "1.6");
    bom.put("version", 1);

    // --- metadata
    ObjectNode metadata = bom.putObject("metadata");
    metadata.put("timestamp", Instant.now().toString());
    if (repoUrl != null) {
      metadata.put("supplier", repoUrl);
    }
    ArrayNode tools = metadata.putArray("tools");
    ObjectNode t = tools.addObject();
    t.put("vendor", "Semgrep");
    t.put("name", "Semgrep");
    // you can enrich with version if you like: t.put("version", "...");

    ArrayNode properties = metadata.putArray("properties");
    addProp(properties, "repoUrl", nvl(repoUrl, ""));
    addProp(properties, "ref", nvl(ref, ""));

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
