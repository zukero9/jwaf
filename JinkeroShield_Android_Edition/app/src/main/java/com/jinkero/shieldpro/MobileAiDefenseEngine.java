package com.jinkero.shieldpro;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * 안드로이드 모바일 프로세서(ARM64 빅리틀 아키텍처)에 최적화된 네이티브 AI 방어 및 무결성 검증 엔진
 */
public class MobileAiDefenseEngine {
    private static final String HMAC_SECRET = "JWAF_ANDROID_PRO_V2_MOBILE_HMAC_PEPPER_2026";
    private int evolutionGeneration = 1;

    public double computeShannonEntropy(String input) {
        if (input == null || input.length() < 6) {
            return 1.5;
        }
        int[] counts = new int[256];
        int len = input.length();
        for (int i = 0; i < len; i++) {
            int c = input.charAt(i) & 0xFF;
            counts[c]++;
        }
        double entropy = 0.0;
        for (int count : counts) {
            if (count > 0) {
                double p = (double) count / len;
                entropy -= p * (Math.log(p) / Math.log(2.0));
            }
        }
        return entropy;
    }

    public int computeThreatScore(String payload) {
        if (payload == null || payload.isEmpty()) {
            return 0;
        }
        String lower = payload.toLowerCase();
        if (lower.contains(".apk") || lower.contains(":5555") || lower.contains("adb connect")
                || lower.contains("redirect_uri=http://") || lower.contains("content://sms")
                || lower.contains("ignore all previous instructions")) {
            return 97;
        }
        double entropy = computeShannonEntropy(payload);
        int baseScore = (int) Math.min(95.0, Math.round(entropy * 17.5));
        return Math.max(4, baseScore);
    }

    public String computeHmacSha256(String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec spec = new SecretKeySpec(HMAC_SECRET.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(spec);
            byte[] raw = mac.doFinal((data == null ? "" : data).getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(raw.length * 2);
            for (byte b : raw) {
                sb.append(String.format("%02x", b & 0xff));
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    public String sha256Hex(byte[] bytes) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(bytes);
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(String.format("%02x", b & 0xff));
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    public int getEvolutionGeneration() {
        return evolutionGeneration;
    }

    public int evolveGeneration() {
        evolutionGeneration++;
        return evolutionGeneration;
    }
}

