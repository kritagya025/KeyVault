package com.keyvault.util;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.util.StringUtils;

import java.net.InetAddress;
import java.net.UnknownHostException;

public final class IpUtils {

    private IpUtils() {
    }

    public static String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (StringUtils.hasText(xForwardedFor)) {
            String[] ips = xForwardedFor.split(",");
            if (ips.length > 0 && StringUtils.hasText(ips[0])) {
                return ips[0].trim();
            }
        }
        return request.getRemoteAddr();
    }

    public static boolean matches(String clientIp, String rule) {
        if (!StringUtils.hasText(clientIp) || !StringUtils.hasText(rule)) {
            return false;
        }

        String trimmedRule = rule.trim();
        String trimmedIp = clientIp.trim();

        // Normalize IPv6 loopback
        if ("0:0:0:0:0:0:0:1".equals(trimmedIp) || "::1".equals(trimmedIp)) {
            if ("127.0.0.1".equals(trimmedRule) || "::1".equals(trimmedRule) || "0:0:0:0:0:0:0:1".equals(trimmedRule)) {
                return true;
            }
        }

        if (trimmedRule.contains("/")) {
            return matchesCidr(trimmedIp, trimmedRule);
        }

        try {
            InetAddress clientAddr = InetAddress.getByName(trimmedIp);
            InetAddress ruleAddr = InetAddress.getByName(trimmedRule);
            return clientAddr.equals(ruleAddr);
        } catch (UnknownHostException e) {
            return trimmedIp.equalsIgnoreCase(trimmedRule);
        }
    }

    private static boolean matchesCidr(String clientIp, String cidr) {
        try {
            String[] parts = cidr.split("/");
            if (parts.length != 2) {
                return false;
            }
            InetAddress targetAddr = InetAddress.getByName(parts[0]);
            int prefixLength = Integer.parseInt(parts[1]);

            InetAddress clientAddr = InetAddress.getByName(clientIp);
            byte[] targetBytes = targetAddr.getAddress();
            byte[] clientBytes = clientAddr.getAddress();

            if (targetBytes.length != clientBytes.length) {
                return false;
            }

            int fullBytes = prefixLength / 8;
            for (int i = 0; i < fullBytes; i++) {
                if (targetBytes[i] != clientBytes[i]) {
                    return false;
                }
            }

            int remainingBits = prefixLength % 8;
            if (remainingBits > 0 && fullBytes < targetBytes.length) {
                int mask = (0xFF << (8 - remainingBits)) & 0xFF;
                return (targetBytes[fullBytes] & mask) == (clientBytes[fullBytes] & mask);
            }

            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
