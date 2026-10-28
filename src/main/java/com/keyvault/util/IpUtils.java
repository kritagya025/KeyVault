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

    public static boolean isValidIpOrCidr(String rule) {
        if (!StringUtils.hasText(rule)) {
            return false;
        }

        String trimmed = rule.trim();
        if (trimmed.contains("/")) {
            String[] parts = trimmed.split("/");
            if (parts.length != 2) {
                return false;
            }
            String ipPart = parts[0].trim();
            int prefix;
            try {
                prefix = Integer.parseInt(parts[1].trim());
            } catch (NumberFormatException e) {
                return false;
            }

            if (isValidIpv4(ipPart)) {
                return prefix >= 0 && prefix <= 32;
            } else if (isValidIpv6(ipPart)) {
                return prefix >= 0 && prefix <= 128;
            }
            return false;
        } else {
            return isValidIpv4(trimmed) || isValidIpv6(trimmed);
        }
    }

    public static boolean isValidIpv4(String ip) {
        if (!StringUtils.hasText(ip)) {
            return false;
        }
        String[] octets = ip.split("\\.", -1);
        if (octets.length != 4) {
            return false;
        }
        for (String octet : octets) {
            if (octet.isEmpty() || octet.length() > 3) {
                return false;
            }
            for (int i = 0; i < octet.length(); i++) {
                if (!Character.isDigit(octet.charAt(i))) {
                    return false;
                }
            }
            if (octet.length() > 1 && octet.startsWith("0")) {
                return false;
            }
            int val;
            try {
                val = Integer.parseInt(octet);
            } catch (NumberFormatException e) {
                return false;
            }
            if (val < 0 || val > 255) {
                return false;
            }
        }
        return true;
    }

    public static boolean isValidIpv6(String ip) {
        if (!StringUtils.hasText(ip) || !ip.contains(":")) {
            return false;
        }
        if (!ip.matches("^[0-9a-fA-F:]+$")) {
            return false;
        }
        try {
            InetAddress addr = InetAddress.getByName(ip);
            return addr.getAddress().length == 16;
        } catch (UnknownHostException e) {
            return false;
        }
    }
}
