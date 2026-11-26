package com.keyvault.util;

/**
 * Shared RFC 4180 CSV escaping utilities with CSV formula injection (CWE-1236) mitigation.
 */
public final class CsvUtils {

    private CsvUtils() {
    }

    /**
     * Escapes a CSV cell value according to RFC 4180 and neutralizes spreadsheet formula injection
     * by prefixing values that start with formula-trigger characters ({@code =}, {@code +},
     * {@code -}, {@code @}, tab, or carriage return) with a single quote.
     *
     * @param value raw cell text (may be {@code null})
     * @return safe CSV-encoded string
     */
    public static String escape(String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }

        String sanitized = isFormulaTrigger(value.charAt(0)) ? "'" + value : value;

        if (sanitized.contains(",")
                || sanitized.contains("\"")
                || sanitized.contains("\n")
                || sanitized.contains("\r")) {
            return "\"" + sanitized.replace("\"", "\"\"") + "\"";
        }

        return sanitized;
    }

    private static boolean isFormulaTrigger(char c) {
        return c == '=' || c == '+' || c == '-' || c == '@' || c == '\t' || c == '\r';
    }
}
