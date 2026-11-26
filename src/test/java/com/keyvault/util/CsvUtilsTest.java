package com.keyvault.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CsvUtilsTest {

    @Test
    void handlesNullAndEmptyStrings() {
        assertEquals("", CsvUtils.escape(null));
        assertEquals("", CsvUtils.escape(""));
    }

    @Test
    void leavesSafePlainTextUnchanged() {
        assertEquals("Production API Key", CsvUtils.escape("Production API Key"));
        assertEquals("2026-11-26T10:00:00", CsvUtils.escape("2026-11-26T10:00:00"));
    }

    @Test
    void quotesRfc4180SpecialCharacters() {
        assertEquals("\"alpha, beta\"", CsvUtils.escape("alpha, beta"));
        assertEquals("\"say \"\"hello\"\"\"", CsvUtils.escape("say \"hello\""));
        assertEquals("\"line1\nline2\"", CsvUtils.escape("line1\nline2"));
    }

    @Test
    void neutralizesFormulaInjectionPrefixes() {
        assertEquals("'=SUM(A1:A2)", CsvUtils.escape("=SUM(A1:A2)"));
        assertEquals("'+1+1", CsvUtils.escape("+1+1"));
        assertEquals("'-cmd|' /C calc'!A0", CsvUtils.escape("-cmd|' /C calc'!A0"));
        assertEquals("'@SUM(1+1)", CsvUtils.escape("@SUM(1+1)"));
        assertEquals("'\t=1+1", CsvUtils.escape("\t=1+1"));
        assertEquals("\"\'\r=1+1\"", CsvUtils.escape("\r=1+1"));
        assertEquals("\"'=SUM(1,2)\"", CsvUtils.escape("=SUM(1,2)"));
    }
}
